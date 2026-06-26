#!/usr/bin/env python3
"""
fs5000_dual.py  —  Bosean FS-5000 Dual-Stream Forensic Logger
==============================================================
STREAM A — Serial (USB/CH340)  → serial_STAMP.jsonl.gz
STREAM B — Audio (headphone jack → USB adapter) → audio_STAMP.jsonl.gz

Phase 1 (first 20s): Collects all audio peaks above noise floor.
  Serial CPS is ground truth for how many real events occurred.
  At 20s: top-N peaks (N=serial count) → median = event threshold.

Phase 2 (live): Only peaks >= calibrated threshold are logged.

Usage:
  python fs5000_dual.py --port COM5
  python fs5000_dual.py --port COM5 --out C:\\path\\to\\logs
  python fs5000_dual.py --list-audio
  pip install pyaudio pyserial
"""

import argparse
import datetime
import gzip
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: pip install pyserial")
    sys.exit(1)

try:
    import pyaudio
except ImportError:
    print("ERROR: pip install pyaudio")
    sys.exit(1)

# ── constants ──────────────────────────────────────────────────────────────
CH340_VID               = 0x1A86
CH340_PID               = 0x7523
BAUD                    = 115200
DEFAULT_SPIKE_THRESHOLD = 0.01
DANGEROUS_THRESHOLD     = 0.20
CHUNK_FRAMES            = 256
PREFERRED_RATES         = [48000, 44100]

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

_LIVE_RE = re.compile(
    rb'DR:(?P<dr>[\d.]+)uSv/h;'
    rb'D:(?P<dose>[\d. ]+)uSv;'
    rb'(?:CPS:(?P<cps>[\d]+);)?'
    rb'CPM:(?P<cpm>[\d]+)'
)

APIS_TO_NAME: dict = {}

def _populate_api_names(pa: pyaudio.PyAudio):
    global APIS_TO_NAME
    for i in range(pa.get_host_api_count()):
        APIS_TO_NAME[i] = pa.get_host_api_info_by_index(i)['name']

# ── packet framing ─────────────────────────────────────────────────────────
def _cs(data: bytes) -> int:
    return sum(data) % 256

def make_packet(payload: bytes) -> bytes:
    hdr  = bytes([0xAA, len(payload) + 3])
    body = hdr + payload
    return body + bytes([_cs(body)]) + bytes([0x55])

# ── NTP query ──────────────────────────────────────────────────────────────
def get_ntp_info() -> dict:
    result = {
        "ntp_source":        "unknown",
        "ntp_last_sync_utc": "unknown",
        "ntp_offset_s":      None,
        "ntp_query_method":  "w32tm",
        "ntp_error":         None,
        "ntp_raw_output":    "",
    }
    try:
        proc   = subprocess.run(
            ["w32tm", "/query", "/status"],
            capture_output=True, text=True, timeout=5
        )
        output = proc.stdout + proc.stderr
        result["ntp_raw_output"] = output.strip()
        for line in output.splitlines():
            line = line.strip()
            ll   = line.lower()
            if ll.startswith("source:"):
                result["ntp_source"] = line.split(":", 1)[1].strip()
            elif ll.startswith("last successful sync time:"):
                result["ntp_last_sync_utc"] = line.split(":", 1)[1].strip()
            elif ll.startswith("last clock update time:"):
                if result["ntp_last_sync_utc"] == "unknown":
                    result["ntp_last_sync_utc"] = line.split(":", 1)[1].strip()
            elif "offset" in ll and "last" not in ll:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    val = parts[1].strip().rstrip("s").strip()
                    try:
                        result["ntp_offset_s"] = float(val)
                    except ValueError:
                        result["ntp_offset_s"] = val
        result["ntp_query_method"] = "w32tm /query /status"
    except FileNotFoundError:
        result["ntp_error"] = "w32tm not found"
    except subprocess.TimeoutExpired:
        result["ntp_error"] = "w32tm timed out"
    except Exception as e:
        result["ntp_error"] = f"w32tm exception: {e}"
    return result

# ── clock anchor ───────────────────────────────────────────────────────────
class ClockAnchor:
    def __init__(self):
        best_gap = None
        for _ in range(32):
            t1 = time.perf_counter_ns()
            w  = time.time_ns()
            t2 = time.perf_counter_ns()
            gap = t2 - t1
            if best_gap is None or gap < best_gap:
                best_gap         = gap
                self._mono_epoch = (t1 + t2) // 2
                self._wall_epoch = w
        self.session_wall_ns  = self._wall_epoch
        self.session_mono_ns  = self._mono_epoch
        self.session_wall_utc = datetime.datetime.fromtimestamp(
            self._wall_epoch / 1e9, tz=datetime.timezone.utc
        ).isoformat()
        whole_s = self._wall_epoch // 1_000_000_000
        self.session_wall_ns_remainder = (
            self._wall_epoch - whole_s * 1_000_000_000
        )

    def now(self) -> tuple:
        mono_now = time.perf_counter_ns()
        delta    = mono_now - self._mono_epoch
        return self._wall_epoch + delta, delta

    def format_wall_ns(self, wall_ns: int) -> str:
        whole_s = wall_ns // 1_000_000_000
        frac_ns = wall_ns  % 1_000_000_000
        base    = datetime.datetime.fromtimestamp(
            whole_s, tz=datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%S')
        return f"{base}.{frac_ns:09d}Z"

# ── gzip log ───────────────────────────────────────────────────────────────
class GzipLog:
    def __init__(self, path: str, header: dict):
        self.path    = path
        self._q      = deque()
        self._event  = threading.Event()
        self._stop   = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name=f'GzipLog:{os.path.basename(path)}'
        )
        first = json.dumps(header, separators=(',', ':')) + '\n'
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(first.encode())
        self._thread.start()

    def write(self, obj: dict):
        self._q.append(obj)
        self._event.set()

    def close(self):
        self._stop.set()
        self._event.set()
        self._thread.join(timeout=8)

    def _run(self):
        while not self._stop.is_set():
            self._event.wait()
            self._event.clear()
            self._drain()
        self._drain()

    def _drain(self):
        if not self._q:
            return
        lines = []
        while self._q:
            lines.append(
                json.dumps(self._q.popleft(), separators=(',', ':'))
            )
        blob = ('\n'.join(lines) + '\n').encode()
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(blob)

# ── serial port discovery ──────────────────────────────────────────────────
def find_serial_port(forced=None) -> str:
    available = list(serial.tools.list_ports.comports())
    print("\nAvailable serial ports:")
    if not available:
        print("  (none detected)")
    for p in available:
        marker = " ← CH340 FS-5000" if (
            p.vid == CH340_VID and p.pid == CH340_PID) else ""
        print(f"  {p.device:<10} {p.description}{marker}")
    print()

    if forced:
        names = [p.device.upper() for p in available]
        if forced.upper() not in names:
            print(f"  {forced} not seen yet — waiting up to 30s...")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                current = [p.device.upper()
                           for p in serial.tools.list_ports.comports()]
                if forced.upper() in current:
                    print(f"  {forced} detected.")
                    break
                time.sleep(1)
                sys.stdout.write('.')
                sys.stdout.flush()
            else:
                print(f"\nERROR: {forced} never appeared.")
                print("  Check: Device Manager → Ports (COM & LPT)")
                print("  https://www.wch-ic.com/downloads/CH341SER_EXE.html")
                sys.exit(1)
        return forced

    for p in available:
        if p.vid == CH340_VID and p.pid == CH340_PID:
            print(f"[AUTO] FS-5000 detected on {p.device}")
            return p.device

    print("ERROR: CH340 not found. Use --port COMx")
    sys.exit(1)

# ── audio device discovery ─────────────────────────────────────────────────
def list_audio_devices(pa: pyaudio.PyAudio):
    print("\nAvailable audio INPUT devices:")
    print(f"  {'Idx':<5} {'API':<24} {'Name':<42} {'Ch':<4} {'Rate'}")
    print(f"  {'-'*5} {'-'*24} {'-'*42} {'-'*4} {'-'*8}")
    for i in range(pa.get_device_count()):
        info = pa.get_device_info_by_index(i)
        if info['maxInputChannels'] < 1:
            continue
        api = APIS_TO_NAME.get(info['hostApi'], str(info['hostApi']))
        print(f"  {i:<5} {api:<24} {info['name'][:41]:<42} "
              f"{int(info['maxInputChannels']):<4} "
              f"{int(info['defaultSampleRate'])}")
    print()

def _try_open_stream(pa, dev_index, rate, chunk, callback):
    try:
        s = pa.open(
            format             = pyaudio.paFloat32,
            channels           = 1,
            rate               = rate,
            input              = True,
            input_device_index = dev_index,
            frames_per_buffer  = chunk,
            stream_callback    = callback,
        )
        return s
    except Exception:
        return None

def find_audio_device_and_open(pa: pyaudio.PyAudio,
                               forced_index,
                               chunk: int,
                               callback) -> tuple:
    """
    Returns (stream, device_index, sample_rate, api_name).
    Searches by device name — survives USB replug index shifts.
    WDM-KS first (confirmed working on this machine).
    """
    api_index_by_name = {}
    for i in range(pa.get_host_api_count()):
        name = pa.get_host_api_info_by_index(i)['name'].lower()
        api_index_by_name[name] = i

    def usb_devices_for_api(api_name_lower):
        api_idx = api_index_by_name.get(api_name_lower)
        if api_idx is None:
            return []
        out = []
        for i in range(pa.get_device_count()):
            info = pa.get_device_info_by_index(i)
            if (info['maxInputChannels'] >= 1
                    and info['hostApi'] == api_idx
                    and 'usb' in info['name'].lower()):
                out.append(i)
        return out

    attempts = []

    # Stage 1: forced index
    if forced_index is not None:
        info = pa.get_device_info_by_index(forced_index)
        for rate in PREFERRED_RATES:
            print(f"  Trying forced [{forced_index}] "
                  f"{info['name'][:30]} @ {rate} Hz ...", end=' ')
            s = _try_open_stream(pa, forced_index, rate, chunk, callback)
            if s:
                print("OK")
                api = APIS_TO_NAME.get(info['hostApi'], '?')
                return s, forced_index, rate, api
            print("failed")
            attempts.append(f"forced [{forced_index}] @ {rate}")

    # Stages 2-5: API priority, USB by name
    api_priority = [
        'windows wdm-ks',
        'windows wasapi',
        'mme',
        'windows directsound',
    ]
    for api_name_lower in api_priority:
        api_display = APIS_TO_NAME.get(
            api_index_by_name.get(api_name_lower, -1),
            api_name_lower
        )
        for dev in usb_devices_for_api(api_name_lower):
            info = pa.get_device_info_by_index(dev)
            for rate in PREFERRED_RATES:
                print(f"  Trying [{api_display}] [{dev}] "
                      f"{info['name'][:28]} @ {rate} Hz ...", end=' ')
                s = _try_open_stream(pa, dev, rate, chunk, callback)
                if s:
                    print("OK")
                    return s, dev, rate, api_display
                print("failed")
                attempts.append(f"[{api_display}] [{dev}] @ {rate}")

    # Stage 6: any USB device not already tried
    seen = set()
    for i in range(pa.get_device_count()):
        info = pa.get_device_info_by_index(i)
        if (info['maxInputChannels'] >= 1
                and 'usb' in info['name'].lower()
                and i not in seen):
            seen.add(i)
            api_display = APIS_TO_NAME.get(info['hostApi'], '?')
            for rate in PREFERRED_RATES:
                print(f"  Trying [{api_display}] [{i}] "
                      f"{info['name'][:28]} @ {rate} Hz ...", end=' ')
                s = _try_open_stream(pa, i, rate, chunk, callback)
                if s:
                    print("OK")
                    return s, i, rate, api_display
                print("failed")
                attempts.append(f"[{api_display}] [{i}] @ {rate}")

    # Stage 7: system default
    try:
        def_idx  = pa.get_default_input_device_info()['index']
        def_info = pa.get_device_info_by_index(def_idx)
        for rate in PREFERRED_RATES:
            print(f"  Trying [default] [{def_idx}] "
                  f"{def_info['name'][:28]} @ {rate} Hz ...", end=' ')
            s = _try_open_stream(pa, def_idx, rate, CHUNK_FRAMES, callback)
            if s:
                api = APIS_TO_NAME.get(def_info['hostApi'], '?')
                print("OK  (system default fallback)")
                return s, def_idx, rate, api
            print("failed")
            attempts.append(f"[default] [{def_idx}] @ {rate}")
    except Exception:
        pass

    print("\nERROR: Could not open any audio input stream.")
    print("Attempted:")
    for a in attempts:
        print(f"  {a}")
    print()
    print("Fix options:")
    print("  1. Run --list-audio and pass index with --audio-device N")
    print("  2. Windows Sound → Recording → USB Device → Properties → Advanced")
    print("     Set: 1 channel, 16 bit, 48000 Hz")
    print("     Uncheck 'Allow exclusive control'")
    print("  3. Unplug/replug the USB audio adapter")
    sys.exit(1)

# ── pulse detector ─────────────────────────────────────────────────────────
class PulseDetector:
    """
    Self-calibrating GM chirp detector.

    Phase 1 — CALIBRATION (first cal_window_s seconds, default 20s):
      Collects every peak above a very low noise floor.
      Serial CPS is fed in via serial_count_add() as ground truth.
      At end of calibration window:
        - All audio peaks sorted descending by amplitude
        - Top-N taken where N = total serial CPS count
        - event_threshold = median of those top-N peaks
        - Calibration record written to audio log

    Phase 2 — LIVE:
      Only peaks >= event_threshold are accepted and logged.
      Refractory (1ms) blocks re-trigger on same chirp's echo only —
      does NOT block legitimately fast consecutive real pulses.
    """

    CAL_WINDOW_S    = 20.0
    FLOOR_THRESHOLD = 0.0001
    REFRACTORY_S    = 0.001

    def __init__(self, clock, log, sample_rate: int,
                 cal_window_s:    float = CAL_WINDOW_S,
                 floor_threshold: float = FLOOR_THRESHOLD,
                 refractory_s:    float = REFRACTORY_S,
                 on_pulse=None,
                 on_calibrated=None):

        self.clock           = clock
        self.log             = log
        self.sample_rate     = sample_rate
        self.cal_window_s    = cal_window_s
        self.floor_threshold = floor_threshold
        self.refractory_ns   = int(refractory_s * 1e9)
        self.on_pulse        = on_pulse
        self.on_calibrated   = on_calibrated

        self._ns_per_sample   = int(1_000_000_000 / sample_rate)
        self._stream_start_ns = None
        self._total_samples   = 0

        # Calibration
        self._calibrated     = False
        self._cal_end_sample = int(cal_window_s * sample_rate)
        self._cal_peaks      = []      # list of float amplitudes
        self._serial_count   = 0
        self._serial_lock    = threading.Lock()

        # Live
        self.event_threshold  = None
        self._seq             = 0
        self._last_trigger_ns = 0

        # Peak finder state machine
        self._state            = 'IDLE'
        self._pulse_peak       = 0.0
        self._pulse_start_mono = 0
        self._peak_mono        = 0

    # ── serial thread feeds CPS ground truth ───────────────────────────
    def serial_count_add(self, cps: int):
        if not self._calibrated and cps > 0:
            with self._serial_lock:
                self._serial_count += cps

    # ── audio callback feeds samples ───────────────────────────────────
    def feed_chunk(self, samples, num_frames: int):
        chunk_arrival_ns = time.perf_counter_ns()

        if self._stream_start_ns is None:
            self._stream_start_ns = (
                chunk_arrival_ns - num_frames * self._ns_per_sample
            )

        chunk_start_idx      = self._total_samples
        self._total_samples += num_frames

        # Trigger calibration completion on the first chunk that
        # crosses the window boundary
        if not self._calibrated and self._total_samples >= self._cal_end_sample:
            self._finalize_calibration()

        for i, s in enumerate(samples):
            amp        = abs(s)
            sample_idx = chunk_start_idx + i

            mono_ns = (
                self._stream_start_ns
                - self.clock.session_mono_ns
                + sample_idx * self._ns_per_sample
            )

            # IDLE: wait for signal to rise above floor
            if self._state == 'IDLE':
                if amp >= self.floor_threshold:
                    self._state            = 'RISING'
                    self._pulse_peak       = amp
                    self._pulse_start_mono = mono_ns
                    self._peak_mono        = mono_ns

            # RISING: track the peak, emit when signal falls back
            elif self._state == 'RISING':
                if amp >= self.floor_threshold:
                    if amp > self._pulse_peak:
                        self._pulse_peak = amp
                        self._peak_mono  = mono_ns
                else:
                    # Signal fell — peak is complete, emit it
                    self._emit_peak(self._pulse_peak, self._peak_mono)
                    self._state = 'IDLE'

    # ── peak emission ──────────────────────────────────────────────────
    def _emit_peak(self, amplitude: float, mono_ns: int):
        if not self._calibrated:
            # Calibration phase — just collect
            self._cal_peaks.append(amplitude)
            return

        # Live phase — qualify against calibrated threshold
        if amplitude < self.event_threshold:
            return

        # Refractory — blocks echo re-trigger only
        if mono_ns - self._last_trigger_ns < self.refractory_ns:
            return

        self._last_trigger_ns = mono_ns
        wall_ns = self.clock.session_wall_ns + mono_ns
        self._seq += 1

        self.log.write({
            "seq":       self._seq,
            "wall_ns":   wall_ns,
            "wall_iso":  self.clock.format_wall_ns(wall_ns),
            "mono_ns":   mono_ns,
            "amplitude": round(float(amplitude), 6),
        })

        if self.on_pulse:
            self.on_pulse(wall_ns, amplitude)

    # ── calibration finalization ───────────────────────────────────────
    def _finalize_calibration(self):
        self._calibrated = True

        with self._serial_lock:
            n_events = self._serial_count

        all_peaks = sorted(self._cal_peaks, reverse=True)
        total     = len(all_peaks)

        if total == 0:
            self.event_threshold = self.floor_threshold * 10
            method = "no_peaks_detected"

        elif n_events == 0:
            # No serial counts — use top 1% of peaks conservatively
            top_n = max(1, total // 100)
            self.event_threshold = all_peaks[top_n - 1]
            method = "serial_zero_fallback_top1pct"

        elif n_events >= total:
            # More serial counts than audio peaks — use median of all
            self.event_threshold = all_peaks[total // 2]
            method = "more_serial_than_peaks_use_median"

        else:
            # Normal: top-N peaks where N = serial count, threshold = median
            top_n_peaks          = all_peaks[:n_events]
            self.event_threshold = top_n_peaks[len(top_n_peaks) // 2]
            method               = "median_of_top_n"

        self.log.write({
            "type":              "calibration_complete",
            "cal_window_s":      self.cal_window_s,
            "serial_counts":     n_events,
            "total_peaks_found": total,
            "event_threshold":   round(self.event_threshold, 8),
            "method":            method,
            "top_20_peaks":      [round(p, 6) for p in all_peaks[:20]],
        })

        if self.on_calibrated:
            self.on_calibrated(self.event_threshold, n_events, total)

    @property
    def pulse_count(self) -> int:
        return self._seq

    @property
    def calibrated(self) -> bool:
        return self._calibrated

    @property
    def cal_seconds_remaining(self) -> float:
        if self._calibrated:
            return 0.0
        if self._stream_start_ns is None:
            return self.cal_window_s
        elapsed = self._total_samples / self.sample_rate
        return max(0.0, self.cal_window_s - elapsed)

# ── serial stream ──────────────────────────────────────────────────────────
def run_serial(port_name, clock, log, spike_threshold,
               quiet, stop_event, audio_pulse_count_fn,
               detector_ref):
    buf      = bytearray()
    last_dr  = None
    last_cpm = None
    seq      = 0
    try:
        with serial.Serial(port_name, BAUD, timeout=0.05) as port:
            port.reset_input_buffer()
            port.write(make_packet(bytes([0x0e, 0x00])))
            time.sleep(0.5)
            port.reset_input_buffer()
            port.write(make_packet(bytes([0x0e, 0x01])))
            time.sleep(0.3)
            ack = port.read(port.in_waiting or 1)
            if ack:
                if ack[0] == 0xAA and len(ack) > 1:
                    skip = 2 + ack[1]
                    if len(ack) > skip:
                        buf.extend(ack[skip:])
                else:
                    buf.extend(ack)

            while not stop_event.is_set():
                chunk = port.read(4096)
                if not chunk:
                    continue
                buf.extend(chunk)
                matches = list(_LIVE_RE.finditer(buf))
                if not matches:
                    if len(buf) > 512:
                        buf = buf[-512:]
                    continue

                for m in matches:
                    try:
                        dr      = float(m.group('dr'))
                        cpm     = int(m.group('cpm'))
                        cps_raw = m.group('cps')
                        cps     = (int(cps_raw) if cps_raw is not None
                                   else (cpm // 60))
                        dose    = float(m.group('dose').strip())
                    except (ValueError, AttributeError):
                        continue

                    # Feed CPS into detector for calibration
                    det = detector_ref[0]
                    if det is not None:
                        det.serial_count_add(cps)

                    wall_ns, mono_ns = clock.now()
                    seq += 1
                    log.write({
                        "seq":      seq,
                        "wall_ns":  wall_ns,
                        "wall_iso": clock.format_wall_ns(wall_ns),
                        "mono_ns":  mono_ns,
                        "dr":       dr,
                        "cpm":      cpm,
                        "cps":      cps,
                        "dose":     dose,
                    })

                    if not quiet and (dr != last_dr or cpm != last_cpm):
                        last_dr  = dr
                        last_cpm = cpm
                        aud = audio_pulse_count_fn()
                        det = detector_ref[0]

                        if det and not det.calibrated:
                            cal_rem  = det.cal_seconds_remaining
                            cal_str  = f"CAL {cal_rem:4.1f}s "
                        elif det and det.event_threshold is not None:
                            cal_str  = f"THR={det.event_threshold:.5f} "
                        else:
                            cal_str  = ""

                        if dr >= DANGEROUS_THRESHOLD:
                            flag = '!!! DANGEROUS !!!'
                        elif dr >= spike_threshold:
                            flag = '*** SPIKE ***'
                        else:
                            flag = ''

                        bar = chr(0x2588) * min(25, int(dr * 100))
                        ts  = datetime.datetime.now(
                            tz=datetime.timezone.utc).strftime('%H:%M:%S')
                        print(
                            f"\r  {ts}  {dr:7.4f} uSv/h  "
                            f"CPS={cps:>4}  CPM={cpm:>5}  "
                            f"AUD={aud:>7}  {cal_str}"
                            f"{bar:<25}  {flag}   ",
                            end='', flush=True
                        )

                buf = buf[max(0, matches[-1].end() - 512):]

    except Exception as e:
        if not stop_event.is_set():
            print(f"\n[serial] error: {type(e).__name__}: {e}")
    finally:
        try:
            with serial.Serial(port_name, BAUD, timeout=2) as p:
                p.write(make_packet(bytes([0x0e, 0x00])))
                time.sleep(0.2)
        except Exception:
            pass

# ── main ───────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="FS-5000 Dual-Stream Forensic Logger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--port',            help='Serial port e.g. COM5')
    ap.add_argument('--out',             default='.', metavar='DIR')
    ap.add_argument('--audio-device',    type=int, default=None, metavar='N')
    ap.add_argument('--list-audio',      action='store_true')
    ap.add_argument('--cal-window',      type=float, default=20.0, metavar='S',
                    help='Calibration window seconds (default 20)')
    ap.add_argument('--floor',           type=float, default=0.0001, metavar='F',
                    help='Noise floor threshold during calibration (default 0.0001)')
    ap.add_argument('--refractory',      type=float, default=0.001, metavar='S',
                    help='Refractory seconds — echo suppression only (default 0.001)')
    ap.add_argument('--spike-threshold', type=float,
                    default=DEFAULT_SPIKE_THRESHOLD)
    ap.add_argument('--quiet',           action='store_true')
    args = ap.parse_args()

    pa = pyaudio.PyAudio()
    _populate_api_names(pa)

    if args.list_audio:
        list_audio_devices(pa)
        pa.terminate()
        return

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    print("Querying NTP status...", end=' ', flush=True)
    ntp_info = get_ntp_info()
    print(f"done.  Source: {ntp_info['ntp_source']}")
    clock = ClockAnchor()

    port_name = find_serial_port(args.port)

    detector_holder = [None]

    def audio_callback(in_data, frame_count, time_info, status):
        import struct as _s
        det = detector_holder[0]
        if det is not None:
            samples = _s.unpack_from(f'{frame_count}f', in_data)
            det.feed_chunk(samples, frame_count)
        return (None, pyaudio.paContinue)

    print("\nOpening audio stream (trying all available options):")
    stream, dev_index, sample_rate, api_name = find_audio_device_and_open(
        pa, args.audio_device, CHUNK_FRAMES, audio_callback
    )

    dev_name = pa.get_device_info_by_index(dev_index)['name']

    forensic_header = {
        "type":                      "forensic_session_header",
        "record":                    0,
        "ntp_source":                ntp_info["ntp_source"],
        "ntp_last_sync":             ntp_info["ntp_last_sync_utc"],
        "ntp_offset_s":              ntp_info["ntp_offset_s"],
        "ntp_query_method":          ntp_info["ntp_query_method"],
        "ntp_error":                 ntp_info.get("ntp_error"),
        "ntp_raw":                   ntp_info.get("ntp_raw_output", ""),
        "session_wall_utc":          clock.session_wall_utc,
        "session_wall_ns":           clock.session_wall_ns,
        "session_wall_ns_remainder": clock.session_wall_ns_remainder,
        "session_mono_epoch_ns":     clock.session_mono_ns,
        "timing_note": (
            "wall_ns = session_wall_ns + mono_ns. "
            "mono_ns from perf_counter_ns — monotonic, never jumps. "
            "session_wall_ns from time_ns at session start, NTP-disciplined."
        ),
        "instrument":                "Bosean FS-5000",
        "serial_port":               port_name,
        "spike_threshold_usvh":      args.spike_threshold,
        "dangerous_threshold_usvh":  DANGEROUS_THRESHOLD,
        "audio_device_index":        dev_index,
        "audio_device_name":         dev_name,
        "audio_api":                 api_name,
        "sample_rate_hz":            sample_rate,
        "resolution_us":             round(1_000_000 / sample_rate, 3),
        "resolution_ns":             round(1_000_000_000 / sample_rate, 1),
        "cal_window_s":              args.cal_window,
        "floor_threshold":           args.floor,
        "refractory_s":              args.refractory,
        "serial_log":                f"serial_{STAMP}.jsonl.gz",
        "audio_log":                 f"audio_{STAMP}.jsonl.gz",
        "session_file":              f"session_{STAMP}.json",
    }

    session_path = os.path.join(out_dir, f"session_{STAMP}.json")
    with open(session_path, 'w') as f:
        json.dump(forensic_header, f, indent=2)

    serial_log_path = os.path.join(out_dir, f"serial_{STAMP}.jsonl.gz")
    audio_log_path  = os.path.join(out_dir, f"audio_{STAMP}.jsonl.gz")
    serial_log = GzipLog(serial_log_path, forensic_header)
    audio_log  = GzipLog(audio_log_path,  forensic_header)

    def on_calibrated(thresh, n_ser, n_aud):
        print(f"\n  [CAL COMPLETE] serial={n_ser} events  "
              f"audio_peaks={n_aud}  "
              f"event_threshold={thresh:.6f}\n")

    detector = PulseDetector(
        clock           = clock,
        log             = audio_log,
        sample_rate     = sample_rate,
        cal_window_s    = args.cal_window,
        floor_threshold = args.floor,
        refractory_s    = args.refractory,
        on_calibrated   = on_calibrated,
    )
    detector_holder[0] = detector

    stop_event    = threading.Event()
    serial_thread = threading.Thread(
        target = run_serial,
        args   = (port_name, clock, serial_log,
                  args.spike_threshold, args.quiet,
                  stop_event, lambda: detector.pulse_count,
                  detector_holder),
        daemon = True,
        name   = 'SerialStream',
    )

    print(f"\n{'='*62}")
    print(f"  FS-5000 DUAL-STREAM FORENSIC LOGGER")
    print(f"{'='*62}")
    print(f"  NTP source      : {ntp_info['ntp_source']}")
    print(f"  NTP last sync   : {ntp_info['ntp_last_sync_utc']}")
    print(f"  NTP offset      : {ntp_info['ntp_offset_s']} s")
    print(f"  Session start   : {clock.session_wall_utc}")
    print(f"  Session wall ns : {clock.session_wall_ns}")
    print(f"  Sub-second ns   : {clock.session_wall_ns_remainder} ns")
    print(f"{'─'*62}")
    print(f"  Serial port     : {port_name}")
    print(f"  Audio device    : [{dev_index}] {dev_name}")
    print(f"  Audio API       : {api_name}")
    print(f"  Sample rate     : {sample_rate} Hz  "
          f"(~{forensic_header['resolution_ns']:.0f} ns / sample)")
    print(f"  Cal window      : {args.cal_window}s  "
          f"(serial CPS = ground truth for threshold)")
    print(f"  Noise floor     : {args.floor}")
    print(f"  Refractory      : {args.refractory*1000:.1f} ms  "
          f"(echo suppression only)")
    print(f"{'─'*62}")
    print(f"  Serial log      : serial_{STAMP}.jsonl.gz")
    print(f"  Audio log       : audio_{STAMP}.jsonl.gz")
    print(f"  Session meta    : session_{STAMP}.json")
    print(f"  Out dir         : {out_dir}")
    print(f"{'─'*62}")
    print(f"  CAL = calibration countdown  THR = live event threshold")
    print(f"  AUD = accepted audio events  (vs serial CPS for correlation)")
    print(f"  Ctrl+C to stop")
    print(f"{'='*62}\n")

    stream.start_stream()
    serial_thread.start()

    try:
        while stream.is_active():
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        try:
            stream.stop_stream()
        except Exception:
            pass
        try:
            stream.close()
        except Exception:
            pass
        try:
            pa.terminate()
        except Exception:
            pass

        serial_thread.join(timeout=3)

        wall_ns, mono_ns = clock.now()
        end_rec = {
            "type":            "session_end",
            "wall_ns":         wall_ns,
            "wall_iso":        clock.format_wall_ns(wall_ns),
            "mono_ns":         mono_ns,
            "audio_pulses":    detector.pulse_count,
            "event_threshold": detector.event_threshold,
        }
        serial_log.write(end_rec)
        audio_log.write(end_rec)
        serial_log.close()
        audio_log.close()

        print(f"\n\nSession complete.")
        print(f"  Session start    : {clock.session_wall_utc}")
        print(f"  Session end      : {clock.format_wall_ns(wall_ns)}")
        print(f"  Duration         : {mono_ns/1e9:.3f} s")
        print(f"  Audio events     : {detector.pulse_count}")
        print(f"  Event threshold  : {detector.event_threshold}")
        print(f"  Serial log       : {serial_log_path}")
        print(f"  Audio log        : {audio_log_path}")
        print(f"  Session meta     : {session_path}")

if __name__ == '__main__':
    main()
