#!/usr/bin/env python3
"""
gps_logger.py — Continuous GPS background logger for Raypager / GL-E750V2 Mudi V2

Runs as a daemon process that continuously reads NMEA from the u-blox GPS dongle
and logs position every LOG_INTERVAL seconds.

Output files:
  - gps_log.csv      — append-only CSV: ts,lat,lon,alt,sats
  - gps_latest.json  — latest fix (atomic overwrite)
  - gps_logger.pid   — PID file for process management

Usage:
    python3 gps_logger.py --start           # daemonize and start logging
    python3 gps_logger.py --stop            # send SIGTERM to running daemon
    python3 gps_logger.py --status          # show daemon status + latest fix
    python3 gps_logger.py --foreground      # run in foreground (for debugging)
"""

import os
import sys
import time
import json
import signal
import select
import termios
import argparse

# ── Configuration ────────────────────────────────────────────────────────────

GPS_DEV        = os.environ.get("GPS_DEV", "/dev/ttyACM0")
GPS_BAUD       = 4800
LOG_INTERVAL   = 60       # seconds between CSV writes
MAX_CSV_LINES  = 50000    # ~2.5 MB, ~35 days at 60s
RETRY_DELAY    = 30       # seconds between serial reconnect attempts
MAX_RETRIES    = 10       # consecutive failures before exit

LOOT_DIR       = "/root/loot/raypager"
GPS_LOG_CSV    = os.path.join(LOOT_DIR, "gps_log.csv")
GPS_LATEST     = os.path.join(LOOT_DIR, "gps_latest.json")
GPS_PID_FILE   = os.path.join(LOOT_DIR, "gps_logger.pid")

running = True


# ── NMEA helpers (from gps.py) ───────────────────────────────────────────────

def _nmea_checksum_ok(sentence):
    if "*" not in sentence:
        return True
    try:
        body, cs = sentence[1:].rsplit("*", 1)
        expected = 0
        for c in body:
            expected ^= ord(c)
        return expected == int(cs.strip(), 16)
    except Exception:
        return False


def _parse_ddmm(raw, hemi):
    if not raw or "." not in raw:
        return 0.0
    dot = raw.index(".")
    if dot < 2:
        return 0.0
    try:
        deg = float(raw[:dot - 2])
        minutes = float(raw[dot - 2:])
    except ValueError:
        return 0.0
    val = deg + minutes / 60.0
    if hemi in ("S", "W"):
        val = -val
    return val


def _open_gps(dev):
    fd = os.open(dev, os.O_RDONLY | os.O_NOCTTY)
    try:
        attr = termios.tcgetattr(fd)
        attr[4] = termios.B4800
        attr[5] = termios.B4800
        attr[3] = attr[3] & ~(termios.ICANON | termios.ECHO | termios.ISIG)
        attr[2] = attr[2] & ~termios.CRTSCTS
        termios.tcsetattr(fd, termios.TCSANOW, attr)
    except Exception:
        os.close(fd)
        raise
    return fd


# ── Signal handler ───────────────────────────────────────────────────────────

def _signal_handler(signum, frame):
    global running
    running = False


# ── CSV rotation ─────────────────────────────────────────────────────────────

def _count_csv_lines(path):
    try:
        with open(path, "r") as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


def _rotate_csv(path):
    backup = path + ".1"
    try:
        if os.path.exists(backup):
            os.remove(backup)
        os.rename(path, backup)
    except OSError:
        pass


# ── Atomic JSON write ────────────────────────────────────────────────────────

def _write_latest(lat, lon, alt, sats):
    data = {
        "ts": int(time.time()),
        "lat": round(lat, 6),
        "lon": round(lon, 6),
        "alt": round(alt, 1),
        "sats": sats
    }
    tmp = GPS_LATEST + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.rename(tmp, GPS_LATEST)


# ── CSV append ───────────────────────────────────────────────────────────────

def _append_csv(lat, lon, alt, sats):
    line_count = _count_csv_lines(GPS_LOG_CSV)
    if line_count >= MAX_CSV_LINES:
        _rotate_csv(GPS_LOG_CSV)
    with open(GPS_LOG_CSV, "a") as f:
        f.write(f"{int(time.time())},{round(lat, 6)},{round(lon, 6)},{round(alt, 1)},{sats}\n")


# ── Main daemon loop ────────────────────────────────────────────────────────

def _daemon_loop(dev):
    global running

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    retries = 0
    fd = None

    while running:
        # Open serial port
        if fd is None:
            try:
                fd = _open_gps(dev)
                retries = 0
            except OSError as e:
                retries += 1
                if retries >= MAX_RETRIES:
                    _log(f"GPS open failed {MAX_RETRIES}x, giving up: {e}")
                    break
                _log(f"GPS open failed ({retries}/{MAX_RETRIES}): {e}, retry in {RETRY_DELAY}s")
                _sleep_check(RETRY_DELAY)
                continue

        buf = b""
        lat = lon = alt = None
        sats = 0
        last_log_time = 0

        while running and fd is not None:
            try:
                ready, _, _ = select.select([fd], [], [], 1.0)
            except (OSError, ValueError):
                _log("GPS select error, reconnecting")
                _close_fd(fd)
                fd = None
                break

            if ready:
                try:
                    chunk = os.read(fd, 512)
                    if not chunk:
                        _log("GPS EOF, reconnecting")
                        _close_fd(fd)
                        fd = None
                        break
                except OSError:
                    _log("GPS read error, reconnecting")
                    _close_fd(fd)
                    fd = None
                    break

                buf += chunk
                lines = buf.split(b"\n")
                buf = lines[-1]

                for raw in lines[:-1]:
                    sentence = raw.decode("ascii", errors="ignore").strip()
                    if not sentence.startswith("$"):
                        continue
                    if not _nmea_checksum_ok(sentence):
                        continue

                    parts = sentence.split(",")
                    msg = parts[0][1:]

                    if msg in ("GNGGA", "GPGGA"):
                        try:
                            fix_q = int(parts[6]) if parts[6] else 0
                            if fix_q > 0:
                                lat = _parse_ddmm(parts[2], parts[3])
                                lon = _parse_ddmm(parts[4], parts[5])
                                sats = int(parts[7]) if parts[7] else 0
                                alt = float(parts[9]) if parts[9] else 0.0
                        except (IndexError, ValueError):
                            pass

                    elif msg in ("GNRMC", "GPRMC"):
                        try:
                            if parts[2] == "A" and lat is None:
                                lat = _parse_ddmm(parts[3], parts[4])
                                lon = _parse_ddmm(parts[5], parts[6])
                        except IndexError:
                            pass

            # Log at interval
            now = time.time()
            if lat is not None and (now - last_log_time) >= LOG_INTERVAL:
                _append_csv(lat, lon, alt, sats)
                _write_latest(lat, lon, alt, sats)
                last_log_time = now

        # Brief pause before reconnect
        if running and fd is None:
            _sleep_check(RETRY_DELAY)

    # Cleanup
    if fd is not None:
        _close_fd(fd)
    _remove_pid()


def _close_fd(fd):
    try:
        os.close(fd)
    except OSError:
        pass


def _sleep_check(seconds):
    end = time.time() + seconds
    while running and time.time() < end:
        time.sleep(1)


def _log(msg):
    try:
        with open("/tmp/gps_logger.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


# ── PID management ───────────────────────────────────────────────────────────

def _write_pid():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(GPS_PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def _remove_pid():
    try:
        os.remove(GPS_PID_FILE)
    except OSError:
        pass


def _read_pid():
    try:
        with open(GPS_PID_FILE) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _is_running():
    pid = _read_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ── Daemonize ────────────────────────────────────────────────────────────────

def _daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)


# ── CLI commands ─────────────────────────────────────────────────────────────

def cmd_start(dev, foreground=False):
    if _is_running():
        print(f"GPS logger already running (PID {_read_pid()})")
        return
    os.makedirs(LOOT_DIR, exist_ok=True)
    if not foreground:
        _daemonize()
    _write_pid()
    _log(f"GPS logger started (PID {os.getpid()}, dev={dev})")
    _daemon_loop(dev)
    _log("GPS logger stopped")


def cmd_stop():
    pid = _read_pid()
    if pid is None or not _is_running():
        print("GPS logger is not running")
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(10):
        time.sleep(0.5)
        if not _is_running():
            print(f"GPS logger stopped (PID {pid})")
            return
    print(f"GPS logger did not stop (PID {pid})")


def cmd_status():
    if _is_running():
        pid = _read_pid()
        status = f"RUNNING (PID {pid})"
    else:
        status = "STOPPED"

    latest = "no fix"
    try:
        with open(GPS_LATEST) as f:
            data = json.load(f)
        age = int(time.time() - data["ts"])
        latest = f"lat={data['lat']:.6f} lon={data['lon']:.6f} sats={data['sats']} age={age}s"
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass

    csv_lines = _count_csv_lines(GPS_LOG_CSV)

    print(f"{status} | {latest} | {csv_lines} fixes logged")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Continuous GPS background logger")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--start", action="store_true", help="Start daemon")
    group.add_argument("--stop", action="store_true", help="Stop daemon")
    group.add_argument("--status", action="store_true", help="Show status")
    group.add_argument("--foreground", action="store_true", help="Run in foreground (debug)")
    ap.add_argument("--dev", default=GPS_DEV, help="GPS serial device (default: %(default)s)")
    args = ap.parse_args()

    if args.start:
        cmd_start(args.dev)
    elif args.foreground:
        cmd_start(args.dev, foreground=True)
    elif args.stop:
        cmd_stop()
    elif args.status:
        cmd_status()


if __name__ == "__main__":
    main()
