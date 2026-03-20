#!/usr/bin/env python3
"""
gps.py — Read GPS fix from u-blox NMEA serial device
Raypager / GL-E750V2 Mudi V2

Reads NMEA sentences from /dev/ttyACM0 (or GPS_DEV env / --dev arg) at 4800 baud.
Outputs a single line:  <lat> <lon>  or exits non-zero if no fix within timeout.

Usage:
    python3 gps.py                    # prints "lat lon" or exits 1
    python3 gps.py --dev /dev/ttyACM0 --timeout 30 --json
"""

import os
import sys
import time
import termios
import argparse
import json
import logging

log = logging.getLogger(__name__)

GPS_DEV     = os.environ.get("GPS_DEV", "/dev/ttyACM0")
GPS_BAUD    = 4800
GPS_TIMEOUT = 30   # seconds to wait for a valid fix


# ── NMEA helpers ──────────────────────────────────────────────────────────────

def _nmea_checksum_ok(sentence: str) -> bool:
    """Verify NMEA checksum (*XX at end)."""
    if "*" not in sentence:
        return True  # no checksum field — accept
    try:
        body, cs = sentence[1:].rsplit("*", 1)
        expected = 0
        for c in body:
            expected ^= ord(c)
        return expected == int(cs.strip(), 16)
    except Exception:
        return False


def _parse_ddmm(raw: str, hemi: str) -> float:
    """Convert NMEA ddmm.mmmm + N/S/E/W to decimal degrees."""
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


def _open_gps(dev: str) -> int:
    """Open serial device and configure for 4800 baud raw read."""
    fd = os.open(dev, os.O_RDONLY | os.O_NOCTTY)
    try:
        attr = termios.tcgetattr(fd)
        # input / output speed
        attr[4] = termios.B4800
        attr[5] = termios.B4800
        # raw mode: disable canonical, echo, signals
        attr[3] = attr[3] & ~(termios.ICANON | termios.ECHO | termios.ISIG)
        # no flow control
        attr[2] = attr[2] & ~termios.CRTSCTS
        termios.tcsetattr(fd, termios.TCSANOW, attr)
    except Exception:
        os.close(fd)
        raise
    return fd


# ── Main reader ───────────────────────────────────────────────────────────────

def read_fix(dev: str = GPS_DEV, timeout: int = GPS_TIMEOUT):
    """
    Block until a valid GPS fix (GGA fix>0 and RMC status A) or timeout.
    Returns (lat, lon, alt, sats) on success, raises RuntimeError on timeout.
    """
    try:
        fd = _open_gps(dev)
    except OSError as e:
        raise RuntimeError(f"Cannot open {dev}: {e}")

    buf = b""
    deadline = time.time() + timeout
    lat = lon = alt = None
    sats = 0
    gga_fix = False
    rmc_valid = False

    try:
        while time.time() < deadline:
            try:
                chunk = os.read(fd, 256)
            except OSError:
                break
            buf += chunk
            lines = buf.split(b"\n")
            buf = lines[-1]  # keep incomplete line

            for raw in lines[:-1]:
                sentence = raw.decode("ascii", errors="ignore").strip()
                if not sentence.startswith("$"):
                    continue
                if not _nmea_checksum_ok(sentence):
                    continue

                parts = sentence.split(",")
                msg = parts[0][1:]  # strip leading $

                # GGA — position + fix quality
                if msg in ("GNGGA", "GPGGA"):
                    try:
                        fix_q = int(parts[6]) if parts[6] else 0
                        if fix_q > 0:
                            lat = _parse_ddmm(parts[2], parts[3])
                            lon = _parse_ddmm(parts[4], parts[5])
                            sats = int(parts[7]) if parts[7] else 0
                            alt = float(parts[9]) if parts[9] else 0.0
                            gga_fix = True
                    except (IndexError, ValueError):
                        pass

                # RMC — recommended minimum / validity flag
                elif msg in ("GNRMC", "GPRMC"):
                    try:
                        status = parts[2]   # A=active, V=void
                        if status == "A":
                            rmc_valid = True
                            # also parse position from RMC as fallback
                            if lat is None:
                                lat = _parse_ddmm(parts[3], parts[4])
                                lon = _parse_ddmm(parts[5], parts[6])
                    except IndexError:
                        pass

                if gga_fix and rmc_valid:
                    return lat, lon, alt, sats

    finally:
        os.close(fd)

    raise RuntimeError(f"No GPS fix within {timeout}s (indoor or no satellites)")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Read GPS fix from NMEA serial device")
    ap.add_argument("--dev",     default=GPS_DEV,    help="Serial device (default: %(default)s)")
    ap.add_argument("--timeout", default=GPS_TIMEOUT, type=int, help="Max wait seconds (default: %(default)s)")
    ap.add_argument("--json",    action="store_true", help="Output JSON instead of 'lat lon'")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING)

    try:
        lat, lon, alt, sats = read_fix(dev=args.dev, timeout=args.timeout)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps({"lat": lat, "lon": lon, "alt": alt, "sats": sats}))
    else:
        print(f"{lat} {lon}")


if __name__ == "__main__":
    main()
