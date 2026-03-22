#!/usr/bin/env python3
"""
opencellid.py — Cell tower verification + contribution via OpenCelliD API
Raypager / GL-E750V2 Mudi V2

Looks up a cell tower (MCC, MNC, Cell-ID, TAC) in the OpenCelliD database.
Unknown towers or location mismatches raise the threat level.
Optionally queues and uploads measurements back to OpenCelliD.

API lookup:  GET  https://opencellid.org/cell/get?key=TOKEN&...&format=json
API upload:  POST https://opencellid.org/measure/add?key=TOKEN  (multipart CSV)

Config: /root/payloads/.../config.json  →  {"opencellid_key": "YOUR_KEY"}
Cache:  /root/loot/raypager/cell_cache/    (gitignored)
Queue:  /root/loot/raypager/upload_queue/  (gitignored, pending uploads)

Threat levels:
  0 = CLEAN    — tower in DB, location matches
  1 = UNKNOWN  — tower not in DB (could be new, could be fake)
  2 = MISMATCH — tower in DB but location far from reported position
  3 = GHOST    — API error or no data at all
"""

import csv
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import math
import logging
import urllib.request
import urllib.parse
import urllib.error
import uuid

from utils import (THREAT_CLEAN, THREAT_UNKNOWN, THREAT_MISMATCH,
                   THREAT_GHOST, THREAT_NOSERVICE, THREAT_LABELS,
                   haversine_km as _haversine_km)

# Some embedded Python builds omit _ssl; fall back to curl for HTTPS
try:
    import ssl as _ssl_mod  # noqa: F401
    _HAS_SSL = True
except ImportError:
    _HAS_SSL = False

log = logging.getLogger(__name__)

# Paths (relative to payload root, resolved at runtime)
_SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
_PAYLOAD_DIR  = os.path.dirname(_SCRIPT_DIR)
CONFIG_FILE   = os.path.join(_PAYLOAD_DIR, "config.json")
CACHE_DIR       = "/root/loot/raypager/cell_cache"
UPLOAD_QUEUE_DIR = "/root/loot/raypager/upload_queue"

# OpenCelliD API
OCID_API_URL    = "https://opencellid.org/cell/get"
OCID_UPLOAD_URL = "https://opencellid.org/measure/add"
API_TIMEOUT     = 8   # seconds

# Distance threshold (km) beyond which a location mismatch is flagged
MISMATCH_KM   = 5.0

# Cache TTL: don't re-query known towers within this window (seconds)
CACHE_TTL     = 86400   # 24 h



# ─── Config / cache helpers ──────────────────────────────────────────────────

def _load_api_key():
    """Read OpenCelliD API key from config.json."""
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        key = cfg.get("opencellid_key", "").strip()
        if not key:
            log.error("opencellid_key missing or empty in %s", CONFIG_FILE)
        return key or None
    except FileNotFoundError:
        log.error("config.json not found at %s", CONFIG_FILE)
        return None
    except json.JSONDecodeError as e:
        log.error("config.json parse error: %s", e)
        return None


def _cache_path(mcc, mnc, cell_id, tac):
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{mcc}_{mnc}_{cell_id}_{tac}.json")


def _cache_read(path):
    try:
        with open(path) as f:
            entry = json.load(f)
        if time.time() - entry.get("cached_at", 0) < CACHE_TTL:
            return entry
        log.debug("Cache expired: %s", path)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def _cache_write(path, data):
    try:
        data["cached_at"] = int(time.time())
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        log.warning("Cache write failed: %s", e)


# ─── curl fallbacks (used when Python _ssl module is unavailable) ────────────

def _curl_get(url, timeout=API_TIMEOUT):
    """HTTP GET via curl -sk (skips cert verification; used without ssl module)."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-A", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
             url],
            capture_output=True, timeout=timeout + 2,
        )
        if r.returncode == 0:
            return r.stdout.decode("utf-8", errors="replace")
        log.warning("curl GET failed (exit %d): %s", r.returncode,
                    r.stderr.decode(errors="replace")[:100])
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.warning("curl GET error: %s", e)
        return None


def _curl_post_multipart(url, filename, file_data, timeout=API_TIMEOUT):
    """Multipart POST via curl -sk; writes file_data to a tmp file."""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv.gz") as tmp:
            tmp.write(file_data)
            tmp_path = tmp.name
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-A", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
             "-F", f"dataFile=@{tmp_path};filename={filename};type=application/octet-stream",
             url],
            capture_output=True, timeout=timeout + 2,
        )
        os.unlink(tmp_path)
        if r.returncode == 0:
            return r.stdout.decode("utf-8", errors="replace")
        log.warning("curl POST failed (exit %d): %s", r.returncode,
                    r.stderr.decode(errors="replace")[:100])
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.warning("curl POST error: %s", e)
        return None


# ─── OpenCelliD API ─────────────────────────────────────────────────────────

def _api_lookup(api_key, mcc, mnc, cell_id, tac):
    """
    Call OpenCelliD API for one cell.
    Returns parsed JSON dict or None on network/API error.
    TAC is passed as 'lac' — OpenCelliD uses the same field for both.
    """
    params = urllib.parse.urlencode({
        "key":    api_key,
        "mcc":    mcc,
        "mnc":    mnc,
        "lac":    tac,
        "cellid": cell_id,
        "format": "json",
    })
    url = f"{OCID_API_URL}?{params}"

    if not _HAS_SSL:
        raw = _curl_get(url, timeout=API_TIMEOUT)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("OpenCelliD curl response not JSON: %s", raw[:200])
            return None

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
        })
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.warning("OpenCelliD HTTP %d: %s", e.code, body[:200])
        try:
            return json.loads(body)   # error responses are JSON too
        except json.JSONDecodeError:
            return None
    except urllib.error.URLError as e:
        log.warning("OpenCelliD network error: %s", e.reason)
        return None
    except Exception as e:
        log.warning("OpenCelliD unexpected error: %s", e)
        return None



# ─── Public API ─────────────────────────────────────────────────────────────

def lookup(cell_info, our_lat=None, our_lon=None):
    """
    Look up cell tower from cell_info dict (output of cell_info.get_cell_info()).

    Args:
        cell_info:  dict from cell_info.py
        our_lat:    our current GPS latitude (optional, for mismatch detection)
        our_lon:    our current GPS longitude (optional)

    Returns dict:
        {
          "threat":       int (THREAT_* constant),
          "threat_label": str,
          "in_db":        bool,
          "db_lat":       float or None,
          "db_lon":       float or None,
          "db_accuracy":  int or None,    # meters
          "distance_km":  float or None,  # distance from our position to DB position
          "reason":       str,
          "cell_id":      int,
          "mcc":          str,
          "mnc":          str,
          "tac":          int or None,
          "rat":          str,
          "timestamp":    int,
          "cached":       bool,
        }
    """
    mcc     = cell_info.get("mcc") or cell_info.get("mcc_nwinfo")
    mnc     = cell_info.get("mnc") or cell_info.get("mnc_nwinfo")
    cell_id = cell_info.get("cell_id")
    tac     = cell_info.get("tac") or cell_info.get("lac", 0)
    rat     = cell_info.get("rat", "?")

    base = {
        "cell_id":   cell_id,
        "mcc":       mcc,
        "mnc":       mnc,
        "tac":       tac,
        "rat":       rat,
        "timestamp": int(time.time()),
        "cached":    False,
    }

    if not all([mcc, mnc, cell_id is not None]):
        return {**base,
                "threat": THREAT_GHOST,
                "threat_label": THREAT_LABELS[THREAT_GHOST],
                "in_db": False,
                "db_lat": None, "db_lon": None, "db_accuracy": None,
                "distance_km": None,
                "reason": "Incomplete cell info (missing MCC/MNC/Cell-ID)"}

    api_key = _load_api_key()
    if not api_key:
        return {**base,
                "threat": THREAT_GHOST,
                "threat_label": THREAT_LABELS[THREAT_GHOST],
                "in_db": False,
                "db_lat": None, "db_lon": None, "db_accuracy": None,
                "distance_km": None,
                "reason": "No OpenCelliD API key configured"}

    # Check cache first
    cache_path = _cache_path(mcc, mnc, cell_id, tac)
    cached = _cache_read(cache_path)
    if cached:
        cached["cached"] = True
        # Re-evaluate mismatch if we now have GPS coords
        if our_lat is not None and cached.get("db_lat") is not None:
            dist = _haversine_km(our_lat, our_lon, cached["db_lat"], cached["db_lon"])
            cached["distance_km"] = round(dist, 2)
            if dist > MISMATCH_KM and cached["threat"] != THREAT_UNKNOWN:
                cached["threat"]       = THREAT_MISMATCH
                cached["threat_label"] = THREAT_LABELS[THREAT_MISMATCH]
                cached["reason"]       = (f"Tower in DB at ({cached['db_lat']:.4f}, "
                                          f"{cached['db_lon']:.4f}) but we are "
                                          f"{dist:.1f} km away")
        return cached

    # Live API lookup
    log.debug("API lookup: MCC=%s MNC=%s CellID=%s TAC=%s", mcc, mnc, cell_id, tac)
    data = _api_lookup(api_key, mcc, mnc, cell_id, tac)

    result = {**base, "db_lat": None, "db_lon": None, "db_accuracy": None,
              "distance_km": None}

    if data is None:
        result.update({
            "threat": THREAT_GHOST,
            "threat_label": THREAT_LABELS[THREAT_GHOST],
            "in_db": False,
            "reason": "API unreachable — cannot verify tower",
        })

    elif data.get("status") == "error" or "lat" not in data:
        msg = (data.get("message") or data.get("error") or "unknown error") if data else "no response"
        result.update({
            "threat": THREAT_UNKNOWN,
            "threat_label": THREAT_LABELS[THREAT_UNKNOWN],
            "in_db": False,
            "reason": f"Tower not in OpenCelliD: {msg}",
        })

    else:
        # Tower found in DB
        db_lat  = float(data["lat"])
        db_lon  = float(data["lon"])
        db_acc  = int(data.get("accuracy", 0))

        result["in_db"]       = True
        result["db_lat"]      = db_lat
        result["db_lon"]      = db_lon
        result["db_accuracy"] = db_acc

        if our_lat is not None and our_lon is not None:
            dist = _haversine_km(our_lat, our_lon, db_lat, db_lon)
            result["distance_km"] = round(dist, 2)

            if dist > MISMATCH_KM:
                result.update({
                    "threat": THREAT_MISMATCH,
                    "threat_label": THREAT_LABELS[THREAT_MISMATCH],
                    "reason": (f"Tower in DB at ({db_lat:.4f}, {db_lon:.4f}) "
                               f"but we are {dist:.1f} km away "
                               f"(accuracy: {db_acc} m)"),
                })
            else:
                result.update({
                    "threat": THREAT_CLEAN,
                    "threat_label": THREAT_LABELS[THREAT_CLEAN],
                    "reason": (f"Tower verified at {dist:.1f} km from our position "
                               f"(DB accuracy: {db_acc} m)"),
                })
        else:
            # No GPS — can only confirm tower exists
            result.update({
                "threat": THREAT_CLEAN,
                "threat_label": THREAT_LABELS[THREAT_CLEAN],
                "reason": f"Tower in OpenCelliD DB (no GPS for position check)",
            })

    _cache_write(cache_path, result)
    return result


# ─── Upload to OpenCelliD ────────────────────────────────────────────────────

# RAT name mapping to OpenCelliD radio field
_RAT_TO_RADIO = {
    "GSM":   "GSM",
    "WCDMA": "UMTS",
    "LTE":   "LTE",
    "NR":    "NR",
}


def _build_csv_row(cell_info, lat, lon):
    """
    Build one OpenCelliD CSV measurement row from cell_info + GPS fix.
    CSV format: radio,mcc,mnc,lac,cid,psc,lon,lat,signal,measured_at,rating,speed,direction
    """
    radio  = _RAT_TO_RADIO.get(cell_info.get("rat", ""), "LTE")
    mcc    = cell_info.get("mcc") or cell_info.get("mcc_nwinfo", "")
    mnc    = cell_info.get("mnc") or cell_info.get("mnc_nwinfo", "")
    lac    = cell_info.get("tac") or cell_info.get("lac", 0)
    cid    = cell_info.get("cell_id", 0)
    # PSC = PCID for LTE, PSC for WCDMA, 0 otherwise
    psc    = cell_info.get("pcid") or cell_info.get("psc", 0)
    signal = cell_info.get("rsrp") or cell_info.get("rssi") or cell_info.get("rscp", -999)
    ts     = cell_info.get("timestamp", int(time.time()))

    return [radio, mcc, mnc, lac, cid, psc, lon, lat, signal, ts, 1, -1, -1]


def _multipart_post(url, fields, filename, file_data):
    """
    Minimal stdlib multipart/form-data POST.
    Falls back to curl when Python _ssl module is unavailable.
    fields: dict of form fields
    filename: name for the file part
    file_data: bytes
    """
    if not _HAS_SSL:
        return _curl_post_multipart(url, filename, file_data)

    boundary = uuid.uuid4().hex
    ctype    = f"multipart/form-data; boundary={boundary}"

    body = io.BytesIO()
    for name, value in fields.items():
        body.write(f"--{boundary}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.write(f"{value}\r\n".encode())

    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="dataFile"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    body.write(file_data)
    body.write(f"\r\n--{boundary}--\r\n".encode())

    data = body.getvalue()
    req  = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": ctype,
                                           "Content-Length": str(len(data)),
                                           "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        log.warning("Upload network error: %s", e.reason)
        return None


def queue_measurement(cell_info, lat, lon):
    """
    Save one measurement to the upload queue (gzipped CSV) for later upload.
    Call this after every successful cell scan when GPS is available.
    GPS coordinates are required — don't queue measurements without a fix.

    Returns path of the queue file written, or None on error.
    """
    if lat is None or lon is None:
        log.debug("queue_measurement: no GPS fix, skipping")
        return None

    os.makedirs(UPLOAD_QUEUE_DIR, exist_ok=True)
    ts       = int(time.time())
    filename = os.path.join(UPLOAD_QUEUE_DIR, f"{ts}_{uuid.uuid4().hex[:8]}.csv.gz")

    row = _build_csv_row(cell_info, lat, lon)
    try:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["radio", "mcc", "mnc", "lac", "cid", "psc",
                         "lon", "lat", "signal", "measured_at", "rating",
                         "speed", "direction"])
        writer.writerow(row)
        gz_data = gzip.compress(buf.getvalue().encode("utf-8"))
        with open(filename, "wb") as f:
            f.write(gz_data)
        log.debug("Queued measurement: %s", filename)
        return filename
    except OSError as e:
        log.warning("queue_measurement write error: %s", e)
        return None


def upload_pending(api_key=None):
    """
    Upload all queued measurements to OpenCelliD and remove them on success.

    Returns dict: {"uploaded": int, "failed": int, "skipped": int}
    """
    if api_key is None:
        api_key = _load_api_key()
    if not api_key:
        log.error("upload_pending: no API key")
        return {"uploaded": 0, "failed": 0, "skipped": 0}

    if not os.path.isdir(UPLOAD_QUEUE_DIR):
        return {"uploaded": 0, "failed": 0, "skipped": 0}

    files = sorted(f for f in os.listdir(UPLOAD_QUEUE_DIR) if f.endswith(".csv.gz"))
    stats = {"uploaded": 0, "failed": 0, "skipped": 0}

    if not files:
        return stats

    log.debug("upload_pending: %d file(s) queued", len(files))

    # OpenCelliD accepts one file per POST; upload individually for reliability
    upload_url = f"{OCID_UPLOAD_URL}?key={urllib.parse.quote(api_key)}"

    for fname in files:
        fpath = os.path.join(UPLOAD_QUEUE_DIR, fname)
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except OSError as e:
            log.warning("Cannot read queue file %s: %s", fname, e)
            stats["skipped"] += 1
            continue

        resp = _multipart_post(upload_url, {}, fname, data)

        if resp is None:
            # Network error — stop, keep files for next attempt
            log.warning("upload_pending: network error, stopping upload batch")
            stats["failed"] += 1
            break

        # OpenCelliD returns "Measurements uploaded." or "Your measurement has been inserted."
        if "uploaded" in resp.lower() or "success" in resp.lower() or "inserted" in resp.lower():
            os.remove(fpath)
            stats["uploaded"] += 1
            log.debug("Uploaded and removed: %s", fname)
        else:
            log.warning("Upload rejected for %s: %s", fname, resp[:200])
            stats["failed"] += 1

    return stats


def threat_summary(result):
    """Return a short human-readable summary line."""
    label = result.get("threat_label", "?")
    reason = result.get("reason", "")
    rat  = result.get("rat", "?")
    mcc  = result.get("mcc", "?")
    mnc  = result.get("mnc", "?")
    cid  = result.get("cell_id", "?")
    return f"[{label}] {rat} {mcc}/{mnc} CellID={cid} — {reason}"


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    """
    Usage:
      opencellid.py                        # lookup only
      opencellid.py <lat> <lon>            # lookup with GPS mismatch check
      opencellid.py <lat> <lon> --queue    # lookup + queue measurement for upload
      opencellid.py --upload               # upload all pending measurements
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    args = sys.argv[1:]

    # --upload mode: flush queue, exit
    if "--upload" in args:
        print("Uploading pending measurements...", file=sys.stderr)
        stats = upload_pending()
        print(f"uploaded={stats['uploaded']} failed={stats['failed']} "
              f"skipped={stats['skipped']}", file=sys.stderr)
        sys.exit(0 if stats["failed"] == 0 else 1)

    # Import here to avoid circular deps when used as module
    try:
        from cell_info import get_cell_info
    except ImportError:
        print("ERROR: cell_info.py not found", file=sys.stderr)
        sys.exit(1)

    print("Querying cell info...", file=sys.stderr)
    info = get_cell_info()
    if not info:
        print("ERROR: No cell info available", file=sys.stderr)
        sys.exit(1)

    our_lat = None
    our_lon = None
    do_queue = "--queue" in args
    coord_args = [a for a in args if a != "--queue"]

    if len(coord_args) >= 2:
        try:
            our_lat = float(coord_args[0])
            our_lon = float(coord_args[1])
        except ValueError:
            pass

    print("Checking OpenCelliD...", file=sys.stderr)
    result = lookup(info, our_lat=our_lat, our_lon=our_lon)

    print(json.dumps(result, indent=2))
    threat = result.get("threat", THREAT_GHOST)
    print(f"\n{threat_summary(result)}", file=sys.stderr)

    # Queue measurement for later upload (only with GPS + non-ghost data)
    if do_queue and our_lat is not None and threat != THREAT_GHOST:
        path = queue_measurement(info, our_lat, our_lon)
        if path:
            print(f"Measurement queued: {os.path.basename(path)}", file=sys.stderr)

    # Exit code = threat level (0–3), usable in payload.sh
    sys.exit(threat)


if __name__ == "__main__":
    main()
