#!/usr/bin/env python3
"""
wigle_cell.py — WiGLE cell tower lookup for Raypager / Argus Pager
Checks if a cell tower (MCC/MNC/TAC/CID) is known to WiGLE and
optionally verifies reported position against GPS.

Mirrors the threat-level convention of opencellid.py so payload.sh
can treat both results uniformly.

API:    GET https://api.wigle.net/api/v2/cell/search
Auth:   Basic base64(api_name:api_token)
Config: config.json → {"wigle": {"api_name": "...", "api_token": "...", "enabled": true}}
Cache:  /root/loot/raypager/wigle_cell_cache/  (JSON, TTL 7 days)

Exit codes:
  0 = CLEAN     — found in WiGLE, position matches GPS
  1 = UNKNOWN   — not found in WiGLE (may be new or unlogged)
  2 = MISMATCH  — found but reported position differs from GPS
  3 = GHOST     — API error, missing config, or incomplete cell info
  4 = NOSERVICE — modem not connected (passthrough, not suspicious)
"""

import base64
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import logging

from utils import (THREAT_CLEAN, THREAT_UNKNOWN, THREAT_MISMATCH,
                   THREAT_GHOST, THREAT_NOSERVICE, THREAT_LABELS,
                   haversine_km as _haversine_km)

try:
    import ssl as _ssl_mod  # noqa: F401
    _HAS_SSL = True
except ImportError:
    _HAS_SSL = False

log = logging.getLogger(__name__)

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PAYLOAD_DIR = os.path.dirname(_SCRIPT_DIR)
CONFIG_FILE  = os.path.join(_PAYLOAD_DIR, "config.json")

WIGLE_API_URL = "https://api.wigle.net/api/v2/cell/search"
CACHE_DIR     = "/root/loot/raypager/wigle_cell_cache"
CACHE_TTL     = 86400 * 7   # 7 days — towers don't move
API_TIMEOUT   = 10          # seconds
MISMATCH_KM   = 5.0         # km threshold for position mismatch


# ─── Config ─────────────────────────────────────────────────────────────────

def _load_credentials():
    """Return (api_name, api_token) or (None, None) if not configured."""
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        w = cfg.get("wigle", {})
        if not w.get("enabled"):
            log.debug("WiGLE disabled in config")
            return None, None
        name  = w.get("api_name", "").strip()
        token = w.get("api_token", "").strip()
        if not name or not token:
            log.warning("wigle.api_name or wigle.api_token missing in config.json")
            return None, None
        return name, token
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        log.warning("Config load failed: %s", e)
        return None, None


def _auth_header(api_name, api_token):
    cred = base64.b64encode(f"{api_name}:{api_token}".encode()).decode()
    return f"Basic {cred}"


# ─── Cache ──────────────────────────────────────────────────────────────────

def _cache_path(mcc, mnc, tac, cid):
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{mcc}_{mnc}_{tac}_{cid}.json")


def _cache_read(path):
    try:
        with open(path) as f:
            entry = json.load(f)
        if time.time() - entry.get("cached_at", 0) < CACHE_TTL:
            return entry.get("results")
        log.debug("Cache expired: %s", path)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def _cache_write(path, results):
    try:
        with open(path, "w") as f:
            json.dump({"cached_at": int(time.time()), "results": results}, f)
    except OSError as e:
        log.warning("Cache write failed: %s", e)


# ─── HTTP (with curl fallback for builds without _ssl) ───────────────────────

def _http_get(url, auth_value, timeout=API_TIMEOUT):
    """GET with Authorization header; falls back to curl -sk if no ssl module."""
    if _HAS_SSL:
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": auth_value,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except Exception as e:
            log.debug("urllib GET failed: %s", e)

    # curl fallback
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-H", f"Authorization: {auth_value}",
             "-H", "Accept: application/json",
             url],
            capture_output=True, timeout=timeout + 5,
        )
        if r.returncode == 0:
            return r.stdout.decode("utf-8", errors="replace")
        log.warning("curl GET failed (exit %d): %s",
                    r.returncode, r.stderr.decode(errors="replace")[:100])
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.warning("curl GET error: %s", e)
    return None



# ─── Lookup ──────────────────────────────────────────────────────────────────

def lookup(cell_info, our_lat=None, our_lon=None):
    """
    Query WiGLE for the given cell tower.
    Returns dict: {threat, threat_label, reason, results, distance_km}
    """
    mcc     = cell_info.get("mcc") or cell_info.get("mcc_nwinfo")
    mnc     = cell_info.get("mnc") or cell_info.get("mnc_nwinfo")
    cell_id = cell_info.get("cell_id")
    tac     = cell_info.get("tac") or cell_info.get("lac", 0)

    base = {"mcc": mcc, "mnc": mnc, "tac": tac, "cell_id": cell_id,
            "distance_km": None, "results": []}

    # NOSERVICE passthrough
    if cell_info.get("noservice"):
        state = cell_info.get("state", "?")
        return {**base, "threat": THREAT_NOSERVICE,
                "threat_label": THREAT_LABELS[THREAT_NOSERVICE],
                "reason": f"Modem not connected (state: {state})"}

    if not all([mcc, mnc, cell_id is not None]):
        return {**base, "threat": THREAT_GHOST,
                "threat_label": THREAT_LABELS[THREAT_GHOST],
                "reason": "Incomplete cell info (MCC/MNC/CID missing)"}

    api_name, api_token = _load_credentials()
    if not api_name:
        return {**base, "threat": THREAT_GHOST,
                "threat_label": THREAT_LABELS[THREAT_GHOST],
                "reason": "WiGLE not configured or disabled"}

    # Cache check
    cpath   = _cache_path(mcc, mnc, tac, cell_id)
    results = _cache_read(cpath)

    if results is None:
        params = urllib.parse.urlencode({
            "mcc": mcc, "mnc": mnc, "lac": tac, "cid": cell_id,
        })
        url = f"{WIGLE_API_URL}?{params}"
        raw = _http_get(url, _auth_header(api_name, api_token))

        if not raw:
            return {**base, "threat": THREAT_GHOST,
                    "threat_label": THREAT_LABELS[THREAT_GHOST],
                    "reason": "WiGLE API not reachable"}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {**base, "threat": THREAT_GHOST,
                    "threat_label": THREAT_LABELS[THREAT_GHOST],
                    "reason": "WiGLE API response parse error"}

        if not data.get("success"):
            msg = data.get("message", "unknown error")
            return {**base, "threat": THREAT_GHOST,
                    "threat_label": THREAT_LABELS[THREAT_GHOST],
                    "reason": f"WiGLE API error: {msg}"}

        results = data.get("results", [])
        _cache_write(cpath, results)

    if not results:
        return {**base, "threat": THREAT_UNKNOWN,
                "threat_label": THREAT_LABELS[THREAT_UNKNOWN],
                "reason": "Tower not found in WiGLE DB"}

    # Tower found — check position if GPS available
    best_dist = None
    if our_lat is not None and our_lon is not None:
        dists = []
        for r in results:
            rlat = r.get("lat") or r.get("trilat")
            rlon = r.get("lon") or r.get("trilong")
            if rlat is not None and rlon is not None:
                try:
                    dists.append(_haversine_km(our_lat, our_lon,
                                               float(rlat), float(rlon)))
                except (TypeError, ValueError):
                    pass
        if dists:
            best_dist = min(dists)

    if best_dist is not None:
        if best_dist > MISMATCH_KM:
            return {**base, "threat": THREAT_MISMATCH,
                    "threat_label": THREAT_LABELS[THREAT_MISMATCH],
                    "reason": f"WiGLE position {best_dist:.1f} km from GPS",
                    "results": results, "distance_km": best_dist}
        return {**base, "threat": THREAT_CLEAN,
                "threat_label": THREAT_LABELS[THREAT_CLEAN],
                "reason": f"WiGLE match, {best_dist:.1f} km from GPS",
                "results": results, "distance_km": best_dist}

    # Found but no GPS to verify position
    return {**base, "threat": THREAT_UNKNOWN,
            "threat_label": THREAT_LABELS[THREAT_UNKNOWN],
            "reason": f"In WiGLE ({len(results)} result(s)) — no GPS to verify position",
            "results": results}


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    """
    Usage:
      wigle_cell.py                  # lookup current tower
      wigle_cell.py <lat> <lon>      # lookup + position check
    Exit code = threat level (0-4).
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    args = sys.argv[1:]
    our_lat = our_lon = None
    if len(args) >= 2:
        try:
            our_lat = float(args[0])
            our_lon = float(args[1])
        except ValueError:
            pass

    try:
        from cell_info import get_cell_info
    except ImportError:
        print("ERROR: cell_info.py not found", file=sys.stderr)
        sys.exit(THREAT_GHOST)

    print("WiGLE: querying cell info...", file=sys.stderr)
    info = get_cell_info()
    if not info:
        print("WiGLE: no cell info available", file=sys.stderr)
        sys.exit(THREAT_GHOST)

    print("WiGLE: checking cell tower...", file=sys.stderr)
    result = lookup(info, our_lat=our_lat, our_lon=our_lon)

    threat = result["threat"]
    label  = result["threat_label"]
    reason = result.get("reason", "")
    dist   = result.get("distance_km")
    dist_s = f"{dist:.1f} km" if dist is not None else "no GPS"

    print(f"WiGLE {label}: {reason} ({dist_s})", file=sys.stderr)
    sys.exit(threat)


if __name__ == "__main__":
    main()
