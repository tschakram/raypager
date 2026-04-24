#!/usr/bin/env python3
"""
unwiredlabs.py — Cell tower verification via UnwiredLabs (LocationAPI)
Raypager / GL-E750V2 Mudi V2

Second source for cell tower verification alongside OpenCelliD.
Uses the UnwiredLabs Geolocation API to look up cell towers.

API:  POST https://us1.unwiredlabs.com/v2/process
Docs: https://unwiredlabs.com/api

Config: /root/raypager/config.json → {"unwiredlabs": {"token": "pk.xxx"}}
Cache:  Shared with OpenCelliD: /root/loot/raypager/cell_cache/

Threat levels (same as opencellid.py):
  0 = CLEAN    — tower in DB, location matches
  1 = UNKNOWN  — tower not in DB
  2 = MISMATCH — tower in DB but location far from GPS position
  3 = GHOST    — API error or no data

Exit codes match threat level for shell integration.
"""

import json
import os
import subprocess
import sys
import time
import logging
import tempfile

from utils import (THREAT_CLEAN, THREAT_UNKNOWN, THREAT_MISMATCH,
                   THREAT_GHOST, THREAT_LABELS,
                   haversine_km as _haversine_km)

log = logging.getLogger(__name__)

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PAYLOAD_DIR = os.path.dirname(_SCRIPT_DIR)
CONFIG_FILE  = os.path.join(_PAYLOAD_DIR, "config.json")

UWL_API_URL  = "https://us1.unwiredlabs.com/v2/process"
API_TIMEOUT  = 10
MISMATCH_KM  = 5.0

CACHE_DIR    = "/root/loot/raypager/cell_cache"
CACHE_TTL    = 86400  # 24 h

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"


# ─── Config / cache ─────────────────────────────────────────────────────────

def _load_token():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        uwl = cfg.get("unwiredlabs", {})
        token = uwl.get("token", "").strip()
        if not token:
            log.info("unwiredlabs.token missing or empty in %s", CONFIG_FILE)
            return None
        return token
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error("config.json error: %s", e)
        return None


def _cache_key(mcc, mnc, cell_id, tac):
    return os.path.join(CACHE_DIR, f"uwl_{mcc}_{mnc}_{cell_id}_{tac}.json")


def _cache_read(path):
    try:
        with open(path) as f:
            entry = json.load(f)
        if time.time() - entry.get("cached_at", 0) < CACHE_TTL:
            return entry
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def _cache_write(path, data):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        data["cached_at"] = int(time.time())
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        log.warning("Cache write failed: %s", e)


# ─── API call via curl (no SSL module on Mudi) ─────────────────────────────

def _api_lookup(token, mcc, mnc, cell_id, tac, radio="lte"):
    payload = {
        "token": token,
        "radio": radio,
        "mcc": int(mcc),
        "mnc": int(mnc),
        "cells": [{
            "lac": int(tac),
            "cid": int(cell_id)
        }],
        "address": 0
    }

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as tmp:
            json.dump(payload, tmp)
            tmp_path = tmp.name

        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(API_TIMEOUT),
             "-A", UA,
             "-H", "Content-Type: application/json",
             "-d", f"@{tmp_path}",
             UWL_API_URL],
            capture_output=True, timeout=API_TIMEOUT + 3,
        )
        os.unlink(tmp_path)

        if r.returncode != 0:
            log.warning("curl POST failed (exit %d): %s",
                        r.returncode, r.stderr.decode(errors="replace")[:100])
            return None

        raw = r.stdout.decode("utf-8", errors="replace")
        return json.loads(raw)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.warning("UnwiredLabs API error: %s", e)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return None
    except json.JSONDecodeError as e:
        log.warning("UnwiredLabs response not JSON: %s", e)
        return None


# ─── RAT mapping ────────────────────────────────────────────────────────────

_RAT_TO_RADIO = {
    "GSM":   "gsm",
    "WCDMA": "umts",
    "LTE":   "lte",
    "NR":    "nr",
}


# ─── Public API ─────────────────────────────────────────────────────────────

def lookup(cell_info, our_lat=None, our_lon=None):
    """
    Look up cell tower via UnwiredLabs API.

    Args:
        cell_info:  dict from cell_info.py
        our_lat:    GPS latitude (optional, for mismatch detection)
        our_lon:    GPS longitude (optional)

    Returns dict with threat, threat_label, reason, db_lat, db_lon, etc.
    """
    mcc     = cell_info.get("mcc") or cell_info.get("mcc_nwinfo")
    mnc     = cell_info.get("mnc") or cell_info.get("mnc_nwinfo")
    cell_id = cell_info.get("cell_id")
    tac     = cell_info.get("tac") or cell_info.get("lac", 0)
    rat     = cell_info.get("rat", "LTE")

    base = {
        "source":    "unwiredlabs",
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

    token = _load_token()
    if not token:
        return {**base,
                "threat": THREAT_CLEAN,
                "threat_label": THREAT_LABELS[THREAT_CLEAN],
                "in_db": False,
                "db_lat": None, "db_lon": None, "db_accuracy": None,
                "distance_km": None,
                "reason": "UnwiredLabs not configured — skipped"}

    # Check cache
    cpath = _cache_key(mcc, mnc, cell_id, tac)
    cached = _cache_read(cpath)
    if cached:
        cached["cached"] = True
        if our_lat is not None and cached.get("db_lat") is not None:
            dist = _haversine_km(our_lat, our_lon, cached["db_lat"], cached["db_lon"])
            cached["distance_km"] = round(dist, 2)
            if dist > MISMATCH_KM and cached["threat"] != THREAT_UNKNOWN:
                cached["threat"] = THREAT_MISMATCH
                cached["threat_label"] = THREAT_LABELS[THREAT_MISMATCH]
                cached["reason"] = (f"Tower in UnwiredLabs at ({cached['db_lat']:.4f}, "
                                    f"{cached['db_lon']:.4f}) but we are "
                                    f"{dist:.1f} km away")
        return cached

    # Live API lookup
    radio = _RAT_TO_RADIO.get(rat, "lte")
    log.debug("UnwiredLabs lookup: MCC=%s MNC=%s CellID=%s TAC=%s radio=%s",
              mcc, mnc, cell_id, tac, radio)
    data = _api_lookup(token, mcc, mnc, cell_id, tac, radio)

    result = {**base, "db_lat": None, "db_lon": None, "db_accuracy": None,
              "distance_km": None, "in_db": False}

    if data is None:
        result.update({
            "threat": THREAT_GHOST,
            "threat_label": THREAT_LABELS[THREAT_GHOST],
            "reason": "UnwiredLabs API unreachable",
        })

    elif data.get("status") == "error":
        msg = data.get("message", "unknown error")
        result.update({
            "threat": THREAT_UNKNOWN,
            "threat_label": THREAT_LABELS[THREAT_UNKNOWN],
            "reason": f"Tower not in UnwiredLabs: {msg}",
        })

    elif data.get("status") == "ok" and "lat" in data and "lon" in data:
        db_lat = float(data["lat"])
        db_lon = float(data["lon"])
        db_acc = int(data.get("accuracy", 0))

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
                    "reason": (f"Tower in UnwiredLabs at ({db_lat:.4f}, {db_lon:.4f}) "
                               f"but we are {dist:.1f} km away "
                               f"(accuracy: {db_acc} m)"),
                })
            else:
                result.update({
                    "threat": THREAT_CLEAN,
                    "threat_label": THREAT_LABELS[THREAT_CLEAN],
                    "reason": (f"Tower verified at {dist:.1f} km "
                               f"(UnwiredLabs accuracy: {db_acc} m)"),
                })
        else:
            result.update({
                "threat": THREAT_CLEAN,
                "threat_label": THREAT_LABELS[THREAT_CLEAN],
                "reason": "Tower in UnwiredLabs DB (no GPS for position check)",
            })
    else:
        result.update({
            "threat": THREAT_GHOST,
            "threat_label": THREAT_LABELS[THREAT_GHOST],
            "reason": f"UnwiredLabs unexpected response: {json.dumps(data)[:200]}",
        })

    _cache_write(cpath, result)
    return result


# ─── CLI entry point ────────────────────────────────────────────────────────

def main():
    """
    Usage:
      unwiredlabs.py                  # lookup only
      unwiredlabs.py <lat> <lon>      # lookup with GPS mismatch check
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

    # Import cell_info to get current cell data
    try:
        from cell_info import get_cell_info
    except ImportError:
        print("ERROR: cell_info.py not found", file=sys.stderr)
        sys.exit(THREAT_GHOST)

    print("Querying cell info...", file=sys.stderr)
    info = get_cell_info()
    if not info:
        print("ERROR: No cell info available", file=sys.stderr)
        sys.exit(THREAT_GHOST)

    print("Checking UnwiredLabs...", file=sys.stderr)
    result = lookup(info, our_lat=our_lat, our_lon=our_lon)

    threat = result["threat"]
    label = result.get("threat_label", "?")
    reason = result.get("reason", "")
    print(f"[{label}] {reason}", file=sys.stderr)

    sys.exit(threat)


if __name__ == "__main__":
    main()
