#!/usr/bin/env python3
"""
utils.py — Shared constants and helpers for Raypager / Argus Pager
Single source of truth for threat levels and geo calculations.
"""

import math

# ─── Threat level constants (used as exit codes in CLI scripts) ──────────────

THREAT_CLEAN     = 0   # Known tower, location OK
THREAT_UNKNOWN   = 1   # Not in DB (could be new, could be fake)
THREAT_MISMATCH  = 2   # In DB but position differs significantly
THREAT_GHOST     = 3   # API error, missing config, or incomplete cell info
THREAT_NOSERVICE = 4   # Modem not connected (NOSERVICE/SEARCH/LIMSRV) — harmless

THREAT_LABELS = {
    THREAT_CLEAN:     "CLEAN",
    THREAT_UNKNOWN:   "UNKNOWN",
    THREAT_MISMATCH:  "MISMATCH",
    THREAT_GHOST:     "GHOST",
    THREAT_NOSERVICE: "NOSERVICE",
}


def threat_label(level):
    """Return human-readable label for a threat level."""
    return THREAT_LABELS.get(level, "?")


# ─── Geo helpers ─────────────────────────────────────────────────────────────

def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points (decimal degrees) in km."""
    if any(v is None for v in (lat1, lon1, lat2, lon2)):
        return None
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2)
         * math.sin(dlam / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
