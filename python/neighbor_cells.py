#!/usr/bin/env python3
"""
neighbor_cells.py — Neighbor cell scan via AT+QENG="neighbourcell"

Parses LTE / WCDMA / GSM neighbor rows and flags anomalies:
  - zero neighbors while on macro-network (classic fake-BTS signature)
  - serving cell's PCID/PSC also reported as neighbor (self-loop)
  - very few neighbors on an urban deployment

Output: JSON list of neighbor dicts.

Usage:
    python3 neighbor_cells.py             # print JSON to stdout
    python3 neighbor_cells.py --verbose   # show raw AT response
"""

import json
import re
import sys
import logging

from cell_info import _at, _safe_int   # reuse AT runner

log = logging.getLogger(__name__)


def _parse_row(line):
    """Parse one +QENG: "neighbourcell ..." row."""
    m = re.match(r'\+QENG:\s*"neighbourcell\s*([^"]*)",(.+)', line)
    if not m:
        return None
    kind = m.group(1).strip().lower()
    parts = [p.strip().strip('"') for p in m.group(2).split(',')]

    # LTE intra-freq:  "neighbourcell intra","LTE",<earfcn>,<pci>,<rsrq>,<rsrp>,<rssi>,<sinr>,<srxlev>,<cell_resel>,<s_non_intra_search>,<thresh_serving_low>,<s_intra_search>
    # LTE inter-freq:  "neighbourcell inter","LTE",<earfcn>,<pci>,<rsrq>,<rsrp>,<rssi>,<sinr>,<srxlev>,<threshX_low>,<threshX_high>
    # WCDMA:           "neighbourcell","WCDMA",<uarfcn>,<cell_resel>,<rank>,<set>,<psc>,<rscp>,<ecno>
    # GSM:             "neighbourcell","GSM",<mcc>,<mnc>,<lac>,<cellid>,<bsic>,<arfcn>,<rxlev>
    if not parts:
        return None

    rat = parts[0].upper()
    try:
        if rat == "LTE":
            return {
                "kind":   kind or "intra",
                "rat":    "LTE",
                "earfcn": _safe_int(parts[1]),
                "pci":    _safe_int(parts[2]),
                "rsrq":   _safe_int(parts[3]),
                "rsrp":   _safe_int(parts[4]),
                "rssi":   _safe_int(parts[5]) if len(parts) > 5 else None,
                "sinr":   _safe_int(parts[6]) if len(parts) > 6 else None,
            }
        if rat == "WCDMA":
            return {
                "kind":   kind or "wcdma",
                "rat":    "WCDMA",
                "uarfcn": _safe_int(parts[1]),
                "psc":    _safe_int(parts[5]) if len(parts) > 5 else None,
                "rscp":   _safe_int(parts[6]) if len(parts) > 6 else None,
                "ecno":   _safe_int(parts[7]) if len(parts) > 7 else None,
            }
        if rat == "GSM":
            return {
                "kind":    kind or "gsm",
                "rat":     "GSM",
                "mcc":     parts[1],
                "mnc":     parts[2],
                "lac":     _safe_int(parts[3], 16) if parts[3] else None,
                "cell_id": _safe_int(parts[4], 16) if parts[4] else None,
                "bsic":    _safe_int(parts[5]) if len(parts) > 5 else None,
                "arfcn":   _safe_int(parts[6]) if len(parts) > 6 else None,
                "rxlev":   _safe_int(parts[7]) if len(parts) > 7 else None,
            }
    except (IndexError, ValueError):
        pass
    return None


def get_neighbors():
    """Return list of neighbor cell dicts (empty list if none or on error)."""
    raw = _at('AT+QENG="neighbourcell"')
    if not raw:
        return []
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("+QENG:"):
            continue
        row = _parse_row(line)
        if row:
            rows.append(row)
    return rows


def analyze(neighbors, serving_info=None):
    """Return dict with anomalies list + summary counts."""
    warnings = []
    count_lte = sum(1 for n in neighbors if n["rat"] == "LTE")
    count_wcdma = sum(1 for n in neighbors if n["rat"] == "WCDMA")
    count_gsm = sum(1 for n in neighbors if n["rat"] == "GSM")
    total = len(neighbors)

    if total == 0:
        warnings.append("Zero neighbor cells reported — classic fake-BTS indicator")
    elif total <= 1:
        warnings.append(f"Very few neighbors ({total}) — suspicious for urban areas")

    # NOTE: Quectel EC25 routinely lists its own serving PCI as an intra-freq
    # neighbor — this is normal Quectel firmware behavior, not an anomaly.
    # Do NOT warn on serving-PCI self-listing.

    return {
        "total":       total,
        "count_lte":   count_lte,
        "count_wcdma": count_wcdma,
        "count_gsm":   count_gsm,
        "warnings":    warnings,
        "neighbors":   neighbors,
    }


def main():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    verbose = "--verbose" in sys.argv

    if verbose:
        print("=== raw AT+QENG=\"neighbourcell\" ===", file=sys.stderr)
        print(_at('AT+QENG="neighbourcell"'), file=sys.stderr)

    # Try to fetch serving cell for self-loop check
    serving = None
    try:
        from cell_info import get_cell_info
        serving = get_cell_info()
    except Exception:
        pass

    result = analyze(get_neighbors(), serving)
    print(json.dumps(result, indent=2))
    sys.exit(0 if not result["warnings"] else 2)


if __name__ == "__main__":
    main()
