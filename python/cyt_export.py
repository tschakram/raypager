#!/usr/bin/env python3
"""
cyt_export.py — CYT-compatible JSON export for Raypager scan results
Raypager / GL-E750V2 Mudi V2

Builds and saves scan reports in the Chasing Your Tail NG JSON format
so cell tower events can be merged with WiFi/Bluetooth surveillance data
for unified timeline analysis.

Report output: /root/loot/raypager/reports/<timestamp>_raypager.json
CYT loot dir:  /root/loot/chasing_your_tail/  (for cross-tool merge)

CYT event schema (shared with chasing-your-tail-pager):
  {
    "source":    "raypager" | "cyt_ng",
    "type":      "cell_tower" | "wifi" | "bluetooth",
    "timestamp": int (Unix),
    "threat":    int (0-3),
    "location":  {"lat": float, "lon": float} | null,
    "data":      { ...type-specific fields... },
    "notes":     [str, ...]
  }
"""

import json
import os
import sys
import time
import logging

log = logging.getLogger(__name__)

REPORT_DIR  = "/root/loot/raypager/reports"
CYT_LOOT    = "/root/loot/chasing_your_tail"

SOURCE      = "raypager"
VERSION     = "1.0"


# ─── Event builders ──────────────────────────────────────────────────────────

def build_cell_event(cell_info, ocid_result=None, anomalies=None,
                     lat=None, lon=None, imei_rotated=False):
    """
    Build one CYT-compatible cell tower event dict.

    Args:
        cell_info:     dict from cell_info.get_cell_info()
        ocid_result:   dict from opencellid.lookup() or None
        anomalies:     list of anomaly strings from cell_info.is_suspicious()
        lat, lon:      GPS fix at time of scan
        imei_rotated:  True if Blue Merle rotation was triggered this session

    Returns a CYT event dict.
    """
    threat = 0
    if ocid_result:
        threat = ocid_result.get("threat", 0)

    # Escalate threat if local heuristics flagged anomalies
    if anomalies and threat < 1:
        threat = 1

    location = {"lat": lat, "lon": lon} if (lat is not None and lon is not None) else None

    # Core cell fields (strip raw AT response to keep report clean)
    cell_data = {k: v for k, v in cell_info.items() if k != "raw"}

    event = {
        "source":    SOURCE,
        "type":      "cell_tower",
        "timestamp": cell_info.get("timestamp", int(time.time())),
        "threat":    threat,
        "location":  location,
        "data": {
            "cell":         cell_data,
            "verification": ocid_result,
            "imei_rotated": imei_rotated,
        },
        "notes": list(anomalies or []),
    }

    # Add MISMATCH / UNKNOWN reason as a note
    if ocid_result and ocid_result.get("reason"):
        reason = ocid_result["reason"]
        if reason not in event["notes"]:
            event["notes"].append(reason)

    return event


def build_report(events, scan_id=None, lat=None, lon=None):
    """
    Wrap a list of events into a full raypager report envelope.

    Args:
        events:   list of event dicts (from build_cell_event)
        scan_id:  unique ID for this scan session (auto-generated if None)
        lat, lon: GPS fix for this scan session

    Returns report dict.
    """
    if scan_id is None:
        import uuid
        scan_id = uuid.uuid4().hex[:12]

    max_threat = max((e.get("threat", 0) for e in events), default=0)

    return {
        "source":     SOURCE,
        "version":    VERSION,
        "scan_id":    scan_id,
        "timestamp":  int(time.time()),
        "location":   {"lat": lat, "lon": lon} if (lat is not None and lon is not None) else None,
        "max_threat": max_threat,
        "event_count": len(events),
        "events":     events,
    }


# ─── Persistence ─────────────────────────────────────────────────────────────

def save_report(report):
    """
    Save report to /root/loot/raypager/reports/<timestamp>_raypager.json.
    Returns the path written, or None on error.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts   = report.get("timestamp", int(time.time()))
    sid  = report.get("scan_id", "unknown")
    path = os.path.join(REPORT_DIR, f"{ts}_{sid}_raypager.json")

    try:
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        log.debug("Report saved: %s", path)
        return path
    except OSError as e:
        log.error("save_report failed: %s", e)
        return None


def load_report(path):
    """Load a previously saved raypager report."""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.error("load_report %s: %s", path, e)
        return None


def list_reports():
    """Return sorted list of report file paths in REPORT_DIR (newest last)."""
    if not os.path.isdir(REPORT_DIR):
        return []
    files = [
        os.path.join(REPORT_DIR, f)
        for f in os.listdir(REPORT_DIR)
        if f.endswith("_raypager.json")
    ]
    return sorted(files)


# ─── CYT merge ───────────────────────────────────────────────────────────────

def merge_with_cyt(raypager_report, cyt_loot_dir=CYT_LOOT):
    """
    Merge raypager events into CYT NG loot directory for unified timeline.

    Writes a combined <timestamp>_merged.json into the CYT loot dir
    containing both the raypager cell events and any existing CYT events
    from the same time window (+/- 1 hour).

    Args:
        raypager_report: dict from build_report()
        cyt_loot_dir:    path to CYT NG loot directory

    Returns path of merged file, or None on error.
    """
    if not os.path.isdir(cyt_loot_dir):
        log.warning("CYT loot dir not found: %s", cyt_loot_dir)
        # Still write raypager events standalone into CYT dir
        os.makedirs(cyt_loot_dir, exist_ok=True)

    scan_ts    = raypager_report.get("timestamp", int(time.time()))
    scan_id    = raypager_report.get("scan_id", "unknown")
    rp_events  = raypager_report.get("events", [])

    # Collect CYT events from same time window
    cyt_events = _load_cyt_events(cyt_loot_dir, scan_ts, window_sec=3600)

    all_events = sorted(
        rp_events + cyt_events,
        key=lambda e: e.get("timestamp", 0),
    )

    merged = {
        "source":      "raypager+cyt_ng",
        "version":     VERSION,
        "scan_id":     scan_id,
        "timestamp":   scan_ts,
        "location":    raypager_report.get("location"),
        "max_threat":  max((e.get("threat", 0) for e in all_events), default=0),
        "event_count": len(all_events),
        "raypager_events": len(rp_events),
        "cyt_events":      len(cyt_events),
        "events":      all_events,
    }

    out_path = os.path.join(cyt_loot_dir, f"{scan_ts}_{scan_id}_merged.json")
    try:
        with open(out_path, "w") as f:
            json.dump(merged, f, indent=2)
        log.debug("Merged report: %s", out_path)
        return out_path
    except OSError as e:
        log.error("merge_with_cyt write error: %s", e)
        return None


def _load_cyt_events(cyt_loot_dir, ref_ts, window_sec=3600):
    """Load CYT NG events from JSON files within ref_ts ± window_sec."""
    events = []
    try:
        files = [
            f for f in os.listdir(cyt_loot_dir)
            if f.endswith(".json") and "merged" not in f
        ]
    except OSError:
        return events

    for fname in files:
        path = os.path.join(cyt_loot_dir, fname)
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        # CYT NG reports are either event lists or report envelopes
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            candidates = data.get("events", [data])
        else:
            continue

        for ev in candidates:
            if not isinstance(ev, dict):
                continue
            ev_ts = ev.get("timestamp", 0)
            if abs(ev_ts - ref_ts) <= window_sec:
                # Tag source if not already set
                if "source" not in ev:
                    ev["source"] = "cyt_ng"
                events.append(ev)

    return events


# ─── Summary helpers ──────────────────────────────────────────────────────────

THREAT_LABELS = {0: "CLEAN", 1: "UNKNOWN", 2: "MISMATCH", 3: "GHOST"}

def report_summary(report):
    """Return a short multi-line text summary of a report."""
    lines = []
    ts      = report.get("timestamp", 0)
    max_t   = report.get("max_threat", 0)
    loc     = report.get("location")
    events  = report.get("events", [])

    lines.append(f"Raypager Report  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}")
    lines.append(f"Scan ID:    {report.get('scan_id', '?')}")
    if loc:
        lines.append(f"Location:   {loc['lat']:.5f}, {loc['lon']:.5f}")
    lines.append(f"Max threat: [{THREAT_LABELS.get(max_t, str(max_t))}]")
    lines.append(f"Events:     {len(events)}")

    for ev in events:
        t      = ev.get("threat", 0)
        label  = THREAT_LABELS.get(t, str(t))
        ts_ev  = ev.get("timestamp", 0)
        cell   = ev.get("data", {}).get("cell", {})
        rat    = cell.get("rat", "?")
        mcc    = cell.get("mcc", "?")
        mnc    = cell.get("mnc", "?")
        cid    = cell.get("cell_id", "?")
        notes  = "; ".join(ev.get("notes", []))
        t_str  = time.strftime("%H:%M:%S", time.localtime(ts_ev))
        lines.append(f"  {t_str} [{label}] {rat} {mcc}/{mnc} CellID={cid}  {notes}")

    return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    """
    Usage:
      cyt_export.py list                   # list saved reports
      cyt_export.py show <path>            # print summary of a report
      cyt_export.py merge <path>           # merge report into CYT loot dir
      cyt_export.py scan [lat lon]         # run full scan + save report
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    args = sys.argv[1:]
    cmd  = args[0] if args else "list"

    if cmd == "list":
        reports = list_reports()
        if not reports:
            print("No reports found.")
        for p in reports:
            r = load_report(p)
            if r:
                ts    = r.get("timestamp", 0)
                sid   = r.get("scan_id", "?")
                mt    = r.get("max_threat", 0)
                label = THREAT_LABELS.get(mt, str(mt))
                t_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
                print(f"{t_str}  [{label}]  {sid}  {os.path.basename(p)}")

    elif cmd == "show":
        if len(args) < 2:
            print("Usage: cyt_export.py show <path>", file=sys.stderr)
            sys.exit(1)
        r = load_report(args[1])
        if not r:
            print("Could not load report.", file=sys.stderr)
            sys.exit(1)
        print(report_summary(r))

    elif cmd == "merge":
        if len(args) < 2:
            print("Usage: cyt_export.py merge <path>", file=sys.stderr)
            sys.exit(1)
        r = load_report(args[1])
        if not r:
            print("Could not load report.", file=sys.stderr)
            sys.exit(1)
        out = merge_with_cyt(r)
        if out:
            print(f"Merged: {out}")
        else:
            print("Merge failed.", file=sys.stderr)
            sys.exit(1)

    elif cmd == "scan":
        # Quick standalone scan: cell_info + opencellid + save
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from cell_info import get_cell_info, is_suspicious
            import opencellid
        except ImportError as e:
            print(f"Import error: {e}", file=sys.stderr)
            sys.exit(1)

        lat = float(args[1]) if len(args) > 1 else None
        lon = float(args[2]) if len(args) > 2 else None

        print("Scanning...", file=sys.stderr)
        info = get_cell_info()
        if not info:
            print("No cell info.", file=sys.stderr)
            sys.exit(1)

        anomalies = is_suspicious(info)
        ocid      = opencellid.lookup(info, our_lat=lat, our_lon=lon)
        event     = build_cell_event(info, ocid, anomalies, lat, lon)
        report    = build_report([event], lat=lat, lon=lon)
        path      = save_report(report)

        print(report_summary(report))
        if path:
            print(f"\nSaved: {path}", file=sys.stderr)

    else:
        print(__doc__, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
