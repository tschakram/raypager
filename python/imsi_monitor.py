#!/usr/bin/env python3
"""
imsi_monitor.py — Continuous IMSI-catcher monitoring daemon

Polls serving cell + neighbor info every N seconds and emits alerts when
any of these anomalies are observed:

  1. RAT downgrade         LTE → WCDMA / GSM
  2. Cipher mode           ciphering disabled (plaintext)
  3. Timing Advance        TA=0 paired with weak signal
  4. Neighbor cells        sudden drop to zero neighbors
  5. LAC/TAC change        same CID but new TAC (cell cloning)
  6. Cell ID flip          TAC stable but different CID repeatedly

State is persisted between runs in STATE_FILE so the daemon survives
restarts without losing history. Alerts are written to ALERT_LOG (JSONL)
and also emitted on stdout.

Usage:
    python3 imsi_monitor.py                       # run forever, 30s poll
    python3 imsi_monitor.py --interval 15         # poll every 15s
    python3 imsi_monitor.py --once                # single sample, exit
    python3 imsi_monitor.py --status              # print current state
"""

import argparse
import json
import os
import sys
import time
import logging
from datetime import datetime

from cell_info import get_cell_info
from neighbor_cells import get_neighbors, analyze as analyze_neighbors

log = logging.getLogger(__name__)

STATE_DIR = "/root/loot/raypager"
STATE_FILE = os.path.join(STATE_DIR, "imsi_monitor_state.json")
ALERT_LOG = os.path.join(STATE_DIR, "imsi_alerts.jsonl")
# Shared history consumed by argus-pager cross_report.py — schema must stay stable
RAT_HISTORY = os.path.join(STATE_DIR, "rat_history.json")
RAT_HISTORY_MAX = 5000

RAT_RANK = {"GSM": 1, "WCDMA": 2, "LTE": 3, "NR": 4}

# Cipher numeric → label (A5/x for GSM, EEA for LTE). SnoopSnitch convention:
#   0 = No encryption (A5/0, EEA0)       → highest severity
#   1 = Weak (A5/1, legacy)              → warn
#   2 = Medium (A5/2)                    → warn
#   3 = Strong (A5/3, EEA1+, EEA2)       → clean
CIPHER_LABELS = {0: "A5/0 (none)", 1: "A5/1 (weak)", 2: "A5/2", 3: "A5/3"}


def _now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "last_rat":         None,
            "last_cell_id":     None,
            "last_tac":         None,
            "last_neighbors":   0,
            "samples":          0,
            "alerts_total":     0,
            "first_seen":       _now(),
        }


def _save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _log_alert(alert):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")


def _append_rat_history(info, prev_rat, neighbors_count, ta_anomaly, tac_change):
    """Append a sample to rat_history.json in the schema argus-pager consumes.

    Schema (compatible with cyt/python/cross_report.py load_rat_anomalies):
      ts, rat, cell_id, mcc, mnc, downgrade, prev_rat, ciphering, ciphering_label
    Extended fields (ignored by legacy reader, used by updated cross_report):
      ta, neighbors, neighbors_vanished, tac_change, cell_id_zero
    """
    if not info or info.get("noservice"):
        return
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(RAT_HISTORY) as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        history = []

    rat = info.get("rat")
    cur_rank = RAT_RANK.get(rat, 0)
    prev_rank = RAT_RANK.get(prev_rat, 0) if prev_rat else cur_rank
    downgrade = bool(prev_rat and cur_rank < prev_rank)

    cipher = info.get("cipher") or {}
    cipher_val = None
    cipher_label = None
    if cipher.get("available"):
        cipher_val = cipher.get("cipher_value")
        cipher_label = CIPHER_LABELS.get(cipher_val)

    entry = {
        "ts":                 int(time.time()),
        "rat":                rat,
        "cell_id":            info.get("cell_id"),
        "mcc":                info.get("mcc"),
        "mnc":                info.get("mnc"),
        "downgrade":          downgrade,
        "prev_rat":           prev_rat,
        "ciphering":          cipher_val,
        "ciphering_label":    cipher_label,
        # Extended fields
        "ta":                 info.get("ta"),
        "neighbors":          neighbors_count,
        "neighbors_vanished": bool(ta_anomaly is False and neighbors_count == 0),
        "tac_change":         bool(tac_change),
        "cell_id_zero":       info.get("cell_id") == 0,
        "tac":                info.get("tac") or info.get("lac"),
        "rsrp":               info.get("rsrp"),
    }
    history.append(entry)
    # Cap file size to avoid unbounded growth
    if len(history) > RAT_HISTORY_MAX:
        history = history[-RAT_HISTORY_MAX:]
    with open(RAT_HISTORY, "w") as f:
        json.dump(history, f)


def detect_anomalies(info, neighbors_result, state):
    """Compare current observation with previous state — return list of alerts."""
    alerts = []
    rat = info.get("rat")
    cid = info.get("cell_id")
    tac = info.get("tac") or info.get("lac")

    # 1. RAT downgrade
    prev_rat = state.get("last_rat")
    if prev_rat and rat and RAT_RANK.get(rat, 0) < RAT_RANK.get(prev_rat, 0):
        alerts.append({
            "type":     "RAT_DOWNGRADE",
            "severity": "HIGH" if rat == "GSM" else "MEDIUM",
            "message":  f"Downgrade {prev_rat} → {rat}",
            "from":     prev_rat,
            "to":       rat,
        })

    # 2. Cipher plaintext
    cipher = info.get("cipher") or {}
    if cipher.get("available") and cipher.get("plaintext"):
        alerts.append({
            "type":     "CIPHER_PLAINTEXT",
            "severity": "HIGH",
            "message":  "Ciphering disabled (A5/0 or EEA0) — network forcing plaintext",
        })

    # 3. Timing Advance anomaly
    ta = info.get("ta")
    rsrp = info.get("rsrp")
    if ta == 0 and rsrp is not None and rsrp < -100:
        alerts.append({
            "type":     "TA_ANOMALY",
            "severity": "MEDIUM",
            "message":  f"TA=0 with weak RSRP {rsrp} dBm",
            "ta":       ta,
            "rsrp":     rsrp,
        })

    # 4. Neighbor-cell disappearance
    n_total = neighbors_result["total"]
    prev_n = state.get("last_neighbors", 0)
    if prev_n >= 3 and n_total == 0:
        alerts.append({
            "type":     "NEIGHBORS_DISAPPEARED",
            "severity": "HIGH",
            "message":  f"Neighbor count collapsed {prev_n} → 0",
        })

    # 5. TAC change on same physical tower (cell cloning)
    prev_cid = state.get("last_cell_id")
    prev_tac = state.get("last_tac")
    if cid and prev_cid == cid and prev_tac and tac and tac != prev_tac:
        alerts.append({
            "type":     "TAC_CHANGE_SAME_CID",
            "severity": "HIGH",
            "message":  f"Same CID {cid} but TAC changed {prev_tac} → {tac} (possible clone)",
        })

    # 6. Cell-ID 0 / spoofed identifier
    if cid == 0:
        alerts.append({
            "type":     "CELL_ID_ZERO",
            "severity": "MEDIUM",
            "message":  "Cell ID reported as 0",
        })

    return alerts


def sample_once():
    """Perform one observation cycle. Returns (info, neighbors_result, alerts)."""
    info = get_cell_info()
    if not info:
        return None, None, [{
            "type": "MODEM_UNREACHABLE",
            "severity": "LOW",
            "message": "Could not query serving cell",
        }]

    neighbors = get_neighbors()
    n_result = analyze_neighbors(neighbors, info)

    state = _load_state()
    prev_rat = state.get("last_rat")
    prev_tac = state.get("last_tac")
    alerts = detect_anomalies(info, n_result, state)

    # Persist sample into shared rat_history.json (cross_report consumer)
    current_tac = info.get("tac") or info.get("lac")
    tac_change = bool(
        info.get("cell_id") and state.get("last_cell_id") == info.get("cell_id")
        and prev_tac and current_tac and current_tac != prev_tac
    )
    _append_rat_history(info, prev_rat, n_result["total"],
                        any(a["type"] == "TA_ANOMALY" for a in alerts),
                        tac_change)

    # Update state
    state["last_rat"] = info.get("rat") or state.get("last_rat")
    state["last_cell_id"] = info.get("cell_id") or state.get("last_cell_id")
    state["last_tac"] = info.get("tac") or info.get("lac") or state.get("last_tac")
    state["last_neighbors"] = n_result["total"]
    state["samples"] = state.get("samples", 0) + 1
    state["alerts_total"] = state.get("alerts_total", 0) + len(alerts)
    state["last_seen"] = _now()
    _save_state(state)

    # Persist alerts
    for a in alerts:
        a["timestamp"] = _now()
        a["mcc"] = info.get("mcc")
        a["mnc"] = info.get("mnc")
        a["cell_id"] = info.get("cell_id")
        a["rat"] = info.get("rat")
        _log_alert(a)

    return info, n_result, alerts


def run_forever(interval):
    log.info("IMSI monitor started, poll every %ds", interval)
    try:
        while True:
            info, n, alerts = sample_once()
            ts = _now()
            if alerts:
                for a in alerts:
                    print(f"[{ts}] [{a['severity']}] {a['type']}: {a['message']}",
                          file=sys.stderr)
            else:
                rat = info.get("rat") if info else "?"
                cid = info.get("cell_id") if info else "?"
                print(f"[{ts}] OK rat={rat} cid={cid} neigh={n['total'] if n else '?'}",
                      file=sys.stderr)
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("IMSI monitor stopped")


def cmd_status():
    state = _load_state()
    print(json.dumps(state, indent=2))
    # Tail last 5 alerts if available
    try:
        with open(ALERT_LOG) as f:
            lines = f.readlines()[-5:]
        print("\n--- recent alerts ---", file=sys.stderr)
        for line in lines:
            print(line.rstrip(), file=sys.stderr)
    except FileNotFoundError:
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--interval", type=int, default=30, help="poll interval seconds")
    p.add_argument("--once", action="store_true", help="run one sample and exit")
    p.add_argument("--status", action="store_true", help="print state and last alerts")
    args = p.parse_args()

    if args.status:
        cmd_status()
        return

    if args.once:
        info, n, alerts = sample_once()
        result = {
            "timestamp": _now(),
            "serving":   info,
            "neighbors": n,
            "alerts":    alerts,
        }
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0 if not alerts else 2)

    run_forever(args.interval)


if __name__ == "__main__":
    main()
