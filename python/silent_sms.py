#!/usr/bin/env python3
"""
silent_sms.py — Continuous Silent-SMS & Binary-SMS & STK(OTA) detector

Polls the modem's SMS storage via AT+CMGL and inspects each PDU for:

  * TP-PID  = 0x40       → Silent SMS (Type 0, no user display)
  * TP-DCS  class 0      → Flash/Class-0 SMS (display-only, often covert)
  * TP-DCS  8-bit data   → Binary SMS (no text)
  * TP-PID  0x7F         → (U)SIM Data Download — OTA SIM update from carrier
  * TP-PID  0x3F/0x3E    → ME Data Download (SIM-toolkit OTA command)

Unlike normal SMS which the user reads in an inbox, silent/binary SMS are
commonly used for covert tracking, forced connection state queries, and
SIM-toolkit provisioning — all things we want to see.

Flagged PDUs are:
  1. logged to JSONL at /root/loot/raypager/silent_sms.jsonl
  2. preserved on the SIM (not deleted) unless --purge is passed
  3. optionally forwarded to the pager via stdout for LED/VIBRATE

Usage:
    python3 silent_sms.py                 # one scan
    python3 silent_sms.py --watch 60      # run forever, 60s poll
    python3 silent_sms.py --watch 30 --purge-binary
    python3 silent_sms.py --enable-urc    # configure AT+CNMI (one-time setup)
"""

import argparse
import json
import os
import re
import sys
import time
import logging
from datetime import datetime

from cell_info import _at

log = logging.getLogger(__name__)

LOOT_DIR = "/root/loot/raypager"
LOG_FILE = os.path.join(LOOT_DIR, "silent_sms.jsonl")
SEEN_FILE = os.path.join(LOOT_DIR, "silent_sms_seen.json")


def _now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


# ─── PDU decoding (minimal — enough for TP-PID/TP-DCS/OA) ──────────────────
# SMS-DELIVER PDU layout (3GPP TS 23.040, received-SMS):
#   <SCA><TP-MTI/...><TP-OA-len><TP-OA-toa><TP-OA-digits>
#   <TP-PID><TP-DCS><TP-SCTS(7)><TP-UDL><TP-UD...>

def _decode_semi_octets(hexstr):
    """Decode phone-number nibble-swapped semi-octets."""
    out = []
    for i in range(0, len(hexstr), 2):
        pair = hexstr[i:i+2]
        out.append(pair[1] + pair[0])
    digits = "".join(out).rstrip("F").rstrip("f")
    return digits


def parse_pdu(pdu_hex):
    """Return dict with TP-PID, TP-DCS, OA, classification. None on parse error."""
    try:
        p = pdu_hex.strip().upper()
        if not re.fullmatch(r"[0-9A-F]+", p):
            return None
        idx = 0
        sca_len = int(p[idx:idx+2], 16); idx += 2
        idx += sca_len * 2                                     # skip SCA
        first_octet = int(p[idx:idx+2], 16); idx += 2
        mti = first_octet & 0x03
        if mti != 0:                                           # only SMS-DELIVER
            return {"mti": mti, "tp_pid": None, "tp_dcs": None, "oa": None,
                    "classification": None, "note": f"MTI={mti}, skipped"}
        oa_len = int(p[idx:idx+2], 16); idx += 2
        idx += 2                                               # TOA
        oa_digits_len = oa_len + (oa_len & 1)                  # pad to even
        oa = _decode_semi_octets(p[idx:idx + oa_digits_len]); idx += oa_digits_len
        tp_pid = int(p[idx:idx+2], 16); idx += 2
        tp_dcs = int(p[idx:idx+2], 16); idx += 2

        classification = []
        if tp_pid == 0x40:
            classification.append("SILENT_SMS")                # Type 0
        if tp_pid == 0x7F:
            classification.append("SIM_DATA_DOWNLOAD")         # OTA to (U)SIM
        if tp_pid in (0x3E, 0x3F):
            classification.append("ME_DATA_DOWNLOAD")          # OTA to ME
        # TP-DCS class bits
        if (tp_dcs & 0x10):
            msg_class = tp_dcs & 0x03
            if msg_class == 0:
                classification.append("FLASH_SMS")
        # 8-bit / binary
        if (tp_dcs & 0x0C) == 0x04:
            classification.append("BINARY_SMS")

        return {
            "mti":            mti,
            "oa":             oa,
            "tp_pid":         tp_pid,
            "tp_pid_hex":     f"0x{tp_pid:02X}",
            "tp_dcs":         tp_dcs,
            "tp_dcs_hex":     f"0x{tp_dcs:02X}",
            "classification": classification,
            "suspicious":     bool(classification),
        }
    except (ValueError, IndexError):
        return None


# ─── AT wrappers ───────────────────────────────────────────────────────────

def enable_urc():
    """Configure modem to route all new SMS to storage + notify immediately."""
    _at("AT+CMGF=0")                         # PDU mode
    _at("AT+CPMS=\"ME\",\"ME\",\"ME\"")      # use modem storage
    r = _at("AT+CNMI=2,1,0,0,0")             # URC on new SMS
    return r is not None


def list_pdus():
    """Return list of (index, pdu_hex, status)."""
    _at("AT+CMGF=0")                         # ensure PDU mode
    raw = _at('AT+CMGL=4')                   # list ALL (stat=4)
    if not raw:
        return []
    # +CMGL: <idx>,<stat>,[<alpha>],<length><CR><LF><pdu>
    out = []
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'\+CMGL:\s*(\d+),(\d+),.*,(\d+)', line)
        if m and i + 1 < len(lines):
            idx = int(m.group(1))
            stat = int(m.group(2))
            pdu = lines[i + 1].strip()
            if pdu and re.fullmatch(r"[0-9A-Fa-f]+", pdu):
                out.append((idx, pdu, stat))
    return out


def delete_sms(idx):
    return _at(f"AT+CMGD={idx}")


# ─── State (dedup seen PDUs) ───────────────────────────────────────────────

def _load_seen():
    try:
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _save_seen(seen):
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(SEEN_FILE, "w") as f:
        json.dump(sorted(seen), f)


def _log_event(event):
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


# ─── Main scan ─────────────────────────────────────────────────────────────

def scan(purge_binary=False):
    seen = _load_seen()
    new_flags = []

    for idx, pdu, stat in list_pdus():
        if pdu in seen:
            continue
        seen.add(pdu)

        parsed = parse_pdu(pdu)
        if parsed and parsed.get("suspicious"):
            event = {
                "timestamp":     _now(),
                "storage_index": idx,
                "storage_stat":  stat,
                "sender":        parsed.get("oa"),
                "tp_pid":        parsed.get("tp_pid_hex"),
                "tp_dcs":        parsed.get("tp_dcs_hex"),
                "flags":         parsed.get("classification"),
                "pdu":           pdu,
            }
            _log_event(event)
            new_flags.append(event)

            if purge_binary and "BINARY_SMS" in parsed.get("classification", []):
                delete_sms(idx)
                event["purged"] = True

    _save_seen(seen)
    return new_flags


def main():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--watch", type=int, default=0, help="run forever, poll N seconds")
    p.add_argument("--enable-urc", action="store_true",
                   help="configure AT+CNMI for new-SMS notification")
    p.add_argument("--purge-binary", action="store_true",
                   help="delete BINARY_SMS after logging")
    p.add_argument("--status", action="store_true", help="print summary")
    args = p.parse_args()

    if args.enable_urc:
        ok = enable_urc()
        print(json.dumps({"enable_urc": ok}))
        return

    if args.status:
        try:
            with open(LOG_FILE) as f:
                events = [json.loads(l) for l in f]
        except FileNotFoundError:
            events = []
        summary = {
            "total_flagged":  len(events),
            "silent_count":   sum(1 for e in events if "SILENT_SMS" in e["flags"]),
            "binary_count":   sum(1 for e in events if "BINARY_SMS" in e["flags"]),
            "flash_count":    sum(1 for e in events if "FLASH_SMS"  in e["flags"]),
            "ota_sim_count":  sum(1 for e in events if "SIM_DATA_DOWNLOAD" in e["flags"]),
            "recent":         events[-5:],
        }
        print(json.dumps(summary, indent=2))
        return

    if args.watch:
        print(f"[silent_sms] watching every {args.watch}s", file=sys.stderr)
        try:
            while True:
                flags = scan(args.purge_binary)
                if flags:
                    for f in flags:
                        print(f"[{f['timestamp']}] {','.join(f['flags'])} "
                              f"from={f['sender']} pid={f['tp_pid']}", file=sys.stderr)
                time.sleep(args.watch)
        except KeyboardInterrupt:
            pass
    else:
        flags = scan(args.purge_binary)
        print(json.dumps({"new_flagged": len(flags), "events": flags}, indent=2))
        sys.exit(0 if not flags else 2)


if __name__ == "__main__":
    main()
