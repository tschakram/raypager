#!/usr/bin/env python3
"""
cell_info.py — Serving cell information via Quectel AT commands
Raypager / GL-E750V2 Mudi V2 (EM050-G modem, OpenWrt 22.03)

Uses gl_modem AT wrapper to query:
  AT+QENG="servingcell"   → full engineering data (Cell-ID, TAC, EARFCN, RSRP...)
  AT+QNWINFO              → quick network info (band, channel)
  AT+COPS?                → operator (MCC+MNC, name)
  AT+CSQ                  → signal quality (RSSI)
"""

import subprocess
import re
import json
import sys
import time
import logging

log = logging.getLogger(__name__)

# Timeout for AT command responses (seconds)
AT_TIMEOUT = 5

# gl_modem binary path on Mudi
GL_MODEM = "gl_modem"


# ─── AT Command Interface ────────────────────────────────────────────────────

def _at(cmd):
    """Send one AT command via gl_modem, return raw response string or None."""
    try:
        result = subprocess.run(
            [GL_MODEM, "AT", cmd],
            capture_output=True,
            text=True,
            timeout=AT_TIMEOUT,
        )
        output = result.stdout.strip()
        if result.returncode != 0 or "ERROR" in output:
            log.warning("AT cmd %s returned error: %s", cmd, output)
            return None
        return output
    except subprocess.TimeoutExpired:
        log.warning("AT cmd %s timed out", cmd)
        return None
    except FileNotFoundError:
        log.error("gl_modem not found — running on Mudi?")
        return None


# ─── Parsers ────────────────────────────────────────────────────────────────

def _safe_int(v, base=10):
    """int() that returns None on failure instead of raising."""
    try:
        return int(v, base) if base != 10 else int(v)
    except (ValueError, TypeError):
        return None


def _parse_qeng_lte(fields):
    """Parse AT+QENG="servingcell" fields for LTE (FDD/TDD).

    fields (0-indexed from after "servingcell"):
      [0]=state  [1]=LTE  [2]=duplex  [3]=MCC  [4]=MNC  [5]=cellID(hex)
      [6]=PCID   [7]=EARFCN  [8]=band  [9]=UL_BW  [10]=DL_BW  [11]=TAC(hex)
      [12]=RSRP  [13]=RSRQ  [14]=RSSI  [15]=SINR  [16]=CQI  [17]=tx_power
      [18]=srxlev
    TA is not exposed in servingcell — queried separately via AT+QCAINFO when supported.
    """
    try:
        return {
            "rat":         "LTE",
            "duplex":      fields[2],
            "mcc":         fields[3],
            "mnc":         fields[4],
            "cell_id":     int(fields[5], 16),          # hex → int
            "cell_id_hex": fields[5].upper(),
            "pcid":        int(fields[6]),
            "earfcn":      int(fields[7]),
            "band":        int(fields[8]),
            "tac":         int(fields[11], 16),          # hex → int
            "rsrp":        int(fields[12]),              # dBm
            "rsrq":        int(fields[13]),              # dB
            "rssi":        int(fields[14]),              # dBm
            "sinr":        int(fields[15]),              # dB
            "cqi":         _safe_int(fields[16]) if len(fields) > 16 else None,
            "tx_power":    _safe_int(fields[17]) if len(fields) > 17 else None,
            "srxlev":      _safe_int(fields[18]) if len(fields) > 18 else None,
        }
    except (IndexError, ValueError) as e:
        log.warning("LTE field parse error: %s | fields: %s", e, fields)
        return None


def _parse_qeng_nr(fields):
    """Parse AT+QENG="servingcell" fields for 5G NR SA/NSA.

    fields: [0]=state [1]=NR [2]=duplex [3]=MCC [4]=MNC [5]=cellID(hex)
            [6]=PCI   [7]=ARFCN [8]=band [9]=TAC(hex) [10]=RSRP [11]=RSRQ [12]=SINR
    """
    try:
        return {
            "rat":         "NR",
            "duplex":      fields[2],
            "mcc":         fields[3],
            "mnc":         fields[4],
            "cell_id":     int(fields[5], 16),
            "cell_id_hex": fields[5].upper(),
            "pci":         int(fields[6]),
            "arfcn":       int(fields[7]),
            "band":        int(fields[8]),
            "tac":         int(fields[9], 16),
            "rsrp":        int(fields[10]),
            "rsrq":        int(fields[11]),
            "sinr":        int(fields[12]),
        }
    except (IndexError, ValueError) as e:
        log.warning("NR field parse error: %s | fields: %s", e, fields)
        return None


def _parse_qeng_gsm(fields):
    """Parse AT+QENG="servingcell" fields for GSM/2G.

    fields: [0]=state [1]=GSM [2]=MCC [3]=MNC [4]=LAC(hex) [5]=cellID(hex)
            [6]=BSIC [7]=ARFCN [8]=band_gsm [9]=rxlev [10]=txp
            [11]=rla [12]=drx [13]=c1 [14]=c2 [15]=GPRS [16]=tch_type
            [17]=ta  (Timing Advance — only valid in DEDICATED state)
    """
    try:
        ta_raw = fields[17] if len(fields) > 17 else None
        return {
            "rat":         "GSM",
            "mcc":         fields[2],
            "mnc":         fields[3],
            "lac":         int(fields[4], 16),
            "cell_id":     int(fields[5], 16),
            "cell_id_hex": fields[5].upper(),
            "bsic":        _safe_int(fields[6]),
            "arfcn":       _safe_int(fields[7]),
            "rxlev":       _safe_int(fields[9]) if len(fields) > 9 else None,
            "ta":          _safe_int(ta_raw),
        }
    except (IndexError, ValueError) as e:
        log.warning("GSM field parse error: %s | fields: %s", e, fields)
        return None


def _parse_qeng_wcdma(fields):
    """Parse AT+QENG="servingcell" fields for WCDMA/UMTS.

    fields: [0]=state [1]=WCDMA [2]=MCC [3]=MNC [4]=LAC(hex) [5]=cellID(hex)
            [6]=UARFCN [7]=PSC [8]=RSCP [9]=ECIO
    """
    try:
        return {
            "rat":         "WCDMA",
            "mcc":         fields[2],
            "mnc":         fields[3],
            "lac":         int(fields[4], 16),
            "cell_id":     int(fields[5], 16),
            "cell_id_hex": fields[5].upper(),
            "uarfcn":      int(fields[6]),
            "psc":         int(fields[7]),
            "rscp":        int(fields[8]),
            "ecio":        int(fields[9]),
        }
    except (IndexError, ValueError) as e:
        log.warning("WCDMA field parse error: %s | fields: %s", e, fields)
        return None


def _parse_qeng(raw):
    """Parse full AT+QENG="servingcell" response."""
    if not raw:
        return None

    # Find the +QENG: line
    match = re.search(r'\+QENG:\s*"servingcell",(.+)', raw)
    if not match:
        log.warning("No +QENG: servingcell in response: %s", raw)
        return None

    # Split CSV, stripping quotes
    parts = [p.strip().strip('"') for p in match.group(1).split(',')]

    # parts[0] = state (NOCONN/SEARCH/LIMSRV/CONNECT)
    # parts[1] = RAT (LTE/NR/WCDMA/GSM)
    state = parts[0]
    rat   = parts[1] if len(parts) > 1 else ""

    # Modem not connected — return minimal dict so callers can distinguish
    # NOSERVICE/SEARCH from a real GHOST (tower without identity)
    if state in ("NOSERVICE", "SEARCH", "LIMSRV"):
        return {"state": state, "noservice": True, "rat": None, "raw": raw}

    result = None
    if rat == "LTE":
        result = _parse_qeng_lte(parts)
    elif rat == "NR":
        result = _parse_qeng_nr(parts)
    elif rat == "WCDMA":
        result = _parse_qeng_wcdma(parts)
    elif rat == "GSM":
        result = _parse_qeng_gsm(parts)
    else:
        log.warning("Unknown RAT: %s (state: %s)", rat, state)
        return None

    if result:
        result["state"] = state
        result["raw"] = raw

    return result


def _parse_qnwinfo(raw):
    """Parse AT+QNWINFO response: +QNWINFO: "FDD LTE",26201,"LTE BAND 3",1650"""
    if not raw:
        return {}
    match = re.search(r'\+QNWINFO:\s*"([^"]+)","(\d+)","([^"]+)",(\d+)', raw)
    if not match:
        return {}
    plmn = match.group(2)
    return {
        "act":     match.group(1),          # e.g. "FDD LTE"
        "plmn":    plmn,
        "mcc_nwinfo": plmn[:3],
        "mnc_nwinfo": plmn[3:],
        "band_name": match.group(3),         # e.g. "LTE BAND 3"
        "channel": int(match.group(4)),
    }


def _parse_cops(raw):
    """Parse AT+COPS? response: +COPS: 0,0,"Telekom.de",7"""
    if not raw:
        return {}
    match = re.search(r'\+COPS:\s*\d+,\d+,"([^"]+)",(\d+)', raw)
    if not match:
        return {}
    act_map = {"0": "GSM", "2": "UMTS", "7": "LTE", "11": "NR", "12": "NR"}
    act_code = match.group(2)
    return {
        "operator_name": match.group(1),
        "act_code":      act_code,
        "act_cops":      act_map.get(act_code, act_code),
    }


def _parse_csq(raw):
    """Parse AT+CSQ response: +CSQ: 20,0  → RSSI in dBm"""
    if not raw:
        return {}
    match = re.search(r'\+CSQ:\s*(\d+),(\d+)', raw)
    if not match:
        return {}
    rssi_raw = int(match.group(1))
    # 99 = unknown; 0–31 → -113 + 2*n dBm
    rssi_dbm = -113 + 2 * rssi_raw if rssi_raw != 99 else None
    return {
        "csq_raw":  rssi_raw,
        "rssi_csq": rssi_dbm,
    }


# ─── Timing Advance probe ──────────────────────────────────────────────────
# TA is not in +QENG="servingcell" for LTE. Quectel EC25 exposes it via
# AT+QCAINFO (field 8 of primary cell row). Falls back silently if unsupported.

def _get_timing_advance():
    """Query Timing Advance via AT+QCAINFO. Returns int (TA units) or None.

    +QCAINFO response (per carrier):
      +QCAINFO: "PCC",<EARFCN>,<bandwidth>,<band>,<PCID>,<RSRP>,<RSRQ>,<RSSI>,<SINR>[,<TA>]
    TA field only present on some firmwares / while in CONNECTED state.
    """
    raw = _at_quiet("AT+QCAINFO")
    if not raw:
        return None
    # Look for PCC row
    m = re.search(r'\+QCAINFO:\s*"PCC"[^\r\n]*', raw)
    if not m:
        return None
    parts = [p.strip().strip('"') for p in m.group(0).split(',')]
    # TA would be the last numeric field when present (position 9 or later)
    for candidate in reversed(parts):
        n = _safe_int(candidate)
        if n is not None and 0 <= n <= 1282:   # LTE TA range
            return n
    return None


# ─── Cipher / encryption mode probe ────────────────────────────────────────
# Note: AT does NOT provide standardized cipher-mode reporting on Quectel.
# We probe several vendor URCs; if none yields data, return None (unknown).
# Absence of data is NOT a clean-signal — it just means we cannot observe.

def _at_quiet(cmd):
    """Like _at() but failures are logged at DEBUG (for optional probes)."""
    import subprocess
    try:
        r = subprocess.run([GL_MODEM, "AT", cmd], capture_output=True,
                           text=True, timeout=AT_TIMEOUT)
        out = r.stdout.strip()
        if r.returncode != 0 or "ERROR" in out:
            log.debug("optional AT %s unsupported: %s", cmd, out)
            return None
        return out
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _get_cipher_mode():
    """Try to detect the active cipher. Returns dict or None if unavailable.

    Known paths tested (best-effort, modem/firmware dependent):
      AT+QNWCFG="ciphering_ind"   — enable network-initiated URCs
      AT+QNWINFO                  — already fetched, no cipher info
      AT+QCSEARCH                 — not cipher, but shows network mode
    On most EC25 firmwares cipher mode is NOT exposed. That is documented
    so the monitor doesn't false-positive when the signal is simply missing.
    """
    # Try to enable cipher indication (harmless if unsupported)
    raw = _at_quiet('AT+QNWCFG="ciphering_ind"')
    if raw and '+QNWCFG:' in raw:
        m = re.search(r'\+QNWCFG:\s*"ciphering_ind",(\d+),(\d+)', raw)
        if m:
            enabled, cipher = m.group(1), m.group(2)
            return {
                "available": True,
                "enabled": int(enabled) == 1,
                "cipher_value": int(cipher),
                "plaintext": int(cipher) == 1,   # 1 = ciphering OFF (plaintext)
            }
    return {"available": False}


# ─── Public API ─────────────────────────────────────────────────────────────

def get_cell_info():
    """
    Query serving cell info from the EM050-G modem.

    Returns dict with keys:
      rat, mcc, mnc, cell_id, cell_id_hex, tac/lac, earfcn/arfcn/uarfcn,
      band, rsrp, rsrq, rssi, sinr, state,
      operator_name, act, band_name, channel,
      csq_raw, rssi_csq,
      timestamp, raw

    Returns None if modem is unreachable or no cell info available.
    """
    # Run all AT queries (sequential — modem may not handle parallel)
    raw_qeng    = _at('AT+QENG="servingcell"')
    raw_qnwinfo = _at("AT+QNWINFO")
    raw_cops    = _at("AT+COPS?")
    raw_csq     = _at("AT+CSQ")

    # Primary source: QENG
    info = _parse_qeng(raw_qeng)
    if info is None:
        log.warning("QENG parse failed — modem may be in limited service")
        info = {}

    # Merge supplementary sources
    info.update(_parse_qnwinfo(raw_qnwinfo))
    info.update(_parse_cops(raw_cops))
    info.update(_parse_csq(raw_csq))

    if not info:
        return None

    # Timing advance (LTE: separate query; GSM: already from QENG)
    if info.get("rat") == "LTE" and info.get("ta") is None:
        info["ta"] = _get_timing_advance()

    # Cipher mode probe (best-effort, often unavailable)
    cipher = _get_cipher_mode()
    if cipher:
        info["cipher"] = cipher

    info["timestamp"] = int(time.time())
    return info


def is_suspicious(info):
    """
    Basic heuristics to flag potentially anomalous cell towers.
    Returns list of warning strings (empty = clean).

    Note: these are low-confidence indicators only. OpenCelliD lookup
    (opencellid.py) provides higher-confidence verification.
    """
    warnings = []

    rsrp = info.get("rsrp")
    rsrq = info.get("rsrq")
    sinr = info.get("sinr")

    # Unusually strong signal (IMSI catchers are often nearby)
    if rsrp is not None and rsrp > -60:
        warnings.append(f"RSRP very strong: {rsrp} dBm (possible nearby tower)")

    # Very poor quality despite strong signal — may indicate fake BTS
    if rsrp is not None and rsrq is not None:
        if rsrp > -70 and rsrq < -15:
            warnings.append(f"Strong signal but poor quality: RSRP={rsrp}, RSRQ={rsrq}")

    # Downgrade to 2G/3G while LTE available — classic IMSI-catcher trick
    rat = info.get("rat", "")
    if rat == "GSM":
        warnings.append("RAT=GSM (2G) — strong IMSI-catcher indicator (forced downgrade)")
    elif rat == "WCDMA":
        warnings.append("RAT=WCDMA (3G) — possible IMSI-catcher downgrade")

    # Cell ID 0 or PCID 0 can indicate spoofed cell
    cell_id = info.get("cell_id")
    if cell_id == 0:
        warnings.append("Cell ID is 0 — suspicious")

    # Timing Advance anomaly: very low TA combined with weak signal → spoofed proximity
    ta = info.get("ta")
    if ta is not None:
        if rat == "LTE" and ta == 0 and rsrp is not None and rsrp < -100:
            warnings.append(f"TA=0 (≤78m) with weak RSRP {rsrp} dBm — spoofed-proximity indicator")
        if rat == "GSM" and ta == 0 and info.get("rxlev") is not None and info["rxlev"] < 20:
            warnings.append(f"GSM TA=0 with rxlev {info['rxlev']} — spoofed-proximity indicator")

    # Cipher / plaintext (A5/0 for GSM, EEA0 for LTE)
    cipher = info.get("cipher") or {}
    if cipher.get("available") and cipher.get("plaintext"):
        warnings.append("Ciphering DISABLED (plaintext) — A5/0 or EEA0 forced → IMSI-catcher")

    # Legacy 2G ciphers (A5/0, A5/1) are weak — GSM itself already warned above
    return warnings


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    print("Querying serving cell info...", file=sys.stderr)
    info = get_cell_info()

    if not info:
        print("ERROR: Could not retrieve cell info", file=sys.stderr)
        sys.exit(1)

    # Pretty JSON output
    output = {k: v for k, v in info.items() if k != "raw"}
    print(json.dumps(output, indent=2))

    warnings = is_suspicious(info)
    if warnings:
        print("\n[!] ANOMALY INDICATORS:", file=sys.stderr)
        for w in warnings:
            print(f"    - {w}", file=sys.stderr)
    else:
        print("[+] No anomalies detected", file=sys.stderr)


if __name__ == "__main__":
    main()
