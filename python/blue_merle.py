#!/usr/bin/env python3
"""
blue_merle.py — Blue Merle IMEI/radio control interface
Raypager / GL-E750V2 Mudi V2

Wraps the Blue Merle toolkit (SRLabs) and gl_modem AT interface for:
  - Reading current IMEI and IMSI
  - Rotating IMEI (random or IMSI-deterministic)
  - Enabling / disabling modem radio
  - Triggering full SIM-swap rotation flow

Blue Merle paths on Mudi:
  /lib/blue-merle/imei_generate.py   — IMEI generator
  gl_modem AT <cmd>                  — AT command wrapper

Docs: https://github.com/srlabs/blue-merle
"""

import subprocess
import re
import sys
import time
import logging

log = logging.getLogger(__name__)

# Paths on Mudi
IMEI_GENERATE  = "/lib/blue-merle/imei_generate.py"
GL_MODEM       = "gl_modem"
POWER_OFF_DEV  = "/dev/ttyS0"

# Timeouts
AT_TIMEOUT     = 5   # seconds
CFUN_TIMEOUT   = 15  # AT+CFUN can be slow (network detach)
IMEI_TIMEOUT   = 30  # imei_generate.py writes to modem


# ─── AT helpers ──────────────────────────────────────────────────────────────

def _at(cmd, timeout=AT_TIMEOUT):
    """Send AT command via gl_modem wrapper. Returns stdout or None."""
    try:
        r = subprocess.run(
            [GL_MODEM, "AT", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        out = r.stdout.strip()
        if r.returncode != 0 or "ERROR" in out:
            log.warning("AT %s → error: %s", cmd, out)
            return None
        return out
    except subprocess.TimeoutExpired:
        log.warning("AT %s timed out", cmd)
        return None
    except FileNotFoundError:
        log.error("gl_modem not found — running on Mudi?")
        return None


def _run(cmd_list, timeout=AT_TIMEOUT):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd_list, capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        log.warning("Command timed out: %s", cmd_list)
        return -1, "", "timeout"
    except FileNotFoundError as e:
        log.error("Command not found: %s", e)
        return -1, "", str(e)


# ─── IMEI / IMSI ─────────────────────────────────────────────────────────────

def get_imei():
    """
    Read current IMEI from modem via AT+GSN.
    Returns IMEI string (15 digits) or None.
    """
    raw = _at("AT+GSN")
    if not raw:
        return None
    # Response is bare IMEI on its own line, optionally with OK
    match = re.search(r'\b(\d{15})\b', raw)
    return match.group(1) if match else None


def get_imsi():
    """
    Read IMSI from SIM via AT+CIMI.
    Returns IMSI string or None (None if no SIM inserted).
    """
    raw = _at("AT+CIMI")
    if not raw:
        return None
    match = re.search(r'\b(\d{10,15})\b', raw)
    return match.group(1) if match else None


# ─── Radio control ───────────────────────────────────────────────────────────

def disable_radio():
    """
    Set modem to airplane mode (AT+CFUN=4).
    Required before IMEI rotation to prevent IMEI leakage to network.
    Returns True on success.
    """
    log.debug("Disabling radio (CFUN=4)...")
    raw = _at("AT+CFUN=4", timeout=CFUN_TIMEOUT)
    if raw is None:
        return False
    log.debug("Radio disabled")
    return True


def enable_radio():
    """
    Restore full modem functionality (AT+CFUN=1).
    Returns True on success.
    """
    log.debug("Enabling radio (CFUN=1)...")
    raw = _at("AT+CFUN=1", timeout=CFUN_TIMEOUT)
    if raw is None:
        return False
    log.debug("Radio enabled")
    return True


def get_radio_state():
    """
    Read current CFUN state.
    Returns int (0=min, 1=full, 4=airplane) or None.
    """
    raw = _at("AT+CFUN?")
    if not raw:
        return None
    match = re.search(r'\+CFUN:\s*(\d+)', raw)
    return int(match.group(1)) if match else None


# ─── IMEI rotation ───────────────────────────────────────────────────────────

def rotate_imei(mode="random"):
    """
    Rotate IMEI using Blue Merle's imei_generate.py.

    Args:
        mode: "random"        → completely random IMEI (-r)
              "deterministic" → IMSI-based pseudo-random IMEI (-d)
                                (same SIM always gets the same IMEI)

    Returns dict:
        {"success": bool, "imei_before": str, "imei_after": str, "mode": str}

    IMPORTANT: Radio must be disabled (CFUN=4) before calling this.
    Device should be powered off after rotation, SIM swapped, location changed.
    """
    flag = "-r" if mode == "random" else "-d"

    imei_before = get_imei()
    log.debug("IMEI before rotation: %s", imei_before)

    rc, out, err = _run(
        ["python3", IMEI_GENERATE, flag],
        timeout=IMEI_TIMEOUT,
    )

    if rc != 0:
        log.error("imei_generate.py failed (rc=%d): %s", rc, err or out)
        return {
            "success":     False,
            "imei_before": imei_before,
            "imei_after":  None,
            "mode":        mode,
            "error":       err or out,
        }

    imei_after = get_imei()
    log.debug("IMEI after rotation: %s", imei_after)

    success = (imei_after is not None and imei_after != imei_before)
    return {
        "success":     success,
        "imei_before": imei_before,
        "imei_after":  imei_after,
        "mode":        mode,
    }


# ─── Power off ───────────────────────────────────────────────────────────────

def poweroff():
    """
    Power off the Mudi device via /dev/ttyS0.
    Call this after IMEI rotation — device must be off before SIM swap.
    This call does not return (device shuts down).
    """
    log.debug("Sending poweroff signal...")
    try:
        with open(POWER_OFF_DEV, "w") as f:
            f.write('{ "poweroff": "1" }')
        time.sleep(3)   # give kernel time to process before we exit
    except OSError as e:
        log.error("poweroff failed: %s", e)
        return False
    return True


# ─── Full rotation flow ───────────────────────────────────────────────────────

def full_rotation(mode="random", do_poweroff=False):
    """
    Complete Blue Merle SIM-swap rotation flow:
      1. Disable radio (prevent IMEI leakage)
      2. Read current IMSI (for deterministic mode)
      3. Rotate IMEI
      4. Verify new IMEI
      5. Power off (optional — caller may want to show UI first)

    Args:
        mode:        "random" or "deterministic"
        do_poweroff: if True, power off after successful rotation

    Returns dict with full status. If do_poweroff=False, caller must
    power off the device after showing the user the instructions.
    """
    result = {
        "step":    None,
        "success": False,
        "mode":    mode,
        "imei_before": None,
        "imei_after":  None,
        "imsi":        None,
        "powered_off": False,
    }

    # Step 1: disable radio
    result["step"] = "disable_radio"
    if not disable_radio():
        result["error"] = "Failed to disable radio"
        return result
    time.sleep(1)

    # Step 2: read IMSI (needed for deterministic mode; log for reference)
    imsi = get_imsi()
    result["imsi"] = imsi
    if mode == "deterministic" and not imsi:
        log.warning("Deterministic mode requested but no IMSI — falling back to random")
        mode = "random"
        result["mode"] = mode

    # Step 3: rotate IMEI
    result["step"] = "rotate_imei"
    rot = rotate_imei(mode)
    result["imei_before"] = rot["imei_before"]
    result["imei_after"]  = rot["imei_after"]

    if not rot["success"]:
        result["error"] = rot.get("error", "IMEI rotation failed")
        # Re-enable radio so device is not bricked
        enable_radio()
        return result

    # Step 4: power off (optional)
    result["step"] = "poweroff"
    result["success"] = True

    if do_poweroff:
        result["powered_off"] = poweroff()

    return result


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    """
    Usage:
      blue_merle.py status                  # show IMEI, IMSI, radio state
      blue_merle.py rotate                  # random IMEI rotation (no poweroff)
      blue_merle.py rotate deterministic    # IMSI-based IMEI rotation
      blue_merle.py rotate --poweroff       # rotate + power off
      blue_merle.py radio off               # disable radio (CFUN=4)
      blue_merle.py radio on                # enable radio (CFUN=1)
    """
    import json
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    args = sys.argv[1:]
    cmd  = args[0] if args else "status"

    if cmd == "status":
        imei  = get_imei()
        imsi  = get_imsi()
        radio = get_radio_state()
        radio_label = {0: "minimum", 1: "full", 4: "airplane"}.get(radio, str(radio))
        print(json.dumps({
            "imei":        imei,
            "imsi":        imsi,
            "radio_state": radio,
            "radio_label": radio_label,
        }, indent=2))

    elif cmd == "rotate":
        mode       = "deterministic" if "deterministic" in args else "random"
        do_off     = "--poweroff" in args
        print(f"Rotating IMEI (mode={mode}, poweroff={do_off})...", file=sys.stderr)
        result = full_rotation(mode=mode, do_poweroff=do_off)
        print(json.dumps(result, indent=2))
        if not result["success"]:
            sys.exit(1)
        if do_off:
            print("Device powering off. Swap SIM, change location, then boot.",
                  file=sys.stderr)

    elif cmd == "radio":
        sub = args[1] if len(args) > 1 else ""
        if sub == "off":
            ok = disable_radio()
            print("Radio disabled" if ok else "ERROR: could not disable radio",
                  file=sys.stderr)
            sys.exit(0 if ok else 1)
        elif sub == "on":
            ok = enable_radio()
            print("Radio enabled" if ok else "ERROR: could not enable radio",
                  file=sys.stderr)
            sys.exit(0 if ok else 1)
        else:
            print(f"Unknown radio subcommand: {sub}", file=sys.stderr)
            sys.exit(1)

    else:
        print(__doc__, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
