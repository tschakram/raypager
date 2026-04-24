#!/usr/bin/env python3
"""
sms_loopback.py — SMS MO/MT loopback test for interception detection

Gated behind explicit config opt-in (sms_loopback.enabled = true) so the
test never runs silently and never sends a message by accident.

Flow:
  1. Check config: sms_loopback.enabled must be true
  2. Generate unique token  RAYPAGER-<timestamp>-<random>
  3. Send SMS to sms_loopback.test_number (defaults to own MSISDN via AT+CNUM)
  4. Poll inbox (AT+CMGL) every 5s for up to timeout_s seconds
  5. Compare content and measure latency
  6. Flag as SUSPICIOUS if:
       - timeout (no MT)
       - latency > threshold_s
       - content mismatch

Results appended to /root/loot/raypager/sms_loopback.jsonl.

Usage:
    python3 sms_loopback.py                   # run once (if enabled)
    python3 sms_loopback.py --force           # run even if disabled
    python3 sms_loopback.py --target +4912345 # override test number
"""

import argparse
import json
import os
import re
import sys
import time
import random
import string
import logging
from datetime import datetime

from cell_info import _at

log = logging.getLogger(__name__)

CONFIG_PATH = "/root/raypager/config.json"
LOOT_DIR = "/root/loot/raypager"
LOG_FILE = os.path.join(LOOT_DIR, "sms_loopback.jsonl")

DEFAULT_TIMEOUT_S = 180          # total MT wait
DEFAULT_LATENCY_WARN_S = 30      # > this = suspicious


def _now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _get_own_msisdn():
    """AT+CNUM returns subscriber number when SIM/carrier provisions it."""
    raw = _at("AT+CNUM")
    if not raw:
        return None
    m = re.search(r'\+CNUM:\s*"[^"]*","([+\d]+)"', raw)
    return m.group(1) if m else None


def _gen_token():
    rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"RAYPAGER-{int(time.time())}-{rnd}"


def _send_sms(number, text):
    """Send SMS in text mode. Returns True on success."""
    _at("AT+CMGF=1")                         # text mode
    _at('AT+CSCS="GSM"')

    # Two-step: AT+CMGS="<num>" → prompt → text + Ctrl-Z
    # gl_modem AT wrapper is line-based; use special two-arg form if it supports it.
    # Fallback: use a small subprocess that writes directly to /dev/smd7 or similar.
    import subprocess
    script = f'AT+CMGS="{number}"\r'
    try:
        # gl_modem "AT" takes single command; for CMGS we chain via combined form:
        full = f'AT+CMGS="{number}"\r\n{text}\x1a'
        result = subprocess.run(
            ["gl_modem", "AT", full],
            capture_output=True, text=True, timeout=30,
        )
        ok = "+CMGS:" in result.stdout or "OK" in result.stdout
        if not ok:
            log.warning("CMGS failed: %s", result.stdout)
        return ok
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        log.error("gl_modem not found")
        return False


def _poll_for_token(token, timeout_s):
    """Poll AT+CMGL for the token. Returns (found, latency_s, content)."""
    _at("AT+CMGF=1")
    start = time.time()
    while time.time() - start < timeout_s:
        raw = _at('AT+CMGL="ALL"')
        if raw and token in raw:
            latency = time.time() - start
            # Try to capture the exact body line that followed the last +CMGL
            body_match = None
            lines = raw.splitlines()
            for i, line in enumerate(lines):
                if "+CMGL" in line:
                    body_match = lines[i+1] if i + 1 < len(lines) else None
                    if body_match and token in body_match:
                        break
            return True, latency, body_match
        time.sleep(5)
    return False, timeout_s, None


def run_test(target=None, timeout_s=DEFAULT_TIMEOUT_S):
    cfg = _load_config().get("sms_loopback", {})
    number = target or cfg.get("test_number") or _get_own_msisdn()
    if not number:
        return {
            "timestamp": _now(),
            "result":    "ERROR",
            "reason":    "No target number (AT+CNUM empty, no test_number in config)",
        }

    latency_warn = cfg.get("latency_warn_s", DEFAULT_LATENCY_WARN_S)
    token = _gen_token()
    text = f"{token} raypager loopback test"

    t0 = time.time()
    sent = _send_sms(number, text)
    if not sent:
        result = {
            "timestamp":   _now(),
            "target":      number,
            "token":       token,
            "result":      "SEND_FAILED",
            "reason":      "AT+CMGS did not return OK (MO blocked or modem error)",
            "suspicious":  True,
        }
    else:
        found, latency, body = _poll_for_token(token, timeout_s)
        send_roundtrip = time.time() - t0
        if not found:
            result = {
                "timestamp":  _now(),
                "target":     number,
                "token":      token,
                "result":     "TIMEOUT",
                "reason":     f"No MT receipt within {timeout_s}s",
                "suspicious": True,
            }
        else:
            content_ok = body is not None and token in body
            suspicious = (latency > latency_warn) or (not content_ok)
            result = {
                "timestamp":     _now(),
                "target":        number,
                "token":         token,
                "result":        "OK" if not suspicious else "SUSPICIOUS",
                "latency_s":     round(latency, 1),
                "roundtrip_s":   round(send_roundtrip, 1),
                "content_match": content_ok,
                "suspicious":    suspicious,
                "reason":        (
                    f"High latency ({latency:.0f}s > {latency_warn}s)" if latency > latency_warn
                    else ("Content modified" if not content_ok else "Passed")
                ),
            }

    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(result) + "\n")
    return result


def main():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--force", action="store_true", help="run even if config disables it")
    p.add_argument("--target", help="override test_number")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    args = p.parse_args()

    cfg = _load_config().get("sms_loopback", {})
    if not cfg.get("enabled") and not args.force:
        print(json.dumps({
            "result": "DISABLED",
            "reason": "sms_loopback.enabled is false in config.json. Use --force to override.",
        }, indent=2))
        sys.exit(1)

    result = run_test(args.target, args.timeout)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("result") == "OK" else 2)


if __name__ == "__main__":
    main()
