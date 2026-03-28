#!/bin/bash
# =============================================================================
# Raypager — IMSI-Catcher Detection & IMEI Rotation
# WiFi Pineapple Pager payload (DuckyScript framework)
#
# Architecture:
#   Pager  →  WiFi+SSH  →  Mudi V2 (GL-E750V2)
#                           ├── gl_modem AT (EM050-G modem)
#                           ├── python/gps.py  (/dev/ttyACM0, u-blox M8130)
#                           └── python3 /root/raypager/python/
#
# Config:  /root/payloads/user/reconnaissance/raypager/config.json
# Loot:    /root/loot/raypager/
# =============================================================================

export PATH="/mmc/usr/bin:/mmc/usr/sbin:/mmc/bin:/mmc/sbin:$PATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:/mmc/lib:${LD_LIBRARY_PATH:-}"

# Ensure this script is readable/executable regardless of how scp set permissions
chmod 755 "$0" 2>/dev/null

PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$PAYLOAD_DIR/config.json"
LOOT_DIR="/root/loot/raypager"

# ── LED color constants ───────────────────────────────────────────────────────
LED_OFF="000000"
LED_GREEN="00ff00"
LED_YELLOW="ffff00"
LED_ORANGE="ff8800"
LED_RED="ff0000"
LED_BLUE="0000ff"
LED_WHITE="ffffff"

# ── Connection config (hardcoded defaults, overridable via config.json) ───────
MUDI_HOST="192.168.8.1"
MUDI_USER="root"
MUDI_KEY="/root/.ssh/mudi_key"
MUDI_PY="/root/raypager/python"

# Override defaults from config.json if python3 is available
if command -v python3 >/dev/null 2>&1 && [ -f "$CONFIG" ]; then
    _h=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d.get('mudi_host',''),end='')" 2>/dev/null)
    _u=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d.get('mudi_user',''),end='')" 2>/dev/null)
    _k=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d.get('mudi_key',''),end='')" 2>/dev/null)
    _p=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d.get('mudi_python',''),end='')" 2>/dev/null)
    [ -n "$_h" ] && MUDI_HOST="$_h"
    [ -n "$_u" ] && MUDI_USER="$_u"
    [ -n "$_k" ] && MUDI_KEY="$_k"
    [ -n "$_p" ] && MUDI_PY="$_p"
fi

SSH_OPTS="-i $MUDI_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -o HostKeyAlgorithms=+ssh-rsa"

# ── SSH helper ────────────────────────────────────────────────────────────────
mudi() {
    ssh $SSH_OPTS "$MUDI_USER@$MUDI_HOST" "$@" 2>/dev/null
}

mudi_py() {
    local script="$1"; shift
    mudi "cd '$MUDI_PY' && python3 '$script' $*"
}

check_mudi() {
    mudi "echo ok" | grep -q "ok"
}

# ── GPS from Mudi (/dev/ttyACM0 @ 4800 baud, u-blox M8130) ───────────────────
GPS_LAT=""
GPS_LON=""

get_gps() {
    local fix
    fix=$(mudi_py "gps.py" "--timeout" "8" 2>/dev/null)
    if [ -n "$fix" ]; then
        GPS_LAT=$(echo "$fix" | cut -d' ' -f1)
        GPS_LON=$(echo "$fix" | cut -d' ' -f2)
        return 0
    fi
    return 1
}

# ── Spinner helpers (capture ID for clean stop) ───────────────────────────────
spin_start() { START_SPINNER "$1"; }
spin_stop()  { STOP_SPINNER "$1" 2>/dev/null; STOP_SPINNER 2>/dev/null; }

# ── Threat → LED/VIBRATE ──────────────────────────────────────────────────────
threat_feedback() {
    case "$1" in
        0) LED $LED_GREEN  ;;
        1) LED $LED_YELLOW; VIBRATE 200 ;;
        2) LED $LED_ORANGE; VIBRATE 300; sleep 0.2; VIBRATE 300 ;;
        3) LED $LED_RED;    VIBRATE 500 ;;
    esac
}

threat_label() {
    case "$1" in
        0) echo "CLEAN"    ;;
        1) echo "UNKNOWN"  ;;
        2) echo "MISMATCH" ;;
        3) echo "GHOST"    ;;
        *) echo "?"        ;;
    esac
}

# ── JSON field helper (runs on Pager) ────────────────────────────────────────
jget() {
    # jget <json_string> <key> [default]
    echo "$1" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('$2','${3:-?}'),end='')" 2>/dev/null
}

# ── Scan ──────────────────────────────────────────────────────────────────────
do_scan() {
    LED $LED_BLUE
    local spid
    spid=$(spin_start "Scanning cell...")

    get_gps

    local cell_json
    cell_json=$(mudi_py "cell_info.py" 2>/dev/null)

    if [ -z "$cell_json" ]; then
        spin_stop "$spid"
        LED $LED_RED
        SHOW_REPORT "Scan failed" "No cell data from Mudi."
        WAIT_FOR_BUTTON_PRESS
        LED $LED_OFF
        return 1
    fi

    local rat mcc mnc cid rsrp tac
    rat=$(jget  "$cell_json" rat  LTE)
    mcc=$(jget  "$cell_json" mcc  -)
    mnc=$(jget  "$cell_json" mnc  -)
    cid=$(jget  "$cell_json" cell_id -)
    rsrp=$(jget "$cell_json" rsrp  -)
    tac=$(jget  "$cell_json" tac   -)

    spid=$(spin_start "Checking OpenCelliD...")

    local ocid_out ocid_threat
    if [ -n "$GPS_LAT" ] && [ -n "$GPS_LON" ]; then
        ocid_out=$(mudi_py "opencellid.py" "$GPS_LAT" "$GPS_LON" "--queue" 2>/dev/null)
        ocid_threat=$?
    else
        ocid_out=$(mudi_py "opencellid.py" 2>/dev/null)
        ocid_threat=$?
    fi

    if [ -n "$GPS_LAT" ] && [ -n "$GPS_LON" ]; then
        mudi_py "cyt_export.py" "scan" "$GPS_LAT" "$GPS_LON" 2>/dev/null
    else
        mudi_py "cyt_export.py" "scan" 2>/dev/null
    fi

    spin_stop "$spid"
    threat_feedback "$ocid_threat"

    local loc_line="No GPS"
    [ -n "$GPS_LAT" ] && loc_line="$(printf '%.4f' "$GPS_LAT"), $(printf '%.4f' "$GPS_LON")"

    local ocid_reason
    ocid_reason=$(jget "$ocid_out" reason "")

    local threat_lbl
    threat_lbl=$(threat_label "$ocid_threat")

    local body
    printf -v body "Cell: %s %s/%s\nID:   %s  TAC:%s\nRSRP: %s dBm\nLoc:  %s\n%s" \
        "$rat" "$mcc" "$mnc" "$cid" "$tac" "$rsrp" "$loc_line" "$ocid_reason"

    SHOW_REPORT "[$threat_lbl]" "$body"
    WAIT_FOR_BUTTON_PRESS
    LED $LED_OFF
    return "$ocid_threat"
}

# ── Status ────────────────────────────────────────────────────────────────────
do_status() {
    local spid
    spid=$(spin_start "Getting status...")
    local bm_out
    bm_out=$(mudi_py "blue_merle.py" "status" 2>/dev/null)
    spin_stop "$spid"

    local imei imsi radio_label
    imei=$(jget       "$bm_out" imei       -)
    imsi=$(jget       "$bm_out" imsi       N/A)
    radio_label=$(jget "$bm_out" radio_label -)

    spid=$(spin_start "Getting GPS...")
    local gps_info="No GPS"
    get_gps && gps_info="$GPS_LAT, $GPS_LON"
    spin_stop "$spid"

    local body
    printf -v body "IMEI:  %s\nIMSI:  %s\nRadio: %s\nGPS:   %s" \
        "$imei" "$imsi" "$radio_label" "$gps_info"
    SHOW_REPORT "Status" "$body"
    WAIT_FOR_BUTTON_PRESS
}

# ── IMEI Rotation ─────────────────────────────────────────────────────────────
do_rotate() {
    local pick rc
    pick=$(NUMBER_PICKER $'IMEI Rotation\n1:Random 2:Determ. 3:Cancel' 1)
    rc=$?; [ $rc -ne 0 ] && return
    [ "$pick" -eq 3 ] && return

    local mode="random"
    [ "$pick" -eq 2 ] && mode="deterministic"

    CONFIRMATION_DIALOG "Rotate IMEI?" \
        "Radio off. Device powers down. Swap SIM + move."
    [ $? -ne 0 ] && return

    LED $LED_BLUE
    local spid
    spid=$(spin_start "Rotating IMEI...")
    local rot_out
    rot_out=$(mudi_py "blue_merle.py" "rotate" "$mode" 2>/dev/null)
    local rot_rc=$?
    spin_stop "$spid"

    if [ $rot_rc -ne 0 ]; then
        LED $LED_RED
        SHOW_REPORT "Rotation failed" "$rot_out"
        WAIT_FOR_BUTTON_PRESS
        LED $LED_OFF
        return 1
    fi

    local imei_before imei_after
    imei_before=$(jget "$rot_out" imei_before ?)
    imei_after=$(jget  "$rot_out" imei_after  ?)

    LED $LED_GREEN
    VIBRATE 200; sleep 0.1; VIBRATE 200

    local body
    printf -v body "Before: %s\nAfter:  %s\n\nPower off Mudi.\nSwap SIM. Move. Reboot." \
        "$imei_before" "$imei_after"
    SHOW_REPORT "IMEI Rotated" "$body"
    WAIT_FOR_BUTTON_PRESS

    CONFIRMATION_DIALOG "Power off Mudi now?"
    if [ $? -eq 0 ]; then
        spid=$(spin_start "Powering off Mudi...")
        mudi_py "blue_merle.py" "radio" "off" >/dev/null 2>&1
        sleep 1
        mudi "echo '{ \"poweroff\": \"1\" }' > /dev/ttyS0" 2>/dev/null
        spin_stop "$spid"
        SHOW_REPORT "Mudi off" "Swap SIM. Move. Reboot Mudi."
        WAIT_FOR_BUTTON_PRESS
    fi

    LED $LED_OFF
}

# ── Reports ───────────────────────────────────────────────────────────────────
do_reports() {
    local spid
    spid=$(spin_start "Loading reports...")
    local report_list
    report_list=$(mudi_py "cyt_export.py" "list" 2>/dev/null)
    spin_stop "$spid"

    if [ -z "$report_list" ]; then
        SHOW_REPORT "No reports" "Run a scan first."
        WAIT_FOR_BUTTON_PRESS
        return
    fi

    local -a rpaths
    local i=1
    while IFS= read -r line; do
        rpaths[$i]=$(echo "$line" | awk '{print $NF}')
        ((i++))
        [ $i -gt 5 ] && break
    done <<< "$report_list"
    local count=$((i - 1))

    [ $count -eq 0 ] && { SHOW_REPORT "No reports" "Run a scan first."; WAIT_FOR_BUTTON_PRESS; return; }

    local NL=$'\n'
    local menu_prompt="Reports 1-$count ($((count+1))=Back):"
    for i in $(seq 1 $count); do
        local label
        label=$(mudi_py "cyt_export.py" "show" "${rpaths[$i]}" 2>/dev/null | head -1)
        menu_prompt="${menu_prompt}${NL}${i}:${label}"
    done
    menu_prompt="${menu_prompt}${NL}$((count+1)):Back"

    local pick rc
    pick=$(NUMBER_PICKER "$menu_prompt" "$((count+1))")
    rc=$?; [ $rc -ne 0 ] && return
    [ "$pick" -gt "$count" ] && return

    local detail
    detail=$(mudi_py "cyt_export.py" "show" "${rpaths[$pick]}" 2>/dev/null)
    SHOW_REPORT "Report" "$detail"
    WAIT_FOR_BUTTON_PRESS
}

# ── Upload pending to OpenCelliD ──────────────────────────────────────────────
do_upload() {
    LED $LED_BLUE
    local spid
    spid=$(spin_start "Uploading...")
    local upload_out
    upload_out=$(mudi_py "opencellid.py" "--upload" 2>&1)
    local rc=$?
    spin_stop "$spid"

    if [ $rc -eq 0 ]; then LED $LED_GREEN; VIBRATE 200; else LED $LED_YELLOW; fi

    SHOW_REPORT "Upload" "$upload_out"
    WAIT_FOR_BUTTON_PRESS
    LED $LED_OFF
}

# ── CYT Merge ─────────────────────────────────────────────────────────────────
do_cyt_merge() {
    local spid
    spid=$(spin_start "Merging CYT...")
    local reports
    reports=$(mudi_py "cyt_export.py" "list" 2>/dev/null | tail -1 | awk '{print $NF}')
    if [ -z "$reports" ]; then
        spin_stop "$spid"
        SHOW_REPORT "No reports" "Run a scan first."
        WAIT_FOR_BUTTON_PRESS
        return
    fi
    local out
    out=$(mudi_py "cyt_export.py" "merge" "$reports" 2>/dev/null)
    spin_stop "$spid"
    SHOW_REPORT "CYT Merge" "$out"
    WAIT_FOR_BUTTON_PRESS
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    LED $LED_WHITE
    local spid
    spid=$(spin_start "Connecting...")
    if ! check_mudi; then
        spin_stop "$spid"
        LED $LED_RED
        SHOW_REPORT "No Mudi" "SSH to $MUDI_HOST failed."
        WAIT_FOR_BUTTON_PRESS
        LED $LED_OFF
        exit 1
    fi
    spin_stop "$spid"
    LED $LED_OFF

    while true; do
        local pick rc
        pick=$(NUMBER_PICKER $'1:Scan 2:Status 3:IMEI\n4:Reports 5:Upload\n6:CYT 7:Exit' 1)
        rc=$?; [ $rc -ne 0 ] && break
        case "$pick" in
            1) do_scan      ;;
            2) do_status    ;;
            3) do_rotate    ;;
            4) do_reports   ;;
            5) do_upload    ;;
            6) do_cyt_merge ;;
            7) break        ;;
        esac
    done

    LED $LED_OFF
}

main
exit 0
