#!/bin/bash
# =============================================================================
# Raypager — IMSI-Catcher Detection & IMEI Rotation
# WiFi Pineapple Pager payload (DuckyScript framework)
#
# Architecture:
#   Pager  →  SSH  →  Mudi V2 (GL-E750V2)
#                      ├── gl_modem AT (EM050-G modem)
#                      └── python3 /root/raypager/python/
#
# Config:  /root/payloads/user/reconnaissance/raypager/config.json
# Loot:    /root/loot/raypager/
# =============================================================================

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

# ── Read config ───────────────────────────────────────────────────────────────
_cfg() { python3 -c "import json,sys; d=json.load(open('$CONFIG')); print(d.get('$1','$2'),end='')" 2>/dev/null; }

MUDI_HOST="$(_cfg mudi_host 192.168.8.1)"
MUDI_USER="$(_cfg mudi_user root)"
MUDI_KEY="$(_cfg mudi_key /root/.ssh/mudi_key)"
MUDI_PY="$(_cfg mudi_python /root/raypager/python)"

SSH_OPTS="-i $MUDI_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -o HostKeyAlgorithms=+ssh-rsa"

# ── SSH helper ────────────────────────────────────────────────────────────────
mudi() {
    # mudi <command>  — run command on Mudi, return its stdout
    ssh $SSH_OPTS "$MUDI_USER@$MUDI_HOST" "$@" 2>/dev/null
}

mudi_py() {
    # mudi_py <script.py> [args...]  — run Python script on Mudi
    local script="$1"; shift
    mudi "cd '$MUDI_PY' && python3 '$script' $*"
}

check_mudi() {
    mudi "echo ok" | grep -q "ok"
}

# ── GPS from Pager ────────────────────────────────────────────────────────────
GPS_LAT=""
GPS_LON=""

get_gps() {
    # Try Pager GPS (gpsd / NMEA)
    local fix
    fix=$(gpspipe -w -n 5 2>/dev/null | grep -m1 '"lat"' | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('lat',''),d.get('lon',''))" 2>/dev/null)
    if [ -n "$fix" ]; then
        GPS_LAT=$(echo "$fix" | cut -d' ' -f1)
        GPS_LON=$(echo "$fix" | cut -d' ' -f2)
        return 0
    fi
    return 1
}

# ── Threat → LED/VIBRATE ──────────────────────────────────────────────────────
threat_feedback() {
    local threat="$1"
    case "$threat" in
        0) LED $LED_GREEN  ;;          # CLEAN
        1) LED $LED_YELLOW             # UNKNOWN — single pulse
           VIBRATE 200 ;;
        2) LED $LED_ORANGE             # MISMATCH — double pulse
           VIBRATE 300; sleep 0.2; VIBRATE 300 ;;
        3) LED $LED_RED                # GHOST / unverified
           VIBRATE 500 ;;
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

# ── Scan ──────────────────────────────────────────────────────────────────────
do_scan() {
    LED $LED_BLUE
    START_SPINNER "Scanning cell..."

    # Get GPS fix first (best-effort)
    get_gps

    # Run cell scan on Mudi
    local cell_json
    cell_json=$(mudi_py "cell_info.py" 2>/dev/null)
    local cell_rc=$?

    if [ $cell_rc -ne 0 ] || [ -z "$cell_json" ]; then
        STOP_SPINNER
        LED $LED_RED
        SHOW_REPORT "Scan failed" "Could not reach modem.\nCheck Mudi SSH."
        WAIT_FOR_BUTTON_PRESS
        LED $LED_OFF
        return 1
    fi

    # Parse key fields from JSON for display
    local rat mcc mnc cid rsrp tac
    rat=$(echo  "$cell_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('rat','?'),end='')"   2>/dev/null)
    mcc=$(echo  "$cell_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('mcc','?'),end='')"   2>/dev/null)
    mnc=$(echo  "$cell_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('mnc','?'),end='')"   2>/dev/null)
    cid=$(echo  "$cell_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('cell_id','?'),end='')" 2>/dev/null)
    rsrp=$(echo "$cell_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('rsrp','?'),end='')"  2>/dev/null)
    tac=$(echo  "$cell_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tac','?'),end='')"   2>/dev/null)

    START_SPINNER "Checking OpenCelliD..."

    # Run OpenCelliD lookup on Mudi
    local ocid_out ocid_threat
    if [ -n "$GPS_LAT" ] && [ -n "$GPS_LON" ]; then
        ocid_out=$(mudi_py "opencellid.py" "$GPS_LAT" "$GPS_LON" "--queue" 2>/dev/null)
        ocid_threat=$?
    else
        ocid_out=$(mudi_py "opencellid.py" 2>/dev/null)
        ocid_threat=$?
    fi

    local threat_lbl
    threat_lbl=$(threat_label "$ocid_threat")

    # Save CYT report on Mudi
    mudi_py "cyt_export.py" "scan" "$GPS_LAT" "$GPS_LON" >/dev/null 2>&1

    STOP_SPINNER

    # Feedback
    threat_feedback "$ocid_threat"

    # Build display text
    local loc_line="No GPS"
    [ -n "$GPS_LAT" ] && loc_line="$(printf '%.4f' "$GPS_LAT"), $(printf '%.4f' "$GPS_LON")"

    local ocid_reason
    ocid_reason=$(echo "$ocid_out" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('reason',''),end='')" 2>/dev/null)

    SHOW_REPORT \
        "[$threat_lbl] $rat $mcc/$mnc" \
        "Cell-ID: $cid\nTAC: $tac\nRSRP: $rsrp dBm\nLoc: $loc_line\n\n$ocid_reason"

    WAIT_FOR_BUTTON_PRESS
    LED $LED_OFF
    return "$ocid_threat"
}

# ── IMEI Rotation ─────────────────────────────────────────────────────────────
do_rotate() {
    # Mode picker
    NUMBER_PICKER "IMEI Rotation" \
        "1:Random IMEI" \
        "2:IMSI-based IMEI" \
        "3:Cancel"
    local pick=$?

    [ "$pick" -eq 3 ] && return

    local mode="random"
    [ "$pick" -eq 2 ] && mode="deterministic"

    CONFIRMATION_DIALOG \
        "Rotate IMEI?" \
        "Radio will be disabled.\nDevice powers off after.\nSwap SIM + change location."
    local confirmed=$?
    [ "$confirmed" -ne 0 ] && return

    LED $LED_BLUE
    START_SPINNER "Rotating IMEI ($mode)..."

    local rot_out
    rot_out=$(mudi_py "blue_merle.py" "rotate" "$mode" 2>/dev/null)
    local rot_rc=$?

    STOP_SPINNER

    if [ $rot_rc -ne 0 ]; then
        LED $LED_RED
        SHOW_REPORT "Rotation failed" "$rot_out"
        WAIT_FOR_BUTTON_PRESS
        LED $LED_OFF
        return 1
    fi

    # Parse result
    local imei_before imei_after
    imei_before=$(echo "$rot_out" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('imei_before','?'),end='')" 2>/dev/null)
    imei_after=$(echo "$rot_out" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('imei_after','?'),end='')" 2>/dev/null)

    LED $LED_GREEN
    VIBRATE 200; sleep 0.1; VIBRATE 200

    SHOW_REPORT \
        "IMEI Rotated" \
        "Before: $imei_before\nAfter:  $imei_after\n\nPower off Mudi.\nSwap SIM card.\nChange location.\nThen reboot."
    WAIT_FOR_BUTTON_PRESS

    # Offer to power off Mudi
    CONFIRMATION_DIALOG "Power off Mudi now?"
    if [ $? -eq 0 ]; then
        START_SPINNER "Powering off Mudi..."
        mudi_py "blue_merle.py" "radio" "off" >/dev/null 2>&1
        sleep 1
        mudi "echo '{ \"poweroff\": \"1\" }' > /dev/ttyS0" 2>/dev/null
        STOP_SPINNER
        SHOW_REPORT "Mudi off" "Swap SIM card.\nChange location.\nThen reboot Mudi."
        WAIT_FOR_BUTTON_PRESS
    fi

    LED $LED_OFF
}

# ── Reports ───────────────────────────────────────────────────────────────────
do_reports() {
    START_SPINNER "Loading reports..."
    local report_list
    report_list=$(mudi_py "cyt_export.py" "list" 2>/dev/null)
    STOP_SPINNER

    if [ -z "$report_list" ]; then
        SHOW_REPORT "No reports" "Run a scan first."
        WAIT_FOR_BUTTON_PRESS
        return
    fi

    # Show last 5 reports as menu
    local count i=1
    declare -a rpaths
    while IFS= read -r line; do
        rpaths[$i]=$(echo "$line" | awk '{print $NF}')
        ((i++))
        [ $i -gt 5 ] && break
    done <<< "$report_list"
    count=$((i - 1))

    [ $count -eq 0 ] && { SHOW_REPORT "No reports" "Run a scan first."; WAIT_FOR_BUTTON_PRESS; return; }

    # Build menu entries
    local menu_args=()
    for i in $(seq 1 $count); do
        local label
        label=$(mudi_py "cyt_export.py" "show" "${rpaths[$i]}" 2>/dev/null | head -1)
        menu_args+=("$i:$label")
    done
    menu_args+=("$((count+1)):Back")

    NUMBER_PICKER "Reports" "${menu_args[@]}"
    local pick=$?

    [ "$pick" -gt "$count" ] && return

    local detail
    detail=$(mudi_py "cyt_export.py" "show" "${rpaths[$pick]}" 2>/dev/null)
    SHOW_REPORT "Report" "$detail"
    WAIT_FOR_BUTTON_PRESS
}

# ── Upload pending to OpenCelliD ──────────────────────────────────────────────
do_upload() {
    LED $LED_BLUE
    START_SPINNER "Uploading to OpenCelliD..."
    local upload_out
    upload_out=$(mudi_py "opencellid.py" "--upload" 2>&1)
    local rc=$?
    STOP_SPINNER

    if [ $rc -eq 0 ]; then
        LED $LED_GREEN
        VIBRATE 200
    else
        LED $LED_YELLOW
    fi

    SHOW_REPORT "Upload done" "$upload_out"
    WAIT_FOR_BUTTON_PRESS
    LED $LED_OFF
}

# ── Status ────────────────────────────────────────────────────────────────────
do_status() {
    START_SPINNER "Checking Mudi status..."
    local bm_out nwinfo_out
    bm_out=$(mudi_py "blue_merle.py" "status" 2>/dev/null)
    STOP_SPINNER

    local imei imsi radio_label
    imei=$(echo "$bm_out" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('imei','?'),end='')" 2>/dev/null)
    imsi=$(echo "$bm_out" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('imsi','N/A'),end='')" 2>/dev/null)
    radio_label=$(echo "$bm_out" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('radio_label','?'),end='')" 2>/dev/null)

    local gps_info="No GPS"
    get_gps && gps_info="$GPS_LAT, $GPS_LON"

    SHOW_REPORT \
        "Mudi Status" \
        "IMEI:  $imei\nIMSI:  $imsi\nRadio: $radio_label\nGPS:   $gps_info"
    WAIT_FOR_BUTTON_PRESS
}

# ── CYT Merge ─────────────────────────────────────────────────────────────────
do_cyt_merge() {
    START_SPINNER "Merging with CYT..."
    local reports
    reports=$(mudi_py "cyt_export.py" "list" 2>/dev/null | tail -1 | awk '{print $NF}')
    if [ -z "$reports" ]; then
        STOP_SPINNER
        SHOW_REPORT "No reports" "Run a scan first."
        WAIT_FOR_BUTTON_PRESS
        return
    fi
    local out
    out=$(mudi_py "cyt_export.py" "merge" "$reports" 2>/dev/null)
    STOP_SPINNER
    SHOW_REPORT "CYT Merge" "$out"
    WAIT_FOR_BUTTON_PRESS
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    LED $LED_WHITE
    START_SPINNER "Connecting to Mudi..."

    if ! check_mudi; then
        STOP_SPINNER
        LED $LED_RED
        SHOW_REPORT "No Mudi" "SSH to $MUDI_HOST failed.\nCheck connection + key."
        WAIT_FOR_BUTTON_PRESS
        LED $LED_OFF
        exit 1
    fi

    STOP_SPINNER
    LED $LED_OFF

    while true; do
        NUMBER_PICKER "Raypager" \
            "1:Scan Cell Tower" \
            "2:Status" \
            "3:Rotate IMEI" \
            "4:Reports" \
            "5:Upload OpenCelliD" \
            "6:Merge CYT" \
            "7:Exit"

        case $? in
            1) do_scan    ;;
            2) do_status  ;;
            3) do_rotate  ;;
            4) do_reports ;;
            5) do_upload  ;;
            6) do_cyt_merge ;;
            7) break      ;;
        esac
    done

    LED $LED_OFF
}

main
