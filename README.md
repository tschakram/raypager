# Raypager

IMSI-catcher detection and IMEI rotation for the **GL-E750V2 Mudi V2** portable 4G LTE router. Verifies cell towers against [OpenCelliD](https://opencellid.org/), triggers [Blue Merle](https://github.com/srlabs/blue-merle) IMEI rotation on threat, and feeds into [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) for unified WiFi/BT/cellular surveillance analysis.

> "Know your enemy and know yourself, and you can fight a hundred battles without disaster." — Sun Tzu

---

## Concept & Goals

| Goal | Approach |
|---|---|
| Detect fake cell towers / IMSI catchers | AT+QENG serving cell data + OpenCelliD verification |
| Verify towers against known database | OpenCelliD lookup (unknown → flagged) |
| Detect location spoofing | GPS mismatch check (tower DB pos vs our GPS) |
| Avoid IMSI/IMEI tracking | Blue Merle IMEI rotation (random or IMSI-based) |
| Cross-reference WiFi/BT surveillance data | CYT JSON export + merge |
| Pager display & control interface | DuckyScript (WiFi Pineapple Pager) |

> **Note on Rayhunter:** Rayhunter (EFF) requires Qualcomm `/dev/diag` — not available on the EM050-G modem. Raypager uses `AT+QENG="servingcell"` directly instead, which provides equivalent cell engineering data (Cell-ID, TAC, EARFCN, RSRP, RSRQ). See [diag research notes](docs/diag-research.md).

---

## Hardware

- **GL-E750V2 Mudi V2** — portable 4G LTE router
  - Modem: Quectel EM050-G (5G sub-6 GHz)
  - Architecture: MIPS / OpenWrt 22.03.x
  - AT interface: `gl_modem AT <cmd>` wrapper
- **WiFi Pineapple Pager** — display/control interface
  - Runs `payload.sh` via DuckyScript framework
  - Connects to Mudi via **WiFi** (192.168.8.1) + SSH
  - USB port free (GPS is on Mudi)
- **u-blox M8130 USB GPS dongle** — plugged into Mudi USB port
  - `/dev/ttyACM0` @ 4800 baud, read by `python/gps.py`
  - Supports GPS + GLONASS + BeiDou (multi-constellation)

---

## Architecture

```
WiFi Pineapple Pager
└── payload.sh  (DuckyScript)
    └── WiFi + SSH → GL-E750V2 Mudi V2
                     ├── python/cell_info.py      AT+QENG → serving cell data
                     ├── python/gps.py            NMEA reader → u-blox M8130 (/dev/ttyACM0)
                     ├── python/opencellid.py     tower lookup + GPS mismatch + upload queue
                     ├── python/blue_merle.py     IMEI rotation via Blue Merle
                     └── python/cyt_export.py     CYT JSON reports + merge

Physical connections:
  GPS dongle  ──USB──▶  Mudi (/dev/ttyACM0, 4800 baud)
  Mudi        ──LTE──▶  Internet (OpenCelliD API)
  Pager       ──WiFi──▶ Mudi (192.168.8.1, SSH)
```

---

## Threat Levels

| Level | Label | Meaning |
|---|---|---|
| 0 | `CLEAN` | Tower in OpenCelliD DB, position matches |
| 1 | `UNKNOWN` | Tower not in database — could be new or fake |
| 2 | `MISMATCH` | Tower in DB but position differs >5 km |
| 3 | `GHOST` | API unreachable / no data |

Anomaly heuristics (local, lower confidence):
- RSRP > −60 dBm (unusually close tower)
- Strong signal + poor quality (high RSRP, low RSRQ)
- Downgrade to 2G/3G while LTE available (classic IMSI-catcher tactic)

---

## Python Modules

All modules are **stdlib-only** (no pip dependencies).

### `python/cell_info.py`
Queries serving cell data from the EM050-G modem via `gl_modem AT`:

```
AT+QENG="servingcell"  →  MCC, MNC, Cell-ID, TAC, EARFCN, RSRP, RSRQ, SINR
AT+QNWINFO             →  band name, PLMN, channel
AT+COPS?               →  operator name
AT+CSQ                 →  RSSI
```

### `python/gps.py`
Reads NMEA sentences from the u-blox M8130 GPS dongle on `/dev/ttyACM0`:
- Pure stdlib — uses `termios` + `os.read()` (no pyserial dependency)
- Sets 4800 baud raw mode, parses `$GNGGA` (fix quality, lat/lon, altitude, sats) and `$GNRMC` (validity)
- Returns `lat lon` on stdout; exits non-zero if no fix within timeout
- Fallback: if no fix (indoors), `get_gps()` in `payload.sh` skips GPS — OpenCelliD lookup proceeds without mismatch check

### `python/opencellid.py`
- Looks up towers in [OpenCelliD](https://opencellid.org/) via REST API
- Compares tower DB position with our GPS fix (Haversine)
- 24h local cache to avoid redundant queries
- **Upload queue:** queues measurements as gzipped CSV for later contribution to OpenCelliD

### `python/blue_merle.py`
Wraps [Blue Merle (SRLabs)](https://github.com/srlabs/blue-merle) for IMEI rotation:
- `disable_radio()` — AT+CFUN=4 (no TX/RX, prevents IMEI leak)
- `rotate_imei(mode)` — random (`-r`) or IMSI-deterministic (`-d`)
- `full_rotation()` — complete flow: radio off → rotate → optional poweroff
- `poweroff()` — `/dev/ttyS0` signal

### `python/cyt_export.py`
- Builds CYT-compatible JSON events from cell scan results
- Saves reports to `/root/loot/raypager/reports/`
- Merges raypager events with CYT NG WiFi/BT events (±1h window)

---

## Pager UI (`payload.sh`)

```
┌─ Raypager ──────────────┐
│ 1. Scan Cell Tower       │  → cell scan + OpenCelliD + LED/VIBRATE feedback
│ 2. Status                │  → IMEI, IMSI, radio state, GPS
│ 3. Rotate IMEI           │  → Blue Merle rotation flow with confirmation
│ 4. Reports               │  → list + detail view of past scans
│ 5. Upload OpenCelliD     │  → flush upload queue
│ 6. Merge CYT             │  → merge last report into CYT loot dir
│ 7. Exit                  │
└──────────────────────────┘
```

LED feedback: Green=CLEAN · Yellow=UNKNOWN · Orange=MISMATCH · Red=GHOST

---

## Setup

### Requirements

#### GL-E750V2 Mudi V2
| Requirement | How to get it |
|---|---|
| OpenWrt 22.03.x | factory firmware |
| Python 3.x | `opkg update && opkg install python3` |
| `curl` | `opkg install curl` (HTTPS fallback for OpenCelliD API) |
| `gl_modem` AT wrapper | pre-installed on GL.iNet firmware |
| Blue Merle | [srlabs/blue-merle](https://github.com/srlabs/blue-merle) — install on Mudi |
| u-blox M8130 GPS dongle | plug into Mudi USB-A port → `/dev/ttyACM0` |
| LTE data active | `gl_modem -B 1-1.2 connect-auto` (after each boot) |

> **Note:** All Python modules are stdlib-only — no `pip install` needed on Mudi.

#### WiFi Pineapple Pager
| Requirement | How to get it |
|---|---|
| Pager firmware with DuckyScript | factory firmware |
| SSH key to Mudi | generate on Pager, add to Mudi's `/etc/dropbear/authorized_keys` |
| WiFi connection to Mudi | configure Pager WiFi client (wlan0cli) → Mudi AP |

---

### File Layout

```
Mudi V2:
  /root/raypager/
  ├── python/
  │   ├── cell_info.py       ← AT+QENG modem queries
  │   ├── gps.py             ← NMEA GPS reader (/dev/ttyACM0)
  │   ├── opencellid.py      ← tower lookup + upload queue
  │   ├── blue_merle.py      ← IMEI rotation wrapper
  │   └── cyt_export.py      ← CYT report export
  ├── config.json            ← gitignored! contains API key
  └── config.example.json    ← template (safe to commit)

Pager:
  /root/payloads/user/reconnaissance/raypager/
  ├── payload.sh             ← DuckyScript entry point
  └── config.json            ← Pager-side connection config (no API key)

Loot (Mudi, gitignored):
  /root/loot/raypager/
  ├── reports/               ← JSON scan reports
  └── upload_queue/          ← OpenCelliD CSV queue
```

---

### Installation

#### 1. Mudi V2

```bash
# Install dependencies
opkg update && opkg install python3 curl

# Clone repo
git clone https://github.com/tschakram/raypager.git /root/raypager
cd /root/raypager

# Create config from template
cp config.example.json config.json
vi config.json   # set opencellid_key + mudi_* values

# Create loot dirs
mkdir -p /root/loot/raypager/reports /root/loot/raypager/upload_queue

# Generate SSH key for Pager → Mudi access (run on Pager, add pub key here)
# echo "ssh-ed25519 AAAA..." >> /etc/dropbear/authorized_keys

# Activate LTE data (needed after every boot)
gl_modem -B 1-1.2 connect-auto
```

#### 2. WiFi Pineapple Pager

```bash
# Connect Pager WiFi client (wlan0cli) to Mudi AP via Pager UI

# Generate SSH key for Mudi access
ssh-keygen -t ed25519 -f /root/.ssh/mudi_key -N ""
# → copy /root/.ssh/mudi_key.pub to Mudi's /etc/dropbear/authorized_keys

# Deploy payload
mkdir -p /root/payloads/user/reconnaissance/raypager
cp payload.sh /root/payloads/user/reconnaissance/raypager/
chmod 755 /root/payloads/user/reconnaissance/raypager/payload.sh

# Create Pager-side config
cat > /root/payloads/user/reconnaissance/raypager/config.json << 'EOF'
{
  "mudi_host": "192.168.8.1",
  "mudi_user": "root",
  "mudi_key": "/root/.ssh/mudi_key",
  "mudi_python": "/root/raypager/python"
}
EOF
```

### `config.json` on Mudi (gitignored)

```json
{
  "opencellid_key": "YOUR_OPENCELLID_API_KEY",
  "mudi_host": "192.168.8.1",
  "mudi_user": "root",
  "mudi_key": "/root/.ssh/mudi_key",
  "mudi_python": "/root/raypager/python"
}
```

Get your free OpenCelliD API key at [opencellid.org](https://opencellid.org/).

---

## Project Status

| Component | Status |
|---|---|
| `AT+QENG` cell data (LTE/NR/WCDMA) | ✅ Done |
| GPS fix via u-blox M8130 on Mudi | ✅ Done |
| OpenCelliD lookup + GPS mismatch | ✅ Done |
| OpenCelliD upload queue | ✅ Done |
| Blue Merle IMEI rotation | ✅ Done |
| DuckyScript Pager UI | ✅ Done |
| CYT JSON export + merge | ✅ Done |
| Rayhunter `/dev/diag` port | ❌ N/A — EM050-G is not Qualcomm |
| Neighbour cell scanning | 🔭 Planned |
| Continuous monitoring mode | 🔭 Planned |

---

## Disclaimer

This project is for **authorized security research and counter-surveillance** purposes only. Detecting IMSI catchers is legal in most jurisdictions — verify local laws before use. Do not use components of this project to intercept communications or track others without authorization.

---

## Related Projects

- [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) — WiFi/BT counter-surveillance
- [Blue Merle by SRLabs](https://github.com/srlabs/blue-merle) — IMEI randomization for Mudi
- [Rayhunter by EFF](https://github.com/EFForg/rayhunter) — IMSI-catcher detection (Qualcomm devices)
- [OpenCelliD](https://opencellid.org/) — open cell tower database
- [WiFi Pineapple Pager Payloads](https://github.com/hak5/wifipineapplepager-payloads)
