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
  - Connects to Mudi via SSH

---

## Architecture

```
WiFi Pineapple Pager
└── payload.sh  (DuckyScript)
    └── SSH → GL-E750V2 Mudi V2
              ├── python/cell_info.py      AT+QENG → serving cell data
              ├── python/opencellid.py     tower lookup + upload queue
              ├── python/blue_merle.py     IMEI rotation via Blue Merle
              └── python/cyt_export.py    CYT JSON reports + merge
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

### On the Mudi V2

```bash
# Clone to Mudi
git clone https://github.com/tschakram/raypager.git /root/raypager

# Copy config template and fill in your OpenCelliD API key
cp config.example.json config.json
vi config.json
```

### On the Pager

```bash
# Deploy payload
cp -r raypager/ /root/payloads/user/reconnaissance/raypager/

# Configure SSH key to Mudi
# Edit config.json: mudi_host, mudi_user, mudi_key, mudi_python
```

### `config.json` (gitignored)

```json
{
  "opencellid_key": "YOUR_OPENCELLID_API_KEY",
  "mudi_host": "192.168.8.1",
  "mudi_user": "root",
  "mudi_key": "/root/.ssh/mudi_key",
  "mudi_python": "/root/raypager/python"
}
```

---

## Project Status

| Component | Status |
|---|---|
| `AT+QENG` cell data (LTE/NR/WCDMA) | ✅ Done |
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
