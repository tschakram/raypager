# Raypager

Adapting [EFF's Rayhunter](https://github.com/EFForg/rayhunter) IMSI-catcher detector for the **GL-E750V2 Mudi V2** portable 4G LTE router. Integrates [OpenCelliD](https://opencellid.org/) for cell tower verification and [Blue Merle](https://github.com/srlabs/blue-merle) for IMSI/IMEI randomization. Feeds into [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) for combined surveillance analysis.

> "Know your enemy and know yourself, and you can fight a hundred battles without disaster." — Sun Tzu

---

## Concept & Goals

| Goal | Tool |
|---|---|
| Detect IMSI catchers / fake cell towers | Rayhunter |
| Verify cell towers against known database | OpenCelliD |
| Avoid being tracked via IMSI/IMEI | Blue Merle |
| Cross-reference with WiFi/BT surveillance data | Chasing Your Tail NG |
| Pager display & control interface | DuckyScript |

---

## Hardware

- **GL-E750V2 Mudi V2** — portable 4G LTE router (OpenWrt-based)
  - Modem: Quectel EM050-G
  - Architecture: MIPS
  - OS: OpenWrt 22.03.x
- **WiFi Pineapple Pager** — display/control interface (DuckyScript)

---

## Components

### Rayhunter
[EFF's Rayhunter](https://github.com/EFForg/rayhunter) analyzes cellular modem diagnostic data to detect anomalies characteristic of IMSI catchers (Stingrays).

> ⚠️ **Compatibility Research Required:** Rayhunter currently targets the Orbic RC400L and TP-Link M7350 (Qualcomm `/dev/diag` interface). Porting to the Mudi V2 (EM050-G modem) requires investigation of diagnostic interface availability. See [research notes](docs/diag-research.md).

### OpenCelliD
Cross-reference detected cell towers against the [OpenCelliD](https://opencellid.org/) open database to identify unknown or suspicious base stations in the area.

### Blue Merle
[Blue Merle by SRLabs](https://github.com/srlabs/blue-merle) provides:
- IMEI randomization
- IMSI-based pseudo-random IMEI generation
- MAC address randomization (WiFi uplink)

Already supports the GL-E750V2 Mudi V2. ✓

---

## DuckyScript Interface

The WiFi Pineapple Pager acts as the control interface via DuckyScript:
- Display current cell tower info and threat level
- Alert on suspicious BTS events (`VIBRATE`, `LED`)
- Trigger Blue Merle IMEI rotation
- Export findings to CYT report

---

## CYT Integration

Suspicious cell tower events are exported as CYT-compatible JSON and merged with WiFi/Bluetooth tracking data from [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) for unified timeline analysis.

---

## Project Status

| Component | Status |
|---|---|
| Rayhunter `/dev/diag` on EM050-G | 🔬 Research |
| OpenCelliD lookup module | 📋 Planned |
| Blue Merle integration | 📋 Planned |
| DuckyScript Pager UI | 📋 Planned |
| CYT JSON export | 📋 Planned |

---

## Disclaimer

This project is for **authorized security research and counter-surveillance** purposes only. Detecting IMSI catchers is legal in most jurisdictions — verify local laws before use. Do not use components of this project to intercept communications or track others without authorization.

---

## Related Projects

- [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager)
- [Rayhunter by EFF](https://github.com/EFForg/rayhunter)
- [Blue Merle by SRLabs](https://github.com/srlabs/blue-merle)
- [OpenCelliD](https://opencellid.org/)
- [WiFi Pineapple Pager Payloads](https://github.com/hak5/wifipineapplepager-payloads)
