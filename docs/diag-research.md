# /dev/diag Compatibility Research

## Rayhunter's Requirement
Rayhunter uses Qualcomm's `/dev/diag` interface to read modem diagnostic messages.
This interface is present on the Orbic RC400L and TP-Link M7350 (both Qualcomm-based).

## Mudi V2 Modem: Quectel EM050-G

- Architecture: **not Qualcomm** — Quectel proprietary baseband (5G sub-6 GHz)
- Interface: USB composite device, exposed as `/dev/ttyUSB*` on OpenWrt
- AT command port: `/dev/ttyUSB2` (typical Quectel mapping)
- `/dev/diag`: **not available** — Qualcomm-specific, not present on EM050-G

## AT Command Interface (gl_modem wrapper)

The Mudi ships with a `gl_modem` wrapper that relays AT commands to the modem:

```bash
gl_modem AT AT+COMMAND       # send AT command
gl_modem AT AT+QNWINFO       # example: query network info
```

Alternatively, direct serial access:
```bash
echo -e 'AT+QNWINFO\r' > /dev/ttyUSB2
```

## Cell Information via AT Commands

The EM050-G supports Quectel's extended AT commands for cell engineering data.
These are the **primary approach** for raypager (replaces Rayhunter `/dev/diag`).

### AT+QENG="servingcell"
Returns detailed serving cell information:
```
+QENG: "servingcell","NOCONN","LTE","FDD",<MCC>,<MNC>,<cellID>,<PCID>,<earfcn>,<freq_band>,<ul_bw>,<dl_bw>,<TAC>,<RSRP>,<RSRQ>,<RSSI>,<SINR>,<srxlev>
```
Key fields: MCC, MNC, Cell ID, TAC, EARFCN, RSRP, RSRQ — sufficient for OpenCelliD lookup.

### AT+QENG="neighbourcell"
Returns neighboring cells — useful for detecting towers that appear/disappear anomalously.

### AT+QNWINFO
Quick network info: `+QNWINFO: "FDD LTE",26201,"LTE BAND 3",1650`
- Access tech, PLMN (MCC+MNC), band, EARFCN/channel

### AT+COPS?
Operator: MCC, MNC, operator name, access tech

### AT+CSQ
Signal quality: RSSI (0–31 scale), BER

### AT+CFUN
Radio control:
- `AT+CFUN=4` — disable TX/RX (airplane mode equivalent)
- `AT+CFUN=1` — full functionality

### AT+GSN / AT+CGSN
Read current IMEI.

## Blue Merle Integration

Blue Merle v2.0 (SRLabs) already supports the GL-E750V2 Mudi V2. AT commands go through:
```bash
gl_modem AT AT+CFUN=4
python3 /lib/blue-merle/imei_generate.py -r    # random IMEI
python3 /lib/blue-merle/imei_generate.py -d    # deterministic IMEI (IMSI-based)
gl_modem AT AT+GSN                             # verify new IMEI
echo '{ "poweroff": "1" }' > /dev/ttyS0       # power off
```

Web interface: LuCI > System > Advanced Settings > Network > Blue Merle

## Research Tasks

- [x] Confirm `/dev/diag` not available on EM050-G (Quectel, not Qualcomm)
- [x] Identify AT command interface: `gl_modem AT` wrapper on `/dev/ttyUSB2`
- [x] Identify primary cell info command: `AT+QENG="servingcell"`
- [x] Confirm Blue Merle compatibility with GL-E750V2
- [ ] Verify `AT+QENG` support on EM050-G via SSH test
- [ ] Map exact `/dev/ttyUSB*` port assignment on OpenWrt 22.03
- [ ] Test `AT+QENG="neighbourcell"` output format on live device
- [ ] Evaluate EARFCN→frequency mapping for band detection
