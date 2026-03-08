# /dev/diag Compatibility Research

## Rayhunter's Requirement
Rayhunter uses Qualcomm's `/dev/diag` interface to read modem diagnostic messages.
This interface is present on the Orbic RC400L and TP-Link M7350.

## Mudi V2 Modem: Quectel EM050-G
- Interface: USB (exposed via `/dev/ttyUSB*` or similar)
- Diagnostic port: TBD — needs investigation
- AT commands: likely available via `/dev/ttyUSB2`

## Research Tasks
- [ ] Check if `/dev/diag` or equivalent exists on Mudi V2
- [ ] Investigate Quectel EM050-G diagnostic protocol
- [ ] Evaluate alternative approaches (AT+QENG cell info commands)
- [ ] Consider using Quectel AT commands as fallback for cell tower info
