# AZE-0004 — Registry persistence by suspicious parent

## Metadata
- **id**: AZE-0004
- **title**: Registry persistence by suspicious parent
- **status**: testing
- **owner**: detection-engineering
- **platform**: defender_xdr
- **severity**: Medium
- **tactic**: TA0003
- **technique**: T1547.001
- **tables**: DeviceRegistryEvents
- **run frequency**: 1 hour
- **lookback**: 1 hour

## Query
```kql
let timeframe = 1h;
let suspicious_parents = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe"]);
DeviceRegistryEvents
| where Timestamp >= ago(timeframe)
| where RegistryKey has_any ("\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce")
| where InitiatingProcessFileName in~ (suspicious_parents)
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Tuning
- exclude approved software installers
- tighten to user-writable paths in registry data
- correlate with nearby process creation or network events

## Triage
1. inspect value data path
2. inspect parent process and user
3. determine persistence intent versus legitimate installation
4. review nearby file and network activity
