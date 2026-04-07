# AZE-0002 — Encoded or download-capable PowerShell

## Metadata
- **id**: AZE-0002
- **title**: Encoded or download-capable PowerShell
- **status**: testing
- **owner**: detection-engineering
- **platform**: defender_xdr
- **severity**: High
- **tactic**: TA0002
- **technique**: T1059.001
- **tables**: DeviceProcessEvents
- **run frequency**: 1 hour
- **lookback**: 1 hour

## Query
```kql
let timeframe = 1h;
DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","DownloadString","Invoke-WebRequest","iwr ","Net.WebClient","Invoke-RestMethod","FromBase64String")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
```

## Tuning
- suppress known admin automation
- narrow to hidden-window or browser/Office parent for stricter variants
- correlate with network or file creation where possible

## Triage
1. check user context and device role
2. inspect full command line
3. review child processes and network follow-on
4. determine whether automation account or admin tooling explains it
