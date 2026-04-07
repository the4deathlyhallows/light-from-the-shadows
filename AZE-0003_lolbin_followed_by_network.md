# AZE-0003 — LOLBIN followed by outbound network connection

## Metadata
- **id**: AZE-0003
- **title**: LOLBIN followed by outbound network connection
- **status**: testing
- **owner**: detection-engineering
- **platform**: defender_xdr
- **severity**: High
- **tactic**: TA0011
- **technique**: T1218 / T1105
- **tables**: DeviceProcessEvents, DeviceNetworkEvents
- **run frequency**: 1 hour
- **lookback**: 1 hour

## Query
```kql
let timeframe = 1h;
let lolbins = dynamic(["mshta.exe","rundll32.exe","regsvr32.exe","cscript.exe","wscript.exe","powershell.exe","pwsh.exe","curl.exe","certutil.exe","bitsadmin.exe"]);
let suspicious_procs =
    DeviceProcessEvents
    | where Timestamp >= ago(timeframe)
    | where FileName in~ (lolbins)
    | project DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessId, ProcTime=Timestamp;
DeviceNetworkEvents
| where Timestamp >= ago(timeframe)
| join kind=inner suspicious_procs on DeviceId
| where InitiatingProcessId == ProcessId
| where Timestamp between (ProcTime .. ProcTime + 10m)
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcTime
```

## Tuning
- exclude approved update tools and management scripts
- narrow by parent process or URL patterns
- optionally require uncommon remote destinations

## Triage
1. confirm process and network events match the same execution
2. review remote IP/URL reputation
3. inspect parent process and user context
4. check for file writes or persistence nearby
