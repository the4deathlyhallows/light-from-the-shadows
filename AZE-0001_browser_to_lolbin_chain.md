# AZE-0001 — Browser to LOLBIN / interpreter execution chain

## Metadata
- **id**: AZE-0001
- **title**: Browser to LOLBIN / interpreter execution chain
- **status**: testing
- **owner**: detection-engineering
- **platform**: defender_xdr
- **severity**: High
- **tactic**: TA0002
- **technique**: T1204.001 / T1059
- **tables**: DeviceProcessEvents
- **run frequency**: 1 hour
- **lookback**: 1 hour
- **response actions**: alert only initially
- **false positives**:
  - browser-launched enterprise scripts
  - developer/admin tooling launched from browser workflows

## Query
```kql
let timeframe = 1h;
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe"]);
let interpreters = dynamic(["powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where FileName in~ (interpreters)
| where InitiatingProcessFileName in~ (browsers)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
```

## Tuning
- allowlist approved enterprise browser-launched workflows
- require suspicious command-line terms for higher-confidence variants
- correlate with DeviceNetworkEvents for better fidelity

## Triage
1. review process lineage
2. review command line for URL, encoded content, or script verbs
3. review nearby network activity
4. review prevalence by device and user
