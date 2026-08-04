# AHK RAT Loader Campaign — Detection Pack

Covers the AutoHotkey-based loader campaign (Morphisec, May 2021) delivering Revenge RAT,
LimeRAT, AsyncRAT, Houdini, and Vjw0rm, including the stikked.ch/StrReverse VBS variant
confirmed in the deobfuscated screenshot.

## Files

- `ahk_rat_loader_detections.yml` — 9 Sigma rules (process_creation, file_event, ps_script)
- `ahk_loader_vbs_obfuscation.yar` — 2 YARA rules for static/content scanning
- `ahk_rat_loader_detections.yaral` — 12 YARA-L 2.0 rules for Google SecOps (Chronicle),
  including two multi-event correlations (LNK→batch, AHK→hidden PowerShell chain) that
  Sigma/classic YARA can't express directly. **Before enabling**: confirm UDM field
  mappings for your log sources (see comments at the top of the file) — in particular
  the PowerShell 4104 script-block rule and the VBS-content-approximation rule are
  flagged as needing verification, since Chronicle's default parsers don't guarantee a
  fixed field for raw script content.

## Rule summary

| # | Rule | Logsource / UDM event | ATT&CK | Level |
|---|------|-----------|--------|-------|
| 1 | AHK-compiled EXE spawns WScript/CScript/PowerShell | process_creation | T1059.005, T1059.001 | high |
| 2 | WScript/CScript spawns hidden/encoded PowerShell | process_creation | T1059.001, T1027 | high |
| 3 | Download from paste-style host (stikked.ch, pastebin, etc.) | process_creation | T1105, T1071.001 | medium |
| 4 | Defender tampering (Set-MpPreference / sc stop WinDefend / reg) | process_creation | T1562.001 | high |
| 5 | LNK created pointing to .bat/.cmd | file_event | T1547.009 | low |
| 6 | Hosts file modified | file_event | T1562.001, T1565.001 | medium |
| 7 | PowerShell reflective load / in-memory download | process_creation | T1055, T1620 | high |
| 8 | Script-block HttpWebRequest cradle to stikked.ch (needs 4104 logging) | ps_script | T1059.001, T1105 | critical |
| 9 | VBS StrReverse+Execute+Chr/Asc decoder (Sigma, content-based backend) | file_event | T1059.005, T1027 | critical |
| YARA-1 | VBS StrReverse+Execute+Chr/Asc decoder (YARA equivalent) | file content | T1059.005, T1027 | high |
| YARA-2 | Compiled AHK dropper heuristic (FileInstall + .vbs + hidden PS) | PE static | T1059.005 | medium |
| YARA-L-1..12 | Same coverage as above, re-expressed for Chronicle UDM, plus 2 multi-event correlations (LNK→batch, AHK→PowerShell chain) | PROCESS_LAUNCH / FILE_CREATION / FILE_MODIFICATION / NETWORK_DNS | see file | low–critical |

## Deployment notes

- Rules 1, 2, 7, 8 (and their YARA-L equivalents) give the strongest signal chained
  together (AHK → script host → hidden/encoded PowerShell → download cradle). The
  YARA-L file includes `ahk_loader_multistage_chain_ahk_to_hidden_powershell`, a
  ready-made multi-event correlation for exactly this — no legitimate baseline expected.
- Rule 8 / the YARA-L script-block rule requires PowerShell Script Block Logging
  (Event ID 4104) enabled via GPO (`Turn on PowerShell Script Block Logging`). Without
  it, the reversed/decoded command is invisible — it's built at runtime inside the VBS
  host and never hits the process command line in plaintext.
- Rule 5 (LNK creation) is intentionally low-severity/noisy alone; pair with rule 4
  (Defender tampering) or, in SecOps, use `ahk_loader_lnk_triggers_batch_script` which
  correlates LNK drop + subsequent .bat/.cmd launch on the same host within 10 minutes.
- `stikked.ch` and the other paste hosts in rule 3 are indicators, not the technique —
  add any additional paste/C2 domains you observe from your own telemetry.
- Sigma `category: ps_script` and `category: file_event` field names assume a
  Sysmon/Winlogbeat-style backend; adjust field mappings (`ScriptBlockText`,
  `TargetFilename`, `FileContent`) if converting for Splunk, Elastic, or Sentinel via
  `sigma-cli`/`pySigma`.
- For the `.yaral` file: Google SecOps YARA-L runs over UDM events, not raw file bytes,
  so the VBS StrReverse content check is only a true content match in classic YARA
  (`ahk_loader_vbs_obfuscation.yar`). The YARA-L version
  (`ahk_loader_vbs_strreverse_obfuscation_udm_approx`) is a best-effort fallback that
  only fires if your pipeline forwards raw script content into a UDM field — verify with
  UDM Search before enabling, and prefer the classic YARA rule if you have any EDR/AV
  file-scanning capability.

## Source

[Experts Warn About Ongoing AutoHotkey-Based Malware Attacks](https://thehackernews.com/2021/05/experts-warn-about-ongoing-autohotkey.html) (The Hacker News, citing Morphisec Labs)
