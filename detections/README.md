# AHK RAT Loader Campaign — Detection Pack

Covers the AutoHotkey-based loader campaign (Morphisec, May 2021) delivering Revenge RAT,
LimeRAT, AsyncRAT, Houdini, and Vjw0rm, including the stikked.ch/StrReverse VBS variant
confirmed in the deobfuscated screenshot.

## Files

- `ahk_rat_loader_detections.yml` — 9 Sigma rules (process_creation, file_event, ps_script)
- `ahk_loader_vbs_obfuscation.yar` — 2 YARA rules for static/content scanning

## Rule summary

| # | Rule | Logsource | ATT&CK | Level |
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

## Deployment notes

- Rules 1, 2, 7, 8 give the strongest signal chained together (AHK → script host →
  hidden/encoded PowerShell → download cradle). Consider a correlation rule that fires
  only when 2+ of these hit the same host within a short window — that combination has
  effectively no legitimate baseline.
- Rule 8 requires PowerShell Script Block Logging (Event ID 4104) enabled via GPO
  (`Turn on PowerShell Script Block Logging`). Without it, the reversed/decoded command
  is invisible — it's built at runtime inside the VBS host and never hits the process
  command line in plaintext.
- Rule 5 (LNK creation) is intentionally low-severity/noisy alone; pair with rule 4
  (Defender tampering) for the specific variant that used an LNK to trigger a
  Defender-disabling batch script.
- `stikked.ch` and the other paste hosts in rule 3 are indicators, not the technique —
  add any additional paste/C2 domains you observe from your own telemetry.
- Sigma `category: ps_script` and `category: file_event` field names assume a
  Sysmon/Winlogbeat-style backend; adjust field mappings (`ScriptBlockText`,
  `TargetFilename`, `FileContent`) if converting for Splunk, Elastic, or Sentinel via
  `sigma-cli`/`pySigma`.

## Source

[Experts Warn About Ongoing AutoHotkey-Based Malware Attacks](https://thehackernews.com/2021/05/experts-warn-about-ongoing-autohotkey.html) (The Hacker News, citing Morphisec Labs)
