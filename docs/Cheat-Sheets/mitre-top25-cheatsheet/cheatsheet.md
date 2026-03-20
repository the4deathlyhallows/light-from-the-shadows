Top 25 MITRE ATT&CK techniques (cheat-sheet)
Below: technique name — ATT&CK ID — one-line detection / hunting idea.
Command and Scripting Interpreter — T1059
Detect: anomalous PowerShell/cmd/python usage, encoded commands, child-process spawning patterns. 
Red Canary
Phishing (Spearphishing Attachment/Link/User) — T1566
Hunt: analyze email delivery patterns, URL click-to-open ratios, suspicious attachment types.
Valid Accounts (credential misuse) — T1078
Detect: logins from new geolocations, impossible travel, concurrent sessions. 
Verizon
Credential Dumping — T1003
Hunt: attempts to access LSASS memory, suspicious usage of credential-dumping tools (Mimikatz).
Exploitation of Public-Facing Application — T1190
Detect: spikes in POST/GET anomalies, web app errors, unexpected file writes to web directories.
Application Layer Protocol (C2 over HTTP/S, DNS) — T1071
Detect: beaconing patterns, periodic small data exfil, anomalous user-agent strings. 
Red Canary
Ingress Tool Transfer — T1105
Hunt: download anomalies from uncommon hosts, embedded downloader activity.
Process Injection — T1055
Detect: parent/child command-line mismatches, process hollowing indicators.
Scheduled Task / Job — T1053
Hunt: new/modified scheduled tasks, odd command lines in task scheduler events.
Masquerading (file/process/paths) — T1036
Detect: filenames mimicking system files, unsigned binaries in unusual folders.
Obfuscated/Encrypted Files or Information — T1027
Hunt: scripts or binaries with high entropy, encoded payloads in benign-looking files.
Lateral Movement: Remote Services (SMB, RDP, SSH) — T1021
Detect: RDP from unusual hosts, SMB writes after authentication, anomalous SSH sessions.
Brute Force — T1110
Detect: repeated failed authentications, credential stuffing patterns.
Exfiltration Over C2 Channel — T1041
Hunt: encrypted outbound channel with abnormal data volumes correlated to endpoints.
Data Encrypted for Impact (Ransomware) — T1486
Detect: large, rapid file modification/rename activity; deletion of shadow copies. 
Verizon
DLL Search Order Hijacking — T1038
Hunt: DLL loads from writable directories or unexpected parent binary paths.
Account Discovery — T1087
Detect: queries to domain controllers for account lists, AD enumeration tools.
System Information Discovery — T1082
Hunt: inventory-gathering commands (systeminfo, hostname, ipconfig), WMI queries.
Network Service Scanning — T1046
Detect: internal port scanning, ICMP sweeps, repeated connection attempts to many ports.
Impair Defenses (disable AV, tamper logs) — T1562
Detect: security service stops, clearing of event logs, changes to detection settings.
Exfiltration Over Web Services — T1567
Hunt: uploads to consumer cloud services or unusual use of web storage APIs.
Archive Collected Data — T1560
Detect: suspicious archive creation (zip/7z/tar) of many user file types.
Access Token Manipulation — T1134
Hunt: token duplication, unusual impersonation/Set-Token API calls.
Remote File Copy (SMB, SCP) — T1105/T1021.002
Detect: large file transfers between hosts via SMB/SCP outside business hours.
Modify/Disable System Recovery (delete backups, shadow copies) — T1490/T1497
Detect: vssadmin usage, deletion of backups or snapshot metadata.
