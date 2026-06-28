# light-from-the-shadows

Production detection engineering portfolio — YARA-L, KQL, Splunk SPL, Python enrichment, and MITRE ATT&CK coverage built from real SOC work.

---

## Repo layout

```
light-from-the-shadows/
├── detections/
│   ├── azure-sentinel/       # KQL-backed Sentinel analytics rules (AZI, AZC, AZD series)
│   ├── defender-xdr/         # Defender XDR detection specs (AZE series)
│   ├── google-secops/        # YARA-L rules for Chronicle
│   ├── splunk/               # SPL detections and correlation searches
│   ├── clickfix/             # ClickFix social engineering detection pack
│   └── Yara/                 # YARA signatures
├── python/
│   ├── enrichment/           # IOC enrichment scripts (VirusTotal, IP lookup, domain tagging)
│   └── exercises/            # Python fundamentals and scripting practice
├── playbooks/                # SOC response playbooks
├── soc-responses/            # Real triage write-ups and alert response templates
├── docs/                     # Detection lifecycle, triage guide, testing checklist, mastery plan
├── mitre-coverage/           # ATT&CK tactic and technique mapping
├── cheat-sheets/             # DFIR, Sysmon, YARA-L, regex, MITRE flash cards
├── deployment/
│   └── bicep/                # Azure Sentinel analytics rule deployment via Bicep
├── templates/                # Sentinel and Defender XDR rule templates
├── postman/                  # API collections for detection testing
├── labs/                     # Lab builds and CTF work (Bandit, etc.)
└── kubernetes/               # Kubernetes security reference material
```

---

## Detection coverage

### Azure Sentinel (KQL)

| ID | Detection | Tactic |
|---|---|---|
| AZI-0001 | Privileged role assignment created or deleted | Privilege Escalation |
| AZI-0002 | Repeated failed sign-ins by IP across multiple users | Credential Access |
| AZI-0003 | App or service principal credential added | Persistence |
| AZI-0004 | New admin caller performing write/delete actions | Privilege Escalation |
| AZC-0001 | Diagnostic settings tampered | Defense Evasion |
| AZD-0001 | Sensitive Key Vault access by unfamiliar caller | Credential Access |

### Defender XDR (KQL)

| ID | Detection | Tactic |
|---|---|---|
| AZE-0001 | Browser to LOLBIN / interpreter execution chain | Execution |
| AZE-0002 | Encoded or download-capable PowerShell | Defense Evasion |
| AZE-0003 | LOLBIN followed by outbound network connection | Command & Control |
| AZE-0004 | Registry persistence by suspicious parent | Persistence |

### Google SecOps (YARA-L)

| Detection | Tactic |
|---|---|
| Log4j LDAP exploitation via User-Agent | Initial Access · T1190 |

### Splunk (SPL)

| Detection | Tactic |
|---|---|
| Ansible/automation admin anomaly detection | Discovery · T1078 |

---

## Python enrichment scripts

| Script | Purpose |
|---|---|
| `enrich_iocs_virustotal.py` | Enrich IOC list against VirusTotal API |
| `tag_suspicious_domains.py` | Tag and classify suspicious domains |
| `ioc-enrich.py` | Core IOC enrichment pipeline |
| `ioc_enricher_basic.py` | Lightweight enrichment for quick triage |
| `search_ip.py` | IP reputation lookup and scoring |

---

## Detection IDs

- `AZI` — Azure identity
- `AZC` — Azure control plane
- `AZD` — Azure data / storage / Key Vault
- `AZE` — Azure endpoint
- `AZX` — Cross-domain correlation (planned)

---

## Author

**Robert Clark** — Detection Engineer · TS/SCI  
Google SecOps · Microsoft Sentinel · Splunk · YARA-L · KQL · Python · Cribl · AWS  
GCFA · CASP+ · Cribl Certified User
