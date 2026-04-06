# Azure Detection Engineering Playbook v2

A Git-ready Azure detection engineering repository for **Microsoft Sentinel** and **Microsoft Defender XDR**.

## What this repo gives you

- a practical operating model for Azure detections
- 10 starter detections written in KQL-backed rule specs
- Sentinel rule YAMLs you can version and refine
- Defender XDR detection specs you can keep in Git
- Bicep starter files for Sentinel analytics rule deployment
- testing, triage, tuning, and promotion guidance
- a lightweight GitHub Actions workflow skeleton

## Suggested workflow

1. Write or update the rule in this repo
2. Test in hunting mode
3. Review false positives and add exclusions
4. Promote to production
5. Deploy Sentinel content with Bicep
6. Keep Defender XDR query/spec parity with the portal config

## Repo layout

```text
azure-detection-playbook-v2/
├── README.md
├── deployment/
│   └── bicep/
│       ├── main.bicep
│       ├── main.parameters.json
│       └── modules/
│           └── scheduledRule.bicep
├── detections/
│   ├── sentinel/
│   │   ├── identity/
│   │   ├── control-plane/
│   │   └── data/
│   └── defender-xdr/
│       ├── endpoint/
│       └── correlation/
├── docs/
├── templates/
└── .github/
    └── workflows/
```

## Detection IDs

- `AZI` = Azure identity
- `AZC` = Azure control plane
- `AZD` = Azure data / storage / key vault
- `AZE` = Azure endpoint
- `AZX` = Cross-domain / correlation

## The first 10 detections in this pack

### Sentinel
1. `AZI-0001` Privileged role assignment created or deleted
2. `AZC-0001` Diagnostic settings tamper
3. `AZI-0002` Repeated failed sign-ins by IP against multiple users
4. `AZI-0003` App or service principal credential added
5. `AZI-0004` New admin caller performing write/delete actions
6. `AZD-0001` Sensitive Key Vault access by unfamiliar caller

### Defender XDR
7. `AZE-0001` Browser to LOLBIN / interpreter execution chain
8. `AZE-0002` Encoded or download-capable PowerShell
9. `AZE-0003` LOLBIN followed by outbound network connection
10. `AZE-0004` Registry persistence by suspicious parent

## How to use this repo

- Replace sample allowlists with your real admins, jump hosts, service principals, and maintenance identities
- Calibrate thresholds with historical data before enabling incidents broadly
- Treat each detection as a product with ownership, change history, tuning notes, and triage steps
