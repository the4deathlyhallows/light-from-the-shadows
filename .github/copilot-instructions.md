# Copilot / AI agent instructions — Light From The Shadows

Purpose
- Help a coding agent become immediately productive working across detection rules, enrichment scripts, playbooks, and small utilities.

Big picture
- This repo is a curated collection (not a single app): detection rules (KQL, Splunk, Sigma, Yara), lightweight Python enrichment scripts, playbooks, and cheat-sheets.
- Data flow: most scripts read simple text inputs (e.g., `iocs.txt`) -> apply regex/type detection -> call enrichment hooks or local lookups -> print or write CSV/text outputs.

Key locations (start here)
- Root README: [README.md](README.md)
- Enrichment scripts: [enrichment-scripts/](enrichment-scripts/) and [scripts/](scripts/) (examples: [scripts/ioc_enricher_basic.py](scripts/ioc_enricher_basic.py), [scripts/NMAP VULN SCAN](scripts/NMAP%20VULN%20SCAN))
- IOC CLI: [ioc-enrich/](ioc-enrich/) and [ioc-enrich/README.md](ioc-enrich/README.md)
- Detection rules: [detections/](detections/) — check `kql/`, `splunk/`, `sigma/`, `Yara/` subfolders (example: [detections/splunk/encoded_powershell_detection.spl](detections/splunk/encoded_powershell_detection.spl))
- Playbooks & cheats: [playbooks/](playbooks/) and [Cheat-Sheets/](Cheat-Sheets/)

Project conventions & patterns
- Small, single-purpose Python CLIs. Prefer adding a minimal `requirements.txt` next to scripts that need external libs.
- Filenames may contain spaces; always quote them in shell commands (see `scripts/NMAP VULN SCAN`).
- IOC pattern: one IOC per line; scripts detect IOC type by regex and enrich via local code or optional APIs.
- Detection rules are stored as raw rule files (no bundling). Expect plain KQL/SPL/YAML rule text.

Developer workflows (practical commands)
1. Create / activate venv and run a script:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # add this file when you introduce deps
python3 scripts/ioc_enricher_basic.py
python3 "scripts/NMAP VULN SCAN"
```

2. Run individual scripts from repo root so relative paths (e.g., `iocs.txt`) resolve correctly.
3. Debug by opening the script in the editor and using the Python debugger; scripts are intentionally simple and print to stdout.

When editing code
- Make minimal, targeted changes. Add or update a `requirements.txt` in the script folder when adding deps.
- Keep detection rules in `detections/*` and enrichment tools in `enrichment-scripts/` or `scripts/` — don't move rule files into new packaging structures.
- If you change an IOC format or IO contract, update the relevant README and example input files (e.g., `iocs.txt`).

Examples to reference
- IOC pattern: [scripts/ioc_enricher_basic.py](scripts/ioc_enricher_basic.py) and [ioc-enrich/ioc-enrich.py](ioc-enrich/ioc-enrich.py)
- Nmap-based example: [scripts/NMAP VULN SCAN](scripts/NMAP%20VULN%20SCAN) (requires `python-nmap`)
- Splunk rule example: [detections/splunk/encoded_powershell_detection.spl](detections/splunk/encoded_powershell_detection.spl)

Integration points & external deps
- Most external deps are script-local (e.g., `python-nmap`). Inspect imports to infer required packages and add them to `requirements.txt`.
- No centralized CI or secret storage detected — do not assume API keys exist. If a script supports an API key, document where to set it in that script's README.

Limitations & expectations
- No test suite or CI found; coordinate before adding repository-level CI.
- Avoid large refactors; maintain the repo's role as a curated collection of artifacts.

Contact & feedback
- If unclear which artifacts are authoritative, ask the repo owner which directories to preserve as-is and which can be refactored.

-- End of guidance --
# Copilot / AI agent instructions — Light From The Shadows

Purpose
- Help an AI coding agent be immediately productive in this repository (detection rules, enrichment scripts, playbooks).

Big picture (what this repo is)
- A collection of detection engineering artifacts: detection rules (KQL, Splunk SPL, Sigma), enrichment scripts (Python), playbooks, and cheat-sheets.
- Not a single application — treat it as a curated knowledge/codebase for detection development and small Python utilities.

Key locations (start here)
- Root README: [README.md](README.md) — project purpose and author notes
- Enrichment scripts: `enrichment-scripts/` and `scripts/` — lightweight Python CLIs (e.g., `scripts/ioc_enricher_basic.py`, `scripts/NMAP VULN SCAN`)
- IOC tool: [ioc-enrich/README.md](ioc-enrich/README.md) and `ioc-enrich/` — a small CLI that parses IOCs by regex
- Detection rules: `detections/` — subfolders: `kql/`, `splunk/`, `sigma/`, `Yara/` — each contains raw rule files and examples
- Cheat sheets and playbooks: `Cheat-Sheets/`, `playbooks/`, `MITRE-coverage/` — reference and methodology

Project conventions and practical notes
- Files are often simple, single-purpose scripts (no packaging). Expect direct `python3 <script>` runs.
- Filenames sometimes contain spaces (e.g., `scripts/NMAP VULN SCAN`) — always quote such paths when invoking from shell.
- Minimal external deps: deduce from imports. Example: `scripts/NMAP VULN SCAN` imports `nmap` (python-nmap). Install per-script when needed.
- IOC processing pattern: read one IOC per line, simple regex type detection, then enrichment hooks. See `ioc-enrich/README.md` and `scripts/ioc_enricher_basic.py`.
- Detection rule format examples: Splunk query example in `detections/splunk/encoded_powershell_detection.spl` uses raw SPL search strings (no packaging or deployment automation present).

Common developer workflows (how to run & debug)
- Run a script: create a venv, install required libs, then run with `python3`:

```bash
python3 -m venv .venv
source .venv/bin/activate
# example dependency for nmap-based script
pip install python-nmap
python3 "scripts/NMAP VULN SCAN"
python3 scripts/ioc_enricher_basic.py
```

- If a script reads `iocs.txt` by default, run it from the repo root or pass the expected filename. Check script top-level `if __name__ == "__main__"` for defaults.
- Debugging: open the script in the editor and run with the Python debugger; many scripts are small and rely on simple file IO and prints.

What I (the agent) should do first when modifying code
- Prefer minimal, focused changes: editing a single script, adding an accompanying README or requirements list.
- When adding dependencies, add a short `requirements.txt` at repo root or in the script folder and update this file.
- Preserve naming and folder conventions (keep detection rules in `detections/*`, enrichment tools in `enrichment-scripts/` or `scripts/`).

Examples to reference in edits
- `scripts/NMAP VULN SCAN` — requires `python-nmap` and expects quoted filename usage.
- `scripts/ioc_enricher_basic.py` — simple IOC read/enrich loop; use as canonical small-script style.
- `detections/splunk/encoded_powershell_detection.spl` — example Splunk rule formatting and naming.

Limitations and expectations
- No CI, tests, or packaging detected — coordinate with the repo owner before adding CI or heavy refactors.
- Avoid assuming external API keys or services exist unless documented (IOC enrichment mentions optional API keys but none are stored here).

If you need clarification
- Ask the repo owner which scripts should be productionized, which directories are authoritative for each detection type, and whether a `requirements.txt` or CI should be added.

-- End of guidance --
