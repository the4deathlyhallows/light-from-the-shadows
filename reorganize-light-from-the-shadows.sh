#!/usr/bin/env bash
# ============================================================
# light-from-the-shadows — repo reorganization script
# Run from the root of your local clone.
# Review each section before running. Safe to run incrementally.
# ============================================================

set -e  # stop on first error

echo "==> Step 1: Create target folder structure"
mkdir -p detections/azure-sentinel
mkdir -p detections/defender-xdr
mkdir -p detections/google-secops
mkdir -p detections/splunk
mkdir -p detections/clickfix
mkdir -p python/enrichment
mkdir -p python/automation
mkdir -p deployment/bicep
mkdir -p docs
mkdir -p templates

echo "==> Step 2: Move AZI / AZC / AZD YAML rules into detections/azure-sentinel"
git mv AZI-0001_role_assignment_change.yaml            detections/azure-sentinel/
git mv AZI-0002_failed_signins_multiple_users.yaml     detections/azure-sentinel/
git mv AZI-0003_app_or_sp_credential_added.yaml        detections/azure-sentinel/
git mv AZI-0004_new_admin_caller_write_delete.yaml     detections/azure-sentinel/
git mv AZC-0001_diagnostic_settings_tamper.yaml        detections/azure-sentinel/
git mv AZD-0001_key_vault_unfamiliar_caller.yaml       detections/azure-sentinel/

echo "==> Step 3: Move AZE endpoint specs into detections/defender-xdr"
git mv AZE-0001_browser_to_lolbin_chain.md             detections/defender-xdr/
git mv AZE-0002_encoded_or_download_powershell.md      detections/defender-xdr/
git mv AZE-0003_lolbin_followed_by_network.md          detections/defender-xdr/
git mv AZE-0004_registry_persistence_suspicious_parent.md detections/defender-xdr/

echo "==> Step 4: Move Clickfix detections folder"
# 'detections /Clickfix Detections' has a space in the parent — handle carefully
git mv "detections /Clickfix Detections" detections/clickfix 2>/dev/null || \
  echo "  [skip] Clickfix folder path may differ — move manually if needed"

echo "==> Step 5: Move Bicep deployment files"
git mv main.bicep              deployment/bicep/
git mv main.parameters.json    deployment/bicep/

echo "==> Step 6: Move templates"
git mv sentinel-rule-template.yaml    templates/
git mv defender-xdr-rule-template.md  templates/

echo "==> Step 7: Move docs"
git mv detection-lifecycle.md   docs/
git mv triage-guide.md          docs/
git mv testing-checklist.md     docs/

echo "==> Step 8: Consolidate enrichment scripts"
# Merge enrichment-scripts/ and ioc-enrich/ into python/enrichment/
if [ -d "enrichment-scripts" ]; then
  git mv enrichment-scripts/* python/enrichment/ 2>/dev/null || true
  rmdir enrichment-scripts 2>/dev/null || true
fi
if [ -d "ioc-enrich" ]; then
  git mv ioc-enrich/* python/enrichment/ 2>/dev/null || true
  rmdir ioc-enrich 2>/dev/null || true
fi

echo "==> Step 9: Move automation scripts"
if [ -d "scripts" ]; then
  git mv scripts/* python/automation/ 2>/dev/null || true
  rmdir scripts 2>/dev/null || true
fi
# cloud trail-analyzer (folder with space) and loose file variant
git mv "cloud trail-analyzer " python/automation/cloud-trail-analyzer 2>/dev/null || \
git mv "cloud-trail analyzer"  python/automation/cloud-trail-analyzer 2>/dev/null || \
  echo "  [skip] cloud-trail-analyzer path unclear — check manually"

echo "==> Step 10: Rename folders with spaces or mixed casing"
# MITRE-coverage -> mitre-coverage
git mv MITRE-coverage mitre-coverage 2>/dev/null || echo "  [skip] MITRE-coverage already clean or missing"
# Soc Responses -> soc-responses (folder)
git mv "Soc Responses" soc-responses 2>/dev/null || echo "  [skip]"
# Cheat-Sheets -> cheat-sheets
git mv Cheat-Sheets cheat-sheets 2>/dev/null || echo "  [skip]"
# Articles  (trailing space) -> articles
git mv "Articles " articles 2>/dev/null || echo "  [skip]"
# Labs -> labs
git mv Labs labs 2>/dev/null || echo "  [skip]"
# Kubernetes -> kubernetes
git mv Kubernetes kubernetes 2>/dev/null || echo "  [skip]"

echo "==> Step 11: Move Python folder contents"
# Existing Python/ folder -> python/ (lowercase)
if [ -d "Python" ]; then
  git mv Python/* python/ 2>/dev/null || true
  rmdir Python 2>/dev/null || true
fi

echo "==> Step 12: Delete scratch/noise files from root"
# Review these before deleting — open each one first to confirm it's truly a scratch file
# Uncomment the lines below once you've confirmed their contents are safe to drop or already captured elsewhere

# git rm "100 Days of Python"
# git rm "2026"
# git rm "90"
# git rm "Claude Prompt"
# git rm "QUERY MASTER"
# git rm "SOC Responses"    # (loose file, not the folder)
# git rm "Table Top"
# git rm "cirt table"
# git rm "splunk ansible"

echo ""
echo "  ^ Step 12 is commented out intentionally."
echo "    Open each file first. If it has real content, move it to docs/ with a proper name."
echo "    If it's a scratch note, uncomment the git rm line and rerun."

echo "==> Step 13: Remove the .zip archive"
# The files inside should already be in the repo as actual files.
# Confirm first, then uncomment:
# git rm azure-detection-playbook-v2.zip

echo ""
echo "==> Step 14: Commit everything"
git add -A
git status   # review before committing

echo ""
echo "  When satisfied with git status output, run:"
echo "  git commit -m 'refactor: reorganize repo into structured layout'"
echo "  git push origin main"

echo ""
echo "==> Step 15 (manual — do in GitHub UI): Add topic tags to the repo"
echo "  Go to: https://github.com/the4deathlyhallows/light-from-the-shadows"
echo "  Click the gear icon next to 'About' on the right sidebar"
echo "  Add tags: detection-engineering  kql  yara-l  siem  google-secops  mitre-attack  python"

echo ""
echo "Done. Next: update README.md to reflect the new folder layout."
