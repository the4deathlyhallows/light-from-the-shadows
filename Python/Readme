# Automation: Populate SOC Response Template

Files added:
- `Soc Responses/response_template.md` — fillable Markdown template with placeholders.
- `scripts/populate_response.py` — small CLI to populate the template from a CSV export.

Quick usage:

1. Ensure your SIEM CSV has headers (examples): `alert_name,hostname,source_ip_domain,timeframe,category,short_summary,evidence,ti_summary,action_taken,recommendation,analyst,attachments,brief_reason`.

2. Run the script:

```bash
python3 scripts/populate_response.py --csv siem_export.csv --row 0 --out filled_report.md
```

3. The script will write a filled Markdown file (default `filled_{alert}_{host}.md`).

Notes:
- Header names are case-insensitive — they are normalized to uppercase for template substitution.
- If a CSV column is missing, the corresponding placeholder will remain in the output for manual editing.
