# T1595-iis-4xx-statistical-anomaly.md

## Alert: IIS 4xx Status Code Statistical Anomaly (per-source-IP)

**MITRE ATT&CK:** T1595 (Active Scanning) — confirmed mapping pulled dynamically from TI risklist where available
**Data source:** index=<INDEX> sourcetype=iis (status=4xx subset)
**Severity baseline:** Medium, escalates based on TI risk score and MITRE mapping presence

### Detects
Source IPs whose 4xx HTTP status code pattern deviates statistically from expected baseline behavior, using Splunk's `anomalies` command (unexpectedness scoring) rather than a static threshold. Enriched with geolocation, TI risk score, and MITRE technique mapping from an internal risklist lookup.

### SPL pattern
```spl
index=<INDEX> sourcetype=iis status=4*
`<WHITELIST_MACRO>`
| iplocation src_ip
| anomalies threshold=0.01 field=status by src_ip
| eval flag=if(unexpectedness>=0.01, "anomalous", "not_anomalous")
| stats earliest(_time) as start_time, latest(_time) as end_time,
    avg(unexpectedness) as unexpectedness, values(host) as orig_host,
    values(dest_ip) as dest_ip, values(http_referer) as http_referer,
    values(http_method) as http_method, values(status) as status,
    values(uri_path) as uri_path, values(Country) as src_country,
    values(cs_User_Agent) as http_user_agent, count as count_findings
  by index, src_ip
| rename src_ip as Name
| join type=outer Name
    [| inputlookup <TI_RISKLIST_LOOKUP>
    | fields Mitre Name Risk]
| rename Name as src_ip, Risk as TI_Risk_Score
| eval TCode=json_array_to_mv(json_extract(Mitre,"{}.Code")),
    TCode_Label=json_array_to_mv(json_extract(Mitre,"{}.Label"))
| eval TI_Risk_Score=if(isnull(TI_Risk_Score),0,TI_Risk_Score),
    TCode=if(isnull(TCode),"N/A",TCode)
| table start_time, end_time, src_ip, TI_Risk_Score, TCode, TCode_Label,
    dest_ip, unexpectedness, orig_host, http_referer, http_method,
    http_user_agent, status, uri_path, src_country, count_findings
| sort -unexpectedness, -src_ip
| head 10
```

### Triage steps
1. Sort by unexpectedness descending; prioritize nonzero TI_Risk_Score
2. Check MITRE mapping (TCode) if present
3. Review src_country for business justification
4. Review uri_path/http_referer for scan/enumeration signatures
5. Check user agent for automation tooling
6. Check for 2xx success interleaved with 4xx pattern (probe-then-access)

### Benign causes
Misconfigured client hitting deprecated endpoint, crawler discovering broken links after site change, QA/monitoring tooling, shared CDN/LB front IP.

### Escalate if
Nonzero TI risk score, populated MITRE mapping, interleaved success after probing, sustained multi-day targeting, no business justification for source geography.

### Close if
Zero risk score, no MITRE tag, isolated single-day anomaly, benign explanation confirmed via deconfliction.

### Tuning
Validate anomalies threshold empirically (currently 0.01); maintain whitelist macro actively; consider minimum count_findings floor; evaluate head 10 cutoff against full anomaly volume.
