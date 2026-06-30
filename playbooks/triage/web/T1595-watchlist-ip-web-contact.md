# T1595-watchlist-ip-web-contact.md

## Alert: Watchlist Source IP — Web Traffic Match (IIS)

**MITRE ATT&CK:** T1595 (Active Scanning) / T1190 (Exploit Public-Facing App)
**Data source:** index=<INDEX> sourcetype=iis (CIM Web data model)
**Severity baseline:** Medium (escalates based on status code + URI pattern)

### Detects
Web traffic from source IPs present on a maintained watchlist (TI feed, prior incident IOCs, or abuse-reported IPs).

### SPL pattern
```spl
(`cim_Web_indexes`) sourcetype=iis
| eval src_ip=coalesce(c_ip, src, src_ip, clientip)
| search src_ip IN (<SRC_IP_WATCHLIST>)
| fillnull value="-"
| stats earliest(_time) as firsttime, latest(_time) as lasttime, count,
    values(cs_host) as site, values(cs_method) as method, values(status) as status,
    values(uri_path) as uri_path, values(uri_query) as uri_query,
    values(url) as url, values(useragent) as useragent by src_ip
| convert ctime(firsttime) ctime(lasttime)
| sort - count
```

### Triage steps
1. Verify watchlist source and freshness
2. Review count, time span, status code distribution
3. Check for exploitation-pattern URIs
4. Check user agent for scanner/tooling signatures
5. Determine single-host vs. multi-host scope

### Benign causes
Cloud/CDN shared infra, stale TI indicator, internal scanner not yet allowlisted, vendor traffic.

### Escalate if
Any 2xx/3xx on sensitive endpoints, sustained activity, multi-IP convergence on narrow target set, exploitation-pattern URIs.

### Close if
All 4xx, single low-count hit, confirmed benign source via deconfliction.

### Tuning
Split into informational vs. behavioral-severity tiers; add indicator age-out logic; build vendor/scanner allowlist.
