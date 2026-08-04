# Investigation Triage Runbook — Benign vs. Malicious Verification

Built from the Mission Control Analyst Queue reviewed on 2026-08-04. Each section covers one
investigation category: what it's checking, the SPL to run, how to read the result, and a
generic close statement to paste into the disposition/comment field once you're confident.

**Before you publish this:** field names, index names, sourcetype names, hostnames, and account
names below reflect this environment and will need scrubbing (`index=*`, `sourcetype=*linux*`
etc. are already generic, but any literal hostnames/account names like `$canetbackupsvc` or
`cyberark01` should be replaced with placeholders). Queries are templates — validate field names
against your own CIM mappings/data models before relying on results.

**Disclaimer:** these queries were not run against a live Splunk instance — I don't have access
to this environment. Test each one against a small time window first and confirm it returns the
fields referenced before trusting the output.

---

## 1. Privileged account password-rotation failures (Linux/RHEL)
*Example: ES-00667 / ES-00666 — "failed attempts to change pass/password"*

**What it detects:** repeated failed password-change events on Linux hosts, often surfaced when
a privileged access management (PAM) tool rotates credentials and the target rejects the new
password.

**Query 1 — timing pattern.** Rotation jobs run on a fixed schedule; attacks don't.
```spl
index=* sourcetype=*linux* OR sourcetype=*rhel* "failed" "password"
earliest=-2d@d latest=now
| bin _time span=15m
| stats count by _time
| sort _time
```
*Benign signal:* count spikes recur at consistent intervals (e.g., every 4 hours).
*Malicious signal:* random/continuous distribution, or a single sharp burst with no prior pattern.

**Query 2 — source consistency.** Rotation comes from one controller; brute force comes from many sources.
```spl
index=* sourcetype=*linux* OR sourcetype=*rhel* "failed" "password"
earliest=-2d@d
| stats count values(user) as accounts earliest(_time) as first latest(_time) as last by dest, src
| convert ctime(first) ctime(last)
| sort - count
```
*Benign signal:* small, stable set of `src` values (your PAM/CPM/PSM servers) touching many `dest` hosts.
*Malicious signal:* many distinct/unfamiliar `src` values, or `src` external to your network.

**Query 3 — cross-reference with PAM system logs (if ingested).**
```spl
index=cyberark (sourcetype=*epv* OR sourcetype=*cpm*)
(Action="*Password*" OR Action="*Change*")
earliest=-2d@d
| table _time, TargetAccount, TargetAddress, Reason, Status
| sort _time
```
*Benign signal:* a rotation job entry exists for the same account/host within a couple minutes of the failure.
*Malicious signal:* no matching rotation job — the failed attempt has no legitimate source.

**Decision:**
- All three queries support rotation (regular timing, consistent source, matching PAM log entry) → **Benign**.
- Any query contradicts it (irregular timing, unfamiliar source, no PAM record) → escalate, do not close.

**Generic close statement:**
> Benign Positive — Failed password-change events confirmed as [PAM tool name] scheduled credential
> rotation against managed account(s) on [host/host group]. Verified: (1) failure timing matches
> known rotation schedule, (2) source of change attempts is the designated PAM controller
> ([hostname/IP]), (3) [PAM audit log / team confirmation] corroborates a rotation job at the same
> time. No unauthorized access indicated. Recommend routing a ticket to [PAM/sysadmin team] to
> resolve the underlying rotation failures (target account lockout/policy mismatch), separate from
> this security disposition. Closed by [analyst], [date].

**Note:** a real-world investigation of this type surfaced a second, unrelated pattern buried in
the same findings — `${jndi}` strings submitted as usernames. That's not a rotation-failure
artifact; see **Section 3a** for how to evaluate it separately before dispositioning the
investigation as a whole.

---

## 2. Sensitive AD data access / NTDS or backup-service activity
*Example: ES-00654 — "Possible BlueHammer-NTDS or Sensitive File Copy Operations"*

**What it detects:** access to NTDS.dit or bulk copy of sensitive files by a service account —
this is also the method used to steal Active Directory credentials, so it needs real verification,
not an assumption of benign.

**Query 1 — what actually ran.**
```spl
index=* (sourcetype=*sysmon* OR sourcetype=*wineventlog*)
(user="*<service_account>*" OR Account_Name="*<service_account>*")
(Image="*ntdsutil*" OR CommandLine="*ntds*" OR CommandLine="*vssadmin*shadow*")
earliest=-2d@d
| table _time, dest, user, ParentImage, Image, CommandLine
| sort _time
```
*Benign signal:* `ParentImage` is a known backup agent (Veeam, CommVault, Windows Server Backup, etc.), not `cmd.exe`/`powershell.exe` launched interactively.
*Malicious signal:* interactive shell as parent, unusual binary path, or execution from a non-DC/non-backup host.

**Query 2 — historical baseline.**
```spl
index=* (user="*<service_account>*" OR Account_Name="*<service_account>*")
(CommandLine="*ntds*" OR Image="*ntdsutil*")
earliest=-30d@d
| bin _time span=1d
| stats count by _time
| sort _time
```
*Benign signal:* recurring activity at the same cadence (daily/weekly) going back weeks.
*Malicious signal:* first-time occurrence, or activity outside the account's established pattern.

**Query 3 — logon context of the account.**
```spl
index=* (Account_Name="*<service_account>*" OR user="*<service_account>*")
sourcetype=*wineventlog* EventCode=4624
earliest=-2d@d
| table _time, dest, src, Logon_Type
| sort _time
```
*Benign signal:* logon source/type matches the expected backup server and scheduled logon type (e.g., service logon type 5).
*Malicious signal:* interactive logon (type 2/10) from an unexpected host.

**Decision:** benign only if all three line up (legitimate parent process, established recurring
pattern, expected logon source/type). Any one contradicting sign → treat as potential credential
theft and escalate per your incident process — do not self-close.

**Generic close statement:**
> Benign Positive — Suspicious But Expected. [Service account] NTDS/sensitive-file access confirmed
> as routine [backup tool name] job. Verified: (1) parent process is the backup agent, not an
> interactive shell, (2) matching activity recurs on [cadence] going back [N] days, (3) logon
> source/type matches the expected backup server and service logon pattern. No credential-theft
> indicators present. Closed by [analyst], [date].

---

## 3. Attack-signature string matches (web/WAF)
*Example: ES-00660 — "malicious attack strings"*

**What it detects:** requests containing known attack payload patterns (SQLi, XSS, path traversal, etc.).

**Query 1 — did anything succeed?**
```spl
index=* sourcetype=*waf* OR sourcetype=*access_combined*
(uri_query="*<script*" OR uri_query="*union select*" OR uri_query="*../../*" OR uri_query="*%00*")
earliest=-2d@d
| stats count values(status) as statuses by src_ip, uri_path
| sort - count
```
*Benign signal:* every hit returns 4xx (blocked/rejected) — the WAF or app stopped it.
*Malicious signal:* any `200`/`302`/`500` response mixed in — the payload may have been processed.

**Query 2 — source reputation/volume.**
```spl
index=* sourcetype=*waf* OR sourcetype=*access_combined*
(uri_query="*<script*" OR uri_query="*union select*" OR uri_query="*../../*")
earliest=-7d@d
| stats count dc(uri_path) as paths_hit values(http_user_agent) as agents by src_ip
| sort - count
```
*Benign signal:* single known scanner IP (internal pen-test/vuln scanner) hitting many paths with a scanner user-agent.
*Malicious signal:* multiple unrelated external IPs, or a targeted, low-volume probe against a sensitive endpoint.

**Decision:** benign only if all matches were blocked *and* the source is a known/allowlisted
scanner. A successful response of any kind means this cannot be closed benign without deeper
investigation of that specific request.

**Generic close statement:**
> Benign Positive — Attack-signature matches confirmed blocked/rejected (all responses 4xx) and
> sourced from [known scanner/internal security tooling, IP]. No successful payload execution
> observed. Closed by [analyst], [date].

---

## 3a. JNDI / Log4Shell canary strings in non-web fields (e.g., SSH usernames, auth logs)

**What it detects:** `${jndi:...}` — the Log4Shell (CVE-2021-44228) trigger string — or fragments
of it, submitted into a field that isn't a typical web parameter. Scanning tools spray this
payload into anything that might get logged (headers, form fields, usernames) hoping *some*
downstream Java/Log4j component processes it, so it shows up in unexpected places like SSH auth
logs. The default reaction should be to treat it seriously, but the single most decisive check is
whether the payload is actually **complete enough to function**.

**Query — check payload completeness.** A working exploit needs a protocol and callback host
(`${jndi:ldap://host/path}`). A bare or truncated fragment (`${jndi` with nothing after it)
cannot perform a JNDI lookup — it's structurally inert, regardless of intent.
```spl
index=* "jndi"
earliest=-2d@d
| rex field=_raw "(?<jndi_string>\$\{jndi[^\"]*)"
| eval complete=if(match(jndi_string, "jndi:\w+://"), "complete_functional", "incomplete_non_functional")
| stats count values(jndi_string) as examples by complete
```
*Lower-risk signal:* every instance is `incomplete_non_functional` — no protocol/host present.
Consistent with a scanner canary check (many scanners use a minimal fragment rather than standing
up real callback infrastructure for every scan) rather than a working exploit attempt.
*Higher-risk signal:* any instance is `complete_functional` — a real protocol and callback host
are present, meaning it *could* trigger a callback if a vulnerable Log4j instance processes it.
Treat with the same urgency as Section 3 above: do not self-close, escalate per your IR process,
and check for outbound DNS/LDAP/RMI connection attempts from any Java-based services that might
have processed the string.

**Real example from this queue (ES-00667/ES-00666):** `sshd` logs across ~30+ internal Linux
hosts showed `Failed password for invalid user ${jndi from <ip> port <port> ssh2` — the submitted
username was consistently the bare fragment `${jndi`, with no protocol or host, on every single
occurrence. Combined with a systematic sweep pattern (many hosts, tight time windows, structured/
repeating source addressing across subnets), this was assessed as a vulnerability-scanner canary
check rather than active exploitation — but held pending confirmation of the scanning tool's
ownership rather than closed on pattern-matching alone. `sshd` itself is a C program and isn't
directly exploitable by this string either way; the only theoretical downstream risk is a
Java-based log pipeline that unsafely processes the raw text.

**Decision:** benign only if (1) every observed instance is confirmed incomplete/non-functional,
and (2) the source is attributed to known/authorized scanning infrastructure or a team confirms
ownership. If either condition fails — a complete payload appears anywhere, or no one can account
for the source — do not close; escalate and keep investigating.

**Generic close statement:**
> Benign Positive — `${jndi}` string(s) observed in [SSH/other] logs confirmed structurally
> incomplete (no protocol/callback host present) and therefore non-functional as a JNDI exploit
> trigger. Pattern consistent with a vulnerability-scanner canary check. Source [attributed to
> <scanner/tool name>, confirmed by <team>] OR [could not be positively attributed; treated as
> low-risk given the non-functional payload — recommend continued monitoring]. No indication of
> actual code execution or outbound callback. Recommend identifying/allowlisting the source to
> reduce future noise. Closed by [analyst], [date].

---

## 4. Duplicate / overlapping correlation searches
*Examples: ES-00663/ES-00664 ("Windows"/"Windows 2"), ES-00658 ("increase failed logs")*

**What it detects:** not a threat category — these are candidates for merging because two
correlation searches likely fired on the same underlying events.

**Query — compare entity/finding overlap between two investigations.** Run once per investigation
ID (swap the `investigation_id` value), then diff the results manually or with a join:
```spl
| savedsearch "Investigation Findings" investigation_id="<ES-00663>"
| table _time, dest, src, user, signature
| append
    [| savedsearch "Investigation Findings" investigation_id="<ES-00664>"
     | table _time, dest, src, user, signature]
| stats count values(investigation_id) as investigations by dest, src, user, _time
| where mvcount(investigations) > 1
```
(If `Investigation Findings` isn't the right saved search name in your environment, pull the
underlying notable events for each investigation ID from the `notable` index instead:
`index=notable investigation_key="<ID>"`.)

*Benign/duplicate signal:* the same `dest`/`user`/`_time` combinations appear under both
investigation IDs — same activity, two searches.
*Distinct signal:* little to no overlap — these are genuinely separate issues and should be
triaged individually, not merged.

**Decision:** if overlap is high, merge the investigations in ES, disposition the redundant one as
**Duplicate**, and consider tuning the correlation searches so they don't both fire going forward.

**Generic close statement:**
> Duplicate — Findings confirmed to overlap with [primary investigation ID] (same host/user/time).
> Consolidated into [primary ID]; recommend reviewing correlation search overlap between
> [search name A] and [search name B] to prevent recurrence. Closed by [analyst], [date].

---

## 5. Web error spikes (HTTP 400s / anomalous byte counts)
*Examples: ES-00655/656/657 ("400 Errors"/"400 codes"/"400 codes pt. 2"), ES-00659 ("Web anomaly bytes")*

**Query 1 — is this one client or many?**
```spl
index=* sourcetype=*access_combined* OR sourcetype=*iis* status=400
earliest=-2d@d
| stats count by src_ip, uri_path, http_user_agent
| sort - count
```
*Benign signal:* concentrated on one `src_ip`/user-agent (a misconfigured internal client, a bot, a broken integration) hitting a small number of paths.
*Malicious signal:* many distinct IPs hitting varied/sensitive paths (could indicate fuzzing/scanning).

**Query 2 — did the byte anomaly coincide with the same traffic?**
```spl
index=* sourcetype=*access_combined*
earliest=-2d@d
| bin _time span=15m
| stats count sum(bytes) as total_bytes by _time, src_ip
| where total_bytes > 10000000
| sort - total_bytes
```
*Benign signal:* the anomalous-bytes window and source line up with the same client causing the 400 spike (e.g., a large failed upload).
*Malicious signal:* byte anomaly from a different, unrelated source — investigate separately (possible exfiltration).

**Decision:** benign if traceable to a single known/internal client or a known deploy/config issue
and no sensitive data was involved in the anomalous transfer.

**Generic close statement:**
> Benign Positive — HTTP 400 spike and byte anomaly traced to [client/system name], caused by
> [root cause, e.g., malformed client request / failed batch upload]. No malicious traffic pattern
> identified. Recommend [fix, e.g., patch client / add validation] to prevent recurrence.
> Closed by [analyst], [date].

---

## 6. Cloud reconnaissance / excessive scanning
*Example: ES-00662 — "AWS Excessive Security Scanning"*

**Query — identify the source and compare against known internal scanners.**
```spl
index=aws sourcetype=aws:cloudtrail
(eventName="Describe*" OR eventName="List*" OR eventName="Get*")
earliest=-2d@d
| stats count values(eventName) as api_calls by sourceIPAddress, userIdentity.arn
| sort - count
```
*Benign signal:* `userIdentity.arn` matches a known vulnerability-scanning role/service (e.g., AWS Inspector, a scheduled Config/Security Hub job, an internal CSPM tool) and `sourceIPAddress` is from your scanning infrastructure.
*Malicious signal:* an unfamiliar IAM principal or external IP performing broad `Describe`/`List` enumeration — classic recon behavior.

**Decision:** benign only if the principal is a known, authorized scanning identity. If you can't
positively identify the ARN, treat as unconfirmed and escalate rather than close.

**Generic close statement:**
> Benign Positive — Excessive API scanning confirmed as [scanner/tool name] running under
> authorized role [ARN]. Activity consistent with scheduled [vulnerability scanning/compliance
> check]. Recommend adding this principal to a suppression list for this correlation search.
> Closed by [analyst], [date].

---

## 7. Generic endpoint process telemetry
*Examples: ES-00665 ("Process"), ES-00661 ("Sysmon Process")*

These titles carry no signal on their own — the query approach is a general triage pass rather
than confirming/denying one hypothesis.

**Query — surface anomalies worth a second look.**
```spl
index=* sourcetype=*sysmon* EventCode=1
earliest=-2d@d
| eval unsigned=if(match(Company,"^$"), "unsigned", "signed")
| stats count by dest, Image, ParentImage, unsigned
| where unsigned="unsigned" OR NOT like(ParentImage, "%Windows%")
| sort - count
```
*Benign signal:* processes are signed, standard parent/child relationships (explorer.exe →
known app, services.exe → known service).
*Malicious signal:* unsigned binaries, unusual parent/child chains (e.g., `winword.exe` spawning
`powershell.exe`), execution from temp/user-writable directories.

**Decision:** benign if nothing in the anomaly filter above returns, or what returns is
explainable (known internal tooling). Escalate anything unsigned + unusual parentage +
non-standard path together.

**Generic close statement:**
> Benign Positive — Reviewed underlying process telemetry; no unsigned binaries or anomalous
> parent/child process relationships identified. Activity consistent with [known application/
> baseline behavior]. Recommend tuning [correlation search name] threshold if this recurs
> frequently with no findings, to reduce queue noise. Closed by [analyst], [date].

---

## Confirmation request template (handoff to another team)

Several sections above require a "confirm with [team]" step before you can close benign — use
this when a disposition depends on someone else's tooling or process (PAM, ServiceNow,
vulnerability scanning, backup admins, etc.). Keep the response on file as your evidence.

> **Subject:** Confirming source of [activity type] — investigation [ES-ID]
>
> Hi [team/name],
>
> We're triaging a security investigation ([ES-ID]) involving [brief description — e.g.,
> "repeated `${jndi}` canary strings submitted as SSH usernames across ~30 internal Linux hosts,
> sourced from a consistent set of internal IPs"]. Based on the pattern ([non-functional payload /
> consistent source / systematic sweep behavior — whichever applies]), this looks consistent with
> [authorized scan / scheduled job], but we want to confirm before closing.
>
> Could you confirm:
> 1. Does [team] run a scan/job matching this activity (tool name, schedule, source IP range)?
> 2. If yes, can we get that source range added to an allowlist/suppression for this detection?
> 3. If no, please let us know so we can escalate instead.
>
> Time window: [first seen] to [last seen]. Sample source IPs: [list]. Sample destination hosts:
> [list].
>
> Thanks,
> [analyst name]

---

## Other suggestions

**Suppress confirmed-benign recurring noise.** Once you've confirmed the PAM rotation pattern,
internal scanner, or backup job above, add the source (IP, account, or asset) to that
correlation search's suppression/allowlist. This is the single biggest lever for reducing queue
volume — several of today's 15 investigations trace back to only 3–4 root causes.

**Consolidate overlapping correlation searches.** The Windows/Windows 2 and 400-error clusters
suggest more than one search is tuned to catch the same activity. Worth an audit of correlation
search logic, not just a one-time merge.

**Document expected change windows.** A short internal reference (PAM rotation schedule, backup
job schedule, known internal scanner IPs/ARNs) that analysts can check against before running any
of the above queries would cut investigation time significantly — right now that context lived
only in your head/an assumption, not anywhere queryable.

**Track disposition evidence, not just the verdict.** For anything posted publicly (GitHub), keep
the query *and* result that justified each close — "confirmed via Query 2, source IP matched
known PAM host X" — so the reasoning is auditable later, not just the Benign/Malicious label.

**Before publishing:** strip all real hostnames, account names, IP addresses, ARNs, and index
names from this document and replace with the placeholder style already used in sections 2–7
(`<service_account>`, `<ES-00663>`, etc.). Sections 1 and 3 above still reference literal
sourcetype patterns only (no environment-specific secrets), but double-check anyway before it
goes to a public repo.
