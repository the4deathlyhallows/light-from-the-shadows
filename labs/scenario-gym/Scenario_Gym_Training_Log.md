# Scenario Gym — Training & Diagnostic Log

**Owner:** Robert Clark · **Purpose:** running diagnostic record across Scenario Gym sessions.

This log is cumulative — each new session gets appended as a new dated entry below the most recent one. It records *diagnostic signal only*: what a session revealed about current strengths and gaps. It does not set or override the adaptive curriculum. The next Scenario Gym session should be chosen by whatever the broader curriculum and recent performance indicate is most useful — not by mechanically continuing the most recent scenario's topic or platform.

---

## Review Schedule (standing — applies to this log and every companion lesson going forward)

The goal is active recall over rereading, and skimming this log over rereading full lessons. Use this cadence for any Scenario Gym lesson doc, not just today's:

| When | What to do | Why |
|---|---|---|
| **Day 0 (session day)** | Read the companion lesson in full once; work the active-recall quiz interactively, one question at a time | First exposure + immediate recall attempt while the scenario is fresh |
| **Day 1–2** | Skim only the "___ should remember" lines in the lesson — no full reread | Cheap reinforcement pass; catches what didn't stick on day 0 |
| **Day 7** | Re-run that lesson's quiz cold, from memory, no notes. Reread only the specific sections you missed | Recall at the 1-week mark is the strongest predictor of long-term retention; rereading everything wastes time on what already stuck |
| **Day 30** | Re-run the quiz cold one more time. If solid, retire it from active recall — keep the doc as a reference only from here on | Confirms durable retention; stops indefinite re-study of mastered material |
| **Before any future session that looks topically related** | 2-minute skim of that lesson's Quick Reference / ATT&CK (or equivalent) section only | Refreshes cues without relearning; not a full reread |
| **Before every Scenario Gym session, regardless of topic** | Skim this log's most recent 1–2 entries only | Primes on recent trend without rereading history |
| **Monthly** | Read this entire log top to bottom | Full history is where cross-session patterns (like the one below) actually become visible — a single entry or two won't show it |

**Note:** this is a manual review rhythm. If it'd help to have actual reminders fire on this schedule (e.g., a day-7 and day-30 nudge per lesson), that can be set up as scheduled tasks — just say the word and which lessons to track.

---

## Entry 1 — 2026-08-15 — AWS IAM / CloudTrail Identity Compromise

**Scenario:** CloudTrail alert on `CreateAccessKey` against IAM user `svc-prod-backup`, created through an assumed-role session (`admin-operations`) the legitimate administrator denied initiating. Exercise covered identity-chain tracing, effective-permission reasoning, attacker-activity scoping, persistence identification, and full attack-path containment.

**Strengths observed:**
Strong detection instincts; natural pivots on suspicious IP/credential usage; increasingly concrete CloudTrail hunting; correctly recognized S3 enumeration/object access, account/key creation, log tampering, and attacker sequencing as a connected kill chain rather than isolated events.

**Primary growth area identified:** AWS identity architecture and authorization depth — IAM user vs. group vs. role, STS/temporary sessions, policy types (identity-based, resource-based, boundary, SCP), trust relationships, and how "effective permissions" is a computed intersection rather than a single document's face value. Core misconception corrected: *an access key is a credential, not a permission set* — the principal's effective authorization determines what it can do.

**Companion materials produced:** `aws_iam_incident_response_lesson.md/pdf` (deep-dive lesson), `section12_test_scenario.pdf` (independent practical follow-up).

---

## Entry 2 — 2026-08-19 — Windows Execution Chain / LOLBin Abuse / Registry Persistence

**Scenario:** Suspicious Windows execution chain —

```
WINWORD.EXE
    → powershell.exe -NoP -W Hidden -enc <base64>
    → PowerShell downloads update.dll to %TEMP%
    → rundll32.exe update.dll,Start
    → rundll32 makes an outbound network connection
```

Investigated using MDE, Sysmon, Windows Security telemetry, process relationships, network activity, DLL loading, and registry persistence.

**Strengths observed:**
Investigation instincts were strong and largely self-directed. Robert independently reconstructed the process tree; asked what caused WINWORD to launch PowerShell; investigated document provenance (email/download/phishing); decoded the base64 PowerShell; determined what the PowerShell payload actually did; investigated outbound network activity; pulled the downloaded file's hash; hunted that hash/domain across other endpoints; checked whether other machines contacted the same infrastructure; looked for follow-on activity; used MDE Advanced Hunting to pivot parent↔child processes; and checked for persistence and defense evasion.

Two detection-engineering wins stood out: (1) when asked to design a detection, Robert moved past "alert on every `CurrentVersion\Run` write" and combined the registry modification with suspicious execution context, user-writable paths, PowerShell involvement, file creation/downloads, rundll32, and network activity; (2) when challenged with "what if the attacker swaps the DLL for a PowerShell script," Robert correctly generalized the detection from a specific `.dll` match toward the underlying behavioral pattern (persistence + user-writable path + suspicious execution context) rather than patching the original rule with a second exact match.

**Gaps / corrections from today** (full treatment in the companion lesson, `windows_lolbin_rundll32_persistence_lesson.md/pdf`):

1. **Legitimate binary vs. legitimate behavior.** Initially called PowerShell "probably legitimate." Correction: `powershell.exe`/`rundll32.exe` can be the genuine Microsoft binary while the *behavior* is still malicious — legitimacy of the binary, execution context, and behavior are three separate questions (the LOLBin abuse model).
2. **Sysmon vs. Windows Security event IDs.** Mixed the two numbering spaces (correctly recalled 4688 = process creation, but folded it into Sysmon's numbering). Needs the underlying model — *what happened on the system → what telemetry represents it* — rather than ID memorization.
3. **`rundll32.exe update.dll,Start` mechanics.** Biggest systems-level gap of the session. Initially pictured the DLL modifying/replacing rundll32. Corrected via a Python `import update; update.Start()` analogy: rundll32 loads and hosts the DLL's exported function inside its own process; rundll32.exe itself is never rewritten.
4. **File on disk vs. execution in memory.** Initially suggested the DLL might never have touched disk — incorrect here, since PowerShell explicitly wrote it to `%TEMP%\update.dll`. Needs a clearer working distinction between file creation, process creation, image/module loading, and true fileless/in-memory technique.
5. **Absence of telemetry ≠ absence of activity.** A missing Sysmon Event ID 7 (image load) alongside a present Event ID 1 (process creation naming the DLL) does not prove the DLL never loaded — it may reflect a collection/config/filtering gap. Needs sharper separation of evidence, inference, confidence, and telemetry visibility.
6. **PID vs. ProcessGuid.** Understood PID-matching as a correlation method but not its weakness — Windows reuses PIDs after process exit. Sysmon `ProcessGuid` (and `ParentProcessGuid`) is the durable per-instance identifier for correlating process-creation and network events to the *same* process instance.
7. **Why attackers favor `%TEMP%` and other user-writable paths.** Correctly suspected permissions were the driver; needs the fuller comparison across `%TEMP%`, AppData, Downloads, ProgramData, and System32 from both an attacker and defender lens.
8. **Evidence vs. inference in incident narratives.** Correctly reconstructed the full chain, but needs more disciplined language — e.g., a network connection to `185.x.x.x:443` shows a connection consistent with C2 staging, it does not by itself prove C2, and port 443 alone doesn't prove the traffic was actually TLS/HTTPS.
9. **Registry Run-key persistence architecture.** Correctly identified `HKCU\...\CurrentVersion\Run` as persistence and correctly reasoned it runs at the current user's logon without requiring admin rights (HKCU scope) — this one landed well and mainly needs reinforcement, not correction.
10. **Detection engineering: avoiding overfitting.** Core lesson of the day. Moved from single-IOC matching (`rundll32 loads update.dll → malicious`) toward layered behavioral logic (persistence mechanism + user-writable path reference + suspicious execution vector + supporting context), and toward explicitly separating *core malicious behavior* from *supporting signals that raise confidence* — the design principle that keeps a detection from requiring the exact attack chain or flooding the SOC.

**Diagnostic read on today's session:** the gaps cluster around Windows *systems*-level mechanics (process/module/registry internals and the telemetry that represents them) and analytical *discipline* (evidence-language precision, ID-model-over-memorization, PID-vs-instance-identity rigor) — not investigative instinct, which is consistently a strength. Detection-engineering reasoning (layered behavioral logic over brittle IOC matching) is trending well and generalized correctly under a challenge scenario today.

**Cross-session pattern (Entry 1 → Entry 2):** both sessions show the same shape — strong, largely self-directed investigative reflexes paired with a gap in the underlying platform mental model beneath those reflexes (AWS identity/authorization architecture on 8/15; Windows process/module/telemetry architecture on 8/19). Worth watching whether this pattern — "the hunting instinct outruns the systems model" — continues to show up as new domains are introduced (e.g., Linux/container internals, network protocol telemetry), since if it does, that's a curriculum-level signal worth acting on generally, independent of any single platform.

**Companion materials produced:** `windows_lolbin_rundll32_persistence_lesson.md/pdf` (deep-dive lesson with active-recall quiz).

---

## Entry 3 — 2026-08-19 — Windows Lateral Movement Mechanics + Threat-Intel Pipeline System Design

**Modality note:** this session ran via ChatGPT rather than Claude — logged here anyway because Scenario Gym is a training program, not a tool-specific log, and diagnostic signal should accumulate in one place regardless of which model ran the session.

**Scenario, part 1 (Windows):** a Windows authentication/lateral-movement investigation built around Security Event 4624 (Logon Type 3, network logon) followed by Event 4672 (special privileges assigned), then extended into the systems mechanics underneath NTLM authentication, Pass-the-Hash, SMB/`ADMIN$`, PsExec, and the Service Control Manager — i.e., not just "what event fired" but "what actually happens inside Windows, in order, to make PsExec-style remote execution possible."

**Scenario, part 2 (pipeline/systems design):** a revisited Palantir interview question — ingest a third-party threat-intel API into a SIEM/pipeline under a 50,000-calls/day limit — which expanded into decoupled ingestion architecture, checkpointing and failure recovery, retry/backoff, idempotency and deduplication, local-state diffing when a feed has no `updated_since`, overlapping lookback windows, and API quota headroom/capacity planning.

**Strengths observed:**
Good investigative intuition and correct instinct to treat 4624/4672/lateral-movement signals as a connected story rather than isolated facts; recognized NTLM as protocol-relevant and Pass-the-Hash as conceptually related before being asked; correctly identified PsExec's category (remote execution tool); on the pipeline side, correctly reached for routing/reuse/dashboards concepts, independently proposed local caching and diffing before being taught the term, independently proposed a heartbeat/gap-detection mechanism for interrupted ingestion before being taught "checkpointing," and independently reasoned that a quota limit shouldn't be fully consumed — arriving at the shape of "quota headroom" unprompted. Across both halves of the session: strong ability to reason toward a structurally correct answer even where the precise vocabulary was missing.

**Gaps / corrections from today** (full treatment in the two companion lessons):

1. **4672 ≠ privilege escalation.** Initial reading treated "special privileges assigned" as itself evidence of an escalation event. Correction: 4672 fires whenever a logon session is granted admin-equivalent rights — including a legitimate admin account logging on normally. It's a *privilege observation*, not a *privilege change* — the escalation question has to be answered separately, by comparing the account's baseline behavior against this specific logon.
2. **Correlation by time proximity instead of by durable identifier.** Initial instinct was to link 4624 and 4672 (and other nearby events) because they occurred close together in time. Correction: use **Logon ID**, the unique identifier Windows assigns per logon session, to correlate every event genuinely produced by *that* session — the same structural fix as Entry 2's PID-vs-ProcessGuid correction, now in the authentication domain instead of the process domain (see Cross-session pattern below — this is now a confirmed recurring gap shape, not a one-off).
3. **NTLM vs. Pass-the-Hash conflation.** Pass-the-Hash was already known conceptually (a strength), but the credential material was misidentified — described as "the hash of the login session" rather than the account's actual NTLM password hash. Correction: PtH abuses the fact that NTLM's challenge-response protocol never requires the plaintext password, only a value derived from the hash — so possessing the hash *is* sufficient to authenticate, no cracking required. A 4624 Type 3 logon using NTLM only proves NTLM was the protocol; it does not by itself prove the hash (rather than a password) was what authenticated.
4. **PsExec understood by function, not by mechanism.** Prior model was "PsExec lets you execute commands remotely" — true but shallow. Missing: the actual chain (SMB session → `ADMIN$` file transfer of the service binary → Service Control Manager RPC call → service creation → `services.exe` spawns `PSEXESVC.exe` → command execution as a child of that service process → named-pipe I/O redirection back to the operator). This is the session's single biggest systems-depth gap, and it directly parallels Entry 2's `rundll32` gap: knowing a tool's *category* without knowing what Windows subsystem actually does the work.
5. **`ADMIN$`/SMB activity treated as sufficient evidence of PsExec.** Needed the correction that admin-share access is necessary-but-not-sufficient — plenty of legitimate remote administration (and several other lateral-movement techniques) also touches `ADMIN$`. The distinguishing evidence is the service-creation step (Event 7045) and the `services.exe → PSEXESVC.exe` parent/child pairing, not the share access alone.
6. **Interview instinct: solution-first instead of requirements-first.** Given the 50,000-calls/day constraint, the immediate reflex was destination architecture (Cribl, routing, S3, dashboards) before establishing basic characteristics of the *source* — pagination, records-per-call, bulk/incremental retrieval support, feed update frequency, whether the quota is hard/sliding/per-key, and what happens on overage. Core correction: **a stated constraint is not automatically the target to design around** — 50,000 calls/day against a feed producing 200,000 new indicators/day at 1,000 records/call is a ~200-call/day problem, not a 50,000-call/day problem, and you can't know that without asking first.
7. **Checkpointing and health monitoring merged into one mechanism.** The initial answer (detect that ingestion traffic stopped, then resume) was directionally right but fused two separate concerns: checkpointing answers *where did processing durably reach*, health monitoring answers *is the pipeline currently working*. Needed the sharper sequencing rule — fetch → validate → normalize → deduplicate → write downstream successfully → **only then** advance the checkpoint — and the reasoning for why advancing early (e.g., right after a successful fetch, before a confirmed downstream write) risks silently dropping data on the next failure.
8. **Idempotency, retry/backoff, deduplication, overlapping lookback, and quota headroom were mostly new formal territory.** The instincts underneath several of these were already present (see Strengths) but the vocabulary, the precise failure-mode reasoning, and the implementation patterns were not yet in place. This is genuinely new-skill acquisition rather than a misconception to correct, so it's tracked as a curriculum priority rather than a "gap" per se.

**Diagnostic read on today's session:** two things stand out beyond the individual corrections. First, the "hunting instinct outruns the systems model" pattern flagged after Entries 1–2 has now shown up a third time, and specifically the *same sub-pattern* recurred exactly: correlating by a proxy signal (time proximity here, PID in Entry 2) instead of a durable per-instance identifier (Logon ID here, ProcessGuid in Entry 2). This is no longer three coincidentally-similar gaps — it's one generalizable skill ("always ask: what's the durable unique identifier for this entity, not the nearby-in-time or reused-value proxy?") that should be drilled explicitly and named as such the next time it shows up in a new domain, rather than re-taught from scratch. Second, a new pattern appeared today that hadn't been visible in the AWS/Windows-process sessions: **solution-first instinct under system-design framing** — reaching for destination architecture before source-side requirements. This is distinct from the systems-model gap; it's a sequencing/discipline gap in how an otherwise-correct set of ideas gets organized and presented, and it is exactly what the interview-practice framework in the curriculum update is built to address (see companion curriculum doc). Both patterns point at the same underlying opportunity: Robert's raw problem-solving is consistently ahead of his formal frameworks, in three different domains now (AWS identity, Windows process internals, and today both Windows auth and pipeline design) — the fix in every case has been "give the existing instinct a name, a structure, and a precise vocabulary," not "build the instinct from scratch."

**Companion materials produced:** `windows_lateral_movement_ntlm_pth_psexec_lesson.md/pdf` (deep-dive lesson on Windows authentication mechanics and lateral-movement telemetry), `threat_intel_pipeline_engineering_lesson.md/pdf` (deep-dive lesson on ingestion pipeline design, checkpointing, idempotency, and quota engineering), `Scenario_Gym_Curriculum.md/pdf` (new — the first standalone adaptive curriculum document; see that file for how today's signals were incorporated).

---

**Reminder:** entries above are diagnostic inputs to the adaptive curriculum, not a directive. The next Scenario Gym session should go wherever current performance and the broader curriculum indicate is most useful — it is not required to continue AWS IAM, Windows process execution, Windows authentication, pipeline design, or any other single thread from this log.
