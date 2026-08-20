# Scenario Gym — Adaptive Curriculum
**Owner:** Robert Clark · **Purpose:** the standing, cumulative curriculum document for Scenario Gym / Technical Gym. Unlike the training log (diagnostic history — what happened and what it revealed), this document is the *plan* — where things stand, what's next, and why. Update it after any session that changes the picture; don't recreate it from scratch.

**First version note:** this is the first standalone curriculum document — prior sessions (Entries 1–2) had diagnostic signal captured in the training log, but no separate plan document existed yet. This file was built by reading the full training log and both companion lessons, so nothing from before today is lost; it's organized going forward.

**Governing philosophy (carried forward from every prior session, restated here so it travels with the curriculum, not just the log):**

- Short, adaptive reps — not long scripted courses.
- Every answer gets pushed one layer deeper than the first response, toward mechanism, not vocabulary.
- Demand specific telemetry/mechanisms; "I'd check the logs" is never a complete answer.
- Distinguish tools from the underlying systems they sit on top of.
- Hints reduce gradually as competence in a domain grows — don't keep hand-holding on something that's already landed.
- Revisit weaknesses later, in a *different* scenario/context than where they first appeared — never the same scenario twice.
- Don't mechanically continue yesterday's topic or platform; let performance signal what's next.
- The target outcome is a strong security/detection/automation engineer over the next year — not an interview-question rehearsal machine. Interview-style questions are diagnostic tools, used when they expose a real gap, never the organizing principle of the whole program.

---

## 1. Domain Map

Four working domains, as of today. The first three are where investigative/technical depth is built; the fourth is a cross-cutting skill exercised *through* the other three, not a separate track.

1. **Windows / endpoint detection engineering** — process, module, registry, and authentication internals; the telemetry that represents each; detection design that survives variation instead of matching one artifact.
2. **Cloud identity & AWS security** — IAM/STS/policy architecture, identity-chain tracing, effective-permission reasoning, attack-path containment.
3. **Threat-intel & security data pipeline engineering** — ingestion architecture, checkpointing/recovery, idempotency, retry/backoff, capacity/quota engineering. **New as of today** — elevated from "a Palantir interview topic" to a first-class domain, because the underlying skills (stateful, fault-tolerant, decoupled data systems) are exactly what "security engineering + detection engineering + systems reasoning + automation + data pipelines" requires, and they generalize far beyond any one interview question.
4. **Systems-design & engineering communication** (cross-cutting) — structuring an answer (requirements → constraints → scale → architecture → data flow → failure modes → state/recovery → security → observability → tradeoffs), organizing correct instincts into precise language, requirements-first reasoning before solution-first reasoning. Practiced *within* domains 1–3, occasionally via an explicit interview-style framing (Section 4) — never its own multi-week track.

---

## 2. Skill Matrix

A living table — update the "Current read" column after sessions that touch a domain; don't rewrite history, add to it.

| Domain | Current read (as of 2026-08-19) | Primary gap right now | Last touched |
|---|---|---|---|
| Windows process/module internals | Strong. LOLBin mental model, telemetry-category-first thinking, ProcessGuid-vs-PID correlation, and behavioral-over-brittle detection design all landed well in Entry 2. Mainly needs periodic reinforcement (Day 7/30 recall), not new correction. | Minor: keep the "evidence vs. inference" language discipline sharp under new scenarios. | Entry 2 (2026-08-19) |
| Windows authentication / lateral movement | New ground, first pass done today. Correlation-by-durable-identifier transferred cleanly from the process domain to the auth domain once named; NTLM vs. Pass-the-Hash distinction corrected; PsExec mechanism gap was the session's biggest single fix. | PsExec/SCM chain and WinRM's alternate signature need a Day-7 cold recall; a *different* lateral-movement mechanism (WMI or scheduled task) hasn't been tested at all yet. | Entry 3 (2026-08-19) |
| AWS IAM / cloud identity | Solid foundation from Entry 1 — access-key-vs-permissions and upstream/downstream investigation are landing. Hasn't been revisited since 8/15; due for a Day-30-style cold check, ideally in a *different* AWS scenario shape than `svc-prod-backup`. | Trust-policy/permission-boundary/SCP interaction depth wasn't tested this deeply yet — Section 12 test scenario is unresolved and still available. | Entry 1 (2026-08-15) |
| Threat-intel / pipeline engineering | New domain as of today. Strong raw instincts (caching/diffing, gap-detection, quota reservation) arrived before the formal vocabulary did — same shape as the other domains' early sessions. Requirements-first vs. solution-first is the one genuinely new *discipline* gap (not a knowledge gap) surfaced today. | Everything in the companion lesson is first-pass knowledge: checkpointing, idempotency, retry/backoff, overlapping lookback, and quota headroom all need a Day-7 cold recall before anything else is layered on. | Entry 3 (2026-08-19) |
| Systems-design communication | First clear data point today (the Palantir question). Correct content, wrong ordering — reached for architecture before requirements. | Needs repeated *light-touch* practice (Section 4) across multiple domains before judging whether this is fixed or still a pattern. | Entry 3 (2026-08-19) |

**Recurring cross-domain pattern to track explicitly (not tied to one domain):** correlate by durable identifier, not by a proxy signal (time proximity, a reusable/reassignable value). This has now shown up as ProcessGuid-vs-PID (Entry 2) and Logon-ID-vs-timing (Entry 3). Next time a new domain is introduced, watch whether this shows up a fourth time in a new shape (e.g., a request ID vs. a timestamp in the pipeline domain, a session token vs. an IP address in a web-auth domain) — if it does, it's confirmed as a standing personal blind spot worth naming directly rather than re-deriving each time.

---

## 3. Adaptive Priority Queue

Not a rigid order — a ranked read on where the next session or two would do the most good, to be overridden freely by whatever actually comes up. Re-rank after every session.

1. **Day-7 cold recall: Windows lateral movement (Entry 3 lesson).** Highest-value near-term rep — the material is freshest and the biggest gap (PsExec/SCM mechanics) needs to actually stick, not just have been explained once.
2. **A lateral-movement scenario using a *different* mechanism than PsExec** (WMI or WinRM) — tests whether the mechanism-first mental model transfers to a new technique, or whether today's learning was PsExec-specific memorization wearing a systems-model costume.
3. **Day-7 cold recall: threat-intel pipeline lesson**, ideally via a *new* failure-mode scenario (not the same Palantir question) — e.g., the collector-crash-mid-ingestion or duplicate-delivery scenarios from the bank below.
4. **AWS revisit, different scenario shape** — the Section 12 test scenario is already sitting there, unresolved, from Entry 1's follow-up. Good candidate whenever cloud identity is due for a spaced-repetition check.
5. **Kerberos-vs-NTLM scenario** — flagged as adjacent-but-not-deep-dived in today's lesson; a full scenario (not just the comparison table) would establish whether this needs its own gap-closing lesson or was sufficiently covered by the NTLM depth already built today.
6. **A light system-design practice rep in a non-pipeline domain** — e.g., "design a detection-rule deployment/versioning system," to test whether the requirements-first discipline generalizes beyond ingestion pipelines specifically, per the Important Coaching Instruction: interview-shaped practice stays occasional and in service of the broader goal, not a track of its own.

---

## 4. Interview / System-Design Practice Framework

**Purpose, stated plainly so it doesn't drift into interview-prep-as-its-own-track:** today's Palantir question showed real signal — good instincts, weak organizing structure. This framework exists to fix *that specific gap* (structuring an answer, requirements before architecture) using system-design-style questions as the exercise format, occasionally, across whichever domain is relevant at the time. It is not a parallel curriculum, and it should not become the majority of any given session.

**The order to answer in — teach this as a habit, not a checklist to recite out loud:**

1. Clarify requirements.
2. Identify constraints.
3. Estimate scale.
4. Design high-level architecture.
5. Explain data flow.
6. Identify failure modes.
7. Explain state/recovery.
8. Discuss security.
9. Discuss observability.
10. Explain tradeoffs.

The threat-intel pipeline lesson's Section 9 ("Applying it end to end") is the first fully worked example of this structure, built from today's actual Palantir question — use it as the reference shape, not a script to memorize word-for-word.

**How to use this going forward:**

- Deploy an interview-style question occasionally (roughly one rep every few sessions, not every session), and only when it's a good fit for reinforcing a domain already in play — e.g., "design an alerting/paging system for detection rule failures" fits naturally after a detection-engineering scenario; forcing an unrelated system-design question in just to practice the format defeats the purpose.
- The goal each time is the same: notice whether requirements/constraints get established *before* architecture gets proposed, without being told to do so. The first few reps may need an explicit nudge ("what would you want to know before designing this?"); later reps should show the habit firing unprompted — that's the actual mastery signal, more than any single correct answer.
- Never let a session's *entire* time budget go to this. It's a five-to-ten-minute structured exercise bolted onto real technical-depth work, not a replacement for it.

---

## 5. Scenario Bank

Future Scenario Gym material. **Order is not fixed** — pull from here based on the priority queue (Section 3) and whatever the most recent session actually revealed; skip around freely. Each entry states what it's built to test, not a script to follow rigidly.

1. **Windows lateral movement via WMI or a scheduled task, not PsExec.** Tests whether "authentication → protocol → network access → execution mechanism → subsystem → telemetry" transfers to an unfamiliar mechanism, or whether today's gains were PsExec-specific. Expect to reach for `WmiPrvSE.exe` / `Win32_Process.Create` or remote `schtasks`/Task Scheduler API and Event 4698 — but the value is in reasoning to it, not in being told the answer.
2. **Kerberos vs. NTLM reasoning.** A scenario where the interesting fact is an *unexpected* NTLM authentication in an environment that should be using Kerberos — tests whether "protocol choice can itself be a signal" lands, and whether Pass-the-Ticket gets connected to Pass-the-Hash as the parallel technique without prompting.
3. **Authentication/session correlation under a harder setup than today's** — e.g., multiple overlapping logon sessions for the same account across several hosts, requiring Logon ID discipline under actual ambiguity rather than a clean two-event example.
4. **API quota exhaustion mid-day.** The pipeline is running normally, then a feed spike or a mistaken retry storm burns through the daily budget by early afternoon. Tests the quota-headroom/graceful-degradation ladder from the pipeline lesson under pressure, not just as a design-time budget.
5. **Collector failure halfway through ingestion.** A crash (not a clean shutdown) partway through a paginated pull. Tests checkpoint correctness and idempotent recovery together — does resuming from the last checkpoint correctly avoid both data loss *and* duplicate downstream writes.
6. **Duplicate delivery.** The exact page-72-replayed scenario, but from the *downstream* system's point of view — given a stream that might contain duplicates, design (or critique) the idempotent write logic that makes it safe, without seeing the upstream collector's code.
7. **Vendor API returning sustained 429s.** Not a single rate-limit blip — a sustained period where the vendor is throttling hard. Tests retry/backoff *policy* under sustained pressure (when does backing off further stop being enough, and does a circuit-breaker-shaped response get proposed) rather than a single retry.
8. **Schema changes breaking ingestion.** The vendor silently changes a field name or type. Tests whether validation is per-record (so this fails loudly and specifically on new/changed records) rather than per-batch (failing the whole pipeline or, worse, silently accepting malformed data) — direct callback to the pipeline lesson's dead-letter and validation discipline.
9. **SIEM unavailable while upstream collection continues.** Tests the buffering/replay properties of the decoupled architecture from the pipeline lesson — does collection keep running and buffering, or does it (incorrectly) treat a downstream outage as a reason to stop pulling from the vendor at all.
10. **Threat-intel IOC enrichment at scale.** A different shape of pipeline question — not "ingest the feed" but "given millions of stored indicators, efficiently enrich new detections against them." Tests whether local-state/caching thinking (Section 7 of the pipeline lesson) extends naturally to a lookup-heavy workload, not just an ingestion-heavy one.

**Note on scope discipline:** this bank will keep growing as new sessions surface new gaps — resist letting it become a fixed syllabus. A scenario earns its place here because a real session exposed the need for it, not because it rounds out a topic list.

---

## 6. Sentinel-Pipeline: Staged Progression

**The goal stated plainly:** Sentinel-Pipeline should gradually stop being "a script that loops through JSON events" and become a small, real instantiation of the concepts in the pipeline lesson — but staged, so each addition forces genuine understanding of one concept at a time rather than being handed a finished, feature-complete pipeline to reverse-engineer.

**Sequencing principle:** each stage below should only start once the *previous* stage's concept has actually been exercised in a Scenario Gym session or independently explained back correctly — not simply because it's next on a list. If a stage's underlying concept hasn't landed yet (per the skill matrix), pause the project progression and revisit the concept in Scenario Gym first.

| Stage | Adds | Forces understanding of | Prerequisite concept |
|---|---|---|---|
| **0 (current baseline)** | Loops through a static JSON event set | — | — |
| **1** | Swap the static file for a simulated REST API (even a tiny local Flask/FastAPI stub is enough) that supports pagination | Pagination mechanics, and that "the data source" is a real interface with its own shape, not just a file to iterate | Section 1 of the pipeline lesson |
| **2** | A checkpoint file recording last-successful-page/cursor, read on startup | Why a checkpoint exists, and the fetch→...→checkpoint sequencing rule | Section 4 of the pipeline lesson |
| **3** | Deliberately inject a mid-run failure (kill the process, or simulate a downstream write failure) and verify the checkpoint behaves correctly on restart | The difference between "no data loss" and "no duplicate data" as two separate properties to test for, not one | Stage 2 landed, plus Section 4's failure-mode table |
| **4** | Idempotent writes keyed on a stable identifier + content hash | The identity-key-vs-change-hash distinction from the pipeline lesson's Python example — implemented, not just explained | Section 5 of the pipeline lesson |
| **5** | Retries with exponential backoff + jitter around the simulated API calls, with injected transient failures (simulate 429/500 responses from the stub API) | Retryable vs. non-retryable failure classification, and why jitter matters — implemented against real (simulated) failure injection, not just described | Section 6 of the pipeline lesson |
| **6** | Malformed-event handling: inject occasional bad records into the simulated feed, route them to a dead-letter file/log instead of crashing the run | Per-record validation vs. per-batch validation, and why silently dropping security data is its own risk | Section 6 of the pipeline lesson |
| **7** | Structured logging + basic metrics (records processed, dead-lettered, retry counts, checkpoint age) | Observability as a first-class concern, not an afterthought — and what's actually worth measuring in an ingestion pipeline | Section 9 of the pipeline lesson (observability) |
| **8** | Configuration externalized (a config file/env vars for API endpoint, batch size, retry limits) instead of hardcoded values | Why configuration separation matters once a pipeline has real failure-handling logic worth tuning without a code change | Stages 1–7 in place |
| **9** | A second downstream destination (e.g., write to both a local file "SIEM" stub and a separate "dashboard" stub) | Fan-out from a single collector — the core payoff of the decoupled-architecture section, made concrete | Section 2 of the pipeline lesson |
| **10** | A simple local cache/state store keyed by indicator ID, with a diff check against incoming records (`old_hash != new_hash`) | Local-state diffing for feeds without `updated_since` — direct implementation of Section 7 | Section 7 of the pipeline lesson |
| **11** | An overlapping lookback re-poll against the simulated feed, tuned against a deliberately-simulated "late edit" in the stub data | Sizing a lookback window against actual (simulated) edit-latency behavior, not guesswork | Stage 10 landed, plus Section 7's sizing reasoning |
| **12** | A minimal queue/buffer between collection and the fan-out destinations (even an in-process queue to start) | Buffering and backpressure as concepts, and when a real queue/stream (Kafka/Kinesis/SQS) would actually be justified vs. overkill | Stages 5–9 in place |
| **13** | Basic unit tests for the checkpoint logic, idempotency logic, and retry classification | Testing failure-handling logic deliberately, not just happy-path logic | Stages 2–6 in place |
| **14** | A simple "quota" simulation — a hard cap on simulated API calls per run, with the pipeline needing to throttle/prioritize when approaching it | Quota headroom and graceful degradation, implemented rather than just discussed | Section 8 of the pipeline lesson |
| **15+** | Candidates once the above lands: real IOC enrichment against the stored local state (ties to scenario-bank item 10), a genuinely swappable destination architecture (real Cribl/queue integration if useful at that point), a basic circuit-breaker around the simulated API | — | Stages 0–14 solid |

**Explicit non-goal:** do not implement stages 5+ before stages 1–4 are solid, and do not treat this table as something to build end-to-end in one sitting. The point of Sentinel-Pipeline, per the project's role in this curriculum, is that *each* stage is a small, understood step — a pipeline that jumps straight to "full production architecture" defeats the purpose of using it as a teaching vehicle.

---

## 7. Review Cadence

The day-0/1-2/7/30/monthly cadence defined in `Scenario_Gym_Training_Log.md` applies to every lesson document in this folder, including the two produced today — see that file for the full schedule. This curriculum document itself is a good candidate for the "monthly, read top to bottom" pass, since that's when cross-session patterns (like the durable-identifier-correlation pattern tracked in Section 2) actually become visible.

---

**Reminder:** this curriculum is a plan, not a script. The next Scenario Gym session should be chosen by whatever current performance and this document's priority queue indicate is most useful — any section here can be reordered or overridden by what an actual session reveals.
