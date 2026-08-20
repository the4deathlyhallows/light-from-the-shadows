# Windows Lateral Movement Deep Dive: Authentication, NTLM, Pass-the-Hash, PsExec & the SCM
### A gap-closing lesson built from your Windows authentication / lateral-movement scenario (August 19, 2026)

You already treat 4624/4672 as a connected story instead of isolated facts, and you already know NTLM and Pass-the-Hash matter here — that's real investigative instinct. What was missing today was the layer underneath: what NTLM authentication actually is mechanically, what Pass-the-Hash actually steals, and — the biggest gap — what Windows subsystems PsExec touches, in order, to turn "I have credentials" into "code is running on a remote machine." This lesson builds that chain the same way the rundll32 lesson built the LOLBin chain: one mechanical layer at a time, tied to the exact telemetry each layer produces.

**The conceptual chain this lesson builds toward:**

```
credential/authentication
    → protocol (NTLM or Kerberos)
    → network access mechanism (SMB / ADMIN$)
    → remote execution mechanism (PsExec, or an alternative)
    → Windows subsystem that does the work (Service Control Manager, or WinRM)
    → resulting processes (services.exe → PSEXESVC.exe, or svchost.exe → wsmprovhost.exe)
    → telemetry / detection
```

Every section below fills in one link of that chain.

---

## 1. Event 4624 and 4672: what they actually assert, and what they don't

**4624 — An account was successfully logged on.** This fires every time a logon session is created, successful. It is not inherently suspicious — most 4624s on any given day are completely ordinary. What makes one worth attention is its **fields**, not its existence:

- **Logon Type** — *how* the logon happened. Type 3 is a **network logon**: no interactive session, no console, typically produced by things like SMB/file-share access, PsExec, and other remote-admin tooling. (Type 2 is interactive/console, Type 10 is RDP, Type 5 is a service starting — knowing the type tells you the *shape* of the access before you know anything else.)
- **Authentication Package** — NTLM or Kerberos. This tells you the *protocol*, which is a separate question from *what technique* is being used (Section 3).
- **Account Name / Domain**, **Source Network Address**, **Logon ID** — who, from where, and — critically — a unique handle for *this specific logon session* (Section 2).

**4672 — Special privileges assigned to new logon.** This fires when a logon session is granted one or more administrator-equivalent privileges (e.g., `SeDebugPrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege`). This is where today's core correction lives:

> **4672 tells you a privileged logon happened. It does not tell you a privilege escalation happened.**

An account that is *already* a domain admin generates a 4672 every single time it logs on anywhere — that's just what a privileged account's normal logon looks like. Windows isn't asserting "something changed just now"; it's asserting "this session holds elevated rights." Treating 4672 as inherently an escalation event will bury you in false positives on every admin's ordinary Tuesday.

**What actually answers the escalation question** is context 4672 doesn't carry by itself:

- Is this the account's **normal** behavior — does this admin account typically log on to this particular host?
- Is the **source** typical — same subnet, same jump host, same hours, as usual?
- Did this 4672 follow a **credential-theft-shaped** sequence (e.g., an NTLM-authenticated network logon from an unusual source, shortly after suspicious process activity on the source machine) rather than an ordinary interactive admin session?
- Is there a **first-seen** relationship anywhere in the chain — first time this account touched this destination, first time this source touched this account, first time this account was seen from this network segment?

**Robert should remember:** 4672 is an *observation about privilege level*, not an *event about privilege change*. The question "did privilege escalation occur?" is answered by comparing this logon against the account's baseline — never by the presence of 4672 alone.

---

## 2. Correlation discipline: Logon ID, not time proximity

**The trap today's scenario was built to expose:** two events happen close together in time — a 4624 and a 4672, or a 4624 and some suspicious follow-on activity — and it's tempting to treat "close in time" as "part of the same story." That's an assumption, not evidence.

**The actual mechanism:** every logon session Windows creates gets a **Logon ID** — a locally-unique hexadecimal identifier (e.g., `0x3E7` for the SYSTEM logon, or something like `0x1A2B3C4D` for a typical interactive/network session) minted at logon time and stamped onto *every subsequent security event produced by that session* — the 4672 that grants it privileges, the 4634 that eventually logs it off, any 5140/5145 share-access events performed under that session, any 4688 process-creation events for processes launched within it, and so on.

```
4624  LogonType: 3   LogonId: 0x9F2A31   AuthenticationPackage: NTLM   AccountName: svc-backup   SourceIP: 10.20.4.17
4672  LogonId: 0x9F2A31   PrivilegeList: SeDebugPrivilege, SeBackupPrivilege, ...
5145  LogonId: 0x9F2A31   ShareName: \\HOST\ADMIN$   RelativeTargetName: PSEXESVC.exe
4688  LogonId: 0x9F2A31   NewProcessName: C:\Windows\PSEXESVC.exe   ParentProcessName: services.exe
```

Every line above is *provably* the same logon session, because they share `LogonId` — not because they happened within some number of seconds of each other. This is precisely the same structural fix as **ProcessGuid over PID** from the last Scenario Gym session: PID gets reused after a process exits, so "same PID nearby in time" is a weak claim; Logon ID is minted once and never reused for a different session, so "same Logon ID" is a strong claim regardless of the time window.

**Python analogy:** this is the difference between joining two log tables on `WHERE timestamp1 - timestamp2 < 5 seconds` versus joining on a shared primary key. The first is a heuristic that can produce false matches under load or coincidence; the second is a guarantee.

```python
# Fragile: proximity-based correlation
def maybe_related(event_a, event_b, window_seconds=5):
    return abs(event_a.time - event_b.time) < window_seconds  # correlation by coincidence

# Correct: identity-based correlation
def same_session(event_a, event_b):
    return event_a.logon_id == event_b.logon_id  # correlation by shared, durable key
```

**Robert should remember:** whenever you're tempted to link two Windows security events because they're close in time, stop and ask "do they share a Logon ID (or ProcessGuid, or another durable identifier)?" instead. Time proximity is a reason to *look*, not a reason to *conclude*.

---

## 3. NTLM: what the protocol actually does

**Simply:** NTLM (NT LAN Manager) is a challenge-response authentication protocol. Its entire job is to let a client prove it knows a secret (derived from the account's password) **without ever sending that secret, or the plaintext password, across the network.**

**At the protocol level, simplified:**

1. **Negotiate** — client tells the server it wants to authenticate.
2. **Challenge** — server sends the client a random challenge value (a nonce).
3. **Response** — the client combines the challenge with a value derived from the account's **NTLM hash** (a one-way hash of the password, stored on the domain controller / local SAM) using a keyed-hash function, and sends *that* back — never the password, never the raw hash itself, over the wire.
4. **Verification** — the server (or, in a domain, the domain controller via Netlogon) independently performs the same computation using its own copy of the account's NTLM hash and checks whether the response matches.

**The critical structural fact for Section 4:** the thing that actually gets used in step 3 — the value the client needs to *compute* a valid response — is the account's **NTLM hash**, not the plaintext password. NTLM was designed so the password itself never has to leave the client, but as a side effect, **the hash is functionally as good as the password** for authentication purposes: if you have the hash, you can compute a valid response to any NTLM challenge, exactly as if you knew the password, without ever needing to reverse or crack it.

**What a 4624 Type 3 with `AuthenticationPackage: NTLM` actually proves:** a network logon occurred, authenticated via the NTLM protocol. That's all. It does **not** by itself tell you whether the client authenticated using a real, freshly-typed password or a stolen hash — both produce a structurally identical NTLM exchange, because NTLM was never designed to distinguish "the user typed this" from "this value was obtained some other way." That distinction has to come from other evidence (Section 4).

**Robert should remember:** NTLM is the *protocol*. It tells you *how* the authentication conversation happened, not *what the attacker actually possessed* to have that conversation. Don't let "NTLM was used" collapse into "Pass-the-Hash was used" — that's an inference, not a fact the protocol field gives you for free.

---

## 4. Pass-the-Hash: what's actually stolen, and why it works

**The correction from today:** Pass-the-Hash does not steal "the hash of the login session" — logon sessions don't have hashes. What gets stolen is the **account's NTLM password hash itself** — a value tied to the *account*, not to any particular logon.

**Where that hash lives, and how it gets stolen:**

- On a Windows machine, the NTLM hashes of accounts that have ever logged on locally are cached in memory inside the **LSASS** process (Local Security Authority Subsystem Service) — this is *why* LSASS memory is such a high-value target, and why credential-dumping tools (Mimikatz and similar) exist specifically to read hashes out of LSASS's memory.
- On a domain controller, NTLM hashes for domain accounts live in the **NTDS.dit** database (the AD database) and in each machine's local **SAM** (Security Account Manager) for local accounts.
- An attacker who already has administrative code execution on *some* machine can dump the hashes cached in that machine's LSASS memory — which typically includes any account that has interactively or remotely authenticated to that machine recently.

**Why possessing the hash is enough:** as established in Section 3, NTLM authentication only ever requires a value *derived from* the hash to answer a challenge — never the plaintext password. An attacker holding the hash can perform that exact same computation a legitimate client would, and produce a response the server will accept as valid. No cracking, no reversing, no plaintext recovery required — the hash **is** functionally equivalent to the password for the purpose of authenticating.

```
Normal auth:    password  → (one-way hash function) → NTLM hash → (used to answer challenge) → authenticated
Pass-the-Hash:  [attacker never has the password]  →  stolen NTLM hash → (used to answer challenge) → authenticated
```

**Python analogy:** imagine an API that authenticates requests with `hmac(secret_key, challenge)`, where `secret_key` is itself derived once from a password and then *cached* somewhere reachable (say, an environment variable). If an attacker reads that cached `secret_key` value straight out of memory, they can compute valid HMACs for any future challenge forever — without ever knowing the original password that produced it. That cached, reusable derived value is the hash; reading it out of memory and reusing it to keep authenticating is Pass-the-Hash.

```python
import hmac, hashlib, os

def ntlm_hash(password: str) -> bytes:
    return hashlib.new("md4", password.encode("utf-16-le")).digest()  # illustrative only

def respond_to_challenge(secret_derived_value: bytes, challenge: bytes) -> bytes:
    return hmac.new(secret_derived_value, challenge, hashlib.sha256).digest()

# Legitimate client: derives the hash locally from a password it knows, uses it, discards it.
# Attacker with Pass-the-Hash: never has the password — reads secret_derived_value
# straight out of memory (e.g., dumped from LSASS) and calls respond_to_challenge()
# with the exact same result. The function has no way to tell the two apart.
```

**Why NTLM vs. Pass-the-Hash are related but not synonymous** (today's key distinction): NTLM is the *protocol that makes this structurally possible* — because it accepts a hash-derived value instead of a password, it can't natively distinguish "legitimate holder of the password" from "anyone who obtained the hash by other means." Pass-the-Hash is the *technique* of exploiting exactly that property. You can have NTLM authentication with no Pass-the-Hash involved (a real password, typed or cached normally) — the protocol alone never proves which one occurred.

**Robert should remember:** the stolen artifact is the account's NTLM password hash, cached in memory or a credential store, not some per-session value. And: seeing NTLM in a log tells you the *protocol*; proving Pass-the-Hash requires *additional* evidence (no corresponding interactive logon by that user anywhere, credential-dumping activity on a source machine, a hash-only tool signature, an account authenticating from a host it's never used before) — never the authentication package field alone.

---

## 5. SMB and `ADMIN$`: the network access layer

**Simply:** SMB (Server Message Block) is the protocol Windows uses for file sharing, printer sharing, and inter-process communication over the network — commonly running over **TCP port 445**. It's the transport that carries both ordinary file access *and*, as you'll see in Section 6, the remote-procedure-call traffic that PsExec and many other admin tools use to control a target machine.

**`ADMIN$`** is one of several **administrative shares** Windows creates automatically on every machine (alongside `C$`, `D$`, etc., and the special `IPC$` share covered next). `ADMIN$` maps to the Windows installation directory — typically `C:\Windows`. Any account with local administrator rights on the target can read and write files there remotely, over SMB, without any special configuration — it's on by default.

```
\\TARGET-HOST\ADMIN$\        ≡        C:\Windows\        (on TARGET-HOST)
```

**What this is used for legitimately and maliciously alike:** remote administration tools use `ADMIN$` (and the closely related `IPC$`, a share dedicated to named-pipe communication rather than files) to stage files on a target — copy a binary, a script, a service executable — before doing something with it. This is exactly the mechanism PsExec uses in Section 6.

**Why `ADMIN$` activity alone doesn't prove PsExec (or anything malicious):** plenty of legitimate remote-administration tooling — software deployment systems, patch management, backup agents, other Sysinternals tools, IT helpdesk utilities — touches `ADMIN$` as a completely ordinary part of their normal operation. The share access is *necessary* for several lateral-movement techniques, but it is very far from *sufficient* evidence on its own. What turns "someone wrote a file to `ADMIN$`" into "this looks like PsExec-style execution" is the next step: what happens with that file (Section 6).

**Telemetry:** share access is visible via **5140** (a network share object was accessed) and **5145** (a network share object was checked for access — the more granular of the two, showing the specific file/pipe within the share), assuming the relevant object-access auditing is enabled — which, like most non-default Windows auditing, often isn't, unless deliberately turned on.

**Robert should remember:** SMB is the transport, `ADMIN$` is a default administrative file-share mapped to `C:\Windows`. Neither one, by itself, is evidence of an attack — they're the raw material several legitimate and malicious tools both use. The signal is in what happens *through* them.

---

## 6. PsExec: the full mechanism, step by step

This was today's biggest systems-level gap, and it's the center of this lesson. PsExec's job is: given valid administrative credentials for a remote machine, run an arbitrary command on that machine and stream its output back. Here is *exactly* how it does that — not "it executes commands remotely," but the actual Windows-subsystem chain underneath that sentence.

```
1. Attacker's PsExec client authenticates to the target over SMB (TCP 445),
   using the supplied credentials — a real password OR a stolen NTLM hash
   (Pass-the-Hash), the protocol exchange looks identical either way.
        │  → Event 4624, Logon Type 3, AuthenticationPackage: NTLM (or Kerberos)
        ▼
2. PsExec copies its small service-hosting binary — historically named
   PSEXESVC.exe — to the target over the ADMIN$ share.
        │  \\TARGET\ADMIN$\PSEXESVC.exe  ≡  C:\Windows\PSEXESVC.exe
        │  → Events 5140/5145 (share/file access), file-creation telemetry
        ▼
3. PsExec's client connects to the target's IPC$ share and opens the
   \PIPE\svcctl named pipe — the RPC endpoint for the Windows
   Service Control Manager (MS-SCMR protocol, RPC carried over SMB).
        │  → Additional 5140/5145 activity against IPC$
        ▼
4. Over that RPC channel, PsExec calls CreateService, registering a new
   Windows service whose executable path points at the PSEXESVC.exe
   binary it just staged in step 2.
        │  → Event 7045 ("A service was installed in the system"),
        │    logged by the Service Control Manager, ImagePath references
        │    PSEXESVC.exe
        ▼
5. PsExec calls StartService over the same RPC channel. services.exe —
   the process that *is* the Service Control Manager on the target —
   launches PSEXESVC.exe as a brand-new process, running in the
   security context the service was configured with (commonly SYSTEM).
        │  → Event 4688 / Sysmon Event ID 1, NewProcessName: PSEXESVC.exe,
        │    ParentProcessName: services.exe   ← extremely high-signal
        │    parent/child pairing; almost nothing legitimate spawns
        │    directly from services.exe outside normal OS service starts
        ▼
6. PSEXESVC.exe, now running on the target, creates a set of named pipes
   used to relay stdin/stdout/stderr between itself and the attacker's
   PsExec client back over the SMB/IPC$ channel.
        ▼
7. PSEXESVC.exe launches the actual requested command (e.g. cmd.exe,
   powershell.exe) as its own child process, wiring that child's I/O to
   the named pipes from step 6.
        │  → Event 4688 / Sysmon Event ID 1, NewProcessName: cmd.exe,
        │    ParentProcessName: PSEXESVC.exe   ← second high-signal
        │    parent/child pairing
        ▼
8. Command output streams back over the named pipe → IPC$ → SMB session
   to the attacker's console, in real time.
        ▼
9. On completion, PsExec (well-behaved, and this includes legitimate
   sysadmin use) calls StopService and DeleteService, and deletes
   PSEXESVC.exe from ADMIN$ — cleaning up after itself.
```

**Why this whole chain matters more than "PsExec does remote execution":** every step above is independently observable telemetry, and — exactly like the LOLBin lesson's point about `rundll32.exe` — **PsExec itself is a legitimate, widely-used Microsoft Sysinternals tool.** Real sysadmins use it constantly for exactly this purpose. The binary being present, or even the service-creation mechanism being used, isn't inherently malicious — the same three questions from the LOLBin lesson apply again: *is the binary legitimate* (usually yes), *is the execution context normal* (an unexpected source host, an unusual account, a first-seen source→destination pairing, off-hours timing), and *is the resulting behavior expected* (what did the spawned command actually do). The mechanism you now know gives you the specific telemetry needed to answer the context and behavior questions with evidence instead of guesswork.

**Python analogy for the whole chain:** think of PsExec as a miniature deployment system. Step 2 is `scp payload_service.py target:/opt/services/`. Steps 3–5 are the equivalent of calling a remote process-supervisor's API (`supervisorctl add payload_service && supervisorctl start payload_service`) rather than SSHing in directly — you're asking an *existing, trusted management daemon on the target* (the SCM, running as `services.exe`, the same way `supervisord` is a trusted daemon) to launch your code for you, rather than launching it yourself directly. Step 7 is that supervisor daemon then `fork/exec`-ing your actual payload as its child. The reason attackers (and legitimate tools) like this pattern is the same reason it's convenient for ops teams: you don't need an interactive session on the target at all — you just need the management API (SCM/RPC) to accept your instructions once.

**Telemetry summary table:**

| Chain step | Telemetry | What it tells you |
|---|---|---|
| Initial SMB authentication | 4624 (Logon Type 3) | Network logon occurred; check `AuthenticationPackage`, source, and account baseline |
| `ADMIN$`/`IPC$` share access | 5140 / 5145 | File/pipe-level access to admin shares — necessary but not sufficient on its own |
| Service registration | **7045** (System log, Service Control Manager source) | A new service was installed — ImagePath is your strongest single clue |
| Service binary process start | 4688 / Sysmon 1, parent `services.exe` | The service's executable actually launched — this parent is the tell |
| Requested command execution | 4688 / Sysmon 1, parent `PSEXESVC.exe` (or the service's own image name) | What the attacker actually ran |
| Cleanup | Corresponding service-deletion activity, file deletion from `ADMIN$` | Well-behaved PsExec usage (legitimate or malicious) tidies up; absence of cleanup is itself sometimes a signal |

**Robert should remember:** the sentence to internalize is *"PsExec doesn't execute code directly — it asks the target's own Service Control Manager to do it, by registering and starting a service, and that service process is what actually runs your command."* `services.exe → PSEXESVC.exe → <requested command>` is the parent/child signature that makes this technique detectable regardless of what the requested command turns out to be.

---

## 7. WinRM / PowerShell Remoting: the other major lateral-movement path

**Simply:** WinRM (Windows Remote Management) is Microsoft's implementation of the WS-Management (WSMan) protocol — an HTTP-based remote-management protocol, listening on **TCP 5985** (HTTP) and **5986** (HTTPS) by default. PowerShell Remoting (`Enter-PSSession`, `Invoke-Command`) is built on top of WinRM, and is the most common way this mechanism gets used, legitimately and maliciously alike.

**Why it matters as a comparison to PsExec:** WinRM takes a structurally different path to the same goal — remote code execution — and that structural difference shows up directly in the telemetry:

| | PsExec (SMB/SCM path) | WinRM / PowerShell Remoting |
|---|---|---|
| Transport | SMB, TCP 445 | HTTP(S)-based WSMan, TCP 5985/5986 |
| Mechanism | Service creation via the Service Control Manager | A pre-existing WinRM listener/service accepts the session directly — no new service is created per session |
| Key host process | `services.exe` → `PSEXESVC.exe` → requested command | `svchost.exe` (hosting the WinRM service) → **`wsmprovhost.exe`** (WSMan Provider Host) → requested command/PowerShell |
| Service-creation telemetry (7045) | Yes, every time | **No** — this is a major reason attackers may prefer WinRM: no 7045 event at all |
| Common legitimate cover | IT admin tooling, software deployment | Extremely common in modern environments: Ansible, DSC, CI/CD runners, admin PowerShell scripting — often *higher* legitimate baseline volume than PsExec |

**What a detection engineer should notice:** the absence of a service-creation event doesn't mean nothing happened — it means you have to watch a different process lineage. `wsmprovhost.exe` spawning as a child of the WinRM-hosting `svchost.exe`, followed by that `wsmprovhost.exe` process spawning further child processes (especially `powershell.exe` doing anything beyond routine administration), is the WinRM-path equivalent of the `services.exe → PSEXESVC.exe` signature.

**Robert should remember:** PsExec and WinRM are two different answers to the same underlying question ("how do I get a remote Windows Service Control Manager or management daemon to run my code for me"), and each leaves a *different* process-lineage fingerprint. Knowing only "PsExec" as a lateral-movement technique means missing every WinRM-based lateral-movement case entirely — which is exactly why this is flagged as a future scenario (see the companion curriculum document).

**Other lateral-movement mechanisms worth knowing by name (not deep-dived here — deliberately left for future scenarios so they're learned through investigation rather than a list):** WMI-based remote execution (`Win32_Process.Create` via the WMI service, `WmiPrvSE.exe` as the telltale host process), scheduled-task-based lateral movement (remote `schtasks`/Task Scheduler API use, `taskeng.exe`/`svchost.exe`-hosted Task Scheduler service as host, Event 4698 for task creation), and RDP-based lateral movement (Logon Type 10, distinct from the Type 3 network logons this lesson focused on).

---

## 8. Kerberos vs. NTLM, briefly

You already know NTLM well after this lesson; Kerberos is worth a comparison, not a full deep-dive, since it wasn't the center of today's scenario:

| | NTLM | Kerberos |
|---|---|---|
| Shape | Challenge-response, no third party involved in the exchange itself | Ticket-based; a trusted third party (the Key Distribution Center, typically the domain controller) issues tickets |
| What's needed to authenticate | A value derivable from the account's password hash | A valid ticket, obtained in advance from the KDC |
| Mutual authentication | No — the client doesn't verify the server's identity | Yes — both sides are cryptographically verified |
| Modern AD default | Fallback only | Preferred/default for domain-joined authentication |
| Analogous credential-theft technique | Pass-the-Hash (steal the NTLM hash) | Pass-the-Ticket / Golden Ticket / Silver Ticket (steal or forge Kerberos tickets) |
| Why seeing NTLM at all can be a signal | In a modern, well-configured AD environment, Kerberos should be used for most domain authentication — an unexpected NTLM logon can itself be worth a second look, since it sometimes indicates a downgrade (forced or otherwise) | — |

**Robert should remember:** Kerberos isn't "safer NTLM" in some vague sense — it's a structurally different trust model (a vouching third party plus mutual authentication) that happens to close off the specific weakness NTLM has. The two protocols have their own parallel credential-theft techniques (Pass-the-Hash vs. Pass-the-Ticket), which is a strong signal this pairing is worth a dedicated future scenario rather than folding it fully into this lesson.

---

## MITRE ATT&CK Mapping

| Chain step | Technique | ATT&CK ID |
|---|---|---|
| Valid credentials used for lateral movement | Valid Accounts | T1078 |
| NTLM hash used without knowing the password | OS Credential Dumping → Pass the Hash | T1550.002 |
| SMB/`ADMIN$` remote service execution (PsExec-style) | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Service creation to execute code | System Services: Service Execution | T1569.002 |
| PowerShell Remoting / WinRM | Remote Services: Windows Remote Management | T1021.006 |
| WMI-based remote execution (adjacent technique) | Windows Management Instrumentation | T1047 |
| Scheduled-task-based lateral movement (adjacent technique) | Scheduled Task/Job | T1053.005 |

---

## Quick Reference: Windows Authentication & Lateral-Movement Investigation Questions

- What Logon Type does this 4624 show, and does that type make sense for how this account normally accesses this system?
- What Logon ID is on this event — and have I used that (not timing) to pull every other event from the same session?
- Does 4672 appearing here reflect a genuine change in this account's privilege, or is this just what a normal logon from this (already-privileged) account looks like?
- Is the authentication package NTLM or Kerberos — and if NTLM, is that expected in this environment, or itself worth a second look?
- If Pass-the-Hash is suspected, what additional evidence do I have beyond "NTLM was used" — a missing corresponding interactive logon, credential-dumping activity on a source host, a first-seen source→account→destination relationship?
- Is there `ADMIN$`/`IPC$` share activity — and if so, did it lead anywhere (a service creation, a scheduled task, a WMI call), or is it isolated and likely benign?
- Is there a 7045 service-installation event, and does the ImagePath point somewhere expected (a real application) or somewhere suspicious (a user-writable path, a generic/temp-looking binary name)?
- What's the parent process of the thing that actually executed — `services.exe` (PsExec-style), `wsmprovhost.exe`/`svchost.exe` (WinRM-style), `WmiPrvSE.exe` (WMI-style), or something else entirely?
- Is this account/source/destination combination something I've seen before, or is this a first-seen relationship worth extra scrutiny on that basis alone?

---

## Active Recall

No answers below — work through these in conversation, one at a time, and expect follow-up challenges rather than acceptance at face value.

1. **4672.** An analyst flags a 4672 event as "proof of privilege escalation." What's wrong with that claim, and what would actually support or refute it?
2. **Logon ID.** Two events happened four seconds apart on the same host. Why isn't that enough to say they're part of the same logon session, and what would actually prove it?
3. **NTLM mechanics.** Explain, without saying the word "hash" more than once, why NTLM never needs to send the plaintext password across the network — and what it sends instead.
4. **Pass-the-Hash.** Precisely state what credential material an attacker needs to perform Pass-the-Hash, where it typically comes from, and why possessing it is sufficient (no cracking required).
5. **NTLM vs. PtH.** A 4624 shows Logon Type 3, AuthenticationPackage NTLM. Is that proof of Pass-the-Hash? Why or why not, and what additional evidence would move you closer to a conclusion either way?
6. **PsExec mechanics.** Walk the full chain from "attacker has credentials" to "command output appears on the attacker's screen" — every step, in order, naming the Windows subsystem and the process involved at each one.
7. **PsExec telemetry.** Which single event ID is the strongest indicator that PsExec-style service-based execution occurred, and why is it stronger than `ADMIN$` share-access telemetry alone?
8. **WinRM contrast.** Why does WinRM-based lateral movement not generate a 7045 event, and what process-lineage signature should you look for instead?
9. **Kerberos vs. NTLM.** Name the structural difference between the two protocols (not just "Kerberos is newer/better"), and name each protocol's corresponding credential-theft technique.
10. **Synthesis.** Given only "Event 4688 shows a new process with ParentProcessName `services.exe`," walk through what you can and cannot yet conclude, and what two or three additional pieces of evidence would most efficiently move you toward a confident determination.

---

## Mastery Checklist — what Robert should be able to explain after mastering this module

- Why 4672 is an observation about privilege level, not evidence of a privilege-escalation event, and what actually distinguishes the two.
- Why Logon ID (not event timing) is the correct correlation key for authentication/session events — and can state the parallel to ProcessGuid vs. PID.
- What NTLM's challenge-response exchange actually sends over the wire, and why that design is what makes Pass-the-Hash structurally possible.
- Precisely what credential material Pass-the-Hash steals (the account's NTLM hash), where it's typically obtained from (LSASS memory, NTDS.dit, SAM), and why no password-cracking step is required.
- The full PsExec execution chain from memory: SMB authentication → `ADMIN$` file staging → SCM RPC (`svcctl`) → `CreateService`/`StartService` → `services.exe` spawns `PSEXESVC.exe` → requested command runs as its child → named-pipe I/O relay → cleanup — and can name the telemetry (4624, 5140/5145, 7045, 4688/Sysmon 1) produced at each step.
- Why `ADMIN$`/SMB activity alone is necessary-but-not-sufficient evidence, and what specifically upgrades it to high-confidence (service creation + the `services.exe → PSEXESVC.exe` parent/child pairing).
- How WinRM/PowerShell Remoting achieves the same outcome as PsExec through a structurally different path (no service creation, `wsmprovhost.exe` as the tell), and why that matters for detection coverage.
- The structural difference between NTLM and Kerberos (challenge-response vs. ticket-based with a trusted third party and mutual authentication), and each protocol's parallel credential-theft technique.

**Reminder:** this document is a reference and review lesson, not a replacement for Scenario Gym sessions. It doesn't set the next session's topic — see the curriculum document for how this fits into the adaptive plan.
