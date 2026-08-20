# Windows Execution Chain Deep Dive: LOLBins, DLL Loading & Persistence
### A gap-closing lesson built from your WINWORD → PowerShell → rundll32 scenario (August 19, 2026)

You already run the investigation the right way — process tree, payload, network, hash, persistence, in that order, without being told to. What was missing today was the Windows *systems* substrate underneath that instinct: how a process actually hosts code, how a DLL relates to the program that loads it, which telemetry source represents which system event, and how to talk about evidence without overclaiming. This lesson is scoped to exactly what today's scenario exposed — not a general Windows internals course.

**Today's chain, for reference throughout:**

```
WINWORD.EXE
    │  (spawns a child process — already anomalous)
    ▼
powershell.exe -NoP -W Hidden -enc <base64>
    │  (base64-encoded command, hidden window, no profile)
    ▼
PowerShell downloads a file over the network
    │
    ▼
update.dll written to %TEMP%
    │  (file creation on disk)
    ▼
rundll32.exe update.dll,Start
    │  (rundll32 loads the DLL into its own process, calls the exported "Start" function)
    ▼
rundll32 makes an outbound network connection
    │
    ▼
HKCU\...\CurrentVersion\Run persistence re-establishes this chain at every logon
```

---

## 0. The mental model that sits under everything below

**Binary legitimacy → execution context → behavior.** These are three independent questions, and conflating them was the root of gap #1 today.

- *Is this binary itself legitimate?* — Is `powershell.exe` the real, signed Microsoft binary? Usually yes, even in an attack.
- *What is the execution context?* — Who spawned it, with what arguments, from what parent, in what session? A word processor spawning a script interpreter with a hidden window and an encoded command is an abnormal context, independent of the binary's legitimacy.
- *What is the behavior?* — What did it actually do — download a file, write to disk, load a DLL, open a network socket, write a registry value?

A **LOLBin** ("living-off-the-land binary") is exactly this gap exploited on purpose: a legitimate, trusted, often pre-installed and digitally signed Windows binary, used to carry out malicious actions, so that binary-reputation-based defenses find nothing wrong. `powershell.exe` and `rundll32.exe` are two of the most common; others worth knowing by category rather than memorizing exhaustively: `mshta.exe` (runs HTML applications, can execute embedded script), `wscript.exe`/`cscript.exe` (runs VBScript/JScript), `certutil.exe` (a certificate utility that can also download files and decode base64), `regsvr32.exe` (registers COM DLLs, also abusable to execute code from a remote script).

**Robert should remember:** never let "the binary is legitimate" end the analysis. Ask what launched it, how, and what it did next — legitimacy of the file says nothing about legitimacy of the action.

---

## 1. The telemetry mental model (learn this once, not per-event-ID)

Gap #2 today wasn't really about mixing up two numbers — it was reaching for a memorized ID before reaching for the underlying question: **what happened on the system, and which telemetry source represents that category of thing?**

Windows exposes overlapping-but-distinct telemetry sources:

- **Windows Security auditing** — built into the OS, off by default for most useful events, coarse-grained. Its flagship security event is `4688` (process creation, when process-creation auditing is enabled).
- **Sysmon** — a free Microsoft Sysinternals tool you install and configure separately. Far more granular than native Windows auditing: separate event types for process creation, network connections, file creation, image/module loads, registry changes, and more. Each event *type* gets its own ID, and the ID is just Sysmon's internal catalog number for that category — there's nothing deeper to memorize about the number itself.
- **MDE / EDR telemetry** — a managed layer that ingests both of the above (plus its own sensors) and exposes them through a normalized schema (e.g., `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents` in Advanced Hunting) — which is *already organized by category*, so the underlying model is even more directly visible there than in raw Sysmon.

The four Sysmon IDs that came up today, worth anchoring to *behavior first, number second*:

| System behavior | Sysmon Event ID | Windows Security Event ID |
|---|---|---|
| A new process was created | **1** | **4688** |
| A process made a network connection | **3** | *(not natively audited — needs Sysmon, firewall, or EDR)* |
| A file was created or overwritten | **11** | *(not natively audited without object-access auditing configured)* |
| A module/image (e.g., a DLL) was loaded into a process | **7** | *(no native equivalent)* |
| A registry value was set | 13 | *(4657, only if object-access auditing is explicitly enabled for that key)* |

**Robert should remember:** don't build a mental lookup table keyed by number. Build one keyed by *behavior* ("a process started," "a network connection happened," "a file appeared," "code got loaded into a process," "a registry value changed"), and treat the ID as a label you can always look up. You already correctly recalled 4688 — the fix is reflexive category-first thinking, not more memorization.

---

## 2. Office spawns PowerShell: process creation and the parent/child signal

**Simply:** WINWORD.EXE — Microsoft Word — started `powershell.exe` as a child process. Word has essentially no legitimate reason to launch a script interpreter on its own; this parent/child pairing is one of the highest-signal anomalies in the entire chain, before you've even looked at what the PowerShell command does.

**At the systems level:** every new process on Windows is created via the `CreateProcess` Win32 API (directly or indirectly). The OS records — and telemetry captures — the new process's image path, its full command line, its parent process, the user/security context it runs as, and its integrity level. The "parent" is simply whichever process called `CreateProcess`; Word, running a malicious macro or exploiting a document-parsing bug, called it to launch PowerShell.

**Python analogy:** think of a document-viewer application that, instead of just rendering a `.docx` file, executes `subprocess.run(["powershell.exe", "-enc", payload])` from inside its own code. A word processor calling out to a general-purpose script interpreter is exactly as odd as a PDF viewer shelling out to `bash` — the "PDF viewer" and `bash` are each fine in isolation; a PDF viewer *launching* bash is the anomaly.

**Telemetry that exposes it** (Sysmon Event ID 1 / Security 4688):

```
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
CommandLine: powershell.exe -NoP -W Hidden -enc SQBFAFgAKAB...
User: CONTOSO\jsmith
```

**What the attacker gains:** inherits the logged-on user's permissions immediately, with no separate malware binary needing to exist yet — the "malware," at this stage, is just an encoded command line.

**What a detection engineer should notice:** Office applications (WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE, POWERPNT.EXE) spawning `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, or `mshta.exe` is a narrow, high-value parent/child rule on its own — false positives are rare in most environments, since legitimate Office-triggered automation is uncommon and usually well-documented.

**Robert should remember:** the parent/child relationship is often your single strongest, cheapest signal — check it before anything else, because it's evidence about *context*, independent of whether the child's specific payload is even decodable yet.

---

## 3. Decoding the command: what process creation telemetry actually proves

**Simply:** the flags `-NoP -W Hidden -enc <base64>` are PowerShell's own command-line switches — `-NoProfile` (skip loading the user's PowerShell profile, which speeds startup and avoids leaving profile-related traces), `-WindowStyle Hidden` (no visible console window), `-EncodedCommand` (the script that follows is base64-encoded, typically UTF-16LE before encoding).

**At the systems level:** the encoding is not encryption — it's a transport convenience PowerShell itself supports, meant to avoid quoting/escaping problems when passing a script on a command line. Decoding it is mechanical: base64-decode, then interpret as UTF-16LE text.

**Python analogy:**
```python
import base64
base64.b64decode(encoded_blob).decode("utf-16-le")
```
This is the entire "mystery" — there's no cryptography to break, just an encoding to reverse.

**What the attacker gains:** the encoded blob defeats simple substring-matching detections looking for plaintext strings like `Invoke-WebRequest` or a suspicious URL, and it avoids the shell-escaping headaches of passing a multi-line script as a literal command-line argument. It does **not** meaningfully hide intent from an analyst, or from EDR products that decode `-enc` payloads automatically for you.

**What a detection engineer should notice:** the presence of `-enc`/`-EncodedCommand` combined with `-W Hidden` and/or `-NoP` is itself a detectable pattern, independent of what the decoded content says — legitimate scripted administration occasionally uses `-enc`, but hidden-window base64 execution spawned from an Office process is a very different prior.

**Worth knowing, one step beyond manual decoding:** you don't have to hand-decode `-enc` every time if the environment has **PowerShell Script Block Logging** enabled (Event ID **4104**, via `Microsoft-Windows-PowerShell/Operational`). PowerShell itself logs the actual script content it's about to execute — already deobfuscated, after any encoding/base64/string-concatenation tricks are resolved — because PowerShell has to have the real code in hand to run it, regardless of how it arrived on the command line. Where it's enabled, 4104 is usually a faster and more complete source of "what did this script actually do" than reconstructing it yourself from the command line. Module Logging (Event ID 4103) is the companion source that captures which cmdlets/pipeline execution actually ran.

**Robert should remember:** decode first, every time, before speculating about what a payload does — the base64 blob is evidence sitting right there, not an obstacle. And check whether Script Block Logging already did that decoding for you.

---

## 4. The network connection: PowerShell reaching out

**Simply:** the decoded PowerShell script made an outbound connection and downloaded a file — this is the "download" step of the "download-and-execute" pattern.

**At the systems level:** PowerShell (via .NET classes like `System.Net.WebClient` or the `Invoke-WebRequest`/`Invoke-RestMethod` cmdlets built on top of them) opens a socket and issues an HTTP(S) request. That connection is visible at the process/socket layer regardless of what's inside the payload.

**Python analogy:**
```python
import requests
data = requests.get(url).content
open(r"C:\Users\jsmith\AppData\Local\Temp\update.dll", "wb").write(data)
```
Two distinct actions in one line of reasoning: a network fetch, then a disk write — telemetry will show both as separate, correlatable events (Section 6 covers *how* they're proven to belong to the same process).

**Telemetry that exposes it** (Sysmon Event ID 3):

```
EventID: 3
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
DestinationIp: 185.220.101.47
DestinationPort: 443
Initiated: true
```

**What the attacker gains:** staged delivery — the malicious payload doesn't need to exist on disk before the initial compromise; it's fetched only after the attacker has code execution, which also lets them swap the payload server-side without changing the phishing document at all.

**What a detection engineer should notice:** a scripting engine (`powershell.exe`, `wscript.exe`, `mshta.exe`) that is not normally network-active in your environment, making an outbound connection, is a strong behavioral signal on its own — before you even know the destination's reputation.

**Robert should remember:** "PowerShell talked to the network" is a *category* of suspicious behavior you can detect on, separate from and prior to knowing whether any specific IP or domain is known-bad.

---

## 5. File creation: the DLL lands on disk (and why %TEMP%)

**Simply:** PowerShell wrote the downloaded bytes to `%TEMP%\update.dll`. This is a real, ordinary file-write — the same OS mechanism any program uses to save a file — performed by a script instead of a human.

**At the systems level:** file creation goes through the `CreateFile` Win32 API (with a write flag) or a managed-code wrapper around it. This matters because it's a **distinct, separately-loggable event** from process creation, network activity, or code execution — which is exactly gap #4 from today. Four different things happened in this chain, and they are four different categories of evidence:

| Category | What it proves | What it does *not* prove by itself |
|---|---|---|
| File creation | Bytes were written to a path on disk | That the file was ever executed |
| Process creation | A program was launched | What that program actually did once running |
| Image/module load | Code from a specific DLL was mapped into a process | That every function inside it ran successfully |
| Code execution *within* a process | Instructions actually ran | — this is the thing everything else is evidence *toward*, not a directly-observed telemetry category by itself in most default configs |

True **fileless** technique is different from this scenario: it means the malicious code never touches disk as its own file at all — e.g., a script reflectively loads a .NET assembly directly into memory from a byte array, or injects shellcode into another process's memory via `CreateRemoteThread`/`VirtualAllocEx`. Today's scenario is explicitly **not** that — PowerShell used a plain, disk-based download-and-write, which is why the initial guess that the DLL "might never have touched disk" was incorrect given the evidence actually present (a Sysmon Event ID 11 for that exact path).

**Why `%TEMP%` (and why attackers like user-writable locations generally):**

| Location | Typical write access | Typical legitimate volume | Why attackers like/dislike it |
|---|---|---|---|
| `%TEMP%` (`...\AppData\Local\Temp`) | Current user, no admin needed | Very high — every app stages temp files here | Favorite: blends into huge legitimate noise, no privilege required |
| `%AppData%` (Roaming/Local) | Current user, no admin needed | High — app configs/caches live here | Favorite: same reasons as %TEMP%, plus often used for persistence payload storage |
| `Downloads` | Current user, no admin needed | Moderate, user-driven | Used opportunistically, but more visible to the user than %TEMP%/AppData |
| `ProgramData` | Often writable by standard users depending on ACLs | Moderate — shared app data | Sometimes used; more visible to defenders, some tooling has hardened ACLs here |
| `System32` | Requires admin/SYSTEM | Extremely high (core OS) baseline, but new *unexpected* files are rare | Attackers generally can't write here without already having elevated privileges — so writes here are less about staging and more about a later-stage, already-privileged foothold |

**What the attacker gains:** the ability to stage a payload *before* obtaining any elevated privileges, in a location with enough legitimate background activity that a naive "alert on any file created in %TEMP%" rule would be useless from false-positive volume alone.

**What a detection engineer should notice:** the *combination* is what matters — not "a file was created in %TEMP%" (too common to alert on alone), but "a scripting engine created an executable/DLL/script file in a user-writable path," which is a much rarer and higher-signal pairing.

**Robert should remember:** file creation, process creation, module loading, and code execution are four separate facts. Know which one your telemetry actually proves before asserting the others followed from it.

---

## 6. What a DLL actually is (before rundll32 makes sense)

**Simply:** a DLL (Dynamic Link Library) is a file full of code and data that other programs can load and use. Critically, **a DLL cannot run by itself** — it has no independent process of its own. It only ever executes *inside* whatever process loads it.

**At the systems level:** a DLL is a Portable Executable (PE) file, the same container format `.exe` files use, but built to be loaded into another process's address space rather than launched directly. It carries an **export table** — a list of named functions inside it that other code is allowed to call. Windows' loader (via `LoadLibrary`) maps the DLL's code and data into the calling process's own memory, and `GetProcAddress` looks up the memory address of a specific exported function by name so it can be called.

**Python analogy:** a DLL is conceptually a `.py` module — a file of code, not a standalone program. You don't "run" a Python module by itself in the normal sense; you `import` it into a running Python process and call a function it exposes:
```python
import update
update.Start()
```
Nothing here launches a new, separate Python process called `update`. The code in `update.py` runs *inside* whatever interpreter process executed `import update` — exactly how a DLL's code runs inside whatever process loaded it.

**Robert should remember:** a DLL is a library, not a program. The question "which process is this DLL's code actually running inside of?" always has an answer, and it's never "its own" — that's what makes rundll32 make sense next.

---

## 7. rundll32.exe: the biggest system-level fix from today

**Simply:** `rundll32.exe update.dll,Start` means: *"rundll32, load `update.dll` and call the function named `Start` inside it."* rundll32 is a small, generic Microsoft utility whose entire job is to load an arbitrary DLL and invoke one exported function from it, based on a command-line argument.

**At the systems level, step by step:**

1. Windows creates a new process for `rundll32.exe` (Section 2's process-creation mechanics apply here too).
2. rundll32 parses its command line into two parts: the DLL path (`update.dll`) and the export name (`Start`).
3. rundll32 calls `LoadLibrary("update.dll")`, which maps the DLL's code and data into **rundll32's own process memory** — not a new process.
4. rundll32 calls `GetProcAddress` to find `Start`'s address inside that now-loaded DLL.
5. rundll32 calls that address like a function call. `update.dll`'s code now executes, but it's running as part of the `rundll32.exe` process the whole time.

```
Before:                              After LoadLibrary + call:
┌─────────────────────┐              ┌─────────────────────┐
│  rundll32.exe        │              │  rundll32.exe         │
│  process memory       │              │  process memory        │
│  ┌─────────────────┐ │              │  ┌─────────────────┐ │
│  │ rundll32's own   │ │    ───▶      │  │ rundll32's own   │ │
│  │ code             │ │              │  │ code             │ │
│  └─────────────────┘ │              │  └─────────────────┘ │
│                       │              │  ┌─────────────────┐ │
│                       │              │  │ update.dll code  │ │
│                       │              │  │ (incl. "Start")  │ │
│                       │              │  └─────────────────┘ │
└─────────────────────┘              └─────────────────────┘
```

`rundll32.exe` itself is never rewritten, replaced, or transformed — it is the constant, generic **host**. `update.dll` is the payload it's instructed to load and run. This is exactly the same relationship as `import update; update.Start()`: the Python interpreter process doesn't get replaced by `update.py` — it just now also contains and executes `update.py`'s code.

**Why attackers like it:** `rundll32.exe` is a signed, ubiquitous Microsoft binary already present on every Windows machine — there's no separate unsigned executable to deliver or flag on binary reputation alone, and its legitimate uses (invoking control panel applets, print UI dialogs, and similar OS-shipped functionality) are common enough that historically some environments under-scrutinized it.

**What a detection engineer should notice:** legitimate `rundll32` invocations are a fairly narrow, learnable set (they typically reference DLLs in `System32`/`SysWOW64` with recognizable export names tied to real OS features). `rundll32.exe` pointed at a DLL path **outside** those system directories — especially a user-writable path like `%TEMP%` — with an unfamiliar export name, is high-signal almost by default.

**Robert should remember:** rundll32 loads and hosts; it does not transform. Whenever you see `rundll32.exe X.dll,FunctionName`, mentally translate it to "a process just imported X and called `X.FunctionName()` inside itself" — same shape as Section 6, now with the actual Windows binary involved.

---

## 8. Module/image load telemetry — and why "missing" isn't "didn't happen"

**Simply:** the moment `LoadLibrary` maps `update.dll` into rundll32's memory, that's a distinct system event — separate from "rundll32.exe started" — and it has its own telemetry category: **image/module load** (Sysmon Event ID 7).

**At the systems level:** this is genuinely the noisiest telemetry category on a Windows system, because *every* process loads dozens to hundreds of DLLs constantly just to run normally (system libraries, UI frameworks, etc.). Because of that volume, **Sysmon's Event ID 7 is not enabled by default even in many well-configured Sysmon deployments** — it's expensive to collect and store at scale, so it's frequently filtered down to only specific, deliberately-chosen DLLs/paths, or left off entirely.

**Why this matters for today's exact discussion:** if you see Sysmon Event ID 1 showing `rundll32.exe update.dll,Start`, but no corresponding Event ID 7 for that DLL load, the most likely explanation in most real environments is a **collection/configuration gap**, not that the load never happened. The command-line evidence in Event ID 1 is strong *inferential* evidence about what rundll32 was instructed to do — but by itself it doesn't *prove* every instruction inside `Start` executed successfully (the DLL could theoretically have failed to load, been corrupted, or exited early — rare, but not zero).

**The language discipline this demands** (this is gap #8, and it belongs here as much as anywhere):

| Say this | Not this | Why |
|---|---|---|
| "Telemetry shows rundll32 was launched with `update.dll,Start` as arguments" | "rundll32 executed the DLL" | The command line is a fact; whether the load *succeeded* is a separate fact you may not yet have |
| "This is consistent with the DLL being loaded and its `Start` export running" | "We confirmed the DLL ran" | "Consistent with" reflects what the evidence supports, not more |
| "We cannot yet establish whether Event ID 7 is absent due to a collection gap or because the load did not occur" | (silently assuming one or the other) | Names the actual uncertainty instead of hiding it |
| "Additional evidence — e.g., the outbound network connection sourced from rundll32.exe's PID/ProcessGuid — would corroborate that `Start` executed" | — | Points at what *would* resolve the uncertainty, which is the useful next step |

In today's scenario specifically, the follow-on outbound network connection *from that same rundll32 process* (Section 9 covers how you prove "same process") is strong corroborating evidence that execution proceeded past the load — even without an Event ID 7 record.

**Robert should remember:** absence of a specific telemetry record is evidence about your *visibility*, not evidence about what happened on the system. Always ask "is this event category even collected here?" before treating its absence as a finding.

---

## 9. Correlating process and network activity: PID vs. ProcessGuid

**Simply:** you saw a process-creation event for `rundll32.exe` and, separately, a network-connection event. How do you prove they're the *same instance* of rundll32 — not just any `rundll32.exe` that happened to run around the same time?

**At the systems level:** Windows identifies a running process by its **Process ID (PID)** — but PIDs are drawn from a limited pool of small integers and are **reused** once a process exits. `PID 6844` might be your malicious rundll32 at 2:14 PM and a completely unrelated, legitimate `svchost.exe` at 2:19 PM after the first process terminated and Windows recycled the number. Matching on PID alone, especially across any meaningful time window, risks correlating events from two entirely different processes that just happened to share a number.

Sysmon solves this by minting a **ProcessGuid** — a globally unique identifier assigned once, at process creation, that never gets reused, ever, even across reboots. Every Sysmon event generated by that process instance (its own creation, its network connections, its file writes, its module loads) carries that same ProcessGuid, so correlating on ProcessGuid instead of PID guarantees you're looking at one specific process instance's activity, full stop.

**Python analogy:** in CPython, `id(obj)` returns an object's memory address — and once an object is garbage-collected, Python is free to reuse that same address for a completely different object later. Relying on `id(obj)` to mean "this specific object, forever" is the same mistake as relying on PID. A `uuid.uuid4()` assigned once at object-creation time and stored as an attribute — never reused, never reassigned — is the ProcessGuid equivalent: a durable instance identity instead of a recyclable slot number.

**Telemetry example, correctly correlated:**

```
Sysmon EventID 1 (process creation)
ProcessGuid: {a1b2c3d4-0000-0000-0000-000000RD888}
Image: rundll32.exe
CommandLine: rundll32.exe C:\Users\jsmith\AppData\Local\Temp\update.dll,Start

Sysmon EventID 3 (network connection)
ProcessGuid: {a1b2c3d4-0000-0000-0000-000000RD888}
DestinationIp: 185.220.101.47
DestinationPort: 443
```

Same ProcessGuid on both events = strong, durable proof that the network connection came from *that specific* rundll32 process instance — this is also your best corroboration for the Section 8 uncertainty (did `Start` actually execute?).

In MDE Advanced Hunting, the equivalent discipline is using the platform's own per-instance process identifiers and the `Initiating Process` fields (which are built to solve the same PID-reuse problem) rather than joining tables on a bare `ProcessId` across a wide time range.

**Robert should remember:** "PID 6844 did X" is a claim that needs a tightly bounded time window to be trustworthy. "ProcessGuid {…} did X" is true regardless of time window or reboot. Always correlate on the durable instance identifier when one is available.

---

## 10. Registry Run-key persistence

**Simply:** the attacker added a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` so that Windows automatically re-runs their command every time this user logs on — no need to re-deliver the phishing document or re-run PowerShell manually.

**Observed value:**

```
Hive:      HKCU\Software\Microsoft\Windows\CurrentVersion\Run
ValueName: OneDriveUpdate
ValueData: rundll32.exe C:\Users\jsmith\AppData\Local\Temp\update.dll,Start
```

**At the systems level:** `HKCU` ("HKEY_CURRENT_USER") is the registry hive scoped to the currently logged-on user — every user has their own, and writing to it requires only that user's own permissions, never administrator rights. During logon, Windows Explorer (and related logon infrastructure) reads the values under this Run key and launches each one as a normal user-context process. It's a documented, ordinary Windows feature — countless legitimate applications use it to auto-start (updaters, chat clients, cloud-sync tools) — which is exactly why persistence hidden here can hide in plain sight, and exactly why the value was named `OneDriveUpdate`: a plausible, low-scrutiny disguise.

**Python analogy:** think of it like a per-user `startup_apps.json` config file that a login script reads on every session start, iterating each entry and executing it — except this one ships with the OS, is trusted by default, and requires no special permission to add an entry.

**Telemetry that exposes it** (Sysmon Event ID 13 — RegistryEvent, value set):

```
EventID: 13
TargetObject: HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate
Details: rundll32.exe C:\Users\jsmith\AppData\Local\Temp\update.dll,Start
Image: powershell.exe
```

**What the attacker gains:** durable execution across reboots/logoffs without needing to repeat initial access, achievable entirely within a standard, unprivileged user context.

**What a detection engineer should notice:** the value name alone (`OneDriveUpdate`) is not suspicious — plenty of legitimate Run entries have generic, product-sounding names. What's suspicious is the **value data**: it references `rundll32.exe`, a user-writable path (`%TEMP%`), and a DLL with no recognizable legitimate purpose. Section 11 formalizes exactly this "don't alert on the container, alert on the combination" principle.

**Robert should remember:** you got this one right on the first pass — HKCU scope, no admin required, executes at logon. The one thing to sharpen further is treating the *value name* as weak evidence and the *value data* as the real signal.

---

## 11. Detection engineering: behavior over brittle IOC matching

**Simply:** a detection built around one specific artifact (a filename, a hash, an exact command line) breaks the instant an attacker changes that one thing. A detection built around the *pattern of behavior* an attack technique requires survives small variations.

**The overfitting trap, made concrete:**

```
Bad:    IF rundll32.exe loads update.dll  THEN malicious
        → defeated by renaming the DLL once.

Better: IF (Run-key value written)
           AND (value data references a user-writable path
                OR an unusual execution mechanism
                    such as rundll32 / powershell / wscript / mshta)
           AND (supporting behavioral context is present)
        THEN raise for review
        → survives DLL rename, export-function rename, and even a
          full swap from a DLL payload to a PowerShell-only payload,
          because none of those change the underlying pattern.
```

This is precisely the generalization Robert already produced correctly today when challenged: "what if they used a PowerShell script instead of a DLL?" — the answer was to keep the persistence-plus-writable-path-plus-suspicious-execution-vector logic and simply widen the execution-mechanism list, rather than writing a second brittle rule.

**At the systems level, the useful separation is:**

- **Core malicious behavior** — the small set of conditions that must be true for this *class* of attack to work at all. For Run-key persistence specifically: a persistence mechanism was created or modified, *and* it references a suspicious execution vector or a user-writable location. This is the part that should gate whether an alert can fire.
- **Supporting signals** — context that doesn't need to be true, but sharply raises confidence and priority when it is present alongside the core behavior: an Office-to-script parent/child chain earlier in the same session, a recent file download, file creation in a user-writable directory shortly before the persistence write, a rare/unseen file hash, external network activity from the same process. None of these should be *required* — but each one present should raise severity.

**Python analogy** (this mirrors additive risk scoring, the same shape used for the AWS detection work): 

```python
def score(event_context):
    s = 0
    if event_context.persistence_written: s += 3       # core
    if event_context.writable_path_referenced: s += 3   # core
    if event_context.suspicious_exec_vector: s += 2      # core
    if event_context.office_to_script_parent: s += 1     # supporting
    if event_context.recent_download: s += 1             # supporting
    if event_context.rare_hash: s += 1                   # supporting
    if event_context.external_network: s += 1            # supporting
    return s

# gate: core conditions alone can already justify review;
# supporting signals push it from "review" to "high-confidence incident"
```

**Why this matters operationally:** a detection that requires the *entire* observed chain (Office → PowerShell → download → rundll32 → this exact DLL → this exact registry value) will miss the next attacker who skips a step or reorders it. A detection that requires only the *core* pattern, with everything else as confidence-boosting enrichment, still fires — and the enrichment keeps it from flooding the SOC with every legitimate Run-key write from a real updater.

**Robert should remember:** ask two separate questions for every detection you design — "what's the smallest set of conditions that has to be true for this technique to work at all?" (core) and "what else, if present, makes me more confident this specific instance is malicious?" (supporting). Never let the second list creep into the first.

---

## MITRE ATT&CK Mapping (for your detection-engineering reference)

Tagging each step of the chain with its technique ID is standard practice for detection engineering — it's how you communicate severity and coverage to other analysts/tools without re-explaining the mechanics every time, and it's the same "category lookup" idea from Section 1, just aimed at a shared external taxonomy instead of an internal one.

| Chain step | Technique | ATT&CK ID |
|---|---|---|
| WINWORD spawns PowerShell | Phishing → user execution via document | T1566 / T1204.002 |
| `-enc` base64 command | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Base64-encoded payload | Obfuscated Files or Information | T1027 |
| PowerShell downloads `update.dll` | Ingress Tool Transfer | T1105 |
| `rundll32.exe update.dll,Start` | System Binary Proxy Execution: Rundll32 | T1218.011 |
| `HKCU...\Run\OneDriveUpdate` | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |
| Outbound C2-consistent connection | Application Layer Protocol (web protocols) | T1071.001 |

**Robert should remember:** you don't need to memorize IDs any more than you needed to memorize Sysmon event numbers — the reflex is the same: identify the behavior first, then attach the label. The label is for communication, not understanding.

---

## Quick Reference: Windows Process/DLL/Persistence Investigation Questions

- What process created this process, with what command line, and does that parent/child pairing make sense for these two programs?
- Is this command line encoded/obfuscated, and have I actually decoded it rather than inferring from the flags alone?
- Did this process touch the network — and is network activity normal for a process of this type?
- Did this process create any files, and if so, in which directory — is that directory user-writable?
- If a DLL is involved: what process is actually hosting/executing its code, and which exported function was invoked?
- Do I have direct evidence (e.g., an image-load event) that the DLL's code ran, or only inferential evidence (e.g., a command line naming it) — and have I said so accurately?
- Am I correlating events by a durable per-instance identifier (ProcessGuid or equivalent), or by a reusable PID across a risky time window?
- Was any persistence mechanism created or modified — and does its *value data* (not just its name) reference a suspicious location or execution vector?
- If I were to write a detection for this, what's the minimal *behavioral* pattern required for the technique to work, versus what's merely supporting context?

---

## Active Recall

No answers below — this section is meant to be worked through in conversation, one question at a time, and each answer will be challenged before moving to the next. Vague or hand-wavy answers get pushed on, not accepted.

1. **Process creation.** A brand-new process appears in your telemetry. Name the two or three fields you'd look at first to judge whether it's suspicious, and say why each one matters.
2. **Network connections.** You see a process you don't normally expect to be network-active making an outbound connection on port 443. What can you conclude, and what can you *not* yet conclude from port number alone?
3. **File creation.** A script process writes a `.dll` file to a user-writable directory. Walk through what this event does and does not prove about what happens next.
4. **DLL loading.** Explain, in your own words, what it means for a DLL to be "loaded" by a process — and what's wrong with saying "the DLL ran."
5. **rundll32.** Given `rundll32.exe helper.dll,DoWork`, describe exactly what rundll32 does, step by step, and what process actually executes `DoWork`'s code.
6. **Exported functions.** What is an exported function, and how does a hosting process find it inside a loaded DLL?
7. **ProcessGuid.** Why is PID insufficient for correlating two events to the same process instance, and what does ProcessGuid solve that PID doesn't?
8. **Parent/child relationships.** Give an example of a parent/child process pairing (not from today's scenario) that would be high-signal on its own, and explain why.
9. **User-writable directories.** Name two locations attackers favor for staging payloads and explain the actual mechanism (not just "permissions") that makes them attractive.
10. **Run-key persistence.** Explain why `HKCU` Run-key persistence doesn't require administrator privileges, and what's actually being read and executed, and when.
11. **Evidence vs. inference.** You have a Sysmon Event ID 1 showing `rundll32.exe payload.dll,Go`, but no Event ID 7 for the load. State, precisely, what you can and cannot claim from this alone.
12. **Behavioral detection design.** Design a detection for a technique you have *not* seen written up — pick any persistence or execution technique you're aware of — and separate its core required conditions from its supporting/enrichment signals.

**Reminder:** this document is a reference and review lesson, not a replacement for Scenario Gym. It doesn't set the next session's topic — that stays adaptive, driven by the training log and whatever the broader curriculum indicates is most useful next.
