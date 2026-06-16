# Chapter 8 — Windows Defender: Enemy Force Disposition

## The Enemy Is Not One Unit

Before you mount an operation against any defensive position, you conduct an intelligence preparation of the battlefield. You map the enemy's order of battle — every unit, every asset, every layer of their defence. Defender isn't a lone sentry you can knife in the dark. It's a layered defensive position with forces deployed in both the forward area (kernel) and rear echelon (user mode).

```
┌──────────────────────────────────────────────────┐
│ User Mode                                         │
│                                                   │
│   MsMpEng.exe          The scan engine process    │
│   ├── mpengine.dll     The core scan library      │
│   ├── MpClient.dll     API for PowerShell/UI      │
│   └── MpRtp.dll        RealTime Protection logic  │
│                                                   │
│   SecurityHealthService.exe   The UI tray icon    │
│   MpCmdRun.exe                CLI interface       │
├──────────────────────────────────────────────────┤
│ Kernel Mode                                       │
│                                                   │
│   WdFilter.sys         Minifilter driver          │
│   WdNisDrv.sys         Network inspection driver  │
│   WdBoot.sys           Early-launch AM driver     │
└──────────────────────────────────────────────────┘
```

**MsMpEng.exe** is the enemy commander — the operations centre. It receives intel from the forward sentries, analyses it against known threat profiles, and issues the order to detain or wave through. It sits in user mode, running as SYSTEM, making all the tactical decisions.

**WdFilter.sys** is the forward checkpoint — sentries posted on every approach route into the base. Every file operation that crosses their position gets halted, inspected, and reported back to the ops centre. Nothing moves without the sentries seeing it.

For our operation, we interact with two components:
1. **WdFilter.sys** — the checkpoint guards that intercept file operations at the perimeter
2. **MsMpEng.exe** — the operations centre that scans and orders quarantine

## The Guard Rotation (RealTime Protection)

RTP is the enemy's patrol schedule — their standing operating procedure for inspecting everything that moves through the area of operations. It's not a periodic sweep; it's a permanent vehicle checkpoint where every convoy stops.

How the guard rotation works:

1. You write a file (or extract an archive, or download something)
2. WdFilter.sys intercepts the I/O operation in the kernel — the sentry stops you at the checkpoint
3. WdFilter radios MsMpEng.exe: "contact at the gate"
4. MsMpEng scans the file content against its signature database — the ops centre runs your face against the wanted posters
5. If clean → wave through, barrier lifts
6. If flagged → detain and quarantine

The inspection happens inline — like a vehicle checkpoint where EVERYTHING stops dead until the sentry clears you through. The application that created the file is PAUSED until the scan completes. This is why dropping an EICAR file sometimes feels slow — your process is standing at the gate while the sentry radios it in.

## The Detention Procedure (Quarantine)

When the enemy identifies a threat, the quarantine flow is their detention SOP:

```
1. WdFilter detects suspicious file via minifilter intercept
2. MsMpEng.exe reads the file content
3. mpengine.dll matches against signatures
4. Decision: QUARANTINE
5. MsMpEng opens the file path again (for the quarantine operation)
   ⚠ INTELLIGENCE CONFIDENCE: MODERATE. This step is inferred from
   behavioral observation — specifically, oplock break patterns that
   indicate a second file open on the same path after scan completion.
   We have NOT reverse-engineered Defender source code. The model fits
   observed behavior consistently across multiple engagements, but the
   internal mechanism may differ from our reconstruction. Treat this as
   assessed enemy doctrine, not confirmed SOP.
6. MsMpEng moves/renames the file to the quarantine folder
   C:\ProgramData\Microsoft\Windows Defender\Quarantine\
7. Original file is replaced with a quarantine stub or deleted
```

**Step 5 is the vulnerability.**

The sentry radios in the contact. The ops centre confirms hostile and orders detention. But then the QRF has to travel back to the checkpoint to actually grab the target. Between the detention order going out over the radio and the QRF physically arriving at the gate — there's dead time. That gap between the sentry's call and the QRF's arrival is where we operate.

## WdFilter.sys: The Checkpoint Guards

WdFilter is a **filesystem minifilter driver**. It registers with the Filter Manager (FltMgr.sys) to intercept specific file operations — like sentries with standing orders to stop and inspect particular types of traffic:

| Operation | What the Checkpoint Does |
|-----------|--------------------|
| `IRP_MJ_CREATE` | Checks if the target entering the gate is on the watch list |
| `IRP_MJ_WRITE` | Inspects cargo after delivery |
| `IRP_MJ_CLEANUP` | Final pat-down on departure |
| `IRP_MJ_SET_INFORMATION` | Watches for anyone trying to change their route or identity |

WdFilter has a high **altitude** (328010) in the filter stack, meaning it's one of the first checkpoints on the approach route. Almost nothing passes through without the sentries seeing it first. You can't dig a fighting position below them and intercept traffic before they do.

### The Scan Pipeline

```
Application writes file
        │
        ▼
WdFilter intercepts ──────► Send file path to MsMpEng
        │                          │
        │ (operation paused)       ▼
        │                   mpengine scans content
        │                          │
        │                   ┌──────┴──────┐
        │                   │             │
        │                 CLEAN        MALWARE
        │                   │             │
        │               Wave through    Detain
        ◄───────────── resume            │
                                         │
                                   Open file again ◄── THE GAP
                                         │
                                   Move to quarantine
```

The sentry calls in the suspect. The ops centre confirms hostile. But between the detention order being issued and the QRF physically arriving to execute the grab — dead time. That dead time is our window of operation.

## The Defensive Perimeter (Detection Layers)

The enemy doesn't rely on a single strand of wire. They've built defence in depth — multiple concentric rings, each catching what slipped through the last. Mutating one thing (like comms patterns) doesn't get you through all five layers.

### Outer Wire: Hash/IOC
The most basic wanted poster system. The enemy has a database of known-bad file hashes (SHA-256). If your face is on the poster, you're done before you reach the gate. This is why every fresh compilation with different flags produces a "new" binary — new face, no poster.

### Second Wire: String Signatures (YARA-like)
Specific byte patterns in the binary. The enemy knows what insurgent communications sound like — specific phrases, specific call sign formats. The `.rdata` section contains string literals, and if the enemy recognises known strings (like `TieringEngineService.exe` from a previous operation), you're flagged.

We defeated this layer with XOR encoding in the previous engagement — encrypting our comms so the pattern-matchers can't read them.

### Third Wire: Import Table Fingerprinting
Which DLLs the program imports and which functions it calls. This is the enemy recognising you by your kit and loadout. If you're carrying distinctive equipment that nobody else on base carries, you stand out:

```
CldApi.dll + ntdll.dll + specific CF_API functions = CF_API exploit
virtdisk.lib + bcrypt.lib + specific functions = disk-mount exploit
```

This is why GaySun (mutated RedSun) was still detected as `DfndrPERedSun.BC` — even with comms encrypted, the operator was still carrying distinctive kit. CldApi.dll is RedSun's signature loadout, and the enemy recognises it on sight.

The trick is to carry the same standard-issue gear as every other soldier on base. Everyone uses kernel32.dll and ntdll.dll. Wear the same uniform, blend in.

### Inner Wire: Behavioral / Heuristic
The enemy isn't just checking your uniform anymore — they're running counter-surveillance, watching how you move:
- Creating a process then injecting into it → suspicious patrol pattern
- Rapid file creation + deletion + junction creation → unusual movement
- Loading unusual DLLs in unusual combinations → wrong kit for the area

This is the hardest layer to defeat. But our operator has a major advantage: the API call pattern is COMMON. `CreateFile`, `DeviceIoControl`, `RemoveDirectory`, `CreateDirectory` — these are everyday base operations. Thousands of legitimate programs make the same movements. Nothing individually suspicious. Walk with purpose, follow normal routes, don't act squirrelly at the gate.

### The Bunker: Cloud Intelligence
The enemy can send suspicious contacts up the chain to specialist intel assets at higher headquarters for deeper analysis. Returns a verdict within seconds. This is "cloud-delivered protection" — the base calling in support from theatre command.

On the target machine, this adds latency but doesn't change the fundamental gap we're exploiting. The detention procedure is the same regardless of whether the identification came from local sentries or higher intel.

## Intelligence Assessment of the Target

From our recon of the target position:

```
OS:                    Windows 11 Home Build 26200 (24H2)
User:                  Standard user (REDACTED)
Tamper Protection:     OFF
HVCI:                  Running (but user-mode ACB OFF)
RealTimeProtection:    TRUE (enabled)
BehaviorMonitoring:    TRUE (enabled)
Cloud Protection:      Likely enabled (default)
Engine Version:        Current (auto-updates)
```

Key intelligence findings:
- **Standard user**: Can't disable the enemy's defences from inside the wire, can't add exclusion zones, can't modify their security posture. Our operation must succeed against a fully manned defensive position — no sabotage option.
- **Tamper Protection OFF**: One layer of the enemy's hardening is absent. We could potentially shut down their operations via service manipulation IF we had admin access. But we don't. Still — a gap in their posture noted for the record.
- **HVCI on, ACB off**: Hypervisor-based Code Integrity is active for kernel drivers, but user-mode Arbitrary Code Guard is OFF. Their hardware-enforced security perimeter doesn't cover our avenue of approach.
- **BehaviorMonitoring on**: Counter-surveillance is running. Our operator needs to move like normal base traffic — no unusual patterns.

## Why Our Operator Evades Detection

Compromised operators — published exploits like RedSun and RoguePlanet — got their faces plastered on every wanted poster in the theatre because:
1. Source code is public → intel analysts built recognition profiles from the source material
2. Distinctive loadouts (CldApi.dll, virtdisk.lib) — carrying kit nobody else carries
3. Specific comms patterns — using phrases the enemy has catalogued
4. Known operational signatures (PE structure fingerprints) — matching a known unit's TTPs

Our new operator has no profile, no prints on file:
1. **Never been deployed before** → no existing profile in any database, no face on any wanted poster
2. **Standard-issue loadout only** → `kernel32.dll`, `ntdll.dll` — same kit every other soldier on base is carrying
3. **No distinctive comms** → XOR-encoded EICAR, no tool names in cleartext. The EICAR itself is a blank round — a training round that draws the exact same defensive response as live fire. The sentries react to it identically to a real threat. We don't need a real weapon to exploit the gap; we just need the enemy to initiate their detention procedure.
4. **Generic silhouette** → looks like any C program compiled with MSVC yesterday. No tattoos, no distinguishing marks.

The API calls we use (`CreateFile`, `DeviceIoControl`, `DeleteFile`, `CreateDirectory`) are called by THOUSANDS of legitimate programs. Our operator walks, talks, and moves like every other soldier on base. There's no distinctive fingerprint.

## Cloud-Delivered Protection — The Satellite Uplink

The "Bunker: Cloud Intelligence" layer deserves its own full section, because it directly affects our timing model — and not in the direction you'd expect.

### MAPS: The Theatre Intelligence Network

**Microsoft Active Protection Service (MAPS)** is the enemy's strategic intelligence network. When the local sentries (WdFilter) flag something they can't positively identify from their own wanted posters, they radio it up the chain to theatre command — Microsoft's cloud analysis infrastructure.

This isn't a courtesy call. It's an integrated kill chain:

1. WdFilter intercepts a file at the checkpoint
2. MsMpEng runs local signature matching (the wanted poster check)
3. If the file is unknown or suspicious but not definitively hostile, MsMpEng transmits metadata (hash, file attributes, partial content) to MAPS
4. MAPS runs the contact against a global intelligence database — every engagement, every sample, every report from every base worldwide
5. Verdict returns: clean, suspicious, or hostile

The local base doesn't operate in isolation. It's feeding intel to and receiving intel from every other Defender installation on the planet. Your file has never been seen before? MAPS knows that too — and "never seen before" is itself a suspicious indicator.

Check MAPS configuration on the target:

```powershell
Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent
```

| MAPSReporting Value | Meaning |
|---------------------|---------|
| 0 | Disabled — base is operating independently, no uplink |
| 1 | Basic — sends minimal metadata (hash, detection name) |
| 2 | Advanced — sends full telemetry (file metadata, partial content, behavioral context) |

Default is **2 (Advanced)**. The base is feeding everything upstream.

### Cloud Block at First Sight — The Pre-emptive Strike

Here's where it gets dangerous — and then immediately useful.

**Cloud Block at First Sight** is the enemy's ability to issue a detention order BEFORE the local scan finishes. If the MAPS cloud verdict arrives while MsMpEng is still running local analysis, the cloud verdict takes priority. The enemy's theatre command can reach down and block a file at any local checkpoint, overriding the local commander's pace.

This means the enemy has TWO parallel analysis tracks:

```
File arrives at checkpoint
        │
        ├──► Local scan (MsMpEng + mpengine.dll)
        │         │
        │         ▼
        │    Local verdict
        │         │
        └──► Cloud query (MAPS)          ◄── PARALLEL
                  │
                  ▼
             Cloud verdict
                  │
        ┌─────────┴─────────┐
        │                   │
   Cloud says BLOCK    Cloud says CLEAN
        │                   │
   IMMEDIATE block    Wait for local scan
   (pre-empts local)  to complete normally
```

The `CloudBlockLevel` setting controls how trigger-happy the cloud is:

| CloudBlockLevel | Name | Behavior |
|-----------------|------|----------|
| 0 | Default | Standard cloud detection — blocks known threats |
| 2 | High | Aggressively blocks unknowns with moderate confidence |
| 4 | High+ | Blocks with minimal confidence — shoot first, ask questions later |
| 6 | Zero Tolerance | Blocks ANYTHING the cloud hasn't explicitly cleared — total lockdown |

```powershell
Get-MpPreference | Select-Object CloudBlockLevel, CloudExtendedTimeout
```

### Cloud Extended Timeout — The Longer Leash

When MsMpEng encounters a suspicious file, it can HOLD the file at the checkpoint for additional time while waiting for the cloud verdict. This is controlled by `CloudExtendedTimeout`:

- **Default for suspicious files**: 10 seconds of additional hold time
- **Maximum configurable**: 50 seconds
- **Purpose**: gives theatre command more time to run deep analysis before the local base has to make a go/no-go decision

During this hold, the application that created the file is PAUSED. The sentry is standing there with his hand on the barrier, radio in the other hand, waiting for the all-clear from higher.

### Sample Submission — The Enemy Takes Your Gear

If the local base can't make a determination, Defender may **upload the entire file** to Microsoft for analysis. Not just metadata — the actual binary. Your operator, shipped to the enemy's rear echelon lab for dissection.

`SubmitSamplesConsent` controls this:

| Value | Behavior |
|-------|----------|
| 0 | Always prompt the user before uploading |
| 1 | Send safe samples automatically (default) |
| 2 | Never send |
| 3 | Send all samples automatically |

### What Cloud Means for the TOCTOU Timing Model

Here's the tactical punchline, and pay attention because this is counterintuitive:

**Cloud protection HELPS the attacker.**

The cloud adds latency to the enemy's decision loop. Every second MsMpEng spends waiting for a MAPS verdict is another second in the gap between check and use. The enemy's own intelligence network is slowing down their QRF response:

```
WITHOUT cloud:
  Detect ──► Scan (fast) ──► Quarantine order ──► Re-open file
  │                                                          │
  └──── GAP: small ──────────────────────────────────────────┘

WITH cloud:
  Detect ──► Scan ──► Cloud query ──► Wait... ──► Verdict ──► Quarantine ──► Re-open
  │                                                                                │
  └──── GAP: LARGER ──────────────────────────────────────────────────────────────┘
```

The `CloudExtendedTimeout` is literally the enemy extending our window of operation. They're calling for air support while we're already inside the wire. By the time the jets arrive, the swap is done.

This doesn't mean we RELY on cloud latency — our oplock-based trigger fires on the re-open regardless of timing. But cloud protection means the timing is MORE forgiving, not less. The enemy's attempt to be more thorough gives us more room to manoeuvre.

Full cloud reconnaissance command:

```powershell
Get-MpPreference | Select-Object Cloud*, MAPS*, SubmitSamplesConsent
```

## Detection Footprint — Know Your Signature

Every operation leaves traces. Every movement through the area creates marks in the mud that a competent tracker can follow. Before you execute, you need to know exactly what signatures you leave on the battlefield — because the enemy's counter-intelligence apparatus is watching, and they've got listening posts you may not even know about.

This section is the enemy's SIGINT capability assessment. Know it before you step off.

### ETW: The Enemy's Wire Taps

**Event Tracing for Windows (ETW)** is the enemy's signals intelligence backbone. These are listening posts hardwired into the operating system itself — passive collection infrastructure that records everything that happens on the box.

The critical provider for our operation:

**`Microsoft-Windows-Kernel-File`** — this provider logs file system operations at the kernel level. Junction creation, file deletion, directory manipulation — every move we make through the filesystem is potentially captured on this wire tap.

ETW doesn't block operations. It doesn't intercept. It just RECORDS. The data sits in event logs, waiting for an analyst to come looking. If no one's listening, the tapes pile up unreviewed. If someone IS listening — if they've got a SOC analyst or a SIEM pulling these feeds in real-time — then your operation is being recorded as it happens.

### Sysmon: The Enemy's Surveillance Network

**Sysmon** (System Monitor) is Microsoft's purpose-built surveillance tool. If ETW is passive wire taps, Sysmon is the enemy's dedicated surveillance team — actively monitoring, filtering, and logging specific events of operational interest.

Sysmon is NOT installed by default. It's an add-on the enemy deploys when they're serious about monitoring. Home users almost never have it. Corporate environments and SOC-monitored networks — that's where Sysmon lives.

The event IDs that light up your operation:

| Sysmon Event ID | Event Name | What It Catches |
|-----------------|------------|-----------------|
| **11** | FileCreate | Fires when a file or directory is created. Your bait file creation, your junction directory creation — Event 11 sees all of it. |
| **15** | FileCreateStreamHash | Fires on reparse point creation. A junction IS a reparse point. This is the event that specifically fingerprints our pivot manoeuvre — the junction swap itself. |
| **23** | FileDelete | Fires on file deletion. When you delete the bait directory to replace it with a junction, Event 23 logs the removal. |

The operational sequence from the enemy's surveillance perspective:

```
Your operation:                    What Sysmon logs:

1. Create bait dir + file    ──►  Event 11: FileCreate (directory)
                                  Event 11: FileCreate (bait file)

2. Oplock fires, delete dir  ──►  Event 23: FileDelete (bait file)
                                  Event 23: FileDelete (directory)

3. Create junction           ──►  Event 11: FileCreate (junction dir)
                                  Event 15: FileCreateStreamHash (reparse point)

4. Defender quarantines      ──►  (Defender's own telemetry)
   the target file
```

Four events in rapid succession, all in `%TEMP%` or `%APPDATA%`, all within milliseconds of a Defender detection event. That's a SIGNATURE. Any detection engineer worth their rank can write a correlation rule: "junction creation in a temp directory within N seconds of a Defender quarantine event = TOCTOU exploit in progress."

### Detection Logic: Temporal Correlation

The individual events aren't suspicious. Programs create files. Programs delete directories. Junctions exist for legitimate purposes.

What makes it detectable is the **temporal correlation**:

```
DETECTION RULE (enemy analyst perspective):

IF:
  - Sysmon Event 11 (FileCreate) in %TEMP% or %APPDATA%
  - FOLLOWED BY Sysmon Event 23 (FileDelete) on same path
  - FOLLOWED BY Sysmon Event 15 (FileCreateStreamHash/reparse point) on same path
  - ALL within < 5 seconds
  - AND a Windows Defender detection event (Event ID 1116/1117) fires
    within ± 10 seconds on the same path or parent directory

THEN:
  → TOCTOU junction swap exploit — HIGH CONFIDENCE
```

The signal isn't any single event. It's the PATTERN — junction creation correlated with a Defender detection in a tight time window. A tracker doesn't follow one footprint; they follow the trail.

### File System Audit Policies

Windows has built-in audit capabilities that don't require Sysmon:

**Advanced Audit Policy → Object Access → Audit File System**

When enabled, this generates Security Event Log entries (Event ID 4663) for file system operations including:
- File creation and deletion
- Directory creation and deletion
- Reparse point operations

```powershell
# Check current audit policy
auditpol /get /subcategory:"File System"
```

Most home machines have this disabled — it generates enormous log volume. But enterprise environments and hardened targets may have it active, especially on sensitive directories.

### WdFilter's Own Logging

WdFilter.sys doesn't just intercept — it can log what it intercepts. Defender's own operational event logs live at:

```
Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational
```

Key event IDs from Defender's own logs:

| Event ID | What It Records |
|----------|-----------------|
| 1116 | Malware detection — the initial identification |
| 1117 | Action taken (quarantine, remove, allow) |
| 1006 | Scan completed |
| 1007 | Action taken to restore quarantined item |

These events record the enemy's OWN operations. They're the after-action reports filed by the checkpoint guards. Event 1116 followed immediately by 1117 on a path that no longer contains the original file — that's the fingerprint of a successful swap. The enemy detained someone, but when they check the cell, the prisoner has been replaced.

### AMSI: What It Does NOT Cover

**Anti-Malware Scan Interface (AMSI)** is the enemy's script and memory scanner. It hooks into PowerShell, VBScript, JScript, Office macros, and .NET assemblies to scan content as it's interpreted or loaded into memory.

**AMSI does NOT cover this attack vector.**

Our operation is a file system race condition exploiting reparse points. We're not executing scripts. We're not loading .NET assemblies through the AMSI-instrumented pipeline. We're making Win32 API calls — `CreateFile`, `DeviceIoControl`, `DeleteFile` — that operate below AMSI's coverage area.

AMSI is the enemy's checkpoint for the scripting highway. We're not on the highway. We're moving through the bush on a dirt track that AMSI doesn't patrol.

### Operational Security Assessment

**What traces your operation leaves:**

| Trace | Source | Default On? | Risk Level |
|-------|--------|-------------|------------|
| Junction creation in temp dir | Sysmon Event 15 | NO (requires Sysmon) | HIGH if present |
| File create/delete sequence | Sysmon Event 11/23 | NO (requires Sysmon) | MEDIUM |
| Defender detection + quarantine | Defender Event 1116/1117 | YES (always) | LOW alone, HIGH if correlated |
| ETW kernel file events | ETW provider | Passive, requires consumer | LOW (rarely monitored live) |
| File system audit events | Security log 4663 | NO (audit policy) | MEDIUM if enabled |
| AMSI telemetry | AMSI hooks | YES but irrelevant | NONE — not in our attack surface |

**Bottom line for the operator:**

On a home machine with no Sysmon, no file audit policies, and no SIEM — your operation leaves almost no actionable traces. Defender logs the detection and quarantine (Events 1116/1117), but those events fire whether or not a TOCTOU swap occurred. The quarantine itself is expected behavior. Without Sysmon's junction-specific logging (Event 15), there's no evidence that the quarantine targeted the wrong file.

On a monitored enterprise box with Sysmon and a SOC watching — your operation is VISIBLE. The junction creation in a temp directory correlated with a Defender detection is a bright flare in the night sky. Any competent threat hunter will see it.

**Know your terrain. A home target and a corporate target are different battlefields.**

## Key Takeaways

- The enemy force = WdFilter.sys (forward sentries in the kernel) + MsMpEng.exe (operations centre in user mode)
- The guard rotation (RTP) intercepts every file operation inline at the checkpoint — nothing moves without inspection
- The gap between the sentry's radio call and the QRF arriving = the TOCTOU window we exploit
- Defence in depth: five concentric perimeter layers from outer wire to bunker
- Compromised operators (published exploits) get their faces on wanted posters within days — distinctive loadouts and comms patterns give them away
- Our operator uses only standard-issue kit (Win32 APIs) = no distinctive fingerprint, no profile on file
- Standard user can't disable the enemy's defences — we go through them, not around them
- Counter-surveillance watches movement patterns, but our operator walks like every other soldier on base
- Cloud protection (MAPS) adds latency to the enemy's decision loop — the satellite uplink WIDENS our ambush window, not narrows it
- `CloudBlockLevel` and `CloudExtendedTimeout` control how long the enemy holds files at the gate waiting for theatre command — more waiting = more time for the swap
- The quarantine re-open (step 5) is assessed from behavioral observation (oplock breaks), not confirmed via source code — moderate confidence
- Sysmon Events 11/15/23 are the enemy's surveillance network for junction operations — if Sysmon is deployed, your swap is VISIBLE
- Home targets without Sysmon leave minimal forensic traces; enterprise targets with Sysmon and a SOC are a different battlefield entirely
- AMSI does not cover this attack vector — our operation moves below the scripting highway on a dirt track AMSI doesn't patrol
- Temporal correlation is the detection signal: junction creation + Defender detection within seconds = high-confidence TOCTOU signature
