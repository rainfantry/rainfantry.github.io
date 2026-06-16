# Chapter 9 — TOCTOU: The Ambush Doctrine

## What Is TOCTOU?

**Time-of-Check to Time-of-Use** — a class of vulnerability where a system checks some condition, then later acts on the result of that check, but the condition changes between the check and the action.

This is ambush doctrine at its core. The enemy sends a recon element to clear the route. They report it safe. But between the recon element passing through and the main body following, you change the terrain. The main body walks into your kill zone.

```
SAFE version (no ambush):
  1. Recon: Is the route clear?     → Yes, route clear
  2. Main body advances             → Route IS clear ✓

TOCTOU version (ambush):
  1. Recon: Is the route clear?     → Yes, route clear
  2. --- AMBUSH FORCE MOVES INTO POSITION ---
  3. Main body advances             → Route is HOSTILE ✗
```

The enemy assumes the ground didn't change between their recon and their advance. We change the ground in that gap.

## TOCTOU in Filesystems

The classic filesystem TOCTOU — same principle, different terrain:

```c
// VULNERABLE CODE (simplified)
if (access("/tmp/safe_file", R_OK) == 0) {     // RECON: is it safe?
    // --- AMBUSH FORCE SWAPS THE FILE ---
    fp = fopen("/tmp/safe_file", "r");           // MAIN BODY: open it
    // Now reading a DIFFERENT file than what was cleared
}
```

Between `access()` and `fopen()`, the attacker replaces the file (or the directory it's in) with something else. The recon element cleared one position but the main body walked into a different one entirely.

## Our Specific TOCTOU

The enemy's quarantine procedure has an ambush-viable gap:

```
The enemy's SOP (simplified):

1. RECON:   Scan file at path P → it's hostile!
2. DECIDE:  Order QRF to detain at path P
3. --- GAP (ambush window) ---
4. ADVANCE: QRF opens file at path P for quarantine
5. ACT:     QRF moves/deletes file at path P
```

In the gap between steps 2 and 4 — between the recon element reporting and the main body advancing — we swap path P. We change the road signs. Path P no longer leads to our bait; it leads (via junction) to a system directory.

Now step 4 opens a file in the SYSTEM DIRECTORY, and step 5 writes there. The enemy operates as SYSTEM, so they have the clearance to write wherever the junction sends them. They just don't know they've been redirected.

## Why This Ambush Works

Four conditions must be true for an ambush to succeed:

### 1. We Control the Terrain
We can create and delete directories in `C:\Temp\`. We can set junctions on directories we own. Standard user permissions are sufficient to prepare the ambush site. No special access required.

### 2. The Enemy Doesn't Re-clear the Route
The enemy's recon element (the scan) clears the route once, then the main body advances on the same path without re-checking. If the enemy re-cleared the route before advancing — opened the file by HANDLE (not by path) — the ambush wouldn't work. The handle would still point to the original position regardless of junction changes. But they don't re-clear. That's the flaw.

### 3. The Enemy Has Superior Firepower
The enemy operates as SYSTEM. If they operated at our privilege level, redirecting them to System32 wouldn't matter — they'd have no access to write there either. The privilege asymmetry is what makes this valuable. We're using the enemy's own firepower against a target we can't reach ourselves.

### 4. The Timing Is Feasible
If the gap between recon and main body were nanoseconds, we couldn't set the ambush in time. But our full swap clocks at ~0.2ms (measured via QPC), and the enemy's scan-to-quarantine reaction gap runs 15-50ms. That's 30-250x headroom. Oplocks give us even more control — the kernel literally holds the enemy's advance for us while we prepare the kill zone.

## Blind Ambush vs. Observed Ambush

Without an observation post (oplock), you're setting a blind ambush — hoping the enemy comes through at the right time:

```
Without oplock — blind ambush (unreliable):
  Set bait → immediately start swapping → HOPE the enemy
  walks through during the swap → maybe contact, maybe not

  Success rate: 10-30% depending on conditions and luck
```

With an observation post (oplock), you have eyes on the enemy's movement. You know exactly when they enter the kill zone:

```
With oplock — observed ambush (reliable):
  Set bait → establish OP → WAIT for enemy movement → OP
  reports contact → execute ambush → enemy walks into kill zone

  Success rate: 80-100%
```

The oplock is your observation post calling the main body's position. It converts a probabilistic blind ambush into a deterministic, observed engagement. You don't HOPE to make contact at the right time — the kernel TELLS you when the enemy enters the kill zone.

## The Full Kill Chain

The complete operation from staging to contact to exfil, step by step:

```
SETUP PHASE — Staging Area
─────────────────────────────────────────────
1. Establish area of operations   C:\Temp\<random>\
2. Select target position         What we want to hit in System32
3. Stage payload                  C:\Temp\<random>\target.dll
   (the asset we want planted — this is our PAYLOAD)

TRIGGER PHASE — Setting the Ambush
─────────────────────────────────────────────
4. Prepare ambush site            C:\Temp\<random>\work\
5. Emplace bait                   C:\Temp\<random>\work\bait.exe
6. Establish observation post     FILE_FLAG_OVERLAPPED
7. OP begins observation          FSCTL_REQUEST_BATCH_OPLOCK
8. Wait for enemy movement        WaitForSingleObject(event, timeout)

   ... Enemy detects bait, moves to engage ...
   ... OP reports contact — kernel halts enemy advance ...

SWAP PHASE — Executing the Ambush (~0.2ms)
─────────────────────────────────────────────
9.  Collapse observation post     CloseHandle(hOplock)
10. Remove bait                   DeleteFileW(bait.exe)
11. Clear ambush site             RemoveDirectoryW(work)
12. Replace the road signs        CreateDirectoryW(work)
                                  SetReparsePoint(work → System32)

   ... Kernel releases the enemy's halted advance ...
   ... Enemy follows the new road signs into the kill zone ...

PAYLOAD PHASE — Rounds on Target
─────────────────────────────────────────────
13. Enemy acts on                 C:\Temp\<random>\work\bait.exe
    which now resolves to         C:\Windows\System32\bait.exe
14. Enemy writes/moves            as SYSTEM → has full access
15. Payload lands on target       in System32

ESCALATION PHASE — Exploitation (optional)
─────────────────────────────────────────────
16. Planted file gets loaded by a SYSTEM service
17. Code execution as SYSTEM — full escalation
```

## Timing Analysis — Quantifying the Kill Zone

| Operation | Time |
|-----------|------|
| CloseHandle (oplock) | ~0.01ms |
| DeleteFileW | ~0.05ms |
| RemoveDirectoryW | ~0.05ms |
| CreateDirectoryW | ~0.02ms |
| SetReparsePoint | ~0.1ms |
| **Total swap time** | **~0.2ms** (measured via QPC) |

The enemy's gap:

| Measurement | Time |
|-------------|------|
| Enemy reaction gap (scan-to-quarantine) | ~15-50ms |
| Our swap time | ~0.2ms |
| **Headroom** | **30-250x** |

The math: 15ms / 0.2ms = 75x at the tight end. 50ms / 0.2ms = 250x at the wide end. We call the conservative minimum 30x because environmental friction — system load, disk latency, scheduling jitter, background I/O — eats into the theoretical floor. Even at 30x, that's completing your ambush thirty times over before the enemy's main body clears the pause point.

We're not threading a needle. We're driving a truck through a hangar door. The swap takes a fifth of a millisecond. The enemy gives us fifteen to fifty. Guaranteed engagement.

## What Could Go Wrong?

### Enemy Maintains Continuous Contact
If the enemy keeps their original scan handle open AND uses that handle (not the path) for quarantine, the junction swap is irrelevant — the handle still points to the original file regardless of what we do to the road signs.

Current intelligence: the enemy re-opens by path for quarantine. They follow the road signs again instead of maintaining a fixed bearing on the original target. This is the flaw. If they fix this — if they start using handles instead of paths — the ambush doctrine is dead.

### No Enemy Movement (OP Reports Nothing)
If the guard rotation (RTP) is off, the enemy never patrols, never detects the bait, and the observation post never reports contact. We detect this via timeout — if no movement in 30 seconds, abort and exfil. No point waiting in an ambush position for an enemy that isn't coming.

### Route Blocked (Junction Countermeasures)
Windows has some anti-junction mitigations in specific components. The enemy may have blocked certain approach routes. We need to verify our specific avenue of approach isn't subject to these countermeasures.

### Counter-Ambush (Behavioral Detection)
If the enemy's counter-surveillance (BehaviorMonitoring) flags the oplock+junction+delete pattern as suspicious movement, our process gets killed — they've identified the ambush force. Mitigation: our movement pattern is common. Many installer programs perform identical operations — create directories, set up files, clean up, create junctions. We look like a logistics convoy, not a fighting patrol. But this needs to be tested on the target.

## The Advantage of a New Operator

Previous operators — RedSun and RoguePlanet — used the same ambush doctrine but with different trigger mechanisms (CF_API, virtual disks). Both had their faces on wanted posters within days.

Our operator:
- **Never been deployed** → no recognition profile exists anywhere in the enemy's intelligence database
- **Standard-issue loadout** → no distinctive kit for import table matching
- **Normal movement patterns** → indistinguishable from legitimate base traffic
- **Fresh face every time** → unique hash on every compilation

The only way the enemy detects us is by watching our movements in real-time (behavioral analysis). And our movements look like a normal logistics program going about its business.

## Modern Fortifications — What They've Hardened

The enemy hasn't been idle. Multiple defensive emplacements have been erected across Windows 11 since this class of attack first appeared in the field. Before we commit to the engagement, we need a terrain assessment — which fortifications are standing, which are manned, and which ones actually block our avenue of approach.

**Mitigations Matrix:**

| Fortification | Default Garrison (Win11 Consumer) | Impact on TOCTOU | Blocks WRITE or EXECUTION? | Bypass |
|---|---|---|---|---|
| **Controlled Folder Access (CFA)** | **OFF** | Blocks writes to protected folders (Documents, Desktop, etc.) even from SYSTEM. Would kill the exploit dead if the target directory is CFA-protected. | WRITE | Target a non-CFA-protected directory. System32 is not CFA-protected by default — CFA guards user data folders, not system folders. If the admin has added custom folders, recon first. |
| **Attack Surface Reduction (ASR)** | **Partial** (some rules ON in audit mode) | Certain rules target process creation from unusual locations, suspicious child processes, and Office macro behaviour. Could block execution of the planted file after it lands. | EXECUTION | Does not affect the file WRITE itself. The junction swap and Defender's write-as-SYSTEM complete regardless. ASR engages downstream when something tries to RUN the planted file. |
| **WDAC (Windows Defender Application Control)** | **OFF** (consumer) / Enterprise-only | Code integrity policies prevent execution of unsigned or unauthorized binaries. A planted DLL that isn't in the WDAC allow-list won't load. | EXECUTION | Doesn't prevent the write. Prevents the run. On consumer Win11 this fortification is unmanned — WDAC requires explicit enterprise deployment. |
| **VBS / HVCI (Virtualization-Based Security)** | **ON** (Win11 default on supported hardware) | Prevents unsigned kernel drivers from loading. Hypervisor-enforced code integrity. | Neither — N/A | Our exploit operates entirely in user mode. VBS/HVCI protects the kernel from unsigned drivers. We're planting user-mode files. This fortification faces a different threat axis entirely. |
| **Smart App Control (SAC)** | **Evaluation or OFF** | Reputation-based blocking of untrusted executables. Files without Microsoft's cloud reputation get blocked on execution. | EXECUTION | Doesn't affect the file write mechanism. Only engages when the planted file is executed. On most machines SAC is in evaluation mode or disabled — it turns itself off permanently if it detects too many blocks. |
| **Tamper Protection** | **ON** | Prevents modification of Defender settings via registry edits, group policy, or programmatic changes. Stops attackers from disabling Defender. | Neither — N/A | Tamper Protection guards the enemy's COMMAND STRUCTURE — their settings, their configuration. It does NOT protect the scan-to-quarantine operational pipeline itself. We're not trying to disable Defender. We're redirecting where Defender writes. Different attack entirely. |

**Tactical assessment:** The critical distinction is WRITE vs. EXECUTION. Our exploit proves arbitrary file write via SYSTEM-privileged Defender operations. Most modern fortifications (ASR, WDAC, SAC) engage at the EXECUTION phase — they block what happens AFTER the file lands, not the landing itself. CFA is the only mitigation that could block the write phase, and it's OFF by default on consumer Windows 11 and doesn't cover System32.

The enemy has fortified the exits, not the supply chain. We're poisoning what comes in through the loading dock, not trying to walk out the front door.

## Previous Engagements — Junction CVEs

We're not the first unit to use junction ambush doctrine. Previous operators have deployed junction-based attacks against specific Windows components, and Microsoft has patched each one individually. The battle damage assessments are public record:

| CVE | Target | What Happened |
|---|---|---|
| **CVE-2020-0668** | Windows Service Tracing | Junction-based EoP. Attacker used a junction to redirect Service Tracing log writes to arbitrary locations. SYSTEM-level write primitive. Patched Feb 2020. |
| **CVE-2020-1088** | Windows Error Reporting (WER) | Junction-based EoP. WER's crash dump pipeline followed junctions during file operations, enabling arbitrary writes as SYSTEM. Patched May 2020. |
| **CVE-2020-0787** | Background Intelligent Transfer Service (BITS) | Junction-based EoP. BITS followed junctions during file move operations. **Used in the wild by threat actors.** This one drew blood in live engagements before the patch landed. Patched Mar 2020. |

**The pattern is critical to understand.** Microsoft patches junction attacks on a per-component basis. Each patch fixes the SPECIFIC service or pipeline that was caught following junctions blindly. They do NOT patch the junction primitive itself — `IO_REPARSE_TAG_MOUNT_POINT` still works exactly as it always has. NTFS junctions are a legitimate filesystem feature used by installers, package managers, and development tools daily.

This means: every time a new Windows component is found to follow junctions during privileged file operations, it's a new vulnerability. The question for our engagement: has Defender's scan-to-quarantine pipeline been specifically hardened against junction redirection?

**Honest assessment:** Unknown without live testing. Microsoft may have patched this specific avenue in a quiet update. They may not have. The CVE pattern suggests they fix junction issues reactively — when a specific component is reported — not proactively across all SYSTEM-privileged file operations. But "suggests" isn't "confirmed." Phase 7 (live-fire exercise) is where we find out if this specific road is still open.

The junction primitive persists. New targets keep appearing. The question is never "do junctions work?" — it's "does THIS target still follow them?"

## Post-Exploitation — What Lands on Target

The current doctrine covers getting ordnance on target — a file written to a privileged location via Defender's own SYSTEM credentials. But what do we DO with that beachhead? Previous sections hand-waved this. Time to be specific.

**Critical caveat first:** The file that lands on target is whatever Defender's remediation pipeline writes during its quarantine operation. This may be the EICAR test string content, a quarantine metadata stub, or a move/delete operation — not necessarily arbitrary attacker-controlled content. The exploit proves arbitrary WRITE LOCATION, not arbitrary WRITE CONTENT. Content control is a separate operational challenge that depends on exactly how the enemy's quarantine procedure handles the file data.

That said — if we achieve controlled content (or even partial content control), these are the escalation paths from a file planted in a privileged directory:

### Path 1: DLL Search Order Hijacking

Windows services running as SYSTEM load DLLs by name, searching through a predictable order of directories. If we plant a DLL in System32 with the right name, a SYSTEM service loads it on next restart or service cycle.

```
Targets of opportunity:
  version.dll     — loaded by dozens of executables
  wer.dll         — Windows Error Reporting
  dbghelp.dll     — loaded by crash handlers
  Any DLL that a SYSTEM service imports but doesn't find
  in its own directory first → falls through to System32
```

The service does our heavy lifting. It loads the planted DLL with its own SYSTEM token. We go from file-on-disk to code-execution-as-SYSTEM without ever calling CreateProcess.

### Path 2: Image File Execution Options (IFEO)

If we can write to the registry via a planted file (or if we can write directly to `C:\Windows\System32`), IFEO lets us set a "debugger" for any executable. When that executable launches, Windows runs our debugger instead.

```
Registry path:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
    Image File Execution Options\<target.exe>\
      Debugger = "C:\path\to\our\binary.exe"

Effect: every launch of target.exe runs our binary first.
```

This requires registry write access or the ability to plant a file that triggers a registry modification. High value if achievable — every launch of the targeted binary is intercepted.

### Path 3: Service Binary Replacement

Direct replacement of a non-critical service executable. The service control manager runs it as SYSTEM on next service start.

```
High risk, high reward:
  - If the service is running, replacement fails (file locked)
  - If the replacement crashes, the service fails visibly
  - If the service has integrity checks, replacement is detected
  - If it works: clean SYSTEM execution on next boot/restart
```

This is the loud approach — kicking in the door rather than slipping through a window. Effective but leaves traces. Only viable if you control the content of the planted file with precision.

### Path 4: Scheduled Task Manipulation — Volatile Environment Hijack

A cross-pollination from the MiniPlasma research tree. The `%windir%` environment variable can be overridden per-user via `Volatile Environment` in the registry. Scheduled tasks that resolve `%windir%` at runtime can be redirected to execute from an attacker-controlled path.

```
The chain:
  1. Plant a file via our TOCTOU write
  2. Modify Volatile Environment to override %windir%
  3. A scheduled task resolves %windir%\System32\cmd.exe
  4. It finds OUR cmd.exe instead of the real one
  5. Code execution in the task's security context
```

This path is indirect — it doesn't require planting directly in System32. But it does require the ability to modify registry values, which may itself require a separate write primitive.

### Path 5: The Content Control Problem

All four paths above assume we control WHAT gets written, not just WHERE. This is the honest gap in the doctrine. Defender's quarantine operation may:

- **Delete** the file at the junction target (destructive, not useful for planting)
- **Move** the file to quarantine (removes content from target, opposite of what we want)
- **Write quarantine metadata** to the path (gives us a file, but with Defender's content, not ours)
- **Copy then delete** (briefly creates a file with original content at the junction target)

The exact behaviour depends on the quarantine implementation and may vary between Defender versions. Phase 7 testing must determine: does the enemy's procedure leave exploitable content at the redirected path, or does it leave garbage? If it leaves garbage, we have a write primitive with no content control — still useful for denial-of-service (overwriting critical files) but not for code execution.

**Bottom line:** The TOCTOU junction swap gives us a SYSTEM-privileged file operation at a location of our choosing. What that operation DOES — write, delete, move, copy — determines which post-exploitation paths are viable. Don't plan the victory parade until you've confirmed what ordnance actually lands.

## Key Takeaways

- TOCTOU = ambush doctrine: the enemy clears the route, you change the terrain, the main body walks into your kill zone
- The enemy scans a file path, we swap where that path leads, the enemy acts on the wrong position
- Oplocks = observation post calling the enemy's exact position — converts a blind ambush into a guaranteed engagement
- Our swap takes ~0.2ms (QPC-measured); the enemy's reaction gap is 15-50ms = 30-250x headroom. Comfortable kill zone.
- A new operator with no profile avoids all the recognition that burned previous operators
- The fundamental flaw is the enemy following the same route twice without re-clearing — reopening by path instead of maintaining handle continuity
- Standard user permissions are sufficient for every phase of the operation
