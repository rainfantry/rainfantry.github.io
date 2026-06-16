# Chapter 11 — Enemy Comms: Defender's RPC Attack Surface

## Mission Brief

Every chapter up to this point has treated Defender as a black box — a sentry you provoke and race against. You drop bait, arm the tripwire, and exploit the gap. But Defender is not just a patrol. It's a full-featured command post with a **radio network** — an RPC interface with **236 documented procedures** exposed by the MpSvc service.

That means any process on the system can, in theory, pick up a radio and call the enemy's operations centre directly. Not provoke it. Not trick it. **Talk to it.** Request scans. Modify configurations. Toggle features. Restore quarantined files. Roll back signatures.

The interface UUID — the enemy's radio frequency — is:

```
c503f532-443a-4c69-8300-ccd1fbdb3839
MpSvc, version 2.0
```

This intelligence comes from a project called **BlueHammer**, which reverse-engineered the RPC interface definition from Defender's binaries and produced a complete IDL (Interface Definition Language) file — `windefend.idl` — listing every procedure, its number, and its parameter signature.

This is not a file scanner you're dealing with. This is a full C2 infrastructure with 236 channels, and we have the codebook.

## What Is RPC?

If you know C but not RPC, here's the short version.

**Remote Procedure Call** lets you call a function in another process as if it were a local function call. Your process (the client) says "call function #6 with these arguments" and the operating system routes that call to the server process, executes it, and returns the result. The client and server can be on the same machine or across a network — the mechanism is identical.

The moving parts:

```
┌──────────────────────────────────────────────────────────────┐
│                         RPC Architecture                      │
│                                                               │
│   CLIENT (your code)           SERVER (MsMpEng.exe / MpSvc)  │
│   ┌─────────────────┐         ┌─────────────────────────┐    │
│   │ Call Proc6(args) │ ──RPC──▶│ ServerMpOnDemandStartScan│   │
│   │                 │         │ (executes as SYSTEM)     │    │
│   │ ◀── result ─────│ ◀──────│                          │    │
│   └─────────────────┘         └─────────────────────────┘    │
│                                                               │
│   Connection:                                                 │
│   RpcBindingFromStringBinding(                                │
│     "ncalrpc:[c503f532-443a-4c69-8300-ccd1fbdb3839]"         │
│   )                                                          │
│                                                               │
│   "ncalrpc" = local RPC (same machine, no network)           │
│   UUID      = which interface (which radio frequency)         │
│   Proc#     = which function to call (which channel)          │
└──────────────────────────────────────────────────────────────┘
```

The IDL file is the **interface definition** — it specifies every procedure the server exposes, what parameters each takes, and what it returns. The MIDL compiler processes the IDL and generates client/server stubs — the glue code that serialises arguments, ships them across the process boundary, and deserialises them on the other end.

Think of it this way:

| RPC Concept | Military Equivalent |
|---|---|
| IDL file | Captured enemy comms plan — every frequency, every callsign, every procedure word |
| UUID | The enemy's radio frequency |
| Procedure number | Channel number on that frequency |
| Client stub | Your radio, tuned to the enemy's frequency |
| Server (MpSvc) | The enemy's operations centre, receiving your transmissions |
| `ncalrpc` binding | Line-of-sight comms (local machine only) |
| MIDL compiler | The signals equipment that builds you a compatible radio |

We have the captured comms plan. We know the frequency. We know every channel. The question is: which channels does the enemy actually let us transmit on?

## The Attack Surface Map

236 procedures is a lot of channels. Not all of them are relevant to our operation. Below is the tactical breakdown — grouped by what they control and why each group matters.

### Scan Control — TOCTOU Force Multiplier

These are the procedures that let you **trigger, pause, and cancel scans programmatically**.

| Proc# | Name | What It Does |
|---|---|---|
| 6 | `ServerMpOnDemandStartScan` | Trigger an on-demand scan on an arbitrary file path |
| 9 | `ServerMpOnDemandControlScan` | Pause, resume, or cancel an active scan |
| 233 | `ServerMpOnDemandCancelScan` | Cancel a scan mid-flight |

**Why this matters for TOCTOU:**

In our current kill chain (Chapter 10), we rely on Real-Time Protection to detect the EICAR bait. We drop the bait, arm the oplock, and wait for the enemy patrol to stumble onto it. The timing is probabilistic — RTP picks it up when it picks it up. Could be 50ms, could be 500ms.

But if we can call `ServerMpOnDemandStartScan` directly with the bait file's path, we get a **deterministic trigger**. We control exactly when the scan starts. The operation goes from ambush-by-opportunity to ambush-by-appointment:

```
CURRENT (RTP trigger — probabilistic):
  1. Drop EICAR bait
  2. Arm oplock
  3. Wait for RTP patrol to stumble onto it  ← VARIABLE timing
  4. Oplock breaks → swap junction

RPC TRIGGER (deterministic):
  1. Drop clean file (not EICAR — no RTP alert)
  2. Arm oplock
  3. Call ServerMpOnDemandStartScan(baitPath)  ← WE control timing
  4. Oplock breaks → swap junction
```

Notice the second approach doesn't even need EICAR. You could drop a clean file, set the oplock, then tell Defender to scan it. The scan itself opens the file — the oplock breaks regardless of whether the file is clean or hostile. The scan is just a mechanism to make Defender open a path we control. The file content doesn't matter. The file PATH matters.

This is the difference between waiting for the enemy convoy to drive through your kill zone on their regular schedule, versus calling in a fake contact report that forces them to send a patrol exactly where you want them.

### Configuration Manipulation — Rewriting the Enemy's SOPs

These procedures let you **modify Defender's configuration** — the rules the enemy operates by.

| Proc# | Name | What It Does |
|---|---|---|
| 46 | `ServerMpRpcConfigSetValue` | Set an arbitrary Defender config value by registry path |
| 47 | `ServerMpRpcConfigDelValue` | Delete a config value |
| 204 | `ServerMpRpcConfigRefresh` | Force Defender to reload its configuration |
| 220 | `ServerMpRpcConfigImportPayload` | Import an entire configuration blob |

**Why this matters:**

Defender's configuration lives in the registry under `HKLM\SOFTWARE\Microsoft\Windows Defender\`. This includes:

- **Exclusion paths** — directories Defender ignores entirely
- **Scan behavior** — what types of files to scan, how deep to recurse
- **Cloud settings** — whether to phone home for cloud-based detection
- **Feature flags** — which protection components are active

If you can call `ConfigSetValue` with the right registry path, you could theoretically add your working directory to the exclusions list. That's not a race condition. That's walking into the enemy's command post and rewriting their patrol orders.

`ConfigRefresh` (Proc204) is the follow-up — after changing the rules, you force the enemy to re-read their orders. Change takes effect immediately.

`ConfigImportPayload` (Proc220) is the nuclear option — import a complete configuration blob. Swap out the entire SOP at once.

### Feature Control — The Kill Switches

The simplest and most brutal procedures in the entire interface.

| Proc# | Name | What It Does |
|---|---|---|
| 0 | `ServerMpEnableFeature` | Enable a Defender feature |
| 1 | `ServerMpDisableFeature` | Disable a Defender feature |

**Why this matters:**

`DisableFeature` is Proc1 — the very first operational procedure after the enable. If you can call it with the right feature ID, you could turn off RTP programmatically. No PowerShell. No `Set-MpPreference`. No admin prompt. Just a raw RPC call.

Of course, this is the one most likely to be locked down by Tamper Protection. The enemy knows this is their most critical switch. But the procedure EXISTS. The channel is on the frequency list. Whether we can transmit on it is a different question.

### Elevation Primitives — The Enemy's Own Ladder

Defender has its own internal elevation mechanism — procedures that open and manage elevation contexts.

| Proc# | Name | What It Does |
|---|---|---|
| 48 | `ServerMpRpcElevationHandleOpen` | Open an elevation handle |
| 49 | `ServerMpRpcElevationHandleAttach` | Attach to an elevation context |
| 51 | `ServerMpRpcElevateCleanHandle` | Elevate a clean handle |

**Why this matters:**

Defender sometimes needs to perform operations that require higher privilege than the calling context. These procedures manage that escalation. If the access controls are weak — if a standard user can call `ElevationHandleOpen` and get back a handle with elevated privileges — that's a privilege escalation primitive built into the enemy's own infrastructure.

The enemy left a ladder leaning against their own wall. The question is whether they locked the gate at the bottom.

### Quarantine Operations — Raiding the Detention Facility

These procedures manage Defender's quarantine — the detention area where flagged files are held.

| Proc# | Name | What It Does |
|---|---|---|
| 34 | `ServerMpEnumerateQuarantinedThreats` | List all quarantined files |
| 35 | `ServerMpQueryQuarantinedThreat` | Query details of a specific quarantined file |
| 37 | `ServerMpDeleteQuarantinedThreat` | Delete a quarantined file permanently |
| 38 | `ServerMpQuarantineRestoreThreat` | Restore a quarantined file to a specified path |
| 39 | `ServerMpDeleteAllQuarantinedThreats` | Purge the entire quarantine |

**Why this matters:**

`RestoreThreat` (Proc38) is the money channel. If you can call it with a controlled path argument, you're telling Defender: "Take this known-malicious file from quarantine and put it HERE." If "HERE" is a system directory you can't normally write to — but Defender CAN because it runs as SYSTEM — that's another file-write primitive. Different mechanism, same effect as the TOCTOU junction swap.

The operational sequence:

```
1. Get a file quarantined (easy — drop EICAR, let RTP grab it)
2. Call RestoreThreat with path = "C:\Windows\System32\target.exe"
3. Defender restores the file to System32, running as SYSTEM
4. Standard user just wrote to System32 via Defender's own hands
```

Whether the path parameter is validated (does Defender check if the restore path matches the original location?) is unknown without testing. But the procedure accepts a path. If that path isn't locked down, this is a cleaner file-write primitive than the TOCTOU race — no timing involved at all.

### Signature and Engine Control — Blinding the Enemy

These procedures control Defender's signature database and scan engine — the enemy's intelligence files and analysis capability.

| Proc# | Name | What It Does |
|---|---|---|
| 42 | `ServerMpUpdateEngineSignature` | Update signatures from a specified path |
| 43 | `ServerMpRollbackEngineSignature` | Roll back to an older signature version |
| 85 | `ServerMpFastPathAddSignature` | Fast-path: add a signature |
| 86 | `ServerMpFastPathRemoveSignature` | Fast-path: remove a signature |

**Why this matters — the downgrade attack:**

`RollbackEngineSignature` is Proc43. If you can call it, you roll the enemy's intelligence back to an older version — one that doesn't know about your payload. Like destroying the enemy's latest intelligence briefing and leaving them with last month's wanted posters.

`UpdateEngineSignature` from a specified path is Proc42. If the path isn't validated, you could point it at a crafted signature database — feeding the enemy disinformation.

`FastPathRemoveSignature` (Proc86) is surgical — remove a specific signature. If you know which signature detects your payload, remove just that one. Targeted intelligence sabotage rather than burning the whole filing cabinet.

### AMSI Control — Blinding the Script Sentries

AMSI (Antimalware Scan Interface) is how Defender inspects scripts — PowerShell, VBScript, JavaScript — before they execute. These procedures interact with that subsystem.

| Proc# | Name | What It Does |
|---|---|---|
| 94 | `ServerMpRpcMemoryScanStart` | Start a memory scan targeting a specific PID |
| 97 | `ServerMpRpcFastMemoryScanStart` | Fast-path memory scan |
| 98 | `ServerMpRpcFastMemoryScanResult` | Get results of fast memory scan |
| 101 | `ServerMpRpcAmsiCloseSession` | Close an AMSI session by handle |

**Why this matters:**

AMSI sessions are the mechanism by which script engines (PowerShell, etc.) feed content to Defender for scanning. `AmsiCloseSession` (Proc101) closes a session by handle. If you can enumerate active AMSI session handles and close them, you potentially blind script-based detection for running script engines.

`MemoryScanStart` (Proc94) is interesting from the other direction — you can request a memory scan of a specific process by PID. Weaponised defensively (point it at a suspicious process) or offensively (cause Defender to spend cycles scanning your decoy process while your real payload runs elsewhere).

### ASR Rules — Whitelisting Your Own Weapon

Attack Surface Reduction rules are Defender's tactical restrictions — blocking specific dangerous behaviors like Office macros spawning child processes, credential theft from LSASS, etc.

| Proc# | Name | What It Does |
|---|---|---|
| 143 | `ServerMpRpcGetAsrBlockedProcesses` | Query which processes ASR has blocked |
| 162 | `ServerMpRpcAsrSetHipsUserExclusion` | Set a user exclusion for ASR rules |

**Why this matters:**

`AsrSetHipsUserExclusion` (Proc162) lets you whitelist a process from ASR rules. If you can call this, you exclude your exploit binary from ASR enforcement. The enemy's tactical restrictions no longer apply to you — like getting your vehicle added to the checkpoint's pre-cleared list.

### Smart App Control — Bypassing Reputation Gates

Smart App Control is Defender's reputation-based blocking — files without established reputation are blocked from executing.

| Proc# | Name | What It Does |
|---|---|---|
| 218 | `ServerMpRpcQuerySmartAppControlState` | Query SAC state |
| 219 | `ServerMpRpcResetSmartAppControlState` | Reset SAC state |
| 234 | `ServerMpRpcForceResetSmartAppControl` | Force-reset SAC state |

**Why this matters:**

Smart App Control operates in evaluation mode, enforcement mode, or off. If you can call `ResetSmartAppControlState` or `ForceResetSmartAppControl`, you potentially toggle it off entirely — removing the reputation gate that blocks unknown executables. Your compiled exploit binary (which has zero reputation) would execute without SAC interference.

### The Full Channel Map — Summary

```
┌────────────────────────────────────────────────────────────────────┐
│         DEFENDER RPC ATTACK SURFACE — 236 PROCEDURES               │
│         UUID: c503f532-443a-4c69-8300-ccd1fbdb3839                │
│                                                                    │
│  ┌─── Scan Control (3 procs) ──── TOCTOU force multiplier         │
│  │    Proc6: StartScan   Proc9: ControlScan   Proc233: Cancel     │
│  │                                                                 │
│  ├─── Config Manipulation (4 procs) ──── Rewrite enemy SOPs       │
│  │    Proc46: SetValue   Proc47: DelValue                          │
│  │    Proc204: Refresh   Proc220: ImportPayload                    │
│  │                                                                 │
│  ├─── Feature Control (2 procs) ──── Kill switches                 │
│  │    Proc0: Enable   Proc1: Disable                               │
│  │                                                                 │
│  ├─── Elevation (3 procs) ──── Enemy's own ladder                  │
│  │    Proc48: Open   Proc49: Attach   Proc51: Elevate              │
│  │                                                                 │
│  ├─── Quarantine (6 procs) ──── Raid the detention facility        │
│  │    Proc34-39: Enum, Query, Delete, Restore, DeleteAll           │
│  │                                                                 │
│  ├─── Signatures (4 procs) ──── Blind the enemy                   │
│  │    Proc42: Update   Proc43: Rollback                            │
│  │    Proc85-86: FastPath add/remove                               │
│  │                                                                 │
│  ├─── AMSI (4 procs) ──── Script sentry control                   │
│  │    Proc94: MemScan   Proc97-98: FastMemScan                     │
│  │    Proc101: CloseSession                                        │
│  │                                                                 │
│  ├─── ASR Rules (2 procs) ──── Whitelist your weapon               │
│  │    Proc143: GetBlocked   Proc162: SetExclusion                  │
│  │                                                                 │
│  ├─── Smart App Control (3 procs) ──── Bypass reputation gate      │
│  │    Proc218: Query   Proc219: Reset   Proc234: ForceReset        │
│  │                                                                 │
│  └─── Remaining ~205 procs ──── Unmapped territory                 │
│       Notification callbacks, status queries, telemetry,           │
│       session management, health reporting, update control,        │
│       threat remediation, network inspection state...              │
└────────────────────────────────────────────────────────────────────┘
```

## Access Control — Who Can Transmit on Which Channel?

Having the codebook doesn't mean you can transmit. The enemy encrypts some channels and monitors others for unauthorised traffic. The access control question is: **what can a standard user actually call?**

### Tamper Protection — Encrypted Channels

Tamper Protection is Microsoft's lockdown mechanism — it prevents modifications to Defender's core settings even by administrators. When Tamper Protection is ON, certain RPC procedures will reject calls even from elevated processes. These are the encrypted channels we can't currently decode.

Procedures most likely guarded by Tamper Protection:
- `ServerMpDisableFeature` (Proc1) — turning off RTP
- `ServerMpRpcConfigSetValue` (Proc46) — modifying config
- `ServerMpRpcConfigDelValue` (Proc47) — deleting config
- `ServerMpRollbackEngineSignature` (Proc43) — signature rollback

Tamper Protection is the enemy's COMSEC (communications security). Even if you're on the right frequency with the right codebook, the encryption prevents you from transmitting anything useful. Breaking COMSEC is a different operation entirely.

### Service Security Descriptor — The Gate Guard

The RPC endpoint's access control starts with the service's security descriptor. Query it:

```cmd
sc sdshow WinDefend
```

This returns an SDDL (Security Descriptor Definition Language) string that defines who can interact with the service. A typical output looks like:

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)...
```

Reading this (the short version):
- `SY` = SYSTEM — full access
- `BA` = Built-in Administrators — broad access
- `BU` / `IU` = Built-in Users / Interactive Users — restricted access

The specific access rights granted to standard users determine which RPC procedures they can reach. This is the first gate. The RPC runtime checks the caller's token against these permissions before dispatching any call.

### Per-Procedure Access Checks — Channel-Level Security

Beyond the endpoint-level check, individual procedures may perform their own authorisation. A procedure might:
- Check if the caller is running elevated
- Verify the caller's token has specific privileges
- Require the caller to be a member of a specific group
- Check Tamper Protection state before proceeding

This is a two-layer defence: the gate guard at the compound entrance (endpoint ACL), and the individual office locks inside (per-procedure checks).

### The Access Matrix — What We Don't Know

| Caller Context | Scan Control | Config | Features | Elevation | Quarantine | Signatures |
|---|---|---|---|---|---|---|
| Standard User | **?** | **?** | **?** | **?** | **?** | **?** |
| Admin (non-elevated) | **?** | **?** | **?** | **?** | **?** | **?** |
| Admin (elevated) | **?** | Likely | Tamper? | **?** | Likely | Tamper? |
| SYSTEM | Yes | Yes | Yes | Yes | Yes | Yes |

Every `?` in this table is unexplored territory. The IDL gives us the map of what channels exist. Actual access testing — building an RPC client, binding to the interface, calling each procedure as different user contexts, and recording what succeeds vs. what returns `ERROR_ACCESS_DENIED` — is the recon mission that hasn't been run yet.

## Reconnaissance Tools

### RpcView — The SIGINT Listening Station

**RpcView** is the primary tool for enumerating RPC interfaces on a live system. Think of it as a signals intelligence platform — it passively intercepts and catalogues every radio frequency the enemy is transmitting on.

Procedure:
1. Download and run RpcView (requires admin for full enumeration)
2. Find the WinDefend / MsMpEng.exe process in the process list
3. Locate the interface with UUID `c503f532-443a-4c69-8300-ccd1fbdb3839`
4. Browse the procedure list — RpcView shows procedure numbers and can display decompiled parameter signatures

RpcView shows you the LIVE interface — what's actually registered and running on your target system. The IDL is the theoretical map; RpcView is boots-on-ground confirmation.

### rpcdump.py — Command-Line SIGINT

From Impacket (Python security toolkit):

```bash
rpcdump.py localhost
```

Enumerates all registered RPC interfaces on the local machine. Less detail than RpcView but scriptable and doesn't require a GUI. Good for automated recon — include it in a pre-engagement enumeration script.

### Reverse Engineering — Reading the Enemy's Mail

The IDL gives you the **signatures** — function names, parameter types, return types. It tells you what the radio channels are called and what format the messages use. It does NOT tell you what happens when the enemy receives the message.

To understand the **implementation** — what each procedure actually does when called — you need to reverse-engineer the binaries:

| Binary | What It Contains |
|---|---|
| `MpSvc.dll` | The RPC server implementation — procedure dispatch, argument validation, access checks |
| `MpClient.dll` | The official RPC client — how Microsoft's own tools call these procedures |
| `mpengine.dll` | The scan engine — what actually happens when a scan is triggered |

Tools: IDA Pro or Ghidra. Load `MpSvc.dll`, find the RPC server registration code, follow the dispatch table to each procedure's implementation. This is where you discover the per-procedure access checks, the parameter validation logic, and the actual behavior.

Reversing `MpClient.dll` is often easier and more immediately useful — it shows you how the OFFICIAL client calls each procedure, what parameters it passes, and what calling conventions it uses. If Microsoft's own client calls Proc6 with these specific parameters in this specific order, that's your template for building your own client.

### The Intelligence Gap

The IDL tells you: "Proc38 is called `ServerMpQuarantineRestoreThreat` and takes parameters X, Y, Z."

It does NOT tell you:
- Does Proc38 validate that the restore path matches the original quarantine source?
- Does Proc38 check if the caller has admin privileges?
- Does Proc38 respect Tamper Protection?
- Does Proc38 actually restore to an arbitrary path, or does it ignore the path parameter entirely?

The captured codebook tells you the enemy has a channel for prisoner transfers. It doesn't tell you whether they verify transfer orders before executing them. Only testing — or reversing the implementation — answers that.

## Cross-Pollination with TOCTOU — The Combined Arms Doctrine

The RPC scan control procedures transform our TOCTOU operation from a single-arm engagement (waiting for the enemy to stumble into the kill zone) into a combined arms operation (directing the enemy into the kill zone on our schedule).

### The Enhanced Kill Chain

```
TOCTOU + RPC Combined Arms:

PHASE 1 — PREPARE THE AMBUSH SITE
  1. Create working directory: C:\Temp\vader_XXXX\cache\
  2. Drop a CLEAN file (no EICAR) to cache\bait.exe
  3. Arm the oplock on cache\bait.exe

PHASE 2 — DIRECT THE ENEMY
  4. Call ServerMpOnDemandStartScan("C:\Temp\vader_XXXX\cache\bait.exe")
     → Defender opens bait.exe for on-demand scan
     → Oplock BREAKS — our callback fires

PHASE 3 — EXECUTE THE AMBUSH
  5. Delete cache\ directory (scorched earth)
  6. Create junction: cache\ → C:\Windows\System32\
  7. Release the oplock
     → Defender resumes, follows the junction
     → Writes to System32 as SYSTEM
```

### Why This Is Superior

**Deterministic timing.** The race condition becomes a controlled engagement. You arm the oplock and immediately trigger the scan. No waiting for RTP. No variable delay. The oplock breaks the instant Defender opens the file for the on-demand scan.

**No EICAR required.** The bait file can be anything — even an empty file. You're not relying on signature detection to trigger the scan. You're directly ordering Defender to scan a path. The file content is irrelevant. This eliminates the risk of EICAR being detected during staging (before the oplock is armed).

**Reduced detection profile.** No EICAR string in memory or on disk at any point. The XOR-decode routine from Chapter 10 becomes unnecessary. Fewer detectable artifacts.

**Repeatable.** If the race fails (junction too slow, Defender completed the scan before the swap), just set up again and call StartScan again. No need to re-drop EICAR and wait for RTP to re-detect it.

### The Access Control Question

The entire combined arms doctrine hinges on one question:

> Can a standard user call `ServerMpOnDemandStartScan` via RPC?

If yes — this is a significant upgrade to the TOCTOU attack. You control the timing completely.

If no — the procedure is admin-only or guarded — you fall back to the RTP trigger from Chapter 10. The TOCTOU race still works; it's just less deterministic.

This is the critical recon question. Answer it and you know whether this is combined arms or single-arm.

## Operational Status — Intel Assessment

Let's be honest about where this sits. This chapter is **intelligence preparation of the battlefield**, not a battle plan. We've intercepted the enemy's codebook and mapped their radio network. We have NOT built a radio and we have NOT attempted to transmit.

### What We Have

- Complete IDL with 236 procedure signatures (BlueHammer's `windefend.idl`)
- The interface UUID and binding information
- Tactical categorisation of procedures by function
- Theoretical combined arms doctrine for TOCTOU + RPC

### What We Don't Have

- **No working RPC client code.** BlueHammer's proof-of-concept (`FunnyApp.cpp`) was deliberately withheld by the instructor. You would need to write an RPC client from scratch using the IDL, compile the stubs with MIDL, and build a binary that binds to the MpSvc interface.
- **No access control testing.** Every `?` in the access matrix is an untested hypothesis. We don't know what a standard user can actually call.
- **No Tamper Protection mapping.** Which procedures are guarded by Tamper Protection and which aren't is unknown without systematic testing.
- **No implementation details.** The IDL gives signatures, not behavior. Whether `RestoreThreat` validates its path parameter is unknown.
- **No live-fire confirmation.** Everything in this chapter is map reconnaissance. The terrain hasn't been physically walked.

### Priority Recon Tasks

If this intelligence is to become operational, these are the tasks in priority order:

```
PRIORITY 1: Build a minimal RPC client
  - Compile the IDL with MIDL to generate client stubs
  - Write a C client that binds to the MpSvc interface
  - Call a benign procedure (e.g., status query) to confirm connectivity

PRIORITY 2: Access control enumeration
  - Call each priority procedure as standard user
  - Record: success, ERROR_ACCESS_DENIED, or other failure
  - Map the actual access matrix

PRIORITY 3: Tamper Protection boundary testing
  - Repeat Priority 2 with Tamper Protection ON vs OFF
  - Identify which procedures Tamper Protection specifically guards

PRIORITY 4: Parameter validation testing
  - For procedures with path parameters (RestoreThreat, StartScan, etc.)
  - Test with arbitrary paths, junctions, symlinks
  - Determine if paths are validated against the original source

PRIORITY 5: Combined arms integration
  - If StartScan is accessible to standard user:
  - Integrate RPC trigger into the TOCTOU kill chain
  - Replace EICAR/RTP trigger with deterministic RPC trigger
```

### Threat Assessment — Why This Matters Beyond TOCTOU

Even without the TOCTOU integration, this attack surface is significant. 236 procedures in a SYSTEM-level service is an enormous surface area. History shows that RPC interfaces in privileged services are a rich source of vulnerabilities:

- **PrintNightmare** — RPC interface in the Print Spooler service (CVE-2021-34527)
- **MS08-067** — RPC interface in the Server service (the Conficker worm)
- **PetitPotam** — RPC interface in the EFS service (NTLM relay)

Every one of these was a well-known RPC interface that existed for years before someone found the exploitable procedure. Defender's 236-procedure interface has received comparatively little public scrutiny.

The codebook is in hand. The frequencies are mapped. Building the radio is the next operation.

---

> COMMS plan intercepted, every CHANNEL charted on the board
> the enemy's own radio — just waiting to be KEYED
