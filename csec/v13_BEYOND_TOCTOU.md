# Chapter 13 — Beyond TOCTOU: The Rootkit Phase

## Mission Pivot

Chapters 1-12 taught you one thing: how Defender works, where the gap is,
and how to exploit a TOCTOU race condition to redirect SYSTEM-level file
operations through a junction swap. That was Phase 1. One vulnerability
class. One weapon.

Phase 2 asks a different question: **what ELSE is broken on this box?**

The TOCTOU exploit targets Defender's scan-then-quarantine pipeline. But
Defender isn't the only thing running as SYSTEM. Every service on the
machine — dozens of them — runs with its own privileges, its own DLL
imports, its own file access patterns. Each one is a potential escalation
path if its security posture has a gap.

This chapter documents what we found when we stopped looking at Defender
and started looking at everything.

## The Reconnaissance Doctrine

### Attack Surface Enumeration

The first step was a systematic audit. Not "poke around and see what's
interesting" — a structured sweep of every privilege escalation vector
Windows exposes to a standard user:

```
VECTOR                          RESULT
─────────────────────────────   ──────────
Writable service binaries       1 vulnerable (Wondershare NativePushService)
Writable service directories    47 services checked, 1 exploitable
Unquoted service paths          None exploitable
PATH DLL hijack (machine)       User-writable directory in machine PATH
Phantom DLL imports             osppc.dll in ClickToRunSvc (Microsoft)
DLL sideloading via proxy       VERSION.dll (generic, manifest-dependent)
COM object hijack               82 "missing" — all false positives (System32)
Registry ACL abuse              No writable service keys
Scheduled task manipulation     No writable SYSTEM task binaries
Named pipe impersonation        No exploitable pipes found
Token manipulation              Requires SeImpersonate (not available)
AlwaysInstallElevated            Disabled (default)
Unpatched kernel CVEs           None found (24H2 current)
Credential harvesting           LSASS protected, no plaintext creds
WMI event subscription          Requires admin to create
autorun/startup persistence     User-level only (no escalation)
Driver signature bypass         HVCI active, blocks unsigned drivers
Print spooler abuse             Patched (PrintNightmare fixed)
```

17 vectors checked. 3 active. The rest hardened by default or patched.
This isn't guesswork — every "None" above was verified with icacls,
registry reads, dumpbin, or service enumeration.

### Why Systematic Matters

Amateurs chase one exploit. They find a CVE writeup online, try to
reproduce it, and when it doesn't work they move on. That's not
penetration testing — that's lottery tickets.

Systematic enumeration means: you check EVERY vector on the target. You
document what's closed and WHY. The negative results are as valuable as
the positives, because they tell you what the defender got right — which
means they tell you where the defender might NOT have got it right on
a different target.

Finding #49 in the engagement log documents 47 third-party services
audited for binary ACL weaknesses. 46 were properly secured. One wasn't.
That one was Wondershare NativePushService — and it became V4 DELTA.

## Hardware Breakpoints: The Blind Spot (Finding #36)

### Why Memory Patching Is Dead

The classic AMSI bypass — `AmsiScanBufferPatch` — writes bytes into
ntdll.dll's .text section. Change the first instruction of AmsiScanBuffer
to `ret` or `xor eax, eax; ret` and AMSI stops scanning. Simple.

Also dead. Defender's Tamper Protection monitors the integrity of
AMSI-related memory regions. Microsoft's Kernel Patch Protection (KPP,
"PatchGuard") watches kernel memory. And even in user mode, Code
Integrity checks can detect .text section modifications at runtime.

Every public AMSI bypass that patches memory — the ones you find in
GitHub repos with names like "amsi-bypass-v2-updated-2024" — is running
on borrowed time. The signature database already knows the patch bytes.
The behavioral heuristics know what "write to .text section of amsi.dll"
looks like. It's a solved problem for the defence.

### Hardware Breakpoints Don't Touch Memory

CPU debug registers (DR0-DR3) are a completely different mechanism.
They're hardware features designed for debuggers — set an address in DR0,
configure DR7 for execution breakpoint, and the CPU raises
EXCEPTION_SINGLE_STEP when the instruction pointer hits that address.

No memory is modified. No bytes are written. No .text section is touched.
The breakpoint exists in silicon, not in RAM. Integrity checks have
nothing to detect because nothing changed.

The VEH (Vectored Exception Handler) catches the single-step exception
and returns a spoofed result:

```
AMSI call flow WITHOUT breakpoint:
  PowerShell → AmsiScanBuffer() → scans script → returns AMSI_RESULT_DETECTED
  
AMSI call flow WITH DR0 breakpoint:
  PowerShell → AmsiScanBuffer() → CPU trap → VEH fires → returns E_INVALIDARG
  AmsiScanBuffer never executes a single instruction.
```

The function is never entered. The scan never happens. PowerShell
receives E_INVALIDARG and interprets it as "AMSI unavailable" — which
means "proceed without scanning." The defensive perimeter opens a door
and doesn't even know it did.

### ETW Gets the Same Treatment

DR1 → EtwEventWrite. Same mechanism. Every event that any process tries
to log through ETW gets intercepted at the CPU level. The handler returns
STATUS_SUCCESS — "event logged successfully" — but nothing was logged.
The telemetry pipeline is now a black hole.

Combined (V3 CHARLIE, the "Dark Room"):
- DR0: AmsiScanBuffer → E_INVALIDARG (AMSI blind)
- DR1: EtwEventWrite → STATUS_SUCCESS (ETW blind)
- Result: complete user-mode telemetry blackout

### Why This Matters for Defender

Defender's user-mode visibility depends on two things:
1. AMSI scanning scripts and .NET assemblies before execution
2. ETW logging process behavior for heuristic analysis

Both are now blind. Defender still has WdFilter.sys in the kernel
(file-level RTP), and it still has cloud protection. But user-mode
behavioral analysis — the "inner wire" from Chapter 8 — is dark.

This is Finding #36 in the engagement log. It's not a new technique
(hardware breakpoint AMSI bypass has been discussed in research since
~2020), but the combination of AMSI + ETW + zero memory modification +
Defender RTP enabled is a clean implementation that demonstrates the
architectural blind spot.

**The takeaway:** Defender's detection model assumes its telemetry
sources are trustworthy. Hardware breakpoints break that assumption
without triggering any integrity alert. The fix would require
kernel-level monitoring of debug register state — which PatchGuard
could do but currently doesn't for user-mode DR0-DR3 on non-protected
processes.

## Service Binary Replacement: CWE-732 (Finding #42)

### The Discovery

47 third-party services were audited using icacls to check binary ACLs.
The question: does ANY service running as LocalSystem have a binary that
a standard user can write to?

Answer: yes. One.

**Wondershare NativePushService** installs its service binary to:
```
C:\Users\apacw\AppData\Local\Wondershare\Wondershare NativePush\WsNativePushService.exe
```

That path is inside another user's AppData — but the ACLs grant write
access to standard users. A third-party installer dropped a SYSTEM
service binary into a user-writable directory and didn't lock the
permissions.

### The Exploit

Windows allows renaming a running executable. The file handle is held by
the service, but rename operations work because they modify the directory
entry, not the file data. So:

```
1. Rename running binary:
   WsNativePushService.exe → WsNativePushService_real.exe

2. Plant replacement:
   Copy our payload as WsNativePushService.exe

3. Wait for service restart (reboot or crash):
   Service control manager starts our binary as SYSTEM

4. Our binary:
   - Writes canary proving SYSTEM execution
   - Launches WsNativePushService_real.exe (stealth — service still works)
```

Standard user → SYSTEM. No exploit chain needed. No memory corruption.
No race condition. Just one misconfigured ACL on one service binary.

This is CWE-732 (Incorrect Permission Assignment for Critical Resource).
The bug is in Wondershare's installer, not in Windows — but the
escalation path is through Windows service infrastructure.

### V5 ECHO: DLL Proxy (Why It Failed Here)

The original plan was to sideload VERSION.dll into NativePushService's
directory — a DLL proxy that forwards all exports to the real System32
copy while running a payload. This is the classic DLL sideload attack.

It failed. NativePushService has a **manifest** that specifies DLL
redirection:

```xml
<dependency>
  <dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" .../>
  </dependentAssembly>
</dependency>
```

With a manifest present, Windows uses the **manifest-directed search
order** which skips the application directory for system DLLs. The proxy
DLL in the service directory is never loaded — Windows goes straight to
System32.

This is Finding #40: manifest hardening blocks DLL sideloading for this
specific target. The DLL proxy technique (V5 ECHO) is still valid against
services WITHOUT manifest protection, just not this one.

## PATH Hijack: The Machine-Level Vuln (Finding #44)

### The Setup

Machine-level PATH (not user PATH) includes:
```
C:\Users\gwu07\.local\bin
```

This directory is user-writable. Any SYSTEM service that resolves a DLL
via standard DLL search order — and the DLL isn't in System32, isn't a
Known DLL, and isn't in the application directory — will search PATH.
If PATH contains a user-writable directory, the user controls what the
service loads.

This is CWE-427 (Uncontrolled Search Path Element), but at the MACHINE
level. It's not a per-application bug — it's a system-wide configuration
weakness. Every service is potentially affected if it imports a DLL that
falls through to PATH search.

### DLL Search Order (Refresher from Chapter 2)

With SafeDllSearchMode enabled (default since XP SP2):

```
1. Application directory (where the .exe lives)
2. C:\Windows\System32
3. C:\Windows\SysWOW64 (16-bit compat, ignore)
4. C:\Windows
5. Current working directory
6. Directories in PATH environment variable  ← WE CONTROL THIS
```

The DLL search order is a waterfall. If the DLL isn't found at step 1,
it falls to step 2. If not at step 2, step 3. And so on down to step 6
— PATH — where our planted DLL waits.

### What Blocks It

Not every DLL reaches step 6:

- **Known DLLs** (`HKLM\...\KnownDLLs` registry key): ~50 system DLLs
  (kernel32, ntdll, user32, etc.) that Windows pre-loads at boot. These
  NEVER hit the search order. They're resolved from a cached section
  object. You can't hijack kernel32.dll via PATH.

- **API Set Schema**: `api-ms-win-*` and `ext-ms-win-*` DLL names are
  NOT real files. They're resolved by a kernel-level schema at load time.
  They never hit disk search. If a dumpbin shows a service importing
  `api-ms-win-core-file-l1-1-0.dll`, that's not a real DLL to hijack.

- **SxS/Manifest redirection**: Services with manifests may have their
  DLL search redirected via Side-by-Side assembly resolution, bypassing
  the normal search order entirely.

### What Falls Through

The valuable targets are DLLs that:
1. Are imported by a SYSTEM service
2. Are NOT in the Known DLLs list
3. Are NOT API Set stubs
4. Are NOT in the application directory
5. Are NOT in System32

These fall through the entire waterfall and land on PATH — where we're
waiting.

## Phantom DLLs: The Highest-Value Finding (#47)

### What Is a Phantom DLL?

A phantom DLL is a DLL referenced in a PE binary's import table that
**does not exist anywhere on disk**. The binary was compiled against a
header that declared the DLL, but the DLL was never shipped. At load
time, the PE loader searches for it, fails to find it, and — depending
on whether it's a standard import or delay-loaded — either crashes or
silently continues.

Delay-loaded imports are the interesting case. The DLL is listed in the
import table but only actually loaded when a code path calls one of its
functions. If that code path is rarely (or never) exercised, the service
runs fine without the DLL. But the PE loader still SEARCHES for it on
certain triggers.

### osppc.dll — Microsoft Office ClickToRunSvc

**ClickToRunSvc** (OfficeClickToRun.exe) is a Microsoft first-party
service that runs as LocalSystem. It manages Office updates, licensing,
and Click-to-Run deployment. It auto-starts with Windows.

ClickToRunSvc's import table includes **osppc.dll** — the Office
Software Protection Platform Client. This DLL handles licensing
validation.

The problem: **osppc.dll does not exist on disk.**

```
C:\> where /r C:\ osppc.dll
INFO: Could not find files for the given pattern(s).
```

Not in System32. Not in the Office directory. Not anywhere. It's a
phantom — referenced in the binary but never shipped.

### The Attack Path

```
1. osppc.dll is delay-loaded by ClickToRunSvc
2. ClickToRunSvc runs as SYSTEM
3. When the licensing code path triggers, the PE loader searches for osppc.dll
4. Search order: app dir → System32 → Windows → CWD → PATH
5. Not found anywhere... falls through to PATH
6. PATH includes C:\Users\gwu07\.local\bin (user-writable)
7. Our planted osppc.dll loads into ClickToRunSvc as SYSTEM
```

Standard user → SYSTEM code execution. Through a first-party Microsoft
service. Using the OS's own DLL search order. No memory corruption, no
race condition, no service restart needed — just wait for Office to
exercise the licensing code path (or trigger it manually via
`schtasks /Run /TN "\Microsoft\Office\Office Automatic Updates 2.0"`).

### Why This Is MSRC-Grade

1. **First-party service**: ClickToRunSvc is Microsoft's own code
2. **First-party search order**: The DLL resolution is the Windows PE
   loader, not a third-party quirk
3. **Default configuration**: The service auto-starts on any machine
   with Office installed. The PATH vulnerability is a separate issue but
   common on developer machines.
4. **Standard user to SYSTEM**: No admin required at any step
5. **Persistent**: Survives reboots. The DLL stays planted until removed.

The combined impact: any machine with Office + a user-writable PATH
directory = local privilege escalation from standard user to SYSTEM,
triggered by normal Office operations.

### Confirmation Procedure

Before submitting to MSRC:

```
1. Process Monitor (ProcMon) capture:
   - Filter: Process Name = OfficeClickToRun.exe
   - Filter: Path contains osppc.dll
   - Filter: Result = NAME NOT FOUND
   → Proves ClickToRunSvc searches for osppc.dll

2. Plant canary DLL in PATH directory
3. Trigger: schtasks /Run /TN "\Microsoft\Office\Office Automatic Updates 2.0"
4. Check canary: type C:\Windows\Temp\osp_telemetry.log
   → Expected: timestamp|SYSTEM|elev=1|pid=XXXX|PHANTOM_OSPPC|OfficeClickToRun.exe

5. Verify host process in canary output matches OfficeClickToRun.exe
6. Reproduce on clean Windows 11 + Office install
```

## Signature Isolation: Why One Death Doesn't Kill the Others

### The Problem

If you build all your payloads with the same XOR key, the same canary
path, the same function names, and the same code structure — Defender
signatures one and they're ALL burned. The detection rule matches byte
patterns, and those patterns are identical across binaries.

### The Solution

Each vector uses a unique signature set:

```
VECTOR   XOR KEY   CANARY PATH                         TAG
V1-V3    0x41      stdout (no disk)                    per-vector
V4       0x52      C:\Windows\Temp\svc_health.log      DELTA_REPLACE
V5       0x37      C:\Windows\Temp\ver_cache.log       ECHO_PROXY
V6       0x63      C:\Windows\Temp\hwmon_diag.log      PATH_VECTOR
V7       0x19      C:\Windows\Temp\osp_telemetry.log   PHANTOM_OSPPC
```

Different XOR key = different encoded byte sequences for the same string.
If Defender signatures the XOR 0x37 encoding of "version.dll" in V5,
that pattern doesn't appear anywhere in V7 (which uses XOR 0x19).

Different canary paths = different file creation patterns. No two
vectors write to the same file. Detection rules based on "creates file
at X path" only match one vector.

Different tags = different string literals in the binary. Even if
Defender inspects the decoded strings, "DELTA_REPLACE" and
"PHANTOM_OSPPC" are distinct fingerprints.

Different code structure = different control flow graphs. V4 has service
plumbing (RegisterServiceCtrlHandler, SetServiceStatus). V5 has DLL
proxy forwarding (GetProcAddress, LoadLibrary). V7 is a minimal DllMain
canary. The binaries look nothing alike to static analysis.

### The Operational Result

Defender catches V5 ECHO? V4 DELTA still works. V7 GOLF still works.
V6 FOXTROT still works. Each vector is an independent operator with its
own identity, its own kit, its own communications. Compromise one, the
rest continue the mission.

## Integration with TOCTOU

The TOCTOU exploit (Chapters 1-12) operates in a different space than
the rootkit vectors:

```
TOCTOU (vader-toctou):
  - Exploits Defender's scan pipeline
  - Race condition on quarantine path resolution
  - Standard user writes to SYSTEM-protected directories
  - Requires Defender RTP to be active (uses the enemy's own mechanism)

Rootkit vectors (vader-rootkit):
  V1-V3: Blind Defender's user-mode telemetry (AMSI/ETW)
  V4: Replace insecure service binary → SYSTEM
  V5: DLL proxy sideloading → code execution in service context
  V6: PATH DLL plant → SYSTEM (any service with PATH-resolved DLL)
  V7: Phantom DLL plant → SYSTEM (ClickToRunSvc, Microsoft first-party)
```

The kill chain integration:

```
Phase 0: vader_shell (listener)
Phase 1: V3 CHARLIE (AMSI + ETW blind)     ← Telemetry dark
Phase 2: TOCTOU write to System32           ← Or skip if using V4/V7
Phase 3: V4/V7 privilege escalation         ← Standard user → SYSTEM
Phase 4: Process injection (future)         ← SYSTEM → persistent access
```

The TOCTOU is the subtle weapon — exploiting the defender's own
mechanism to write where you shouldn't. The rootkit vectors are the
blunt instruments — misconfigured ACLs, missing DLLs, search order
abuse. Both arrive at the same destination: SYSTEM-level code execution
from a standard user account, with Defender RTP enabled, on a fully
patched Windows 11 box.

## Lessons Learned

### What the Defence Gets Right

Most of the 17 vectors we checked are properly hardened:
- Service binaries in Program Files with correct ACLs
- Known DLLs registry prevents hijack of common system DLLs
- Manifest/SxS redirection blocks sideloading on protected services
- Named pipes require impersonation tokens we don't have
- HVCI blocks unsigned kernel drivers
- PrintNightmare is patched
- AlwaysInstallElevated is off by default

Windows 11 24H2 is a harder target than any previous version. The
attack surface is genuinely reduced. Finding three active vectors out
of seventeen is a good result for the attacker — and proof that the
defence is working for the other fourteen.

### What the Defence Gets Wrong

1. **Third-party installers are the weakest link.** Microsoft can
   harden its own services, but vendors like Wondershare ship SYSTEM
   service binaries to user-writable paths. One sloppy installer
   nullifies years of OS hardening.

2. **PATH is a system-wide trust assumption.** Any user-writable
   directory in machine PATH is a SYSTEM-level vulnerability for every
   service that resolves DLLs via search order. This should be audited
   by Defender, or flagged during installation. It isn't.

3. **Phantom DLLs are invisible to defenders.** A DLL that doesn't
   exist can't be signature-checked, can't be integrity-verified, can't
   be monitored. The absence IS the vulnerability. Defender's model is
   "scan files that exist" — it has no mechanism for "alert on files
   that SHOULD exist but don't."

4. **Hardware breakpoints are unmonitored.** Debug registers are
   per-thread state in ring 3. No kernel component currently monitors
   DR0-DR3 for non-debugger processes. The telemetry infrastructure
   (AMSI, ETW) trusts that its entry points are reachable — but
   hardware breakpoints make them unreachable without modifying memory.

### What This Means for the Next Target

Every machine is different. The vectors that work here (Wondershare,
Office ClickToRunSvc, .local/bin in PATH) might not exist on another
box. But the METHODOLOGY transfers:

1. Enumerate all services and their binary ACLs
2. Check machine PATH for user-writable directories
3. Dump imports of SYSTEM services, filter Known DLLs and API Sets
4. Look for phantom DLLs (imports that don't resolve to any file)
5. Check for manifest/SxS protection on sideload candidates

The tools are icacls, dumpbin, reg query, and PowerShell. The thinking
is: where does the OS trust something it shouldn't?
