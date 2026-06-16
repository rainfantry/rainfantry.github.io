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
```
dumpbin /headers mpengine.dll | findstr "high entropy"
```

Or in CFF Explorer / PE-bear: look for IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
in the DLL characteristics field.

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
    endbr64                ; ← CET checks for this
    push rbp
    mov rbp, rsp
    ...

; If you redirect an indirect call to the middle of a function:
my_function+0x10:
    mov rax, [rcx]         ; ← no ENDBRANCH here
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
```
Get-ProcessMitigation -Name MsMpEng.exe
```

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
// Compiler-generated epilogue:
if (stack_cookie != __security_cookie ^ frame_pointer) {
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
// Safe unlink check:
if (chunk->flink->blink != chunk || chunk->blink->flink != chunk) {
    // Corrupted list detected → terminate or heap corruption error
    RtlReportCriticalFailure();
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

You can also enumerate programmatically:
```c
// GetProcessMitigationPolicy() with each PROCESS_MITIGATION_POLICY enum value
GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep));
GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr));
GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
// ... etc
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

---

## Drill 03 — Information Leak

Go to `DRILLS/03_info_leak/`. A vulnerable program has an out-of-bounds
read bug. Your mission: leak a DLL base address, calculate the offset
to `system()`, and print the base address to prove ASLR is defeated.

ASLR is ON. DEP is ON. You can't brute-force. Find the leak. Read
the pointer. Do the math.

## Drill 04 — ROP Chain

Go to `DRILLS/04_rop_chain/`. A vulnerable program has a stack
overflow with DEP enabled. Stack cookies are OFF (we're isolating
DEP for this exercise). Your mission: build a ROP chain that calls
`VirtualProtect` to mark your shellcode page as executable, then
redirect execution to it.

You have the DLL base (no ASLR for this drill — we combine mitigations
in later drills). Find gadgets with `rp++` or `ROPgadget`. Chain them.
Pop the shell.
