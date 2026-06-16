# Chapter 06 — Crash Triage: Separating Gold From Gravel

**VADER-RCE Field Manual**
**Prerequisite**: Ch01-05
**Drill**: DRILLS/06_crash_triage/

---

## Why You Need This

Your fuzzer works. It's running. Crashes are piling up in the output
directory — dozens, hundreds, thousands. Every crash is a file that
made mpengine.dll do something it shouldn't. That's the good news.

The bad news: most of those crashes are JUNK.

Null pointer dereferences. Read violations at non-controllable addresses.
Assertion failures where a developer's own sanity check caught the problem
before anything interesting happened. Timeouts from infinite loops.
These are gravel.

Buried in the gravel — maybe 1-5% of total crashes — are the ones that
matter. Write violations at attacker-controlled addresses. Vtable
pointer corruptions. Heap overflows where the adjacent object has a
function pointer. THOSE are gold.

Without triage, you spend weeks manually loading crash after crash into
WinDbg, staring at registers, trying to figure out if each one matters.
You'll burn out or miss the good ones entirely.

With triage, you dedup the pile, run automated classification, sort by
exploitation potential, and focus your manual analysis on the top 10%.
The TOCTOU campaign taught this the hard way — 50+ findings, 0 CVEs from
the primary line. Better triage = better targeting. Don't repeat the
mistake at the memory corruption layer.

---

## Crash Deduplication: Collapse The Pile

Before you analyse ANYTHING, you dedup. The same underlying bug,
triggered by different input mutations, produces dozens or hundreds
of separate crash files. They look different on disk but they're
all the same root cause.

10,000 crash files might represent 50-200 unique bugs. Analysing all
10,000 is insanity. Analysing 200 is work.

### How Dedup Works

**Stack hash** — hash the top N frames of the call stack at crash time.
Same stack = same bug (usually). N=5 is a reasonable default. Too few
frames and you merge different bugs that share a common crash point.
Too many and you split one bug into variants based on caller context.

```
Crash A stack:        Crash B stack:        Crash C stack:
ntdll!RtlpFreeHeap   ntdll!RtlpFreeHeap   mpengine!ParseOLE
mpengine!ParsePNG     mpengine!ParsePNG     mpengine!ScanStream
mpengine!ScanBuffer   mpengine!ScanBuffer   mpengine!ScanFile
mpengine!ScanStream   mpengine!ScanStream
mpengine!ScanFile     mpengine!ScanFile

Stack hash (top 3):
A: hash(RtlpFreeHeap + ParsePNG + ScanBuffer) = 0xABCD1234
B: hash(RtlpFreeHeap + ParsePNG + ScanBuffer) = 0xABCD1234  ← same as A
C: hash(ParseOLE + ScanStream + ScanFile)     = 0xDEAD5678  ← different bug
```

A and B are the same bug. C is a different bug. Two unique crashes, not three.

**Crash address** — the instruction pointer where the crash occurred.
Useful as a secondary grouping. Multiple unique stack hashes can share
a crash address (different paths to the same vulnerable instruction).

**Exception code** — the Windows exception code. `0xC0000005` is
ACCESS_VIOLATION, `0xC0000374` is HEAP_CORRUPTION, `0xC0000409` is
STATUS_STACK_BUFFER_OVERRUN. Group by this for a high-level overview
before going deeper.

### Dedup Tools

- **AFL/WinAFL built-in** — WinAFL already deduplicates somewhat by
  crash filename. Each unique crash gets a file named with the
  mutation path. But it's imprecise — same bug from different seeds
  gets separate files.
- **BugId** — SkyLined's crash deduplication tool. Runs each crash
  under cdb (command-line WinDbg), generates a consistent bug ID from
  the crash signature. Groups crashes by root cause.
- **Custom crash_triage.py** — we'll build this. Takes the crash
  directory, runs each unique file through WinDbg, extracts signatures,
  deduplicates, and classifies.

**Rule: dedup FIRST. Always.** Don't touch WinDbg manually until you've
collapsed the pile to unique bugs. Discipline saves weeks.

---

## WinDbg Crash Analysis: The Primary Tool

WinDbg is where you determine what happened and whether you can
weaponise it. Every crash gets loaded into WinDbg. No exceptions.
GDB doesn't exist in this world. This is Windows. WinDbg is God.

### Loading A Crash

Two modes:

**From a crash dump (.dmp file):**
```
windbg -z C:\path\to\crashdump.dmp
```

**Attaching to a live process (for reproducible crashes):**
```
windbg -p <pid>
```
Or launch the target under WinDbg:
```
windbg -c "g" C:\path\to\target.exe input_file.bin
```

### The First Five Commands

Every single crash. No thinking. Just run these:

```
0:000> !analyze -v
```
Automated analysis. WinDbg tries to figure out what happened.
Gives you exception type, faulting instruction, registers, stack,
and a first-pass classification. Read the output. Don't skip it.
It's wrong sometimes, but it's a starting point.

```
0:000> .exr -1
```
Exception record. What EXACTLY went wrong. You'll see:
```
ExceptionAddress: 00007ffa`12345678 (mpengine!ParsePNG+0x1a3)
ExceptionCode: c0000005 (Access violation)
ExceptionFlags: 00000000
NumberParameters: 2
Parameter[0]: 0000000000000001   ← 1 = WRITE violation, 0 = READ violation
Parameter[1]: 00000000`deadbeef  ← the address that was accessed
```

That Parameter[0] is critical. **Write violation = more exploitable
than read violation.** A write means the attacker can corrupt memory.
A read means information disclosure (useful, but not direct code exec).

```
0:000> .ecxr
```
Sets the context to the exact moment of the crash. After this, all
register and stack commands show the state AT the crash, not where
the debugger broke in.

```
0:000> r
```
Register dump. All of them. You're looking for:
- **RIP/EIP** — where the crash instruction is
- **RAX, RCX, RDX, R8** — if any of these contain values from the input
  file, the attacker controls them
- **RSP** — stack pointer, tells you if the stack is sane

```
0:000> k
```
Call stack. Who called whom to get here. This is your breadcrumb trail
from "file was opened" to "crash happened." Read it bottom-up to
understand the execution path.

### Beyond The First Five

Once you know the basics, go deeper:

```
0:000> !heap -p -a <faulting_address>
```
Heap page info. If the crash involves a heap address, this tells you:
- What heap the address belongs to
- The allocation size
- Whether the block is allocated, freed, or corrupted
- For freed blocks: who freed it (if page heap is on)

```
0:000> u <RIP>
```
Disassemble around the crash point. See the actual instruction that
faulted and the instructions around it. Context matters — the crash
instruction alone doesn't tell you if the address was attacker-controlled.
The instructions that LOADED the register do.

```
0:000> dps <address> L10
```
Dump pointer-sized values. If a crash address looks like a vtable or
object, this shows you what pointers are there. Recognise function
addresses vs garbage vs file data.

---

## The !exploitable Extension

Microsoft released a WinDbg extension that classifies crashes by
exploitation potential. It's a heuristic — an educated guess — but
it's your first automated pass.

### Installing And Running

Load the extension:
```
0:000> .load msec.dll
0:000> !exploitable
```

Output looks like:
```
EXPLOITABLE

Recommendation: EXPLOITABLE — Write Access Violation starting at
mpengine!ParseOLE+0x00000000000002a7

Description: User Mode Write AV

Short Description: WriteAV
Faulting Instruction: mov qword ptr [rax+10h], rcx

Classification: EXPLOITABLE
```

### The Four Categories

**EXPLOITABLE:**
- Write AV where the target address appears attacker-influenced
- Read AV where the value read is used as a code pointer (RIP/EIP)
- Write AV near null (yes — near null, not just null, because of
  large structure offsets: `[rax+0x100]` where `rax=0` writes to `0x100`)

This is your Priority 1. These crashes have a clear path to memory
corruption or code execution.

**PROBABLY_EXPLOITABLE:**
- Heap corruption detected (free list inconsistency, double-free signal)
- Stack buffer overflow detected (stack cookie triggered)
- Exception in a function known to handle untrusted data

These need manual analysis but are often real. Heap corruption means
something already overwrote heap metadata — the question is whether
you control WHAT was written.

**PROBABLY_NOT_EXPLOITABLE:**
- Read AV at null or near-null address
- Read AV at a non-attacker-controlled address
- Division by zero

These are usually DoS-only. But "usually" isn't "always." A read AV
can be an information leak if the read value gets sent somewhere the
attacker can observe it. Don't blindly discard — flag and review later.

**UNKNOWN:**
- Can't determine from the crash context alone
- Often needs manual analysis to resolve

### Don't Blindly Trust !exploitable

This is critical. The extension is a HEURISTIC. It looks at the crash
snapshot — one moment in time. It doesn't trace data flow. It doesn't
understand heap grooming. It doesn't know that a "PROBABLY_NOT" read
violation happens right before a write that uses the read value.

Cases where !exploitable gets it wrong:
- **False negative**: Read AV classified as PROBABLY_NOT, but the read
  feeds into a function pointer dereference two instructions later.
  The READ is the info leak, the WRITE comes next.
- **False negative**: Null deref classified as NOT, but the program
  catches the exception and continues with corrupted state.
- **False positive**: Write AV classified as EXPLOITABLE, but the write
  address is a fixed offset from a non-controllable base. You can
  trigger the write but can't aim it.

Use !exploitable as the FIRST PASS. Sort the pile. Then manually verify
everything in the top two tiers, and spot-check the bottom two.

---

## Manual Exploitability Assessment

This is where the real skill lives. A machine can classify. A human
determines if a crash becomes a weapon.

### The Key Question

For every crash, ask ONE question:

**"Can I control the value that caused the crash?"**

Not "did it crash." Not "is it a write." The question is CONTROL.
If the faulting address or the faulting value traces back to bytes
in the input file — bytes you chose — that crash is exploitable.

### Tracing Control

The crash instruction:
```
mov [rax], rcx
```

Step 1 — What's in RAX (the target address)?
```
0:000> r rax
rax=0000000041414141
```
That's ASCII "AAAA". Smells like it came from the input.

Step 2 — Where did RAX get that value? Look at preceding instructions:
```
mov rax, [rbx+0x18]     ; loaded from object at rbx+0x18
```

Step 3 — What's at rbx+0x18?
```
0:000> dq @rbx+0x18 L1
00000000`12340018  00000000`41414141
```

Step 4 — Is that object's memory filled with input data?
```
0:000> db @rbx L40
00000000`12340000  41 41 41 41 41 41 41 41  AAAAAAAA
00000000`12340008  41 41 41 41 41 41 41 41  AAAAAAAA
...
```

Input data in the object. Object field used as write target. EXPLOITABLE.
Now find the exact file offset that maps to `rbx+0x18` and you can
write any address there.

### The Assessment Checklist

Run through this for every Priority 1 and Priority 2 crash:

```
[ ] Is this a WRITE violation or READ violation?
    Writes > Reads for exploitation.
    Reads are useful for info leaks (ASLR bypass).

[ ] Does the attacker control the faulting address?
    If yes → arbitrary write primitive → EXPLOITABLE.
    Check: does the address contain file-derived bytes?

[ ] Does the attacker control the value being written?
    If yes AND the address is controlled → arbitrary write.
    Full arbitrary write = game over. This is the best primitive.

[ ] Is the crash near a function pointer or vtable dereference?
    Look at the next few instructions after the crash point.
    If a vtable call follows → corruption here = code execution.

[ ] Is this a heap overflow or UAF?
    Heap overflows and UAFs are more exploitable than stack issues
    on modern Windows. Stack cookies catch most stack overflows.
    The heap has no cookies.

[ ] Can you reach this crash reliably?
    Reproducibility matters. A crash that happens 1 in 100 times is
    harder to exploit than one that hits every time. Check: does the
    same input file always crash? Same address? Same register state?

[ ] What mitigations apply?
    CFG, ASLR, DEP — note which are active. A crash that gives you
    RIP control but CFG is enabled means you need a CFG bypass first.
```

---

## Root Cause Analysis

The crash is the SYMPTOM. The bug is the CAUSE. Triage tells you
what's exploitable. Root cause tells you what to fix in your exploit.

### Heap Overflow Root Cause

The crash: Write AV past the end of a heap allocation.

```
0:000> !heap -p -a 0000000012340100
    address 0000000012340100 found in
    _HEAP @ 7ffa00000000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        00000000123400e0 0008 0000  [00]   00000000123400f0    00040 - (busy)
```

Allocation is `0x40` bytes (64 bytes) starting at `0x123400f0`.
The crash address `0x12340100` is at offset `0x10` into the allocation.
But the WRITE went to `0x12340130` — offset `0x40` — that's past the end.

Root cause: the parser allocated 64 bytes but wrote 80+ bytes.
Find where the size was read from the file. Find where the copy loop
uses a different size. That's your overflow vector.

### Use-After-Free Root Cause

The crash: Access to freed memory.

```
0:000> !heap -p -a 0000000012340100
    address 0000000012340100 found in
    _HEAP @ 7ffa00000000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        00000000123400e0 0008 0000  [00]   00000000123400f0    00040 - (free)
          Trace: 0x1234
          7ffa12345678 mpengine!ParseOLE+0x203  ← who freed it
          7ffa12345000 mpengine!ScanBuffer+0x50
```

The block was freed by `ParseOLE+0x203`. But something still holds a
pointer and used it. Find the dangling pointer. Find the code path
that freed the object without nulling the pointer. That's your UAF.

### Type Confusion Root Cause

The crash: Access violation at a strange address that doesn't look
like a valid heap or code pointer.

```
0:000> r
rax=4f4c450041414141    ← "AAAA" + "OLE" — that's mixed file data and format magic
rcx=0000000012340000
Faulting instruction: call qword ptr [rax]
```

RAX is being used as a vtable pointer, but it contains file data.
Something interpreted a data buffer as an object. Find the cast or
the variant dispatch that used the wrong type. That's your confusion.

---

## Page Heap: The Magnifying Glass

Normal heap operation delays the symptoms. A heap overflow at time T
might not crash until time T+1000 when the corrupted memory is finally
used. By then, the original overflow site is long gone from the stack.
You're debugging the SYMPTOM, not the CAUSE.

Page heap fixes this.

### Enabling Page Heap

```
gflags.exe /p /enable MsMpEng.exe /full
```

What this does: places a GUARD PAGE immediately after every heap
allocation. One byte past the allocation boundary = instant crash.
No delayed corruption. No "the crash happened somewhere else." The
crash IS the overflow.

For freed memory: the page becomes inaccessible. Any use-after-free
crashes at the exact moment of reuse, with a stack trace showing
exactly who tried to use freed memory.

### When To Use It

**Use normal heap for fuzzing.** Page heap is 10-100x slower. Your
fuzzer goes from 500 execs/sec to 5. That kills throughput.

**Use page heap for triage.** When you have a crash and need the
exact root cause, reproduce it under page heap. The crash point
shifts from "somewhere downstream" to "the exact guilty instruction."

```
Workflow:
1. Fuzz with normal heap → collect crashes
2. Dedup crashes → unique bugs
3. Reproduce interesting crashes under page heap → exact root cause
4. Verify exploitability with precise corruption data
```

### Disabling Page Heap

```
gflags.exe /p /disable MsMpEng.exe
```

Always disable after analysis. Running a system service under full
page heap permanently will murder performance.

---

## Crash Classification Priority

Here's the sorting hat. Every unique crash goes into one of these tiers.

```
PRIORITY 1 — Develop exploit immediately
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Write AV with attacker-controlled address AND value
  → Arbitrary write. This is the holy grail. You choose WHERE and WHAT.
  
- Vtable/function pointer dereference of attacker data
  → Direct code execution. Corrupt the vtable → next virtual call = yours.
  
- Heap overflow adjacent to object with function pointer
  → Overflow into the neighbor's vtable. Spray the heap to guarantee
    adjacency. You know how (Chapter 01).

PRIORITY 2 — Investigate further
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Write AV with partially controlled address
  → You control some bits but not all. Might be exploitable with
    heap grooming to constrain the address range.
  
- Read AV that could become an info leak
  → If the read value is returned/logged/observable, this defeats ASLR.
    Info leak + separate write primitive = full exploit.
  
- Heap corruption detected (double-free, metadata inconsistency)
  → Might be exploitable with heap grooming. Need to understand the
    allocation pattern to know.

PRIORITY 3 — Document but deprioritise
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Read AV on null or near-null
  → Usually a null pointer dereference. DoS only. No memory corruption.
  
- Null pointer dereference (non-read/write)
  → Developer forgot a null check. Not exploitable on modern Windows
    (null page is not mappable from usermode).
  
- Integer overflow causing DoS but no memory corruption
  → The integer wraps, allocation gets a wrong size, but nothing
    actually overflows. Just a hang or safe crash.
  
- Stack overflow with cookie intact
  → Stack cookie (/GS) catches it before return. STATUS_STACK_BUFFER_OVERRUN.
    Cookie bypass is possible but hard. Move on unless everything else is dry.

DISCARD — Don't waste time
━━━━━━━━━━━━━━━━━━━━━━━━━━
- Timeout / hang (no memory corruption, just slow or infinite loop)
- Assertion failure (developer-placed check worked correctly — this is
  the software PROTECTING ITSELF, not a vulnerability)
- Access violation in known-safe cleanup/destructor code (crash during
  error handling cleanup, not during the vulnerable operation)
```

---

## Automated Triage Pipeline

You're not doing this by hand for 200 unique crashes. crash_triage.py
will automate the bulk of it. Here's what the pipeline does:

### For Each Unique Crash

```
1. Launch WinDbg in batch mode (cdb -z <dumpfile> -c "commands; q")
2. Run !exploitable → get classification
3. Extract exception record → type, code, address, read/write
4. Extract register state → look for file-derived patterns (0x41414141, etc.)
5. Extract call stack → top 10 frames
6. Extract faulting instruction → disassemble crash point
7. Classify into priority tier (P1/P2/P3/DISCARD)
8. Generate one-page report
```

### Output Format

```
===== CRASH TRIAGE REPORT =====
File: crash_00042.bin
Exception: ACCESS_VIOLATION (WRITE)
Address: 0x0000000041414141
Exploitable: EXPLOITABLE (msec)
Priority: P1

Registers at crash:
  RAX=0x41414141  RCX=0x00007ffa12345678
  RDX=0x0000000000000040  R8=0x0000000000000000

Faulting instruction:
  mpengine!ParsePNG+0x1a3: mov [rax], rcx

Call stack (top 5):
  mpengine!ParsePNG+0x1a3
  mpengine!ScanBuffer+0x50
  mpengine!ScanStream+0x88
  mpengine!MpScanFile+0x120
  mpengine!ScannerEntry+0x40

Notes: RAX contains pattern 0x41414141 — likely attacker-controlled.
       Write AV with controlled target address. HIGH PRIORITY.
===============================
```

### The Final Output

A sorted list. P1 crashes at the top. Discard at the bottom.
You read the top 10. Manually verify. Pick the best candidate.
Start building the exploit.

```
TRIAGE SUMMARY — mpengine fuzzing campaign
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total crashes:     8,432
After dedup:         187
Priority 1:           3   ← THESE are your targets
Priority 2:          14
Priority 3:          98
Discarded:           72
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Three P1 crashes out of 8,432 raw files. That's 0.036%.
This is why you triage.

---

## What This Looks Like With mpengine.dll Crashes

mpengine is a C++ monster with virtual dispatch everywhere.
When the fuzzer finds a crash in mpengine, expect to see:

**Common mpengine crash patterns:**

1. **Parser overflow** — size field read from file, used directly
   as memcpy length. Stack: `ParsePNG → ScanBuffer → MpScanFile`.
   The size at fault comes from a file header field.

2. **Object lifetime bug** — parser creates objects during scan,
   error path frees some but not all. Dangling pointer used on
   the next file. Stack: `ScanStream → ParseOLE → ScanBuffer` with
   a freed-block access.

3. **Type dispatch confusion** — container format (ZIP, OLE) contains
   an embedded file. Inner parser expects Type A, gets Type B.
   Stack shows two parser names in the same trace — `ParseZIP` calling
   `ParsePE` when the content was actually a PDF.

4. **Integer overflow in allocation** — width * height * channels
   wraps a 32-bit integer. Small allocation, large write.
   Registers show the overflowed value vs the actual data size.

**mpengine-specific triage notes:**
- mpengine runs as SYSTEM. Any code execution = SYSTEM shell.
- mpengine processes files from email, web downloads, USB, network
  shares. Attack surface is MASSIVE.
- mpengine can be triggered remotely by sending a file. No user
  interaction required. This is why Microsoft pays top bounty for
  mpengine RCE.

---

## Mapping To The Doctrine

The 0x1security compass: crash → leak memory → execute arbitrary code.

Triage is the GATE between "crash" and "leak memory."

Without triage, you have thousands of crashes and no direction.
You're a soldier standing in a field of spent casings trying to figure
out which one came from the rifle that matters. Hopeless.

With triage, you have a ranked list. Three P1 crashes. Fourteen P2s.
You know which ones give you write primitives. You know which ones
have attacker-controlled registers. You know which ones are near
vtable dereferences. You have DIRECTION.

The doctrine also says: "more than 50% of 0-days are created from a
crash found through fuzzing." But not ANY crash. The RIGHT crash.
The one that gives you a controlled write, or a vtable corruption,
or an info leak that defeats ASLR. The fuzzer finds thousands.
Triage finds the one.

Step 3 of the doctrine — crash → leak → execute — only advances when
you have a crash worth developing. Everything before this chapter
teaches you how crashes happen. Everything after this chapter teaches
you how to turn a good crash into a weapon. This chapter is the filter.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Crash triage** | Process of sorting crashes by exploitation potential to focus manual analysis on the most promising candidates |
| **Deduplication** | Collapsing multiple crash files into unique bugs by stack hash, crash address, or exception code |
| **Stack hash** | Hash of the top N call stack frames at crash time; same hash = same bug |
| **!exploitable** | Microsoft WinDbg extension that classifies crashes as EXPLOITABLE / PROBABLY_EXPLOITABLE / PROBABLY_NOT / UNKNOWN |
| **Page heap** | Debug heap mode (gflags) that places guard pages after every allocation; catches overflows at the exact overflow instruction |
| **Exception record** | Windows structure describing what went wrong: exception code, faulting address, read vs write |
| **Write AV** | Write access violation — attempt to write to invalid/protected memory; more exploitable than read AV |
| **Read AV** | Read access violation — attempt to read from invalid/protected memory; potential info leak |
| **Arbitrary write** | Attacker controls both the target address AND the written value; strongest exploitation primitive |
| **Crash dump** | Snapshot of process state at crash time (.dmp file); loadable in WinDbg for offline analysis |
| **BugId** | SkyLined's crash deduplication tool; generates consistent bug identifiers from crash signatures |
| **gflags** | Global Flags Editor; Windows tool for enabling page heap, heap tail checking, and other debug aids |
| **Root cause** | The original bug (overflow, UAF, type confusion) that produces the crash symptom |
| **Faulting instruction** | The specific CPU instruction that triggered the exception |

---

## Drill 06 — Crash Triage

Go to `DRILLS/06_crash_triage/`. A directory of crash dumps is waiting.

Your mission:
1. Dedup the crashes by stack hash — how many unique bugs?
2. Run !exploitable on each unique crash — sort by classification
3. Manually assess the top candidates — which ones have controlled writes?
4. Enable page heap and reproduce the best P1 — find the exact root cause
5. Write a one-page assessment: bug class, controlled values, exploitation path

This is the skill that turns "I found crashes" into "I found the crash
that becomes an exploit." Without this, everything after is guesswork.
