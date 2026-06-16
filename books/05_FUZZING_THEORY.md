# Chapter 05 — Fuzzing Theory: The Automated Assault

**VADER-RCE Field Manual**
**Prerequisite**: Ch01-04 (Heap Internals, Overflow Patterns, UAF/Type Confusion, Mitigations)
**Drill**: DRILLS/05_first_harness/

---

## Why You Need This

The TOCTOU campaign was 14 versions. 50+ manual tests. 7 test programs.
Every single mutation was hand-crafted — change a junction target, tweak
timing, adjust an oplock callback. You found real bugs. MSRC got a
submission. But here's the problem you already identified:

**Zero automation.**

Problem #2 from the campaign post-mortem. You were a sniper — one shot,
one target, manually aimed. That works for logic bugs (TOCTOU races,
junction redirects, oplock abuse). Logic bugs require understanding.

Memory corruption bugs are different. They hide in the COMBINATORIAL
SPACE of input parsing. A ZIP file has dozens of header fields, each
with a range of valid and invalid values. Multiply every field by every
possible value by every combination with other fields — you're looking
at billions of input variants. No human tests a billion inputs. Not in
a lifetime.

A fuzzer tests a million inputs per hour. While you sleep.

The TOCTOU campaign manually explored ~50 variants of a race condition
over weeks. A coverage-guided fuzzer explores millions of parser code
paths per day, automatically evolving its inputs toward the code that
hasn't been tested yet. The crash that gives you an RCE might be a file
with one corrupted byte in a length field three headers deep in a nested
archive. You'd never think to try it. The fuzzer doesn't think — it TRIES.

This chapter is the theory. Next chapters build the infrastructure.

---

## What Fuzzing Is

Fuzzing is brute-force exploration of a program's input space. You throw
massive volumes of semi-random input at a program and watch for crashes.

```
INPUT GENERATOR → [mutated file] → TARGET PROGRAM → {crash | no crash}
         ↑                                                    |
         └────────── feedback (optional) ─────────────────────┘
```

That's it. The details are in how you generate the input and whether
you use feedback. Those details are the difference between finding
nothing in a week and finding 47 unique crashes overnight.

### Why Manual Testing Misses Bugs

Consider a minimal ZIP file parser. Just the local file header:

```
Offset  Size  Field
0       4     Signature (PK\x03\x04)
4       2     Version needed
6       2     Flags
8       2     Compression method
10      2     Last mod time
12      2     Last mod date
14      4     CRC-32
18      4     Compressed size      ← integer overflow candidate
22      4     Uncompressed size    ← integer overflow candidate
26      2     Filename length      ← controls how much data to read
28      2     Extra field length   ← controls how much data to read
30      var   Filename
30+n    var   Extra field
```

That's 15 fields in ONE header. A real ZIP has central directory entries,
end-of-central-directory records, ZIP64 extensions, encryption headers.
Hundreds of fields. Each field interacts with every other field.

What happens when `compressed_size = 0xFFFFFFFF` but the actual data
is 10 bytes? When `filename_length = 0` but there's no filename?
When `extra_field_length = 0x7FFF` and the file is only 40 bytes long?
When the compression method is an undefined value?

You tested 50 TOCTOU variants manually. A ZIP parser has MILLIONS of
potentially interesting input combinations per header. And mpengine
parses ZIP, RAR, 7z, CAB, PDF, DOC, PE, ELF, ISO, VHD, and fifty more
formats. You're not going to manually craft test cases for all of them.

The fuzzer will.

---

## Three Approaches To Fuzzing

### 1. Dumb Fuzzing (Mutation-Based, No Feedback)

Take a valid input file. Flip random bits. Feed it to the target.

```
VALID.zip → flip byte 14 → test → no crash
VALID.zip → flip byte 27 → test → no crash
VALID.zip → flip bytes 18-21 (compressed size) → test → CRASH
```

**Pros**: Dead simple. No knowledge of the target needed. Fast.
**Cons**: Shallow coverage. Most mutations produce garbage that gets
rejected by the first parser check. The fuzzer spends 99% of its time
hitting the same early error path. It never reaches the deep parser
logic where the real bugs hide.

**Military analogy**: Suppressive fire into a treeline. You might hit
something, but you're burning ammo without knowing where the enemy is.

### 2. Grammar-Based Fuzzing (Generation-Based)

Build a model of the file format. Generate inputs that are STRUCTURALLY
valid but have corrupted values in specific fields.

```python
# Pseudocode - grammar-aware ZIP generator
def generate_zip():
    header = ZipLocalHeader()
    header.signature = PK_MAGIC      # valid signature (passes first check)
    header.version = random_uint16() # might be weird but parser continues
    header.compressed_size = 0xFFFFFFFF  # edge case: trigger integer issues
    header.filename_length = random(0, 65535)  # might exceed actual data
    # ... construct rest of valid-ish structure
    return header.serialize()
```

**Pros**: Gets past the initial format validation. Reaches deeper parser
code. Can target specific fields you suspect are vulnerable.
**Cons**: Requires manual work to write the grammar for each format.
If your model is wrong, you miss bugs. If the parser has undocumented
extensions, your grammar doesn't cover them.

**Military analogy**: Targeted fire based on recon. Better than spray.
But your intel is only as good as your recon. If the enemy moved, you're
hitting empty positions.

### 3. Coverage-Guided Fuzzing (THE KING)

Instrument the target binary so you can see WHICH CODE PATHS each input
exercises. Mutate inputs. Keep the mutations that discover new paths.
Discard the ones that don't. Automatically evolve toward maximum coverage.

```
Seed corpus → mutate → execute → NEW CODE PATH FOUND?
                                    ├── YES: save to corpus, mutate further
                                    └── NO: discard, try different mutation

Iteration 1:    100 paths covered
Iteration 1000: 847 paths covered  (evolved from the first 100)
Iteration 1M:   2,341 paths covered
Iteration 10M:  2,589 paths covered ← plateau approaching
```

**Pros**: No knowledge of the format needed. The fuzzer LEARNS the format
by observing which mutations reach new code. Fully automatic. State of
the art. This is what Google uses on Chrome, what Microsoft uses on
Windows, what everyone serious uses.

**Cons**: Requires instrumentation of the target binary (harder for
closed-source). Slower per-execution than dumb fuzzing because of the
instrumentation overhead. But dramatically more effective per hour.

**Military analogy**: Fire-and-adjust with real-time drone recon. You
shoot, the drone tells you where the round landed relative to the enemy,
you adjust. Every round gets closer. The drone IS the coverage feedback.

**This is what we use.** Everything from here on assumes coverage-guided
fuzzing.

---

## Coverage-Guided Fuzzing: The Deep Dive

### What Binary Instrumentation Means

Coverage-guided fuzzing needs to know which code paths the target
executes for each input. To do that, you INSTRUMENT the binary —
insert monitoring code at key points (usually the start of every
basic block or every edge between blocks).

Three ways to instrument:

**Compile-time instrumentation** (needs source code):
LLVM's SanitizerCoverage adds coverage tracking at compile time.
Every basic block gets a counter. After execution, you read the counters
to see what was hit. Fastest. But we don't have mpengine.dll source.

**Static binary rewriting** (no source needed):
Rewrite the binary on disk, inserting instrumentation at each basic
block. Tools like AFL's QEMU mode. Works but fragile — rewriting x86
binaries is hard because instruction boundaries aren't always clear.

**Dynamic binary instrumentation** (no source needed, runtime):
A runtime framework intercepts execution and adds instrumentation
dynamically. **DynamoRIO** and **Intel PIN** do this. DynamoRIO is
what WinAFL uses. The target runs inside DynamoRIO's sandbox, which
tracks every basic block and edge transition at runtime.

```
                    ┌─────────────────────────────┐
  mutated file ───→ │ DynamoRIO (instrumentation)  │
                    │  ┌───────────────────────┐   │
                    │  │ mpengine.dll           │   │
                    │  │   parse_zip()          │   │ → coverage map
                    │  │     decompress()       │   │   (which edges hit)
                    │  │       validate_crc()   │   │
                    │  └───────────────────────┘   │
                    └─────────────────────────────┘
```

DynamoRIO adds overhead (~2-5x slower per execution), but the coverage
data it provides makes the fuzzer ORDERS OF MAGNITUDE more effective
over time.

### Edge Coverage vs Block Coverage

**Block coverage**: Track which basic blocks are executed. A basic block
is a straight-line sequence of instructions with one entry and one exit.

**Edge coverage**: Track transitions BETWEEN blocks. This is more
granular and finds more bugs.

```
     ┌───┐
     │ A │
     └─┬─┘
    ┌──┴──┐
    ↓     ↓
  ┌───┐ ┌───┐
  │ B │ │ C │
  └─┬─┘ └─┬─┘
    └──┬──┘
       ↓
     ┌───┐
     │ D │
     └───┘

Block coverage: {A, B, C, D}  — knows blocks were hit but NOT the paths
Edge coverage:  {A→B, A→C, B→D, C→D}  — knows the exact paths taken
```

Why edges matter: Imagine an input that takes A→B→D, and another that
takes A→C→D. Both hit all four blocks. Block coverage says "100% covered,
nothing new." Edge coverage sees that A→B and A→C are different edges.
Different inputs exploring different paths.

AFL and WinAFL use edge coverage. This is one reason they find bugs
that block-coverage fuzzers miss.

### The Corpus: Seed → Mutate → Discover → Repeat

The corpus is the fuzzer's arsenal of interesting inputs.

```
INITIAL STATE:
  corpus/ contains 5 seed files (minimal valid files you provide)

CYCLE 1:
  Pick seed_1.zip from corpus
  Mutate: flip byte 18 (compressed_size field)
  Execute target with mutated file
  DynamoRIO reports: edges {A→B, B→C, C→X} — edge C→X is NEW
  Save mutated file as corpus/id_000006 (new seed!)

CYCLE 2:
  Pick id_000006 from corpus (the one that found edge C→X)
  Mutate further: flip byte 22 (uncompressed_size)
  Execute target
  DynamoRIO reports: edges {A→B, B→C, C→X, X→Y} — edge X→Y is NEW
  Save as corpus/id_000007

CYCLE 10,000:
  corpus has grown from 5 seeds to 847 files
  Each file exercises a different combination of code paths
  The fuzzer keeps mutating files that found new paths
```

This is a GENETIC ALGORITHM applied to bug finding. The "fitness
function" is code coverage. Inputs that explore new territory survive.
Inputs that don't are discarded. Over millions of iterations, the
corpus evolves toward inputs that exercise deep, complex parser paths —
exactly where the bugs hide.

### Corpus Minimization

After a fuzzing campaign, your corpus might have 10,000 files. Many
cover overlapping code paths. **Corpus minimization** finds the
smallest set of inputs that achieves the same total coverage.

```
Before:  10,000 files → 2,589 edges covered
After:    312 files  → 2,589 edges covered (same coverage, 97% fewer files)
```

Why minimize: Fewer files = faster fuzzing cycles = more mutations per
hour. You minimize periodically and when sharing corpus between machines.

### The Coverage Plateau

Every fuzzing campaign hits a wall. The coverage graph goes:

```
Edges
Found
  ^
  │           .-----------  plateau (stuck)
  │         ./
  │       ./
  │     ./
  │   ./
  │  /
  │ /
  │/
  └──────────────────────→ Time
```

When the fuzzer stops finding new paths, you need one or more of:
- **Better seeds** (files that already exercise deep paths)
- **A dictionary** (magic bytes and keywords for the format)
- **A different harness** (targeting a different parsing function)
- **A different fuzzing strategy** (grammar-aware mutations)
- **Structure-aware mutations** (custom mutator that understands the format)

The plateau is INFORMATION. It tells you the fuzzer has exhausted what
it can discover from random mutation alone. Time to give it better tools.

---

## WinAFL: Our Primary Weapon

### What It Is

WinAFL is a fork of American Fuzzy Lop (AFL) for Windows. AFL is the
most influential fuzzer ever written — Michal Zalewski (lcamtuf) created
it at Google in 2013 and it changed the field. WinAFL adapts AFL's
coverage-guided approach for Windows binaries using DynamoRIO for
instrumentation.

### Persistent Mode: Speed Through Looping

Normal fuzzing: start process → feed input → check crash → kill process.
Process creation is SLOW on Windows (~10ms per spawn). At 10ms per test,
you get ~100 executions/second. Pathetic.

**Persistent mode**: Start the process ONCE. Call the target function in
a loop. Mutate the input file between calls. No process restart.

```
Process starts → setup (load DLLs, init state)
  │
  ├→ WinAFL restores function state
  │   ├→ Mutate input file on disk
  │   ├→ Call target_function(input_filename)
  │   ├→ Record coverage
  │   └→ Loop back ─────────────────────────┐
  │                                          │
  ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
```

**Typical throughput**: 500-10,000+ exec/sec depending on target
complexity. That's 43 million to 864 million tests per day. From one
machine.

### How WinAFL Detects Crashes

WinAFL catches:
- **Access violations** (read/write to unmapped or protected memory)
- **Heap corruption** detected by the allocator
- **Unhandled exceptions** (division by zero, illegal instruction)
- **Timeouts** (target hung — infinite loop or deadlock)

Each crash is saved with the input that caused it and a stack hash
for deduplication. Same crash from different inputs = one unique crash.

---

## Alternatives: LibFuzzer and Honggfuzz

### LibFuzzer

In-process coverage-guided fuzzer from the LLVM project. The fuzzer
and target run in the SAME process. Your harness implements one function:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Parse 'data' as if it's a file
    parse_format(data, size);
    return 0;
}
```

**Pros**: Extremely fast (no IPC, no file I/O). Great for practice.
**Cons**: Needs source code to compile with LLVM instrumentation.
We don't have mpengine.dll source. Good for learning on open-source
targets, not for our actual mission.

### Honggfuzz

Supports hardware-based coverage via Intel Processor Trace (PT).
No need for DynamoRIO — the CPU itself records which branches were
taken. Lower overhead than DBI. Also supports persistent mode.

**Pros**: Hardware coverage = fast, low overhead. Good for binaries.
**Cons**: Intel PT support on Windows is finicky. DynamoRIO is more
battle-tested for Windows binary fuzzing.

### Why WinAFL First

```
mpengine.dll is:
  ✗ Not open source     → rules out compile-time instrumentation (LibFuzzer)
  ✓ Windows binary      → WinAFL is purpose-built for this
  ✓ Has clear entry points (scan functions) → good for persistent mode
  ✓ DynamoRIO handles instrumentation → no source needed
```

We start with WinAFL. If we hit a throughput wall, Honggfuzz with
Intel PT is the fallback.

---

## The Harness: Your Most Important Code

The harness is the bridge between the fuzzer and the target. It's the
custom code YOU write that:
1. Loads the target DLL
2. Resolves the function to fuzz
3. Calls that function in a loop with fuzzer-mutated input
4. Handles setup/teardown cleanly

### Design For mpengine.dll

```c
// Simplified harness concept — real version in Chapter 07
#include <windows.h>

typedef int (*ScanFunc)(const char *filename, int flags);

int fuzz_target(char *filename) {
    // === SETUP (runs once at process start) ===
    static HMODULE hEngine = NULL;
    static ScanFunc pfnScan = NULL;

    if (!hEngine) {
        hEngine = LoadLibraryA("mpengine.dll");
        if (!hEngine) return -1;

        // Resolve the scan entry point
        // (real offset found through reversing — Chapter 08)
        pfnScan = (ScanFunc)GetProcAddress(hEngine, "ScanFile");
        if (!pfnScan) return -1;
    }

    // === FUZZ LOOP (called millions of times) ===
    // WinAFL mutates 'filename' on disk before each call
    pfnScan(filename, 0);

    return 0;
}
```

### The Art of Harness Writing

**Minimize per-iteration setup.** Everything that can run ONCE at
startup should run once. LoadLibrary, function resolution, global init —
all in the static block. The fuzz loop should be as thin as possible:
call the target function, return. Every microsecond of overhead costs
you thousands of tests per hour.

**Maximize coverage of target code.** Your harness should call the
function that parses the DEEPEST. Don't fuzz a wrapper that validates
the filename then calls the real parser — fuzz the real parser directly.
The deeper you hook, the more parser code gets covered per execution.

**Reset state between iterations.** Persistent mode calls the function
in a loop WITHOUT restarting the process. If the parser allocates memory
and doesn't free it, you'll leak. If it sets global flags, they'll be
stale on the next iteration. The harness needs to either:
- Call the target in a way that cleans up naturally, or
- Manually reset critical global state between calls

### Common Harness Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Too much setup per iteration | Low exec/sec (< 50) | Move setup to static init |
| No state reset | False crashes, OOM after 10k iterations | Reset globals, free leaked memory |
| Wrong target function | High exec/sec but zero crashes, low coverage | Reverse the binary, find the actual parser entry |
| Harness masks crashes | Target crashes but harness catches exception | Don't wrap target call in try/catch |
| Input via memory, not file | Fuzz file-based parser by feeding memory buffer | Match the target's actual input method |

---

## Seed Corpus Design

Your seed corpus is the starting gene pool. Better seeds = faster
coverage growth = more bugs found in less time.

### Rule 1: Minimal Valid Files

Start with the SMALLEST valid file for each format. Why?

```
Seed: 50-byte minimal ZIP     → fuzzer mutates 50 bytes
Seed: 15MB real-world ZIP     → fuzzer mutates 15 million bytes

Small seed: 1,000 exec/sec × meaningful mutations = fast exploration
Large seed: 50 exec/sec × mostly wasted mutations = slow, wasteful
```

The fuzzer explores FASTER from small seeds. Each mutation has a higher
chance of affecting a meaningful parser field when there are fewer
total bytes.

### Rule 2: One Seed Per Parser Entry Point

mpengine has separate parsing paths for each format. You need seeds
that exercise each path:

```
seeds/
  ├── minimal.zip        (ZIP parser)
  ├── minimal.pdf        (PDF parser)
  ├── minimal.doc        (OLE parser)
  ├── minimal.exe        (PE parser)
  ├── minimal.rar        (RAR parser)
  ├── minimal.cab        (CAB parser)
  ├── minimal.iso        (ISO parser)
  ├── minimal.vhd        (VHD parser)
  └── nested.zip         (ZIP containing PDF — triggers recursive parsing)
```

### Rule 3: Seeds From The Wild

Real-world malware samples make EXCELLENT seeds. They already exercise
deep parser paths because they're designed to evade detection — which
means they hit edge cases, use unusual field combinations, and stress
parsers in ways a minimal file never would.

Sources:
- **MalwareBazaar** (abuse.ch) — free, community-contributed
- **VirusTotal** (if you have access) — largest collection
- **theZoo** (GitHub) — curated malware samples for research

A corpus of 100 real malware samples per format type gives the fuzzer
a massive head start. It doesn't need to DISCOVER those deep paths
from scratch — it starts there and mutates further.

---

## Dictionaries: Feeding The Fuzzer's Vocabulary

A dictionary is a file of tokens — magic bytes, keywords, field markers
— that the fuzzer can inject during mutation. Without a dictionary, the
fuzzer has to discover these values by random chance. With one, it can
intelligently insert format-specific values.

### ZIP Dictionary

```
# zip.dict
# Magic signatures
"\x50\x4b\x03\x04"   # Local file header
"\x50\x4b\x01\x02"   # Central directory entry
"\x50\x4b\x05\x06"   # End of central directory
"\x50\x4b\x07\x08"   # Data descriptor
"\x50\x4b\x06\x06"   # ZIP64 end of central directory

# Compression methods
"\x00\x00"            # Stored (no compression)
"\x08\x00"            # Deflate
"\x0c\x00"            # BZIP2
"\x0e\x00"            # LZMA
```

### PDF Dictionary

```
# pdf.dict
"%PDF-"
"/Type"
"/Pages"
"/Page"
"/Catalog"
"stream"
"endstream"
"endobj"
"xref"
"trailer"
"/Filter"
"/FlateDecode"
"/Length"
"startxref"
"%%EOF"
```

With these dictionaries, the fuzzer doesn't randomly stumble on
`PK\x03\x04` — it INJECTS it at various positions, exploring what
happens when a ZIP signature appears where a PDF keyword was expected.
Cross-format confusion bugs. Exactly the kind of thing a manual tester
would never try.

---

## Reading The Fuzzer Output

WinAFL's status screen shows real-time metrics. Here's what matters:

```
+-- WinAFL 2.x (drills target) ---+
|       run time : 0 days, 4 hrs  |
|    last crash  : 0 days, 0 hrs  |
|  total execs   : 18,472,039     |
|   exec speed   : 1,284/sec      |  ← throughput
|                                  |
| paths found    : 2,341          |  ← coverage (should grow)
| new paths      : +12 (last hr)  |  ← growth rate
| pending        : 47             |  ← inputs not yet mutated
|                                  |
| unique crashes : 7              |  ← WHAT WE'RE HERE FOR
| unique hangs   : 3              |  ← also interesting
+----------------------------------+
```

### Key Metrics

**exec/sec**: Raw throughput. Higher = more exploration per hour.
- Below 100: Something is wrong (harness doing too much per iteration)
- 100-500: Acceptable for complex targets
- 500-2000: Good. Standard for DynamoRIO-instrumented targets
- 2000+: Excellent. Lean harness, fast target function

**paths found**: Total unique edge combinations discovered. Should
increase rapidly at first, then slow. If it plateaus AND you have
zero crashes, consider better seeds or a dictionary.

**unique crashes**: Deduplicated by crash address and call stack hash.
7 unique crashes from 18 million executions is a GOOD campaign. Each
crash gets saved in `crashes/` with the input that triggered it.

**unique hangs**: Target didn't return within the timeout. Could be an
infinite loop triggered by the input. Worth investigating — some hangs
are exploitable (resource exhaustion, algorithmic complexity attacks).

**new paths (growth rate)**: If this drops to zero and stays there for
hours, you've hit the coverage plateau. Time for better seeds, a
dictionary, or a different target function.

---

## RunPod Infrastructure

George runs fuzzers on RunPod (RTX 5090, expendable cloud instance).
This is the right call.

### Why Cloud

- **24/7 uptime**: Fuzzing is a numbers game. More hours = more coverage.
  Your local machine needs to sleep. RunPod doesn't.
- **Dedicated resources**: Fuzzing is CPU-intensive. Running it locally
  makes your machine unusable for everything else.
- **No local impact**: If a fuzzed input triggers something unexpected
  on the host, it's a disposable cloud instance, not your daily driver.
- **Parallel campaigns**: Run multiple fuzzers against different format
  parsers simultaneously. One instance per campaign.

### Tooling (Built In Later Chapters)

- `fuzz_runner.py` — Manages fuzzing campaigns: starts WinAFL with
  correct arguments, monitors exec/sec, restarts on stalls
- `crash_triage.py` — Processes crash directory automatically: deduplicates
  by stack hash, classifies by type (read AV, write AV, call AV), flags
  probable exploitability
- `coverage_tracker.py` — Plots coverage growth over time, alerts on
  plateau

These tools run on RunPod alongside the fuzzer. You check in periodically
to review crashes and adjust strategy. The infrastructure does the
grinding.

---

## What This Looks Like Against mpengine.dll

Putting it all together for the actual target:

```
1. SEED CORPUS
   minimal files: zip, pdf, doc, exe, rar, cab, iso, vhd
   + 100 malware samples per format from MalwareBazaar
   + format-specific dictionaries

2. HARNESS
   Loads mpengine.dll
   Resolves scan entry point (found through reversing)
   Calls scan function in persistent-mode loop
   WinAFL mutates input file between calls

3. INSTRUMENTATION
   DynamoRIO instruments mpengine.dll + dependencies
   Tracks edge coverage across all parser code paths

4. EXECUTION
   WinAFL on RunPod: 1000+ exec/sec target
   Multiple campaigns in parallel (one per format family)
   24/7 operation

5. OUTPUT
   crashes/ directory fills with inputs that triggered bugs
   crash_triage.py classifies each: read AV, write AV, call AV
   write AV on controlled data = potential exploit
   call to controlled address = probable exploit
```

The TOCTOU campaign found Defender's logic bugs through understanding.
The fuzzing campaign finds Defender's memory bugs through brute-force
coverage exploration. Both approaches find real bugs. Together they
cover the entire attack surface.

---

## Mapping To The Doctrine

The 0x1security compass has four points:

1. Search for knowledge, not 0-days.
2. See paths, see blocks, find substitutes.
3. Crash -> leak memory -> execute arbitrary code.
4. **To find crashes, you need FUZZING.**

This chapter IS point four. Everything in chapters 01-04 taught you
WHAT to do with a crash once you have one. Heap overflow → corrupt
adjacent object. UAF → replace freed memory → hijack vtable. Type
confusion → misaligned fields → function pointer control.

But you need the crash first. And finding crashes in a parser that
handles dozens of file formats with hundreds of fields each is not
a manual operation. It's a VOLUME operation. The fuzzer generates
volume. The harness targets the right code. The coverage feedback
makes every iteration smarter than the last.

Point 3 of the doctrine is the exploitation chain: crash → leak → exec.
Point 4 is how you ENTER that chain. Without fuzzing, you're back to
the TOCTOU campaign — brilliant manual work that found real bugs but
took weeks per target and missed the memory corruption bugs entirely.

The manual TOCTOU campaign taught you how Defender thinks.
The automated fuzzing campaign finds where Defender bleeds.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Fuzzing** | Automated testing by feeding massive volumes of semi-random input to a program and watching for crashes |
| **Mutation-based fuzzing** | Generating test inputs by randomly modifying (mutating) existing valid files |
| **Grammar-based fuzzing** | Generating test inputs using a model of the file format structure |
| **Coverage-guided fuzzing** | Fuzzing that instruments the target to track code coverage, evolving inputs toward new paths |
| **Binary instrumentation** | Inserting monitoring code into a compiled binary at runtime (DynamoRIO) or statically |
| **DynamoRIO** | Dynamic binary instrumentation framework; injects coverage tracking into Windows binaries at runtime |
| **Edge coverage** | Tracking transitions between basic blocks (A→B), more granular than block coverage |
| **Corpus** | The fuzzer's collection of interesting inputs, evolved through coverage feedback |
| **Corpus minimization** | Reducing a corpus to the smallest set of inputs that achieves the same total coverage |
| **Coverage plateau** | When the fuzzer stops discovering new code paths; signals need for better seeds or strategy |
| **WinAFL** | AFL fork for Windows using DynamoRIO; our primary fuzzing tool for closed-source Windows binaries |
| **Persistent mode** | Calling the target function in a loop without process restart; dramatically increases throughput |
| **Harness** | Custom code that loads the target, resolves functions, and calls them in a loop for the fuzzer |
| **Seed file** | Initial input file provided to the fuzzer before mutations begin |
| **Dictionary** | File of format-specific tokens (magic bytes, keywords) the fuzzer injects during mutation |
| **exec/sec** | Fuzzer throughput: number of test executions per second |
| **Unique crash** | Crash deduplicated by stack hash; distinct bug, not just a different input triggering the same fault |

---

## Drill 05 — First Harness

Go to `DRILLS/05_first_harness/`. A simple vulnerable DLL is waiting
with a parsing function that has a heap overflow.

Your mission:
1. Write a WinAFL harness that loads the DLL and calls the parsing function
2. Create a minimal seed file for the parser's expected format
3. Write a format dictionary with the parser's magic bytes
4. Run WinAFL with DynamoRIO instrumentation
5. Find the crash (it's there — the fuzzer will find it in under 5 minutes)
6. Analyze the crash input: which byte mutation triggered the overflow?

This is your first automated crash. After 14 manual TOCTOU versions,
you're about to watch a machine find a bug while you do nothing.

That's the point.
