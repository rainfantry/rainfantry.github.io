# Chapter 13 — The 0x1security Doctrine: Search For Knowledge, Not For Bugs

**VADER-RCE Field Manual**
**Prerequisite**: All prior volumes (TOCTOU campaign, Volumes I-III)
**Drill**: N/A — this is doctrine

---

## Volume IV: War College — Strategic Doctrine

Everything before this chapter was TACTICAL. Heap internals, overflow patterns,
UAF chains, fuzzing theory, crash triage, exploit primitives, target reversing —
those are weapons and techniques. Individual skills. The ability to field-strip
a rifle doesn't make you a strategist.

This chapter is different. This is doctrine. Strategic-level thinking that
determines WHETHER you find anything at all. You can master every technique in
Volumes I through III and still waste years producing nothing — because you
were looking in the wrong places, in the wrong way, for the wrong things.

The 0x1security framework comes from the Israeli security research community.
Specifically, from a researcher with 15+ CVEs including government work.
Fifteen. Not blog posts. Not talks. Not "responsibly disclosed information
disclosures." Fifteen remote code execution and privilege escalation
vulnerabilities in production software, found over the course of a career
spent inside the guts of things that wanted to stay hidden.

When someone with that track record tells you how to think about research,
you shut the fuck up and listen.

---

## The Core Principle: Knowledge Before Bugs

### The Bug Hunter's Trap

Here's what most security researchers do:

1. Pick a target (usually whatever's trending on Twitter)
2. Run a scanner / grep for known patterns / throw a fuzzer at it
3. Pray for crashes
4. If crash, write a blog post
5. If no crash, abandon target and repeat from step 1

This is RECONNAISSANCE BY FIRE — spray ammunition in a direction and see
if anything screams. It works. Sometimes. It finds shallow bugs in soft
targets. The kind of bugs that five other researchers already reported.
The kind that get patched before your disclosure email gets read. The kind
that score a 5.3 CVSS and nobody cares.

You know what this approach DOESN'T find? The bugs that matter. The design
flaws buried three abstraction layers deep. The race conditions that only
manifest under specific scheduling. The trust boundary violations where
Component A assumes Component B already validated the input, and Component B
assumes Component A did it, and NOBODY DID.

Those bugs don't live on the surface. Scanners don't find them. Greps don't
find them. Naive fuzzing doesn't find them. They live in the GAP between
intended behavior and actual behavior — and you can only see that gap if
you understand BOTH.

### The 0x1security Principle

**Search for knowledge, not for bugs.**

Don't hunt vulnerabilities. Hunt understanding. The vulnerabilities are a
BYPRODUCT of understanding. They fall out of the research like shell casings
from a firefight.

When you understand a system deeply enough — its architecture, its assumptions,
its trust model, its failure modes — the bugs become OBVIOUS. You look at
a code path and think "this trusts the length field from the file header
without validating it against the remaining buffer size." You don't need a
fuzzer to tell you that. You can SEE it because you understand what the
code is supposed to do and you can see where it doesn't.

This is the difference between a sniper and a machine gunner. The machine
gunner expends a thousand rounds to suppress an area. The sniper expends
one round to eliminate a specific target. Both have their uses. But the
sniper had to study the terrain, understand the wind, calculate the drop,
and KNOW exactly where the target would be standing before pulling the
trigger.

Knowledge. Before. Bugs.

### The TOCTOU Proof

The TOCTOU campaign against Windows Defender proved this doctrine in practice.

We didn't start by running exploits against Defender. We started by STUDYING
it. ProcMon traces. Minifilter analysis. FILE_OBJECT lifecycle mapping.
Understanding the three-phase scan pipeline: detect → scan → quarantine.
Mapping the trust boundaries between MsMpEng.exe and WdFilter.sys.

From that understanding, we identified 30+ findings. Thirty. Not from
scanning. Not from fuzzing. From READING. From understanding what the system
was supposed to do and then asking "but what if it doesn't?"

The junction-based TOCTOU attack line ultimately failed — Defender's
FILE_OBJECT binding, identity gate, and content re-verification turned out
to be robust against our primary attack. But we didn't walk away empty-handed.
We walked away with a COMPLETE MAP of how Windows Defender processes files
at the kernel level. That map is worth more than any single bug. It tells
us where to look NEXT. It tells us what the architecture protects and —
more importantly — what it DOESN'T.

The HWBP pivot that gave us AMSI and ETW bypass? That came from the map.
We saw a block on one path and found a substitute. That's doctrine in action.

---

## See Paths, See Blocks, Find Substitutes

This is the second pillar. Three words that define the entire tactical
approach to security research: PATHS, BLOCKS, SUBSTITUTES.

### PATHS: How Data Flows

A path is the journey data takes through a system. Input enters at one
end, decisions happen in the middle, actions come out the other end.
Every program is a series of paths.

```
USER INPUT
    │
    ▼
┌─────────────┐
│   PARSER     │◄── Reads raw bytes, interprets structure
├─────────────┤
│  VALIDATOR   │◄── Checks parsed values against rules
├─────────────┤
│  DISPATCHER  │◄── Routes to handler based on parsed type
├─────────────┤
│   HANDLER    │◄── Processes the content, allocates memory
├─────────────┤
│   ACTION     │◄── Does something: scan, quarantine, execute
└─────────────┘
```

Each transition is a trust boundary. The parser trusts the raw bytes to
have SOME structure (they might not). The validator trusts the parser to
have extracted the fields correctly (it might not). The dispatcher trusts
the validator to have rejected malformed input (it might not). Every
"might not" is a potential vulnerability.

Your job in Phase 1 of research is to MAP EVERY PATH. Not some paths.
Not the obvious paths. EVERY path. Where does input enter? What parses it?
What decisions are made? What code runs as a result of those decisions?
What privileges does that code have?

For Defender's mpengine.dll, the paths look like:

```
FILE ON DISK
    │
    ▼
WdFilter.sys minifilter intercepts I/O
    │
    ▼
MsMpEng.exe receives scan request
    │
    ▼
mpengine.dll identifies file format (PE, script, archive, doc...)
    │
    ▼
Format-specific parser runs (PE parser, script engine, archive extractor...)
    │
    ▼
Signature matching against parsed content
    │
    ▼
Decision: clean / suspicious / malicious
    │
    ▼
Action: allow / quarantine / remediate
```

Each arrow is a path. Each box is a trust assumption. The format
identification trusts the file header. The parser trusts the format
identification. The signature engine trusts the parser output. Anywhere
that trust is misplaced, you have a potential bug.

### BLOCKS: Where They Said "No"

A block is a deliberate security boundary. The developers KNEW this
was a dangerous transition and put up a wall.

In the TOCTOU campaign, we hit multiple blocks:

- **FILE_OBJECT binding**: Defender binds to the kernel file object
  at scan start. Swapping the file path via junction after binding
  doesn't change what Defender reads. That's a block on path substitution
  at the filesystem level.

- **Content re-verification**: Even if you could swap content, Defender
  re-verifies after the scan completes. The quarantine decision is
  based on CURRENT content, not the content that was scanned. That's
  a block on delayed substitution.

- **Identity gate**: The file's identity (hash, metadata) is checked
  at multiple points. A file that changes identity mid-pipeline gets
  flagged or re-scanned. That's a block on mutation attacks.

Each of these blocks tells you something critical: the developers
THOUGHT ABOUT this attack. They anticipated it. They defended against it.
That means THIS path is hardened.

But it also means something else. It means there are paths they DIDN'T
think about. The existence of a block on Path A implies the existence
of an unblocked Path B — because no defense is infinite and every
engineering team has finite time. They chose to block THESE paths.
What didn't they choose?

### SUBSTITUTES: The Roads They Forgot

This is the punchline. When the direct path is blocked, you find
the path they didn't block. Not because they were stupid — because
they were human. They had a threat model. They defended against the
threats in their model. Your job is to find the threats that WEREN'T
in their model.

**The HWBP Pivot**:

Junction-based TOCTOU was blocked. Defender's kernel-level file binding
defeated path substitution. Direct path: closed.

But the GOAL wasn't "use junctions." The goal was "bypass Defender's
detection." The junction was one PATH to that goal. When it was blocked,
we asked: what other paths exist?

Hardware Breakpoint Debug Registers (HWBP) weren't monitored by Defender.
They exist in a completely different layer — CPU debug registers, not
filesystem operations. Defender's entire defense was built around
filesystem-level attacks. It watches files. It watches file objects. It
watches file paths. It does NOT watch debug registers.

Same goal. Different path. The substitute worked.

AMSI bypass via HWBP: set a hardware breakpoint on `AmsiScanBuffer`'s
return, patch the return value. Defender never sees the malicious script.

ETW bypass via HWBP: set a hardware breakpoint on `NtTraceEvent`, force
a return before the event is written. Telemetry goes dark.

Neither of these was "found" by scanning. Both were found by understanding
the architecture deeply enough to see that the defense existed in ONE
layer and didn't extend to ANOTHER layer. See the block. Find the
substitute.

---

## The Research Pipeline: CRASH, LEAK, EXECUTE

The third pillar gives you a STAGED methodology for memory corruption
research. Don't try to jump from zero to RCE. That's not how it works.
Not in practice. Not ever.

### Stage 1: CRASH

> More than 50% of 0-days are created from a crash found through fuzzing.

That's not a guess. That's the historical record. The majority of remote
code execution vulnerabilities in major software started as a crash
someone found — often by accident — and then spent weeks or months
turning into a reliable exploit.

**Your first objective is to make the target crash.** Any crash.
Anywhere. Doesn't matter if it's exploitable yet. A crash proves
INSTABILITY in the code. It means the parser made an assumption about
the input that turned out to be wrong. The assumption that was wrong
is the foundation of your exploit.

How to get crashes:

- **Fuzzing**: Mutate valid files, feed them to the target, monitor for
  crashes. WinAFL, AFL++, libFuzzer. This is the volume play.
  Chapter 05 covered fuzzing theory. Chapter 06 covered crash triage.

- **Manual crafting**: Understand the parser, construct inputs that
  violate specific assumptions. Shorter field counts than expected.
  Larger sizes than allocated. Negative values where unsigned was
  assumed. Recursive structures that exceed stack depth.

- **Differential testing**: Same input, two implementations. If
  Parser A and Parser B produce different results, at least one of
  them has a bug. Feed the divergent input to both and see which one
  crashes.

A crash is not a vulnerability. Not yet. A crash is EVIDENCE that a
vulnerability exists somewhere near the crash site. It's a bullet hole
in the wall — proof someone was shooting, and a clue about where the
shooter was standing.

### Stage 2: LEAK

From a crash, you need to extract INFORMATION. Modern exploitation
requires defeating ASLR (Address Space Layout Randomization), which
means you need to know where things are in memory before you can
redirect execution to them.

A memory leak gives you that knowledge. Specifically:

- **Heap base address**: where the heap starts, so you know where
  your controlled data will be allocated
- **Module base address**: where ntdll.dll, kernel32.dll, or the target
  binary itself is loaded, so you know where gadgets live
- **Stack address**: for stack pivoting techniques
- **Vtable pointers**: for type confusion attacks — knowing the vtable
  address of an object tells you what class it is AND where the
  module is loaded

How to get leaks:

- **Out-of-bounds read (OOB read)**: The parser reads past the end
  of a buffer. What's sitting past the end? Adjacent heap metadata.
  Pointers from other objects. Module addresses. If the read value
  is returned to the attacker (in an error message, a response, a
  rendered output), that's a leak.

- **Uninitialized memory disclosure**: The program allocates a buffer,
  doesn't zero it, then copies it to output. Whatever was in that
  memory from the last allocation is now in the output. Previous
  allocations leave pointers, sizes, flags — all useful.

- **Format string bugs**: `printf(user_input)` instead of
  `printf("%s", user_input)`. If the attacker controls the format
  string, `%p` reads values off the stack. Stack frames contain
  return addresses. Return addresses are module pointers. Module
  pointers defeat ASLR.

The leak stage converts "I can crash it" into "I can crash it AND
I know where everything is in memory." That's a fundamentally different
situation.

### Stage 3: EXECUTE

With a crash primitive and an information leak, you have:

1. A way to corrupt memory (the crash)
2. Knowledge of the memory layout (the leak)

Now you chain them:

1. Trigger the leak to obtain addresses
2. Compute the target address (gadget, shellcode, function pointer)
3. Trigger the corruption to overwrite a control value (function pointer,
   vtable entry, return address) with the computed target
4. Trigger the corrupted control value to be used
5. Execution redirected to attacker-controlled code

Each step is its own engineering challenge. The corruption needs to be
PRECISE — not just "write garbage somewhere" but "write THIS value at
THAT address." The trigger needs to be RELIABLE — not a one-in-a-million
timing window but a deterministic sequence. The execution redirect needs
to land on USEFUL code — a ROP chain, a JOP chain, a shellcode allocation.

This is where Chapters 01-07 come together. Heap internals tell you how
memory is laid out. Overflow patterns tell you how to corrupt adjacent
objects. UAF tells you how to reclaim freed memory. Mitigations tell you
what you need to bypass. Exploit primitives tell you what shapes of
corruption are useful.

### The Discipline: Don't Jump Stages

The most common mistake in exploit development is trying to jump from
CRASH directly to EXECUTE. "I found a crash, let me write a full exploit
this weekend."

No. You don't have a leak yet. You don't know the memory layout. You're
guessing addresses. You're hardcoding offsets that change every reboot
(ASLR), every update (binary recompilation), every system (different
heap state). Your "exploit" works on your machine on Tuesday morning
and fails everywhere else.

CRASH → LEAK → EXECUTE. In order. Each stage is a prerequisite for the
next. Each stage is its own research project. Respect the pipeline.

---

## Target Selection Doctrine

Not all targets are equal. Where you point your attention determines
whether months of work produce a critical CVE or a wasted quarter.
Target selection is a strategic decision — treat it like one.

### Attack Surface Mapping

Before committing to a target, map its attack surface. This is
reconnaissance, not exploitation. You're answering one question:
**what does this target parse, and does it trust what it parses?**

For any software target:

| Question | Why It Matters |
|----------|----------------|
| What file formats does it parse? | Each parser is a separate attack surface |
| What network protocols does it speak? | Network-reachable parsers = remote attack surface |
| What input does it accept from users? | User input that reaches parsers without sanitization |
| What does it trust vs verify? | Trust without verification = vulnerability surface |
| What privileges does it run at? | SYSTEM/root bugs are worth more than user-level |
| Is parsing reachable pre-auth? | Pre-auth RCE is the highest impact class |

For Defender specifically:
- Parses: EVERY file format. Literally hundreds of parsers in mpengine.dll.
  PE, ELF, Mach-O, ZIP, RAR, 7z, CAB, MSI, PDF, Office docs (OOXML, OLE),
  scripts (JS, VBS, PowerShell), email formats (MIME, MSG, EML), disk
  images, fonts, certificates... the list is enormous.
- Runs as: NT AUTHORITY\SYSTEM — the highest privilege on Windows
- Reachable: pre-authentication. Drop a file on disk, Defender scans it.
  No user interaction required.
- Trusts: file format headers, length fields, offset tables — all
  attacker-controlled data inside the malicious file

That's a MASSIVE attack surface running at MAXIMUM privilege with
MINIMAL user interaction. This is why Defender is a high-value target.
This is also why it's a high-competition target — everyone knows this.

### Maturity Assessment

How many researchers have ALREADY been fuzzing this target? The
answer determines whether you'll find bugs or waste cycles covering
the same ground.

**Heavily fuzzed targets** (Chrome V8, libxml2, OpenSSL):
- Large teams with custom fuzzers running 24/7 on cloud infrastructure
- Google's OSS-Fuzz has been covering these for years
- Surface-level bugs are long gone
- Remaining bugs are deep, complex, multi-step — high skill to find
- Not impossible, but you're competing against well-funded teams

**Moderately fuzzed targets** (PDF parsers, image codecs, archive handlers):
- Some fuzzing has been done but coverage is incomplete
- Format-specific edge cases may not be covered
- Third-party implementations often less fuzzed than first-party
- Good territory for a solo researcher with patience

**Under-fuzzed targets** (niche format parsers, embedded device firmware,
antivirus engines, ICS/SCADA protocols):
- Limited or no public fuzzing coverage
- Developers may not have security testing in their pipeline
- Bugs live closer to the surface
- Higher probability of findings per hour of research

mpengine.dll sits in an interesting spot: the MAIN parsing paths (PE,
common archives) have been fuzzed by Tavis Ormandy and others.
But the OBSCURE format handlers — CHM, HLP, WIM, specific OLE stream
sub-parsers — are less covered. Niche parsers inside a high-privilege
process. That's the sweet spot.

### The Kill Criteria

Here's the part nobody teaches: **when to quit a target.**

Researchers fall in love with their targets. They spend three months
reversing a parser, find nothing, and spend three MORE months because
"I've invested too much to stop now." That's the sunk cost fallacy
wearing a hoodie and drinking energy drinks.

Kill criteria — decide BEFORE you start:

- **Time box**: If no crash within N hours of fuzzing with decent coverage,
  re-evaluate the corpus and harness. If still nothing after 2N hours,
  consider pivoting.

- **Coverage plateau**: If code coverage stops increasing and you've
  already optimized your corpus, the fuzzer has explored what it can
  reach. Either improve the harness (deeper instrumentation, format-aware
  mutation) or pivot.

- **Architecture review**: If reversing reveals that the parser is
  simple, well-written, and uses safe APIs (bounded copies, checked
  arithmetic), the probability of memory corruption drops. Logic bugs
  may exist, but if you're hunting memory corruption, pivot.

- **Competition signal**: If someone else publishes a CVE in the exact
  parser you've been fuzzing, that's actually a GOOD sign (the parser
  IS buggy) AND a bad sign (someone else got there first). Decide
  whether to go deeper or find the next parser.

Never fall in love with a target. A target is not your identity. It's
a terrain feature. If the terrain is unfavorable, maneuver to better
ground.

---

## The Three Phases of Understanding

This is the operational framework for studying a target. Before you
write a single line of fuzzer harness code, you go through three
phases. Each phase builds on the last. Skipping phases is how you
end up fuzzing the wrong function with the wrong corpus getting the
wrong coverage.

### Phase 1: RECON — External Observation

Map the target from the OUTSIDE. You don't disassemble anything yet.
You observe behavior.

**Tools**: Process Monitor, API Monitor, Wireshark, strace/ltrace,
filesystem monitoring, network captures.

**Questions to answer**:

- What files does the target read/write during normal operation?
- What registry keys does it access?
- What DLLs does it load?
- What network connections does it make?
- What child processes does it spawn?
- What named pipes / shared memory / COM objects does it use?

For Defender, ProcMon showed us EVERYTHING the TOCTOU campaign needed
to understand the scan pipeline externally. We saw WdFilter.sys
intercepting file creates. We saw MsMpEng.exe reading file contents.
We saw the quarantine action at the end. We mapped the entire pipeline
without opening a disassembler.

**What you're building**: An EXTERNAL MODEL of the target. A map that
says "when file X arrives, components A, B, and C are involved, they
communicate via channels D and E, and the decision is made at point F."

### Phase 2: REVERSING — Internal Anatomy

Open the binary in Ghidra or IDA. Now you're looking INSIDE.

**Tools**: Ghidra, IDA Pro, x64dbg, WinDbg, Binary Ninja.

**Questions to answer**:

- What functions handle the input you identified in Phase 1?
- What does the parser expect the input to look like?
- Where does it allocate memory for parsed data?
- What validation does it perform on input fields?
- What validation does it SKIP?
- Where are the trust boundaries between components?
- What error handling exists? What happens on malformed input?

This is where Chapter 08 (Target Reversing) becomes operational.
You're not browsing the binary for fun. You're answering SPECIFIC
questions that emerged from Phase 1. "ProcMon showed MsMpEng.exe
reading the ZIP central directory. WHICH function in mpengine.dll
parses the central directory? What does it do with the file count
field? Does it validate the offset table?"

**What you're building**: An INTERNAL MODEL of the target. Function-level
understanding of how input is parsed, what's validated, what's trusted,
where memory is allocated and freed.

### Phase 3: HYPOTHESIS — Prediction Before Fuzzing

This is the phase that separates researchers from script kiddies.
You've observed the target externally (Phase 1). You've reversed
its internals (Phase 2). Now you form SPECIFIC, TESTABLE hypotheses
about where bugs should be.

Not "there might be a bug somewhere in the ZIP parser." That's useless.

Specific: "The ZIP parser reads the `compressedSize` field from the
local file header at offset 18. It uses this value to allocate a
decompression buffer at function `sub_180042A30`. The allocation
size is `compressedSize + 0x10` for a header structure. If
`compressedSize` is 0xFFFFFFF0 or larger, the addition wraps to a
small value, causing a heap overflow when the full compressed data
is copied into the undersized buffer."

THAT is a hypothesis. It identifies:
- The specific field (compressedSize)
- The specific function (sub_180042A30)
- The specific arithmetic (compressedSize + 0x10)
- The specific failure mode (integer overflow → undersized allocation)
- The specific consequence (heap overflow during decompression)

You can now craft a SINGLE test file that validates or invalidates
this hypothesis. If the crash happens as predicted, you have a
root-caused vulnerability. If it doesn't, you learn something new
about the parser's validation — maybe it checks for overflow,
maybe it caps the size, maybe it uses safe integer arithmetic.
Either way, your model improves.

**What you're building**: A set of PREDICTIONS that guide focused
testing. Each prediction either yields a bug or improves your model.
There is no wasted work.

---

## Lessons From The TOCTOU Campaign

The TOCTOU campaign against Windows Defender was the field manual's
first operation. It ran for weeks. It produced 30+ findings. It
ultimately failed to achieve the primary objective (reliable file
substitution during the scan-to-quarantine window). And it was a
COMPLETE SUCCESS from a doctrine perspective.

Here's why.

### What We Mapped

Through sustained research, we built a comprehensive model of
Defender's file processing architecture:

- **WdFilter.sys**: Kernel minifilter driver. Intercepts
  IRP_MJ_CREATE (file open), IRP_MJ_WRITE (file modify),
  IRP_MJ_CLEANUP (handle close). Fires scan events to
  user-mode MsMpEng.exe via filter communication port.

- **FILE_OBJECT binding**: When a scan starts, Defender obtains a
  reference to the kernel FILE_OBJECT. Subsequent reads use THIS
  object, not the file path. Changing the path after binding
  doesn't redirect reads. This defeated junction-based substitution.

- **Content verification**: Post-scan, pre-quarantine, Defender
  re-reads content to verify it matches what was scanned. This
  defeated delayed substitution.

- **Identity gate**: File identity (hash, size, metadata) is
  checked at transition points. A file that changes identity
  mid-pipeline triggers re-scan or abort.

- **Scan pipeline timing**: We measured the window between scan
  start and quarantine. It's tight. Even without the binding
  defense, the race window is narrow.

Every one of these findings is KNOWLEDGE. Not bugs — knowledge.
Understanding of a system that didn't exist in public documentation
anywhere. We built this model from scratch through observation
and reversing.

### How Each Finding Fed The Next

Finding #1 (WdFilter intercepts file operations) told us WHERE
to look. Finding #5 (FILE_OBJECT binding) told us WHY junction
substitution failed. That failure (#5) pointed us toward the
question of WHAT ELSE binds to the file identity, which led to
Finding #12 (content re-verification). Finding #12's existence
confirmed that the scan pipeline was defense-in-depth, which
meant the ENTIRE filesystem-level attack surface was hardened.

This is how knowledge compounds. Each finding constrains the
search space for the next finding. After 15 findings, you're
not searching randomly — you're following a logical chain of
"if THIS is true, then THAT must also be true, which means
THIS OTHER THING might be vulnerable."

### The HWBP Pivot

The most important lesson from the TOCTOU campaign:

The primary attack line (filesystem-level TOCTOU) failed.
The blocks were too strong. Junction substitution, oplock racing,
path mutation — all defeated by FILE_OBJECT binding and content
re-verification.

If we'd been hunting bugs instead of hunting knowledge, we
would have stopped here. "Target is hardened, move on."

But we were hunting knowledge. And the knowledge said: "Defender's
defenses are concentrated at the filesystem layer. What about
OTHER layers?"

Hardware Breakpoint Debug Registers (DR0-DR3) exist at the CPU
level. They're designed for debugging — set a breakpoint on a
memory address, and the CPU triggers a debug exception when that
address is accessed. They work WITHOUT modifying the target code.
No patching. No injection. Just a register write.

Defender monitors filesystem operations exhaustively. It does NOT
monitor debug registers. It has no reason to — debug registers
are a debugging tool, not an attack vector. Or so the threat
model assumed.

AMSI bypass: set HWBP on `AmsiScanBuffer` return instruction.
When the break fires, patch EAX to return `AMSI_RESULT_CLEAN`.
Defender's AMSI provider sees every script as clean. Invisible
at the filesystem layer.

ETW bypass: set HWBP on `NtTraceEvent` entry. When the break
fires, force a return before the event is logged. Telemetry
pipeline goes silent. Defender's cloud analytics get nothing.

See the path. See the block. Find the substitute. The TOCTOU
campaign didn't fail — it found a block that pointed to an
unblocked path.

### The Strategic Lesson

The TOCTOU campaign cost weeks of research and produced zero
filesystem-level exploits. By the "hunt bugs" metric, it was
a failure. Zero CVEs. Zero bug bounties. Zero glory.

By the "hunt knowledge" metric, it was the foundation of
everything that came after. The HWBP bypasses. The understanding
of Defender's architecture. The ability to assess Defender's
strength in specific areas and weakness in others. The target
model that tells us exactly where to point the fuzzer when
we're ready.

All of that came from UNDERSTANDING, not from scanning.

---

## Doctrine Applied To New Targets

This framework isn't specific to Defender. It applies to any
target you'll ever research. Here's how to apply it going forward.

### Before Fuzzing mpengine.dll

mpengine.dll is the next target. It's a massive binary — 15+ MB
of file parsers, emulation engines, signature matching, and
detection logic. You could throw WinAFL at it right now and
get crashes within hours. Don't.

**Phase 1 (RECON)**: What file formats trigger which code paths?
Use ProcMon + carefully chosen test files to map which internal
functions handle which formats. An EXE takes path A. A ZIP takes
path B. A PDF takes path C. Map them.

**Phase 2 (REVERSING)**: For your chosen format, reverse the
parser completely. Not "skim the decompiler output." COMPLETELY.
Every branch. Every allocation. Every size calculation. Every
trust assumption. Draw the data flow diagram. Mark where input
fields influence buffer sizes, loop counts, array indices.

**Phase 3 (HYPOTHESIS)**: Form specific predictions. "This
parser reads a 16-bit length field at offset 4 and allocates
that many bytes. But the copy loop uses a 32-bit counter from
offset 8. If offset 8 is larger than offset 4, the copy exceeds
the allocation." NOW craft your seed files to test exactly that.
NOW point the fuzzer at exactly that function with exactly that
seed.

The difference between "fuzz mpengine.dll" and "fuzz the CHM
LZXC decompression handler in mpengine.dll with seeds designed
to trigger integer overflow in the block size calculation" is
the difference between reconnaissance by fire and a precision
strike.

### Before Attacking Copilot

If you pivot to AI security (Copilot, coding assistants, LLM
agents), the same doctrine applies. Different domain, same method.

**Phase 1 (RECON)**: What are the trust boundaries? Where does
user input enter the system? What does the LLM trust? What can
the LLM's tool calls do? What authorization separates "the LLM
asked for it" from "the user asked for it"?

**Phase 2 (REVERSING)**: Understand the context handling. How is
the system prompt protected? What injection boundaries exist
between system prompt, user message, tool results, and RAG
context? How does the action authorization layer decide whether
to execute a tool call?

**Phase 3 (HYPOTHESIS)**: "If I inject a system-prompt-like
instruction in a RAG document that the LLM retrieves, will the
LLM follow it? If I craft a tool result that contains a
follow-up instruction, will the LLM execute the next tool call
the result asks for?"

Same framework. Different target. The researcher who understands
the trust model will find the prompt injection the scanner missed.
The researcher who understands the action authorization will find
the privilege escalation the fuzzer can't reach.

### The Universal Pattern

No matter the target:

1. Map the input surface
2. Trace the data paths
3. Identify the trust boundaries
4. Understand the defenses
5. Form hypotheses about where trust is misplaced
6. Test those hypotheses precisely
7. Learn from every result — positive or negative

The tools change. The target changes. The technique set changes.
The method doesn't.

---

## Standing Orders

These are non-negotiable. They're the rules of engagement for
all security research conducted under this doctrine. They apply
to every target, every campaign, every session.

### Order 1: Never Fuzz A Target You Haven't Reversed

Fuzzing without reversing is shooting blindfolded. Your fuzzer
might have great coverage of the format parser's HAPPY PATH and
zero coverage of the ERROR HANDLING paths where the actual bugs
live. You won't know because you can't see.

Reverse the target first. Understand the parser. Identify the
functions that handle untrusted input. THEN write your harness
to call those functions. THEN design your corpus to exercise
the paths you identified. THEN fuzz.

The time you spend reversing is repaid tenfold in fuzzer
efficiency. A blind fuzzer runs for weeks and finds nothing.
A targeted fuzzer runs for hours and finds what you predicted.

### Order 2: Never Submit A Crash You Haven't Root-Caused

A crash is not a vulnerability report. A crash is raw material.
Before you submit ANYTHING to a vendor:

1. Reproduce the crash reliably
2. Identify the exact instruction that faults
3. Understand WHY it faults (what memory was corrupted, where)
4. Trace the corruption backwards to the root cause
5. Determine if it's exploitable (can you control the corruption?)
6. Write a minimal proof-of-concept that demonstrates the root cause

If you can't explain why the crash happens, you don't understand
it. If you don't understand it, you can't assess exploitability.
If you can't assess exploitability, your vendor report will say
"here's a crash" and get triaged as low severity. A root-caused
report with exploitability analysis gets triaged as critical.

Same bug. Different write-up. Vastly different response.

### Order 3: Never Claim A Vuln You Can't Explain

This is Order 2's older brother. If another researcher asks
"how does this work?" and you can't explain it from first
principles — from the vulnerable code path to the corruption
to the exploitation — you don't have a finding. You have a
screenshot.

The ability to explain is the proof of understanding. If you
understand it, you can explain it. If you can't explain it,
you don't understand it. And if you don't understand it, you
can't reliably exploit it, and you can't accurately assess its
severity, and you can't write a proper advisory.

This also protects you from false positives. "I think this
might be a crash" is not a finding. "This crashes because
function X reads a length field at offset Y, uses it to index
into array Z without bounds checking, and when the length
exceeds the array size by N bytes, it reads N bytes of
adjacent heap metadata" — that's a finding.

### Order 4: Document Everything

Your future self is a different person. Three months from now
you will not remember why you reversed that specific function,
what your hypothesis was, or why you chose that particular seed
file. You will look at your own work and think "what the fuck
was I doing?"

Document it NOW:

- **Research log**: Date, target, function, hypothesis, result.
  Every session. Every finding. Every dead end.

- **Target model**: Continuously updated diagram/notes showing
  what you understand about the target's architecture. This is
  the PRODUCT of your research, even if you find zero bugs.

- **Crash analysis**: For every crash, full root cause analysis
  before moving on. Register state. Backtrace. Memory dump.
  Root cause. Exploitability assessment.

- **Methodology notes**: What worked. What didn't. What you'd
  do differently. This is how you improve.

The research log is not bureaucracy. It is operational memory.
Without it, you repeat mistakes, re-explore dead ends, and
lose findings in the noise. With it, you build on every session's
work like compound interest.

### Order 5: When Stuck, Go Deeper — Not Wider

When you stop finding things, the temptation is to pivot to a
new target. "Maybe mpengine is too hard. Let me try Chrome.
Actually, let me try a Linux kernel driver. Actually, let me
try..."

This is the death spiral. You accumulate shallow knowledge of
many targets and deep knowledge of none. Every pivot resets your
understanding to zero. You never reach the depth where the real
bugs live.

When you're stuck, the answer is almost always: GO DEEPER into
the CURRENT target.

- Stuck on the parser? Reverse the function it calls. And the
  function THAT calls. Trace the full call chain.
- Stuck on the input? Examine the format specification more
  carefully. Read the RFC. Read other implementations.
- Stuck on the crash? Improve your debugging setup. Add more
  breakpoints. Log more state. The answer is in the data.
- Stuck on exploitation? Study the heap layout more carefully.
  Run the allocation sequence a hundred times and map the
  deterministic patterns.

Depth compounds. Width dissipates. Go deeper.

---

## The Philosophy Beneath The Method

One final thing. This is the part that doesn't fit in an operations
manual but matters more than anything in it.

The 0x1security doctrine isn't just a research methodology. It's a
way of seeing. It teaches you to look at a system and ask not
"where are the bugs?" but "HOW DOES THIS WORK?" That question — how
does this work — is the most powerful question in security research.
It's also the most powerful question in engineering, in science, in
any discipline that deals with complex systems.

The bugs are DOWNSTREAM of understanding. They are a CONSEQUENCE of
knowledge, not the purpose of it. A researcher who hunts bugs finds
bugs — sometimes. A researcher who hunts understanding finds bugs as
a side effect — always. Because understanding reveals the gaps between
intent and implementation, and those gaps are where every vulnerability
lives.

This is not soft advice. This is the hardest discipline in the field.
It requires patience when you want results. It requires depth when
everything incentivizes breadth. It requires saying "I don't
understand this well enough yet" when your ego says otherwise.

Fifteen CVEs came from this approach. Not fifteen blog posts. Not
fifteen theoretical attack scenarios. Fifteen confirmed, patched,
credited vulnerabilities in production software, found by someone
who searched for knowledge and let the bugs come to him.

That's the doctrine. Follow it.

---

## Summary — Key Takeaways

- **Knowledge before bugs.** Don't hunt vulnerabilities. Hunt understanding.
  The vulnerabilities are a byproduct of deep knowledge. Scanners find
  surface bugs. Researchers who understand the target find the bugs the
  scanners missed.

- **See paths, see blocks, find substitutes.** Map how data flows through
  the system (paths). Identify where defenses exist (blocks). When a path
  is blocked, find alternate routes the defenders didn't anticipate
  (substitutes). The TOCTOU→HWBP pivot is the proof of concept for this
  entire pillar.

- **CRASH → LEAK → EXECUTE.** Staged methodology. Don't jump from zero
  to RCE. Make it crash first. Extract memory information second. Chain
  them into controlled execution third. Each stage is a prerequisite.
  Respect the pipeline.

- **Target selection is strategic.** Map attack surface, assess fuzzing
  maturity, evaluate competition. Hunt in under-fuzzed parsers inside
  high-privilege processes. Don't fall in love with a target — set kill
  criteria before you start.

- **Three phases: RECON → REVERSING → HYPOTHESIS.** Observe externally
  first. Disassemble internally second. Form specific testable predictions
  third. Then — and ONLY then — fuzz.

- **The TOCTOU campaign proved the doctrine.** Zero filesystem-level
  exploits. Thirty findings. Complete architectural map. HWBP bypass
  discovered as a lateral pivot. Success measured in knowledge, not in
  CVE count.

- **Never fuzz what you haven't reversed.** Blind fuzzing wastes cycles.
  Targeted fuzzing, guided by reversing and hypothesis, produces results
  orders of magnitude faster.

- **Never submit what you haven't root-caused.** A crash is raw material,
  not a finding. Root-cause every crash. Assess exploitability. Write the
  report that gets triaged as Critical, not the one that gets triaged as
  Low.

- **Document everything.** Research logs, target models, crash analyses,
  methodology notes. Your future self is a different person. Build
  operational memory.

- **When stuck, go deeper, not wider.** Depth compounds. Width dissipates.
  The bugs live at the bottom, not at the surface. Resist the pivot.
  Reverse the next function. Read the next RFC section. Trace the next
  allocation. The answer is in the data.

- **Understanding reveals gaps between intent and implementation.**
  Every vulnerability lives in that gap. A researcher who hunts
  understanding will always find more than a researcher who hunts bugs.
  This is the entire doctrine in one sentence.

---

*"Search for knowledge, not for 0-days."*
*— 0x1security*
