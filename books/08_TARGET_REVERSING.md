# Chapter 08 — Target Reversing: Know Thy Enemy

**VADER-RCE Field Manual**
**Prerequisite**: Ch01-07
**Drill**: (all previous drills prepare for this)

---

## Why You Need This

Fuzzing is blind. You throw millions of mutated files at a target and wait
for crashes. It works. But you're fighting with your eyes closed.

Reversing gives you SIGHT.

With reversing you know:
- WHICH parsers handle WHICH file formats inside mpengine.dll
- WHERE memory gets allocated and what controls the size
- WHAT validation exists before data is trusted
- HOW the parser dispatches between format handlers
- WHERE the error paths free objects (and whether they null the pointers)

Without reversing you're firing into fog. You don't know if your fuzzer
is hitting the right code. You don't know if your seed files are reaching
the parser you care about. You don't know what validation you need to
bypass to reach the allocation you want to overflow.

You already did external reconnaissance. The TOCTOU campaign used ProcMon
to observe Defender from the OUTSIDE — watching file operations, seeing
the scan pipeline fire, tracking the minifilter's behaviour. That was
signals intelligence. You intercepted communications.

Now you crack open the binary itself. IDA and Ghidra show you the INSIDE.
The actual instructions. The actual control flow. The actual trust
boundaries where the parser stops checking and starts trusting file data.

This is the 0x1security doctrine made literal: "Understand where trust
boundaries live in code." Reversing IS the act of finding those boundaries.
You can't map what you can't see.

---

## Tools of the Trade

### IDA Pro

Industry standard disassembler and decompiler. The Hex-Rays decompiler
plugin turns raw x86/x64 assembly into readable pseudo-C. Best auto-analysis
on the market for Windows PE binaries. Function detection, cross-referencing,
type propagation — all best-in-class.

The catch: $1,000-3,000 for a personal license. Worth it if this becomes
your profession. Not required to start.

### Ghidra

Free. Open-source. Released by NSA in 2019. Decompiler quality is
comparable to Hex-Rays for most targets. Slightly slower auto-analysis.
Slightly worse at inferring types on complex C++ code. But the price
is right and the feature set is complete.

**This is what you should use.** Free, capable, actively developed.
Java-based (runs on anything). The decompiler window is your primary
workspace — it turns assembly into pseudo-C that you can actually read.

### x64dbg

Live debugger for dynamic analysis on Windows. Open-source. You attach
it to a running process, set breakpoints, step through instructions,
inspect memory and registers in real time. Where Ghidra shows you what's
POSSIBLE, x64dbg shows you what ACTUALLY HAPPENS when a specific file
is scanned.

### Binary Ninja

Middle ground between IDA and Ghidra. Personal license ~$300. Good API,
good decompiler, modern UI. Solid choice if you want something between
free and four figures.

### WinDbg

Microsoft's debugger. Essential for crash analysis (Chapter 06 already
covered this). When a fuzzer crash dump needs triage, WinDbg + `!heap`
+ `!exploitable` is the toolchain.

### The Stack

**Ghidra** for static analysis (reading the binary offline, mapping
functions, understanding structure). **x64dbg** for dynamic analysis
(watching code execute live, verifying your static analysis). **WinDbg**
for crash analysis (triaging fuzzer results). These three cover everything.

---

## PE Structure: Reading The Binary's Blueprint

Before you load mpengine.dll into Ghidra, you need to understand what
you're looking at. Windows executables and DLLs use the PE (Portable
Executable) format. It's not complicated — it's a table of contents
for binary code.

### Headers

```
┌─────────────────────────┐
│ DOS Header              │  Legacy. Contains "MZ" magic and PE offset.
├─────────────────────────┤
│ PE Signature            │  "PE\0\0" — confirms this is a PE file.
├─────────────────────────┤
│ COFF File Header        │  Machine type, number of sections, timestamp.
├─────────────────────────┤
│ Optional Header         │  Entry point, image base, section alignment,
│                         │  subsystem, data directory pointers.
├─────────────────────────┤
│ Section Table           │  Array of section headers — name, virtual
│                         │  address, size, characteristics (R/W/X).
└─────────────────────────┘
```

### Sections (What Lives Where)

| Section  | Contains | Why You Care |
|----------|----------|--------------|
| `.text`  | Executable code — all the functions | Where the parser logic lives |
| `.data`  | Initialized global/static data | Global state, config values |
| `.rdata` | Read-only data: imports, exports, strings, vtables | Import/export tables, string references for format detection |
| `.rsrc`  | Resources (icons, manifests, embedded files) | Usually not relevant for exploitation |
| `.reloc` | Relocation table for ASLR | Base address fixups |

### Import Table — What The Binary Calls

The import table lists every external DLL and function the binary uses.
This reveals CAPABILITIES. If mpengine.dll imports `CreateFileW`,
`ReadFile`, `VirtualAlloc`, `HeapAlloc` — you know it does file I/O
and dynamic memory allocation. If it imports crypto functions, it
handles encrypted content.

```
dumpbin /imports mpengine.dll
```

Look for: `HeapAlloc`, `HeapFree`, `VirtualAlloc`, `VirtualFree`,
`malloc`, `free`, `memcpy`, `memmove`, `CreateFileW`, `ReadFile`.
Every one of these is a potential site where corruption happens.

### Export Table — What The Binary Exposes

The export table lists functions that other code can call. These are
your ENTRY POINTS — the doors into the binary.

```
dumpbin /exports mpengine.dll
```

For mpengine.dll, you're looking for scan functions: anything with
`Scan`, `Parse`, `Check`, `Detect` in the name. These are the functions
that accept external input (the file being scanned) and process it.
Your fuzzer harness calls these. Your reversing starts here.

---

## Attack Surface Mapping: The Five-Step Method

This is the core of the chapter. A systematic method for going from
"I have a 15MB DLL" to "I know exactly which functions to fuzz."

### Step 1 — Identify Entry Points

What functions accept external input? For mpengine.dll, the scan
functions are the front door. Start with the exports:

```
Exports found in mpengine.dll:
    MpScanFile
    MpScanBuffer
    MpScanStream
    ...
```

Each of these takes a file path, a memory buffer, or a stream interface.
These are the functions where attacker-controlled data enters the binary.

In Ghidra: find these in the Symbol Table (filter by "Export"), then
read their decompiled code. They'll set up context, call internal
initialization, then dispatch to the actual scan logic.

### Step 2 — Trace The Input Flow

From the entry point, follow the data. The scan function doesn't parse
files directly — it dispatches. The flow looks like this:

```
MpScanFile(path)
    → open file, read header bytes
    → identify_format(header_bytes)
    → dispatch to format-specific parser
        → parse_zip(data)   if PK\x03\x04
        → parse_pdf(data)   if %PDF-
        → parse_pe(data)    if MZ
        → parse_ole(data)   if \xD0\xCF\x11\xE0
        → ...
```

In Ghidra, you trace this by following function calls from the entry
point. Each `call` instruction is a step deeper. Use the decompiler
view — it shows function calls as readable pseudo-C, not raw `call`
instructions.

The key insight: the format detection function is a DISPATCH POINT.
It reads magic bytes from the file header and branches to the correct
parser. Finding this function is finding the map of ALL parsers.

### Step 3 — Map The Parsers

The format detection function contains the magic byte checks. In
decompiled code it looks like this:

```c
// Ghidra decompiler output (cleaned, names added by you)
int identify_and_dispatch(byte *header, int header_len, Context *ctx) {
    if (header[0] == 0x50 && header[1] == 0x4B &&
        header[2] == 0x03 && header[3] == 0x04) {
        return parse_zip(ctx);          // PK\x03\x04
    }
    if (header[0] == 0x25 && header[1] == 0x50 &&
        header[2] == 0x44 && header[3] == 0x46) {
        return parse_pdf(ctx);          // %PDF
    }
    if (header[0] == 0x4D && header[1] == 0x5A) {
        return parse_pe(ctx);           // MZ
    }
    // ... more format checks ...
}
```

Sometimes it's a switch statement, sometimes a chain of if/else,
sometimes a lookup table indexed by a computed value. Regardless of
form, this function maps FORMAT → PARSER. Every branch is a different
attack surface.

**How to find it from Ghidra**: Search for string references. Look for
strings like `"ZIP"`, `"PDF"`, `"PK"`, `"%PDF"`. The function that
references multiple format identifier strings is your dispatch point.
Alternatively, find the magic byte constants: search for the hex value
`0x04034B50` (ZIP local file header magic, little-endian). The function
containing that comparison is your target.

Cross-reference the dispatch function: right-click → "References to" →
see ALL parsers that get called from this point.

### Step 4 — Find The Allocations

Within each parser, find where memory gets allocated. These are the
sites where corruption can happen.

```c
// Ghidra decompiler output — what you're looking for
void parse_zip_entry(ZipContext *ctx, byte *data) {
    uint32_t comp_size = *(uint32_t *)(data + 0x12);   // from file
    uint32_t uncomp_size = *(uint32_t *)(data + 0x16);  // from file

    byte *buf = (byte *)HeapAlloc(heap, 0, uncomp_size); // allocation

    decompress(data + offset, comp_size, buf, uncomp_size); // fill
    // If comp_size or uncomp_size is attacker-manipulated...
}
```

For each allocation, answer three questions:
1. **What determines the size?** A field from the file? A calculated value?
   A hardcoded constant?
2. **Is the size validated?** Is there a check before the allocation that
   rejects absurd values?
3. **How much data gets written into the buffer?** Does the write use the
   same size as the allocation, or a different one?

If the size comes from a file field and there's no validation — that's
a potential integer overflow leading to heap overflow. If the write
uses a different size variable than the allocation — that's a potential
mismatch overflow.

In Ghidra, search for calls to `HeapAlloc`, `malloc`, `operator new`,
`VirtualAlloc` within each parser function. The decompiler shows you
the arguments. The first argument to `malloc` is the size — trace
backwards to see where that value comes from.

### Step 5 — Map Trust Boundaries

This is the hardest and most valuable step. Every parser has a point
where data transitions from UNTRUSTED to TRUSTED. Before that point,
the parser checks magic bytes, validates sizes, confirms offsets are
within bounds. After that point, the parser uses values from the file
without re-checking.

The vulnerability lives at the TRANSITION. Where the parser stops
checking but the check was incomplete.

```c
// TRUST BOUNDARY EXAMPLE
void parse_record(byte *data, int total_len) {
    // --- UNTRUSTED ZONE ---
    uint16_t type = *(uint16_t *)(data + 0);
    uint32_t length = *(uint32_t *)(data + 2);

    if (length > total_len - 6) {       // bounds check
        return;                          // VALIDATION
    }
    // --- TRANSITION ---

    // --- TRUSTED ZONE ---
    // Parser now uses 'length' without further checking
    uint16_t sub_count = *(uint16_t *)(data + 6);
    for (int i = 0; i < sub_count; i++) {   // sub_count NOT validated
        process_sub_record(data + 8 + i * 32);  // could overflow
    }
}
```

The parser validated `length` against `total_len`. Good. But it never
validated `sub_count`. The loop walks through memory based on an
unchecked file field. If `sub_count * 32` exceeds the actual data,
the parser reads past the buffer. Out-of-bounds read at minimum,
potentially worse depending on what happens with that data.

In Ghidra, you find these by reading the decompiled parser functions
and asking: "for every value that comes from the file, is there a
check before it's used as a size, index, offset, or count?" If the
answer is no — mark it.

---

## Ghidra Walkthrough: From Import To Attack Surface Map

### Project Setup

1. Launch Ghidra. File → New Project. Select a directory. Name it
   something like `VADER_mpengine`.
2. File → Import File. Select `mpengine.dll`.
   - Ghidra auto-detects the PE format and architecture (x86/x64).
   - Accept defaults. Click OK.
3. Double-click the imported file to open it in the CodeBrowser.
4. Ghidra asks: "Analyze?" → YES. Accept default analyzers.
   - For a 15MB DLL, analysis takes 5-15 minutes. Let it finish.
   - The progress bar in the bottom-right shows status.

### Finding Exports

Window → Symbol Table. This opens a panel listing every symbol
Ghidra found. Click the "Source" column header to sort. Filter by
typing in the filter bar. Exported functions have source "Import"
or "Export" depending on Ghidra version — look for function names
that match what `dumpbin /exports` showed you.

Double-click an export name → Ghidra jumps to that function in both
the disassembly and decompiler views.

### The Decompiler View

This is your primary workspace. When you click on a function in the
disassembly listing, the decompiler window on the right shows pseudo-C.

```c
// Raw Ghidra decompiler output — typical mpengine function
undefined8 FUN_1400a3b10(longlong param_1, int param_2, longlong param_3)
{
    undefined8 uVar1;
    longlong lVar2;

    lVar2 = (**(code **)(*(longlong *)(param_1 + 0x18) + 0x20))(param_1 + 0x18);
    if (lVar2 == 0) {
        uVar1 = 0xffffffff80004005;
    }
    else {
        uVar1 = FUN_1400a2e70(lVar2, param_2, param_3);
    }
    return uVar1;
}
```

This looks like garbage. It IS readable — just not yet. The function
names are auto-generated (`FUN_1400a3b10`), the parameter types are
unknown (`longlong param_1`), and the variable names are meaningless
(`uVar1`). Your job is to rename them as you understand what they do.

### Renaming And Annotating

This is where reversing becomes YOURS. As you understand each function:

- **F2 on a function name** → rename it to what it does.
  `FUN_1400a3b10` → `dispatch_format_parser`
- **F2 on a variable** → rename it.
  `param_1` → `scan_context`, `lVar2` → `parser_handle`
- **Right-click a type → Retype Variable** → set the correct type.
  Change `longlong` to `ScanContext *` after you define the struct.
- **L on an address** → add a label/comment.
  Mark important locations: "TRUST BOUNDARY HERE", "SIZE FROM FILE",
  "NO VALIDATION ON THIS FIELD".

The decompiler output improves dramatically as you add type information.
That unreadable mess above becomes:

```c
// After renaming and retyping
HRESULT dispatch_format_parser(ScanContext *ctx, int format_id,
                                ParseParams *params)
{
    ParserHandle *parser;

    parser = ctx->vtable->get_parser(ctx, format_id);
    if (parser == NULL) {
        return E_FAIL;
    }
    return execute_parser(parser, format_id, params);
}
```

Same function. Same bytes. Now you can read it.

### Cross-Referencing

Right-click any function → References → Find references to this function.
This shows you every call site — every place in the binary that calls
this function. Essential for:

- Finding all callers of `HeapAlloc` within a specific parser
- Tracing backwards from an allocation to understand what controls the size
- Finding all paths that lead to a specific parser entry point

### Bookmarks

Ctrl+D to bookmark the current location. Use bookmarks to mark:
- Parser entry points (one per format)
- Allocation sites within parsers
- Trust boundary transitions
- Functions that look interesting but you haven't fully analysed yet

---

## Pattern Recognition In Decompiled Code

With practice, you'll start recognising exploitable patterns on sight
in the decompiler window. Here are the ones that matter most.

### The Allocation Pattern (Potential Overflow)

```c
// Ghidra decompiler output (cleaned up)
uint32_t size = *(uint32_t *)(file_data + 0x10);   // size from file
byte *buf = (byte *)HeapAlloc(heap, 0, size);       // allocate
memcpy(buf, file_data + 0x14, size);                // copy

// SAFE if size is validated before this point.
// VULNERABLE if not. Attacker sets size = 0xFFFFFFFF,
// HeapAlloc returns NULL or tiny buffer, memcpy overwrites heap.
```

Also watch for the integer overflow variant:

```c
uint16_t count = *(uint16_t *)(file_data + 0x08);
uint32_t total = count * sizeof(Record);   // can overflow!
Record *recs = (Record *)HeapAlloc(heap, 0, total);
for (int i = 0; i < count; i++) {
    read_record(&recs[i], file_data);      // writes past allocation
}
```

### The Dispatch Pattern (Type Confusion Potential)

```c
uint8_t type = *(uint8_t *)(record + 0);
switch (type) {
    case 1: handle_text(record); break;
    case 2: handle_image(record); break;
    case 3: handle_link(record); break;
    // What if type = 255 and there's no default case?
    // Or worse: default falls through to handle_text
    // with data that isn't text format?
}
```

Missing default cases in type dispatch switches are textbook type
confusion bugs. The parser assumes the type field is within range
because the file spec says it should be. The attacker doesn't care
what the spec says.

### The Lifetime Pattern (UAF Potential)

```c
ParserObj *obj = create_parser_context(data);
int status = parse_section(obj, data + offset);
if (status == PARSE_ERROR) {
    destroy_parser_context(obj);   // frees obj
    // BUG: function continues, parent still holds pointer to obj
    // Next access to obj → use-after-free
}
// ... more code that uses obj ...
log_result(obj->status);           // BANG — dangling pointer
```

Look for error paths where `free`/`delete`/`destroy` is called but
the function doesn't immediately return. If code continues after
freeing and later uses the freed pointer, that's a UAF.

### The Bounds Check Gap

```c
uint32_t offset = *(uint32_t *)(data + 0x04);
uint32_t length = *(uint32_t *)(data + 0x08);

// Checks offset is within buffer
if (offset > buffer_size) return ERROR;

// Checks length is within buffer
if (length > buffer_size) return ERROR;

// Does NOT check offset + length
// If offset = 0xFFFFFFF0 and length = 0x20,
// both pass individually but offset + length wraps to 0x10
memcpy(dest, data + offset, length);   // reads from wild address
```

Each value is validated individually but the COMBINATION is not.
`offset + length` can overflow. This is a classic integer overflow
leading to out-of-bounds read or write.

---

## Dynamic Analysis With x64dbg

Static analysis with Ghidra tells you what's POSSIBLE. Dynamic analysis
with x64dbg tells you what ACTUALLY HAPPENS when a specific file is
processed.

### Attaching To MsMpEng.exe

MsMpEng.exe runs as SYSTEM. You can't attach a debugger from a normal
user session. You need SYSTEM-level access:

```
PsExec -s -i x64dbg.exe
```

`PsExec -s` launches the debugger as SYSTEM. `-i` makes it interactive
(shows the window on your desktop). Alternatively, enable kernel
debugging and use WinDbg in kernel mode, but x64dbg is faster for
usermode analysis.

Once attached: File → Attach → select MsMpEng.exe.

### Setting Breakpoints On Parser Entry

From your Ghidra analysis, you know the address of the parser entry
point. In x64dbg, `Ctrl+G` → enter the address → F2 to set breakpoint.

Now drop a test file (a ZIP, a PDF, whatever matches the parser you're
analysing) into a scanned directory. Defender triggers a scan. Your
breakpoint hits. You're now INSIDE the parser, watching it execute
live.

### Stepping Through

| Key | Action |
|-----|--------|
| F7  | Step into (follow function calls) |
| F8  | Step over (execute function calls without entering) |
| F9  | Run until next breakpoint |
| F2  | Toggle breakpoint at cursor |

Watch the register window. When the parser reads a value from your file,
you'll see it appear in a register. When it calls `HeapAlloc`, you'll
see the size in RCX (first argument on x64). When it does `memcpy`,
you'll see source, destination, and count in RCX/RDX/R8.

### Memory Inspection

Right-click an address → Follow in Dump. You can watch the heap buffer
get allocated and filled. You can see exactly what data lands where.
When you're testing a crafted file, you can verify your mutations
are reaching the right code path and landing in the right buffer.

This is the feedback loop: Ghidra shows you WHERE to look. x64dbg
shows you WHAT HAPPENS when your specific input hits that code.

---

## Symbols: Function Names From Microsoft

Without symbols, every function in Ghidra is `FUN_14001A3B0` and every
variable is `var_38`. You can still reverse-engineer the binary, but
it's slow. You're deducing purpose from behaviour.

With symbols, you get function names, struct definitions, and variable
names. The code becomes readable without renaming everything manually.

Microsoft publishes symbols for many system components:

```
symchk /s srv*C:\Symbols*https://msdl.microsoft.com/download/symbols mpengine.dll
```

This downloads the PDB (Program Database) file matching your specific
version of mpengine.dll from Microsoft's symbol server. Load the PDB
into Ghidra: File → Load PDB → select the downloaded file.

The decompiler output transforms. `FUN_14001A3B0` becomes
`CZipParser::ParseLocalFileHeader`. `param_1` becomes `this`.
`var_38` becomes `uncompressed_size`. Night and day.

Not all components have full symbols. Some have partial symbols (function
names but no types). Some have none. mpengine.dll symbol availability
varies by version — newer versions may have less. Check the symbol server
first. Whatever you get is better than nothing.

---

## mpengine.dll Deep Dive

### What We Know (From The TOCTOU Campaign + Public Research)

Size: ~15MB compiled. Hundreds of exported functions. Multiple embedded
parsers for every common file format. This is a MASSIVE attack surface.

Architecture (already confirmed through ProcMon external observation):
```
MsMpEng.exe (service process, SYSTEM privileges)
    └── loads mpengine.dll (the scan engine)
            ├── File detection (magic bytes, headers)
            ├── Format identification (classify file type)
            ├── Parser dispatch (route to correct parser)
            │     ├── ZIP parser
            │     ├── PDF parser
            │     ├── PE (EXE/DLL) parser
            │     ├── OLE/DOC parser
            │     ├── RTF parser
            │     ├── JavaScript emulator
            │     ├── VBScript emulator
            │     └── ... dozens more
            ├── Emulation engine (executes scripts/macros in sandbox)
            └── Verdict (clean/malware/PUA)
```

### What To Map

The attack surface map is the OUTPUT of this chapter. Create
`TARGETS/mpengine/RECON.md` with:

**1. Format dispatch points** — the function(s) that identify file type
and route to the correct parser. Address, branch targets, formats handled.

**2. Parser entry points** — one entry per format. At minimum:
- ZIP (PK\x03\x04) — nested files, compression, directory parsing
- PDF (%PDF-) — stream objects, filters, JavaScript
- PE (MZ) — section parsing, resource parsing, import table
- OLE (\xD0\xCF\x11\xE0) — DOC/XLS/PPT, macro extraction
- RTF ({\rtf) — embedded objects, font table
- JavaScript — emulator/interpreter, string parsing
- VBScript — emulator, execution engine

**3. Allocation sites per parser** — every `HeapAlloc`/`malloc`/`new`
call within each parser, with notes on what controls the size and
whether validation exists.

**4. Error handling paths** — where objects get freed on error, and
whether dangling pointers survive past the free.

**5. Trust boundary transitions** — where each parser stops validating
and starts using file data as trusted values.

### Prior Art

Tavis Ormandy at Google Project Zero published analysis of mpengine.dll
in 2017. His methodology is documented and instructive: he identified
the NScript (JavaScript) emulator as the most complex parser and found
type confusion bugs in its object handling. Google "Tavis Ormandy
MsMalware Protection Engine" for the write-ups. His approach was
exactly this: map parsers, find trust boundaries, target the most
complex code paths.

---

## Mapping To The Doctrine

The 0x1security compass has three points that map directly to this
chapter.

**Point 1: "Search for knowledge, not for 0-days. Understand where
trust boundaries live in code."**

This chapter is LITERALLY that doctrine. You're not sitting down with
Ghidra to find a CVE. You're sitting down to UNDERSTAND the target.
Where does mpengine.dll read file data? Which functions parse which
formats? Where does it allocate buffers? Where does it stop checking?
The knowledge IS the point. The bugs appear as a byproduct of the
knowledge — they're trust boundaries that were drawn wrong.

**Point 2: "See the paths, see what blocks you, find a substitute way."**

In the TOCTOU campaign, you used ProcMon to see the paths Defender
takes through the filesystem. You saw the blocks — FILE_OBJECT binding,
content re-verification. You found substitutes — different timing,
different junction placement.

Now you do the same thing one level deeper. Ghidra shows you the paths
through the binary. You see the blocks — size checks, bounds validation,
type verification. You find the gaps — unchecked fields, missing default
cases, integer overflow opportunities. Same doctrine. Deeper level.
ProcMon was the periscope. Ghidra is the full reconnaissance satellite.

**Point 3: "Crash → leak memory → execute arbitrary code."**

When you finish the attack surface map and turn the fuzzer loose on the
parsers you've identified, the crashes it finds are not random. They're
hits on the trust boundaries you mapped. You KNOW which parser crashed.
You KNOW what allocation was involved. You KNOW what field was malformed.
The crash is the beginning of exploitation, not the end of fuzzing.
Leak memory to defeat ASLR. Use the leak to calculate addresses.
Corrupt a function pointer with a known address. Code execution.

The reversing makes EVERYTHING downstream more efficient. Every hour
spent in Ghidra saves ten hours of blind fuzzing.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Disassembler** | Tool that converts machine code (raw bytes) into assembly instructions |
| **Decompiler** | Tool that converts assembly into pseudo-C; Ghidra and Hex-Rays (IDA) both provide this |
| **PE (Portable Executable)** | Windows binary format for .exe and .dll files; has headers, sections, import/export tables |
| **Import table** | PE section listing external DLLs and functions the binary calls; reveals capabilities |
| **Export table** | PE section listing functions the binary exposes to callers; these are your entry points |
| **Cross-reference (xref)** | A record of where a function or address is called/referenced from; essential for tracing data flow |
| **Magic bytes** | Fixed byte sequence at the start of a file that identifies its format (e.g., PK\x03\x04 for ZIP, MZ for PE) |
| **Trust boundary** | The point in code where input transitions from validated (untrusted) to assumed-valid (trusted) |
| **Attack surface map** | Document listing all entry points, parsers, allocations, and trust boundaries in a target binary |
| **Symbols (PDB)** | Debug information files providing function names, type definitions, and variable names for a binary |
| **Format dispatch** | The function/switch that identifies file format and routes to the correct parser; finding this maps all parsers at once |
| **Static analysis** | Examining a binary without executing it (Ghidra, IDA); shows all possible paths |
| **Dynamic analysis** | Examining a binary while it executes (x64dbg, WinDbg); shows actual path taken for specific input |
