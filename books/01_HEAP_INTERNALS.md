# Chapter 01 — Heap Internals: The Ammunition Depot

**VADER-RCE Field Manual**
**Prerequisite**: vader-toctou BOOK Ch01-03 (handles, filesystem, CreateFile)
**Drill**: DRILLS/01_heap_overflow/

---

## Why You Need This

In the TOCTOU campaign you attacked Defender's LOGIC — the order it does things.
That's a race condition. It's clever but the architecture can defend against it
(and did — FILE_OBJECT binding, content re-verification, identity gate).

Memory corruption is different. You're attacking the MACHINE ITSELF — the CPU's
assumptions about what's in memory. There's no "re-verification gate" for a heap
overflow. If you corrupt a pointer, the CPU follows it. Period. The CPU doesn't
have opinions. It has instructions.

Every file parser in mpengine.dll does this:
1. Read bytes from a file
2. Allocate a buffer (`malloc`/`HeapAlloc`)
3. Copy data into that buffer
4. Parse the buffer contents to decide if the file is malicious

If step 3 writes MORE bytes than step 2 allocated — that's a heap overflow.
The extra bytes overwrite whatever's sitting next to the buffer in memory.
If what's sitting next to the buffer is a function pointer, a vtable entry,
or a size field for another allocation — you own the process.

Defender parses files as SYSTEM. Corrupt its heap → redirect execution →
SYSTEM shell. From a file you sent over email. That's RCE.

---

## The Heap: How Memory Works At Runtime

### Stack vs Heap (The Barracks vs The Depot)

You already know the stack from C. Every function call pushes a frame:
local variables, return address, saved registers. Stack is AUTOMATIC —
allocated on function entry, freed on function return. Size known at compile time.

The heap is MANUAL. When your code needs memory and doesn't know how much
until runtime, it asks the heap allocator:

```c
// Stack allocation — size known at compile time
char buf[256];  // 256 bytes, always, on the stack frame

// Heap allocation — size known only at runtime
int size = read_header(file);  // could be 10 bytes or 10 million
char *buf = (char *)malloc(size);  // ask the heap for 'size' bytes
// ... use buf ...
free(buf);  // give it back when done
```

**Military analogy**: The stack is your barracks — fixed rooms, assigned at check-in,
cleared at checkout. The heap is the ammunition depot — you requisition what you need,
use it, return it. The depot manager (heap allocator) tracks what's allocated and
what's free. If you write past your requisition boundary, you're scribbling on
someone else's ammo crate.

### Windows Heap Architecture

Windows has TWO heap implementations active on modern systems:

**NT Heap** (legacy, still used for large allocations):
- `HeapCreate()` / `HeapAlloc()` / `HeapFree()` / `HeapDestroy()`
- Manages memory in SEGMENTS (contiguous virtual memory regions)
- Free chunks tracked in FREELISTS (linked lists of available memory)
- Each chunk has a HEADER: size, flags, pointers to adjacent chunks

**Segment Heap** (modern, used by most system processes including MsMpEng.exe):
- Default heap for system processes on Windows 10+
- Variable-size pages, better randomization, metadata separated from data
- Harder to exploit than NT Heap (by design)
- Still exploitable — just requires different techniques

**Low Fragmentation Heap (LFH)** — a subsystem within both:
- Handles small allocations (≤16KB) using fixed-size "buckets"
- Bucket sizes: 8, 16, 24, 32, ... up to 16384 bytes
- Allocation goes to the bucket that fits. 13-byte request → 16-byte bucket.
- LFH randomizes allocation order within a bucket (ASLR for heap chunks)

**What this means for exploitation**:
The heap allocator puts your buffer NEXT TO other allocated objects.
If you overflow buffer A, you corrupt the object immediately after A in memory.
What that object IS determines what you can do:
- If it's another buffer → you control its contents (info leak, arbitrary write)
- If it's a structure with a function pointer → you redirect execution
- If it's a heap chunk header → you corrupt the allocator itself (heap metadata corruption → arbitrary write on next free/alloc)

---

## Heap Overflow: Writing Past The Boundary

### The Fundamental Bug

```c
// VULNERABLE CODE — this is what you're looking for in mpengine.dll
void parse_record(FILE *f) {
    // Read the "length" field from the file
    uint32_t length;
    fread(&length, 4, 1, f);         // attacker controls this value

    // Allocate a buffer based on the length
    char *buf = (char *)malloc(256);  // fixed 256-byte buffer

    // Read 'length' bytes into the 256-byte buffer
    fread(buf, 1, length, f);         // if length > 256 → OVERFLOW

    process_record(buf);
    free(buf);
}
```

The parser trusts the length field from the file. The file is attacker-controlled.
Set length = 512. Parser allocates 256 bytes but reads 512. The extra 256 bytes
overwrite whatever follows the buffer on the heap.

This is the EXACT pattern fuzzers find. They mutate the file, changing length
fields to absurd values, and watch for crashes. A crash on a heap overflow
means the overwritten memory was used later — which means it's potentially
exploitable.

### Heap Layout (What's Next To Your Buffer)

```
HEAP MEMORY (simplified):
┌──────────────┬──────────────┬──────────────┬──────────────┐
│  CHUNK HDR   │  YOUR BUFFER │  CHUNK HDR   │  NEXT OBJECT │
│  (8-16 bytes)│  (256 bytes) │  (8-16 bytes)│  (varies)    │
├──────────────┼──────────────┼──────────────┼──────────────┤
│  size, flags │  AAAAAAAAAA  │  size, flags │  vtable ptr  │
│  prev, next  │  AAAAAAAAAA  │  prev, next  │  data fields │
│              │  AAAAAAAAAA  │              │  callback fn │
└──────────────┴──────────────┴──────────────┴──────────────┘
                               ↑
                    OVERFLOW HITS HERE
```

When you overflow "YOUR BUFFER" by 256 bytes:
- First you corrupt the NEXT chunk's HEADER (size, flags, linked list pointers)
- Then you corrupt the NEXT OBJECT's DATA (vtable pointer, data fields, callbacks)

If NEXT OBJECT has a vtable pointer (C++ virtual function table):
```
Normal:  vtable_ptr → [func1_addr, func2_addr, ...]
                        ↓
                     legitimate code

Corrupted: vtable_ptr → [ATTACKER_ADDR, ...]
                          ↓
                       attacker's shellcode / ROP gadget
```

When the program calls a virtual function on the corrupted object:
`obj->vtable[0]()` → jumps to YOUR address. Code execution.

---

## Use-After-Free: The Ghost Requisition

### The Fundamental Bug

```c
void process_data(void) {
    Object *obj = (Object *)malloc(sizeof(Object));  // allocate
    obj->callback = legitimate_function;

    // ... use obj ...

    free(obj);       // freed — memory returned to heap

    // ... more code ...

    // BUG: obj is still used after free
    obj->callback(); // calls whatever is now at that memory address
}
```

After `free(obj)`, the memory goes back to the heap allocator's free list.
The POINTER `obj` still holds the old address, but the memory might be
REALLOCATED to something else.

**The attack**:
1. Object A is allocated, used, then freed
2. Attacker triggers a NEW allocation of the SAME SIZE
3. Heap allocator gives the same memory (it was just freed)
4. Attacker's data now occupies the memory where Object A used to be
5. Code still thinks Object A is there → calls attacker-controlled function pointer

**Military analogy**: You checked out of your barracks room. Someone else
checked in and rearranged the furniture. Your buddy still has your old room
number and walks in expecting your gear — instead he picks up a weapon
the new occupant left on the nightstand. That weapon fires wherever it's
pointed.

### UAF In A Parser

```c
void parse_file(FILE *f) {
    Record *rec = parse_record(f);    // allocates Record, fills fields
    Metadata *meta = parse_meta(f);   // allocates Metadata

    if (meta->type == INVALID) {
        free(rec);                    // free the record
        // MISSING: rec = NULL;
    }

    // ... later in the function ...
    if (rec->needs_processing) {      // UAF — rec was freed!
        rec->handler(rec->data);      // calls whatever is at rec's memory now
    }
}
```

A fuzzer finds this by:
1. Crafting a file where `meta->type == INVALID` (triggers the free)
2. But `rec->needs_processing` is nonzero (triggers the use-after-free)
3. Between the free and the use, another allocation fills that memory
4. CRASH — the "handler" function pointer is garbage → access violation

---

## Integer Overflow: The Accounting Error

### The Fundamental Bug

```c
void read_entries(FILE *f) {
    uint16_t count;
    fread(&count, 2, 1, f);           // attacker controls: e.g., 65535

    // Integer overflow: count * sizeof(Entry) wraps around
    // 65535 * 264 = 17,301,240 → but if stored in uint16_t or
    // if sizeof(Entry) is large enough, multiplication overflows
    size_t total = count * sizeof(Entry);  // might wrap to small value!

    Entry *entries = (Entry *)malloc(total);  // allocates TINY buffer

    // Reads count entries into the tiny buffer → MASSIVE OVERFLOW
    for (int i = 0; i < count; i++) {
        fread(&entries[i], sizeof(Entry), 1, f);
    }
}
```

The multiplication `count * sizeof(Entry)` wraps around due to integer overflow.
`malloc` gets a small value. The loop reads `count` full entries. Heap overflow.

This is EXTREMELY common in file parsers. Every time you see:
```c
size = field_from_file * element_size;
buf = malloc(size);
```
...you should ask: can `field_from_file * element_size` overflow?

---

## What The Fuzzer Does (Preview — Chapter 05 Goes Deep)

A coverage-guided fuzzer (WinAFL) does this:
1. Takes a seed file (valid ZIP, valid PDF, etc.)
2. **Mutates** it — flips bits, changes length fields, inserts bytes, deletes sections
3. Feeds the mutated file to the parser (mpengine.dll via our harness)
4. Records which CODE PATHS the parser took (via binary instrumentation)
5. If a mutation triggered a NEW code path → keep that mutation as a new seed
6. If a mutation caused a CRASH → save it for triage
7. Repeat millions of times

The fuzzer doesn't understand the file format. It just mutates and observes.
But because it tracks code coverage, it naturally evolves inputs that reach
deeper and deeper into the parser — hitting edge cases the developer didn't
think of.

The developer wrote: `if (length > MAX_SIZE) return ERROR;`
The fuzzer finds: what if length == MAX_SIZE exactly? What about MAX_SIZE + 1?
What about 0? What about 0xFFFFFFFF?

The fuzzer finds bugs BECAUSE it has no understanding. It tries every dumb
thing a human wouldn't think to try. And it tries millions per hour.

---

## Mapping To What You Know

| TOCTOU Concept | RCE Equivalent |
|----------------|----------------|
| Race condition (timing between check and use) | Memory corruption (bytes written past allocation boundary) |
| Junction redirect (make Defender follow wrong path) | Pointer corruption (make CPU follow wrong address) |
| Oplock (freeze Defender mid-operation) | Heap spray (fill memory with controlled data to land corruption predictably) |
| FILE_OBJECT binding (kernel tracks real identity) | ASLR (randomizes addresses so attacker can't predict where to jump) |
| ProcMon (observe Defender's operations) | WinDbg + !heap (observe heap layout and corruption) |
| Manual version iteration (v2→v16) | Fuzzer does this automatically, millions of times |

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Heap overflow** | Writing past the end of a heap-allocated buffer, corrupting adjacent memory |
| **Use-after-free (UAF)** | Accessing memory after it's been freed; memory may contain attacker data |
| **Type confusion** | Using an object as the wrong type; attacker controls fields at unexpected offsets |
| **Integer overflow** | Arithmetic wraps around (e.g., 65535 + 1 = 0 in uint16_t), leading to undersized allocation |
| **Heap spray** | Filling the heap with controlled data so corruption lands on predictable content |
| **Vtable** | Virtual function table — array of function pointers in C++ objects; corruption = code execution |
| **Chunk header** | Metadata at the start of each heap allocation (size, flags, free list pointers) |
| **LFH** | Low Fragmentation Heap — bucket-based allocator for small allocations, randomized |
| **Segment heap** | Modern Windows heap implementation with separated metadata and better randomization |

---

## Drill 01 — Heap Overflow Exploitation

Go to `DRILLS/01_heap_overflow/`. A vulnerable program is waiting.
Your mission: overflow the heap buffer, corrupt the adjacent object's
function pointer, redirect execution to your shellcode.

The target is compiled WITHOUT mitigations (no ASLR, no DEP, no CFG).
This is training — we add mitigations in later drills.

Read the target source. Find the overflow. Write the exploit.
