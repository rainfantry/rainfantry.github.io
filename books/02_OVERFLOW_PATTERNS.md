# Chapter 02 — Overflow Patterns: The Corruption Playbook

**VADER-RCE Field Manual**
**Prerequisite**: Ch01 Heap Internals
**Drill**: DRILLS/01_heap_overflow/ (continues), DRILLS/02_uaf_exploit/

---

## Three Corruption Classes That Get RCE

Chapter 01 showed you WHAT corruption looks like. This chapter shows you
HOW each type translates to code execution, and WHERE to find them in
real parsers.

You're building a detection instinct. When you see a pattern in disassembly
or decompiled code, you need to instantly recognise: "that's exploitable."

---

## Pattern 1: Stack Buffer Overflow

### The Classic (Mostly Dead, Still Worth Knowing)

```c
void parse_name(FILE *f) {
    char name[64];          // stack buffer, 64 bytes
    uint32_t len;
    fread(&len, 4, 1, f);
    fread(name, 1, len, f); // overflow if len > 64
}
```

**What gets corrupted**: Saved frame pointer, RETURN ADDRESS, saved registers.

```
STACK (grows downward):
┌─────────────────┐ LOW ADDRESS
│ name[0..63]     │  ← our buffer
├─────────────────┤
│ saved EBP/RBP   │  ← overwrite this = control frame pointer
├─────────────────┤
│ RETURN ADDRESS   │  ← overwrite this = control EIP/RIP
├─────────────────┤
│ caller's frame   │
└─────────────────┘ HIGH ADDRESS
```

Overwrite the return address → when the function does `ret`, CPU jumps
to YOUR address instead of the caller. Classic. Simple.

**Why it's mostly dead on modern Windows**:
- `/GS` (stack cookies) — compiler inserts a canary value before the return
  address. If it's corrupted on function return → crash, not exploitation.
- DEP (Data Execution Prevention) — stack memory is non-executable. Even if
  you overwrite the return address, you can't jump to shellcode on the stack.
- ASLR — return address of what? You don't know where anything is loaded.
- CFG (Control Flow Guard) — indirect call targets must be in a valid set.

**Still relevant because**: Some legacy code is compiled without /GS. Some
embedded code has no DEP. And the CONCEPT of overwriting control data is
universal — it's the same on the heap, just different metadata.

---

## Pattern 2: Heap Buffer Overflow (PRIMARY TARGET)

### Overwriting Adjacent Object Data

You saw this in Ch01. The key variables are:

1. **Overflow source**: Which buffer are we overflowing?
2. **Overflow sink**: What's adjacent in memory that we're corrupting?
3. **Trigger**: When is the corrupted data USED?

```c
// VULNERABLE PATTERN — seen in every real-world parser
void parse_chunk(FILE *f) {
    Header *hdr = malloc(sizeof(Header));  // 32 bytes
    Data *data = malloc(sizeof(Data));     // 128 bytes

    fread(hdr, 1, sizeof(Header), f);
    
    // Bug: hdr->payload_size from file, but data is only 128 bytes
    fread(data->buffer, 1, hdr->payload_size, f);
    
    // Later — uses a field in whatever follows data in memory
    // If we overflowed data->buffer, the next object is corrupted
}
```

### The Corruption-to-Execution Bridge

Raw corruption isn't enough. You need the corrupted value to be USED in
a way that gives you control. The strongest primitives:

**Function pointer overwrite** (BEST — direct code execution):
```
Corrupt: obj->callback = attacker_controlled_address
Trigger: obj->callback()  → CPU jumps to your address
```

**Vtable pointer overwrite** (COMMON in C++ code):
```
Corrupt: obj->vtable_ptr = address_of_fake_vtable
Trigger: obj->virtual_method()  → reads fake vtable → jumps to your address
```

**Size field overwrite** (POWERFUL — leads to secondary overflow):
```
Corrupt: next_obj->size = 0xFFFFFFFF
Trigger: memcpy(next_obj->data, src, next_obj->size)  → MASSIVE overflow
```

**Linked list pointer overwrite** (CLASSIC heap exploitation):
```
Corrupt: freed_chunk->fwd = target_addr; freed_chunk->bck = data_addr
Trigger: On next free/alloc, allocator writes data_addr to target_addr
         → arbitrary write primitive → overwrite got/vtable/etc
```

---

## Pattern 3: Integer Overflow → Undersized Allocation

### The Arithmetic Trap

This is the MOST COMMON entry point for heap overflows in real parsers.
The overflow isn't direct — it happens because a size calculation wraps.

```c
// Real-world pattern: read count + element_size from file
uint32_t count, elem_size;
fread(&count, 4, 1, f);      // attacker: 0x10000001 (268435457)
fread(&elem_size, 4, 1, f);  // attacker: 0x00000020 (32)

// Multiplication overflow on 32-bit:
// 0x10000001 * 0x20 = 0x200000020
// Truncated to 32 bits: 0x00000020 (just 32 bytes!)
size_t total = (uint32_t)(count * elem_size);

char *buf = malloc(total);    // allocates 32 bytes

// Loop reads 268 million * 32 bytes into a 32-byte buffer
for (uint32_t i = 0; i < count; i++) {
    fread(buf + (i * elem_size), 1, elem_size, f);
}
```

### Where To Look For This

In disassembly, look for:
- `mul` or `imul` followed by `call malloc` / `call HeapAlloc`
- No overflow check between the multiply and the allocation
- The multiplied values come from file input (traced back to `fread`/`ReadFile`)

In decompiled code (IDA/Ghidra), look for:
```c
size = field1 * field2;      // no check for overflow
ptr = operator_new(size);    // or HeapAlloc
```

### The Fix (What Good Code Looks Like)

```c
// Safe: checks for overflow before allocating
if (count > 0 && elem_size > SIZE_MAX / count) {
    return ERROR_OVERFLOW;
}
size_t total = count * elem_size;
char *buf = malloc(total);
```

When the CHECK is missing → vulnerability. Fuzzers find this by trying
extreme values for count and elem_size until the multiplication wraps.

---

## Pattern 4: Off-By-One → Heap Metadata Corruption

### The Subtle Variant

```c
char *buf = malloc(256);
for (int i = 0; i <= 256; i++) {  // BUG: <= instead of <
    buf[i] = data[i];
}
```

One byte past the allocation. Just one. But that one byte might land on:
- The NEXT chunk's size field → allocator thinks chunk is larger → later
  operations overflow further (escalation)
- A flag byte that controls whether the chunk is "in use" or "free" →
  double-free condition (escalation to arbitrary write)

Off-by-one is harder to exploit but not impossible. On the NT Heap,
one byte of size corruption can be escalated to full arbitrary write
through careful heap grooming (arranging allocations so specific
objects are adjacent).

---

## Heap Grooming: Controlling The Layout

### The Problem

Modern allocators randomize allocation order (LFH, segment heap).
You can't predict what's next to your buffer.

### The Solution: Heap Spray + Heap Feng Shui

**Heap spray**: Allocate THOUSANDS of objects of the same size.
Eventually they fill up the LFH bucket, and new allocations
become predictable (sequential).

```
Before spray: [random] [your buf] [random] [random]
After spray:  [target] [target] [target] [your buf] [target] [target]
```

Now when you overflow, you KNOW you're hitting a target object
because they're everywhere.

**Heap feng shui**: Carefully allocate and free objects to create
"holes" in specific sizes, then trigger the target allocation
to fill one of your holes. Now you know exactly what's adjacent.

```
Step 1: Allocate A, B, C, D (same size)
        [A] [B] [C] [D]

Step 2: Free B and D (create holes)
        [A] [___] [C] [___]

Step 3: Trigger victim allocation → fills first hole
        [A] [VICTIM] [C] [___]

Step 4: Allocate attacker data → fills second hole? No...
        Actually, we want attacker BEFORE victim. So:

Step 1: Allocate A, B, C (same size, our data)
Step 2: Free B (hole)
Step 3: Trigger victim allocation into the hole
        [OURS] [VICTIM] [OURS]
Step 4: Overflow from left OURS into VICTIM
```

This is advanced — Phase 4 territory. You need to understand it
conceptually now so you recognise it in crash analysis later.

---

## Exploitation Primitives Cheat Sheet

| Primitive | What You Control | How You Get Code Exec |
|-----------|-----------------|----------------------|
| **Function pointer overwrite** | A callback/handler field | Direct call to your address |
| **Vtable pointer overwrite** | C++ object vtable | Virtual function dispatch to your address |
| **Arbitrary write** | Write WHAT to WHERE | Overwrite GOT entry, vtable, or stack return address |
| **Arbitrary read (info leak)** | Read from any address | Defeat ASLR — learn module base addresses |
| **Size corruption** | A length/size field | Secondary overflow with controlled size |
| **Type confusion** | Object type tag/flag | Object used as wrong type, fields misaligned → pointer at wrong offset |

### The Chain

Real exploits chain multiple primitives:

```
Info leak (defeat ASLR)
    → Learn module base address
        → Calculate target address (gadget, function)
            → Arbitrary write (overwrite control data)
                → Code execution
```

In Drill 01, we skip the chain because there's no ASLR.
Drills 03+ add each mitigation so you learn to chain.

---

## What This Looks Like In mpengine.dll (Preview)

mpengine.dll is a ~15MB DLL with hundreds of file format parsers.
Each parser is a function that reads structured data from a file.

The pattern you're looking for in every parser:

```
1. Read a size/count/length field from the file
2. Use that field to allocate memory or control a loop
3. Missing: validation that the field is within safe bounds
```

A fuzzer probes this automatically. But KNOWING what the fuzzer is
looking for lets you:
- Write better seed files (exercise the parser's allocation paths)
- Build smarter harnesses (target specific format handlers)
- Triage crashes faster (recognise the corruption type instantly)
- Prioritise bugs (function pointer overwrite > null deref)

---

## Drill Progression

After completing Drill 01 (heap overflow, no mitigations):

| Drill | What It Adds | What You Learn |
|-------|-------------|----------------|
| 02 | Use-after-free target | Different corruption primitive, heap reuse |
| 03 | ASLR enabled | Info leak → base address → calculate target |
| 04 | DEP enabled | ROP chain to bypass non-executable memory |
| 05 | Write a WinAFL harness | Transition from manual exploit to automated discovery |
| 06 | Triage real crashes | Assess exploitability from crash dumps |

Each drill builds on the previous. The skills stack.
By Drill 05, you're writing harnesses that find bugs automatically.
By Drill 06, you can look at a crash and tell if it's worth pursuing.
