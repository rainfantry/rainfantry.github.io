# Chapter 03 — UAF & Type Confusion: The Ghost and the Impostor

**VADER-RCE Field Manual**
**Prerequisite**: Ch01 Heap Internals, Ch02 Overflow Patterns
**Drill**: DRILLS/02_uaf_exploit/

---

## Why You Need This

Chapter 01 gave you the overview. Chapter 02 showed you overflow patterns.
Now we go DEEP on the two bug classes that produce the most exploitable
crashes in modern software: **Use-After-Free** and **Type Confusion**.

These aren't separate things. They're stages on the same spectrum.
UAF is about using memory that's been returned to the allocator.
Type confusion is about using memory as the wrong type of object.
A UAF where freed memory gets reallocated as a different type IS a
type confusion. They feed each other.

Why these two specifically? Because the 0x1security doctrine says:
**crash → leak memory → execute arbitrary code.** UAF and type confusion
produce the BEST crashes — the ones that give you a function pointer or
vtable to corrupt, which gives you direct code execution. A null pointer
dereference is a crash. A UAF with a reachable vtable is a WEAPON.

mpengine.dll is C++ heavy. C++ uses virtual function dispatch everywhere.
Every C++ object with virtual methods has a vtable pointer. Corrupt that
pointer through a UAF or type confusion, and the next virtual function
call jumps to your address. This is the single most common exploitation
primitive in browser exploits, PDF exploits, and — yes — antimalware
engine exploits.

---

## Use-After-Free: The Full Picture

### Object Lifecycles on the Heap

Every heap object has three states:

```
ALLOCATED → IN USE → FREED
    ↓                   ↓
 pointer valid     pointer DANGLING (still holds old address)
 memory yours      memory returned to allocator
 reads/writes OK   reads/writes = UNDEFINED BEHAVIOR
```

A UAF happens when code keeps using a pointer after the object moves to
state 3. The pointer doesn't know the object is gone. Pointers don't have
opinions. They have addresses.

### Why The Allocator Helps You

Here's the critical insight most people miss: the heap allocator is your
ALLY in UAF exploitation, not your enemy.

When you call `free(obj)`, the allocator puts that memory on a free list.
When the next `malloc(same_size)` happens, the allocator hands back
THAT SAME MEMORY. This isn't a quirk — it's optimization. Reusing
recently-freed memory means it's still in CPU cache. Fast.

```
Timeline:
t0: obj = malloc(64)      → address 0x1000
t1: use obj normally
t2: free(obj)             → 0x1000 goes to free list
t3: evil = malloc(64)     → allocator returns 0x1000 (same address!)
t4: code uses obj again   → but obj points to evil's data
```

**NT Heap free list is LIFO** (Last In, First Out). Most recently freed
chunk is returned first. This makes UAF exploitation almost deterministic
if you can control what gets allocated next.

**LFH** randomizes the order for same-bucket allocations — but only within
a bucket. If you drain the bucket by doing many allocations, new pages get
added and allocation becomes sequential again. The randomization is finite.

**Segment Heap** separates metadata from user data (harder to corrupt
heap internals) but the reuse pattern is similar: recently freed blocks
get reused.

### The Three Conditions For Exploitation

A UAF is exploitable when ALL THREE hold:

1. **Free**: An object is freed while a pointer to it still exists
2. **Reallocate**: The attacker can trigger a new allocation of the SAME SIZE
   that fills the freed memory with controlled content
3. **Use**: The dangling pointer is dereferenced after reallocation,
   treating attacker data as the original object's fields

Miss any one and you have a crash, not an exploit.

### Condition 1: How Objects Get Freed While Still Referenced

**Error path that skips cleanup:**
```c
Status parse_container(Stream *s) {
    Entry *e = new Entry();
    SubEntry *sub = new SubEntry(e);  // sub holds pointer to e
    
    if (!validate(e)) {
        delete e;           // e freed
        return ERR_INVALID; // BUG: sub still holds pointer to e
    }                       // if this function doesn't return here,
                            // sub->parent (which is e) gets used later
    
    process(sub);           // sub->parent → dangling pointer
    delete sub;
    delete e;
    return OK;
}
```

**Reference counting bugs:**
```c
void release_ref(Object *obj) {
    obj->refcount--;
    if (obj->refcount == 0) {
        free(obj);          // freed because refcount hit zero
    }
}

// But what if two threads call release_ref simultaneously?
// Thread A: reads refcount = 1, decrements to 0, frees
// Thread B: reads refcount = 1 (stale), decrements to 0, frees again
// → DOUBLE FREE (variant of UAF)
```

**Callback during destruction:**
```c
void Container::clear() {
    for (auto &item : items) {
        item->on_remove(this);  // callback might reference other items
        delete item;            // those other items might be freed already
    }
}
```

The pattern: any time object A holds a pointer to object B, and B gets
freed without A knowing, you have a potential UAF. In complex C++ code
with dozens of objects cross-referencing each other, this happens
CONSTANTLY. That's why fuzzers find so many UAFs — the state space for
object lifetime interactions is enormous.

### Condition 2: Controlling The Replacement

After the free, you need to spray the right data into the freed slot.
The replacement allocation must be:

**Same size** (so the allocator returns the same slot):
```c
// Original object was 64 bytes
// We need our replacement to also be 64 bytes
// File format parsers help here — many allocate buffers
// whose size comes from file fields we control
```

**Controlled content** (so the fields we care about have our values):
```
Original Object (64 bytes):
┌──────────┬──────────┬──────────┬──────────┐
│ vtable   │ field_a  │ field_b  │ callback │
│ 8 bytes  │ 8 bytes  │ 8 bytes  │ 8 bytes  │
│ → legit  │ data     │ data     │ → legit  │
│   code   │          │          │   func   │
└──────────┴──────────┴──────────┴──────────┘

Attacker Replacement (64 bytes):
┌──────────┬──────────┬──────────┬──────────┐
│ fake     │ junk     │ junk     │ target   │
│ vtable   │          │          │ addr     │
│ → gadget │ AAAAAAAA │ AAAAAAAA │ → shell  │
│          │          │          │   code   │
└──────────┴──────────┴──────────┴──────────┘
```

In a file parser, the replacement is another piece of the file being
parsed. You craft the file so that after the bug triggers the free,
the parser continues reading the file and allocates a buffer of the
right size — filled with your data from the file.

### Condition 3: The Triggering Use

The final piece: code uses the dangling pointer in a way that follows
your corrupted data. The strongest triggers:

**Virtual function call** (most common in C++ targets):
```c
obj->virtual_method();
// Compiles to:
//   mov rax, [obj]          ; load vtable pointer
//   call [rax + offset]     ; call function from vtable
// If obj points to attacker data:
//   rax = attacker_value    ; fake vtable address
//   [rax + offset] = ?      ; whatever's at that address
```

**Indirect function call** (callback / function pointer field):
```c
obj->handler(obj->data);
// If obj is freed and replaced:
//   handler = attacker_controlled_address
//   data = attacker_controlled_argument
// You control BOTH the function called AND its argument
```

**Read of a pointer field, then dereference** (info leak path):
```c
next = obj->next_ptr;
value = next->data;
// If obj is freed, next_ptr = attacker value
// Dereference reads from arbitrary address → info leak
```

---

## Double-Free: The Evil Twin

A double-free is freeing the same memory twice. It's a UAF variant where
the "use" is another free operation.

```c
void cleanup(Context *ctx) {
    free(ctx->buffer);       // first free
    if (ctx->needs_cleanup) {
        free(ctx->buffer);   // second free — DOUBLE FREE
    }
}
```

### Why Double-Free Is Dangerous

When you free memory twice, the allocator adds the same chunk to the
free list TWICE. Next two allocations of that size return the SAME address:

```
free(chunk)   → free_list: [chunk]
free(chunk)   → free_list: [chunk, chunk]  (same pointer, twice)

alloc_A = malloc(size) → returns chunk (first copy off free list)
alloc_B = malloc(size) → returns chunk (second copy — SAME ADDRESS)

Now alloc_A and alloc_B point to the same memory.
Write to alloc_A → modifies alloc_B's content
Write to alloc_B → modifies alloc_A's content
```

This is an **overlapping allocation** primitive. You control one view
of the memory (alloc_A) and the program uses the other view (alloc_B)
as a legitimate object. You can overwrite any field of alloc_B through
alloc_A — without ever touching alloc_B directly.

### Double-Free → Arbitrary Write (NT Heap)

On the NT Heap, free list chunks contain forward and backward pointers
(flink/blink). When the allocator unlinks a chunk from the free list:

```c
// Simplified unlink operation:
chunk->blink->flink = chunk->flink;
chunk->flink->blink = chunk->blink;
```

If you control flink and blink through the double-free (because you've
written to the chunk between the two frees):

```
chunk->flink = target_address     (WHERE to write)
chunk->blink = value_to_write     (WHAT to write)
```

The unlink writes `value_to_write` to `target_address`. Arbitrary write.
From an arbitrary write, you overwrite a function pointer or vtable
and get code execution.

Modern allocators (LFH, Segment Heap) have safe-unlinking checks that
detect corrupted flink/blink. But the overlapping allocation primitive
from double-free still works — you just exploit it differently (corrupt
object data instead of heap metadata).

---

## Type Confusion: Using The Wrong Blueprint

### What It Is

Type confusion happens when code treats a memory region as Type A,
but it actually contains (or was allocated as) Type B. The fields
don't align. What Type A thinks is a data buffer, Type B has as a
function pointer. Follow the function pointer → you're executing
attacker data.

```
Type A layout (what the code expects):
Offset 0:  int32  flags        (4 bytes)
Offset 4:  int32  count        (4 bytes)
Offset 8:  char   data[56]     (56 bytes)

Type B layout (what's actually there):
Offset 0:  void*  vtable       (8 bytes)    ← overlaps flags + count
Offset 8:  void*  callback     (8 bytes)    ← overlaps data[0..7]
Offset 16: char   name[48]     (48 bytes)
```

If the code reads `typeA->data[0..7]` and dereferences it as a pointer,
it's actually reading `typeB->callback` — which the attacker controls
if they control Type B's creation.

### How Type Confusion Happens

**1. Union misuse (C/C++):**
```c
union ParsedValue {
    int64_t  as_int;
    double   as_float;
    char    *as_string;    // pointer!
};

struct Field {
    int type;               // 0=int, 1=float, 2=string
    union ParsedValue value;
};

void process(Field *f) {
    if (f->type == 2) {
        printf("%s", f->value.as_string);  // dereferences as pointer
    }
}

// Attacker controls the file. Sets type=2 but puts an integer
// value in the union. Code dereferences an integer as a pointer.
// If the integer is attacker-controlled → info leak or crash.
```

**2. Dynamic cast failure / missing type check:**
```c++
class Base { virtual void process() = 0; };
class TypeA : public Base { 
    int data[16]; 
    void process() override;
};
class TypeB : public Base { 
    void (*callback)();     // function pointer at different offset than TypeA::data
    char buffer[60];
    void process() override;
};

void handle(Base *obj) {
    // SHOULD check: TypeA *a = dynamic_cast<TypeA*>(obj);
    // INSTEAD does:
    TypeA *a = static_cast<TypeA*>(obj);  // no runtime check
    a->data[0] = value;  // if obj is actually TypeB, this writes
                         // over TypeB::callback
}
```

`static_cast` doesn't check at runtime. If `obj` is actually a `TypeB`,
the write to `data[0]` corrupts `TypeB::callback`. Next time someone
calls `obj->callback()` → your address.

**3. Index/tag confusion in variant types:**
```c
// Parser reads a "type" field from the file
int type = read_byte(file);

// Uses type as index into handler table
handlers[type](data);

// If type can be 0-255 but the table only has 10 entries...
// handlers[200] reads past the table → jumps to whatever's there
```

**4. COM interface confusion (Windows-specific, relevant to mpengine):**

COM objects expose interfaces through `QueryInterface`. If an object
returns the wrong interface pointer (or if the caller doesn't check the
return HRESULT):

```c++
IUnknown *pUnk = get_object();
IStream *pStream;
HRESULT hr = pUnk->QueryInterface(IID_IStream, (void**)&pStream);
// If we skip checking hr... and the object doesn't support IStream...
// pStream might be garbage, or might point to a different interface
// with different method offsets in its vtable
pStream->Read(buf, size, &bytesRead);  // calls wrong vtable slot
```

### Type Confusion In Parsers

File format parsers are TYPE CONFUSION FACTORIES. Here's why:

A file format has multiple record/chunk types. The parser reads a type
tag, then interprets the data according to that type. If the parser
doesn't validate the tag against the actual data length, or if it
reuses a buffer without clearing it:

```c
Record *parse_record(FILE *f) {
    Record *rec = malloc(sizeof(Record));
    rec->type = read_byte(f);
    
    switch (rec->type) {
        case TYPE_TEXT:
            rec->text.length = read_int(f);
            fread(rec->text.data, 1, rec->text.length, f);
            break;
        case TYPE_IMAGE:
            rec->image.width = read_int(f);
            rec->image.height = read_int(f);
            rec->image.pixels = malloc(rec->image.width * rec->image.height);
            break;
        case TYPE_LINK:
            rec->link.target_offset = read_int(f);
            rec->link.callback = resolve_link;  // function pointer
            break;
    }
    return rec;
}

// Later, code processes records:
void render(Record *rec) {
    if (rec->type == TYPE_LINK) {
        rec->link.callback(rec);  // calls function pointer
    }
}
```

**The attack**: Craft a file where the type byte says TYPE_LINK, but the
data that follows is actually TYPE_TEXT format. The `rec->link.callback`
field overlaps with wherever the text data lands in the union. If you
control those bytes (you do — they're from the file), you control the
function pointer.

Or more subtly: parse a TYPE_TEXT record first (fills the struct with
text data). Then parse a TYPE_LINK record into the SAME buffer without
clearing it. If the LINK parsing path doesn't initialise all fields,
some fields retain the TEXT data — which the attacker controlled.

---

## UAF → Type Confusion: The Combo

The most powerful UAF exploits ARE type confusions:

```
1. Object A (type: Parser, 64 bytes) is allocated and used
2. Object A is freed (but dangling pointer remains)
3. Object B (type: Buffer, 64 bytes) is allocated at same address
   Object B is filled with attacker-controlled file data
4. Dangling pointer to Object A is used
   Code thinks it's using a Parser struct
   But it's actually reading Buffer content (attacker data)
   Parser's vtable field now contains attacker bytes
5. Virtual function call on the "Parser" → jumps to attacker address
```

This is a UAF that BECOMES a type confusion at the moment of use.
The memory was freed as Parser, reallocated as Buffer, used as Parser.
The type confusion happens because the allocator doesn't track types —
it only tracks sizes.

### The Exploitation Pipeline

```
UAF found by fuzzer (crash on dangling pointer dereference)
    ↓
Analyse: what type was freed? What size?
    ↓
Find an allocation of the same size that we control content of
    ↓
Craft the replacement to look like a valid object but with
corrupted control fields (vtable, callback, size)
    ↓
Trigger the dangling pointer use
    ↓
If it dereferences a pointer → info leak (defeat ASLR)
If it calls a function → code execution
If it uses as size → secondary overflow → bigger primitive
```

---

## What The Fuzzer Sees

When a fuzzer hits a UAF, the crash signature looks different from
a heap overflow:

**Heap overflow crash:**
```
Access violation writing 0x????????
EIP/RIP at known code address (in the parser)
Faulting instruction: mov [reg+offset], value  (writing past buffer)
Heap corruption detected at 0x????????
```

**UAF crash:**
```
Access violation reading 0x????????
EIP/RIP at known code address
Faulting instruction: mov reg, [reg]  (reading from freed memory)
OR: call [reg]  (calling through freed vtable)
The accessed memory is on a free list or has been reallocated
```

**Type confusion crash:**
```
Access violation at unexpected address
EIP/RIP might be a WEIRD value (attacker-influenced)
If the confused type has a function pointer where data should be,
the CPU tries to execute "data" as code → crash at data-as-address
```

The `!exploitable` WinDbg extension (Chapter 06) classifies these
automatically. UAF with a function pointer dereference =
"EXPLOITABLE — User Mode Write AV starting at attacker-controlled address."

---

## mpengine.dll Specifics

### Why mpengine Is A UAF/Type Confusion Target

1. **Heavy C++ usage**: Virtual dispatch everywhere → vtable pointers everywhere
2. **Complex object graphs**: Parser creates dozens of cross-referencing objects
   per file → complex lifetime management → UAF opportunities
3. **Multiple format parsers share infrastructure**: A ZIP containing a PDF
   triggers both parsers, sharing objects → type confusion between parser
   contexts
4. **Error paths are under-tested**: Normal file → all objects freed cleanly.
   Malformed file → error path might free some objects but leave dangling
   pointers to others.
5. **Recursive parsing**: A ZIP containing a ZIP containing a DOC → deeply
   nested parser calls → complex stack of object lifetimes

### Fuzzing Strategy For UAF/Type Confusion

When we build the fuzzer harness (Chapter 05), we target these specifically:

- **Seed files with mixed types**: Archive containing multiple different
  file types (triggers multiple parsers, complex object interactions)
- **Corrupted type tags**: Change record type bytes in the seed file
  (forces parser to interpret data as wrong type)
- **Truncated files**: Cut off mid-record (triggers error paths that
  might not clean up properly → dangling pointers)
- **Duplicated sections**: Same section header appearing twice (parser
  might free the first, keep pointer, then allocate second at same address)

---

## Mapping To The Doctrine

The 0x1security compass says: search for knowledge, not for bugs.

This chapter is knowledge. You now understand:
- HOW objects live and die on the heap
- WHY freed memory gets reused (allocator optimization)
- WHAT happens when reused memory is the wrong type
- WHERE these bugs appear in parser code (error paths, type dispatch,
  object cross-references)

When you look at mpengine.dll in IDA (Chapter 08), you won't just
see functions — you'll see LIFETIMES. Which objects get created in
which order. Which error paths free some but not all. Which type tags
control which code paths.

The bugs won't be invisible anymore. The understanding produces the bugs.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Dangling pointer** | Pointer to memory that has been freed; still holds old address |
| **Object reuse** | Heap allocator returns recently-freed memory for new allocation of same size |
| **LIFO free list** | NT Heap returns most-recently-freed chunk first; makes UAF reuse predictable |
| **Double-free** | Freeing the same memory twice; creates overlapping allocations on free list |
| **Overlapping allocation** | Two pointers to the same memory from a double-free; write through one, read through other |
| **Type confusion** | Using memory as the wrong type; fields at wrong offsets, data read as pointers |
| **Vtable hijack** | Corrupting a C++ object's vtable pointer to redirect virtual function calls |
| **Static cast** | C++ cast with no runtime type check; enables type confusion if used on wrong type |
| **Safe unlinking** | Allocator check that flink/blink pointers are consistent before unlink; prevents classic heap metadata corruption |
| **Type tag** | Field in a record/struct that identifies which variant it is; corrupting this = type confusion |

---

## Drill 02 — UAF Exploitation

Go to `DRILLS/02_uaf_exploit/`. A vulnerable program has a UAF bug.

Your mission:
1. Identify the dangling pointer (where is the object freed but still used?)
2. Trigger a replacement allocation of the same size with controlled data
3. Craft the data so the vtable pointer points to your fake vtable
4. Trigger the virtual function call on the dangling pointer
5. Redirect execution to win()

No mitigations. Pure UAF → type confusion → vtable hijack → code exec.
This is the core primitive you'll use against mpengine.dll.
