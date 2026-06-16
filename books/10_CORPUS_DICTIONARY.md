# Chapter 10 — Corpus & Dictionary Design: Feeding The Machine

**VADER-RCE Field Manual**
**Prerequisite**: Ch05 (Fuzzing Theory), Ch08 (Target Reversing), Ch09 (Harness Construction)
**Drill**: DRILLS/10_corpus_build/

---

## Why You Need This

Your fuzzer is a weapon. A good one. Coverage-guided, instrumented,
wired directly into mpengine.dll through the harness you built.

It's also starving.

A fuzzer with no corpus is a machine gun with no ammunition. It can
cycle and click all day — nothing comes out. A fuzzer with a SHIT
corpus is worse: it fires blanks. Millions of executions burning CPU
and electricity, every mutated input rejected by the first parser
check because your seed files were garbage that never got past the
format signature validation.

The corpus is your ammunition. The dictionary is your tracer mix —
special tokens that light up code paths the random mutator would
never find on its own. Together they determine whether your campaign
produces 200 unique crashes in 48 hours or zero crashes in a month.

This is logistics. Not glamorous. But armies that win wars win the
supply chain first. You don't outfight the enemy — you outfeed
your own machine.

---

## Seed Corpus — Your Starting Ammunition

### What A Corpus Is

A seed corpus is a collection of input files that the fuzzer uses as
starting points for mutation. Each file is a "seed." The fuzzer picks
a seed, mutates it (flip bits, insert bytes, splice with another seed),
feeds the mutant to the target, checks for new coverage, and repeats.

```
SEED CORPUS
  ├── minimal.pdf      (exercises PDF parser)
  ├── minimal.zip      (exercises ZIP parser)
  ├── minimal.pe       (exercises PE parser)
  ├── minimal.doc      (exercises OLE parser)
  ├── minimal.rar      (exercises RAR parser)
  ├── minimal.cab      (exercises CAB parser)
  └── minimal.iso      (exercises ISO parser)
          │
          ▼
   FUZZER (mutate → execute → measure coverage → keep or discard)
          │
          ▼
   GROWN CORPUS (seeds that discovered new code paths)
```

The seed corpus is your initial investment. The fuzzer grows it
automatically through coverage feedback. But the QUALITY of your
initial seeds determines how fast the fuzzer discovers interesting
code and how deep it penetrates.

### Quality Over Quantity

This is the single most important rule of corpus construction:

**10 well-chosen seeds beat 10,000 random files.**

Why? Because the fuzzer is a MUTATOR, not a generator. It takes your
seeds and makes small changes. If your seed is a 50MB PDF with
embedded fonts, JavaScript, and 400 pages of content, the fuzzer has
to mutate through a vast space of bytes that are irrelevant to the
parser's edge cases. Most mutations will change something cosmetic.
Very few will hit the fields that control allocation sizes, pointer
arithmetic, or format dispatch.

If your seed is a 247-byte minimal valid PDF — just enough structure
to pass validation and reach the rendering/parsing code — then nearly
EVERY mutation is hitting something the parser cares about. The
signal-to-noise ratio is orders of magnitude better.

This is why special forces are more effective per-operator than
conscript armies. Each seed is an operator. Make each one count.

### The Minimality Principle

Every seed should be the SMALLEST valid file that exercises its target
code path. Not "small." SMALLEST. Strip everything that isn't required
for the parser to accept the file and reach the code you care about.

For a PDF seed targeting the page tree parser:
- You need: %PDF header, one page object, catalog, xref table, trailer
- You don't need: fonts, images, JavaScript, metadata, bookmarks

For a ZIP seed targeting the decompression code:
- You need: local file header, compressed payload, central directory, EOCD
- You don't need: multiple files, ZIP64 extensions, encryption, comments

The goal is a file where every single byte matters to the parser.
When the fuzzer flips a byte, it should change something MEANINGFUL.

### The Diversity Principle

Each seed in your corpus should exercise a DIFFERENT code path through
the target. If you have five PDF seeds and they all take the same
path through the parser, four of them are dead weight. The fuzzer
will discover the same code paths from any of them.

Diversity means:

- **Different format features**: one PDF with streams, one with
  cross-reference streams, one with linearization
- **Different compression methods**: ZIP with DEFLATE, ZIP with STORE,
  ZIP with BZIP2
- **Different nesting**: flat archive, nested archive (ZIP inside ZIP),
  archive with many entries
- **Different edge values**: normal lengths, zero lengths, maximum
  lengths, off-by-one lengths

Each seed is a beachhead. You want beachheads on DIFFERENT beaches,
not five landing craft on the same strip of sand.

---

## Building Corpus For mpengine.dll

### The Target Format List

mpengine.dll is Microsoft Defender's scan engine. It parses damn near
everything. From Ch08's reversing work, you identified the format
dispatch table. Here are the priority formats for your seed corpus:

| Format | Why It's Priority | Parser Complexity |
|--------|-------------------|-------------------|
| PDF    | Complex nested structure, JavaScript support, massive attack surface | Very High |
| ZIP    | Universal container, recursive scan (ZIP in ZIP), integer overflow candidates | High |
| PE     | Executables are Defender's primary target, deep analysis paths | Very High |
| OLE/DOC | Legacy format, complex FAT-based structure, macro support | High |
| RAR    | Proprietary compression, historically buggy parsers | Medium |
| CAB    | Windows native format, multiple compression algorithms | Medium |
| 7z     | Complex header structure, multiple codecs | Medium |
| ISO    | Disk image format, filesystem parsing | Medium |
| VHD    | Virtual disk, triggers filesystem mount parsing | Medium |
| ELF    | Linux binary format, cross-platform scan capability | Low-Medium |

You need at minimum ONE seed per format. Better: 2-3 seeds per
high-priority format, each exercising different features.

### Minimal Seed Construction — By Hand

Building seeds by hand is the gold standard. You control exactly what
goes in. You know every byte. You can make it minimal by construction
rather than by stripping.

#### Minimal Valid PDF (247 bytes)

```
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF
```

Hex dump of the critical header bytes:

```
00000000  25 50 44 46 2d 31 2e 34  0a                       |%PDF-1.4.|
```

That `%PDF-1.4` signature is the first thing mpengine checks. Without
it, the PDF parser never engages. The rest is the minimal object graph:
catalog → pages → page. No content streams, no fonts, no images. Just
enough skeleton that the parser walks the full page tree code path.

#### Minimal Valid ZIP (local header + central dir + EOCD)

```python
import struct

# Local file header
local_header = struct.pack('<4sHHHHHIIIHH',
    b'PK\x03\x04',    # signature
    20,                 # version needed (2.0)
    0,                  # flags
    0,                  # compression (STORE)
    0,                  # mod time
    0,                  # mod date
    0,                  # CRC-32
    5,                  # compressed size
    5,                  # uncompressed size
    5,                  # filename length
    0                   # extra field length
)
filename = b'a.txt'
file_data = b'AAAAA'

# Central directory entry
central_dir = struct.pack('<4sHHHHHHIIIHHHHHII',
    b'PK\x01\x02',    # signature
    20,                 # version made by
    20,                 # version needed
    0,                  # flags
    0,                  # compression
    0,                  # mod time
    0,                  # mod date
    0,                  # CRC-32
    5,                  # compressed size
    5,                  # uncompressed size
    5,                  # filename length
    0,                  # extra length
    0,                  # comment length
    0,                  # disk number start
    0,                  # internal attrs
    0,                  # external attrs
    0                   # local header offset
)

# End of central directory
cd_offset = len(local_header) + len(filename) + len(file_data)
cd_size = len(central_dir) + len(filename)
eocd = struct.pack('<4sHHHHIIH',
    b'PK\x05\x06',    # signature
    0,                  # disk number
    0,                  # disk with CD
    1,                  # entries on disk
    1,                  # total entries
    cd_size,            # CD size
    cd_offset,          # CD offset
    0                   # comment length
)

with open('minimal.zip', 'wb') as f:
    f.write(local_header + filename + file_data)
    f.write(central_dir + filename)
    f.write(eocd)
```

Hex dump of the result:

```
00000000  50 4b 03 04 14 00 00 00  00 00 00 00 00 00 00 00  |PK...............|
00000010  00 00 05 00 00 00 05 00  00 00 05 00 00 00 61 2e  |..............a.|
00000020  74 78 74 41 41 41 41 41  50 4b 01 02 14 00 14 00  |txtAAAAAPK......|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 05 00 00 00  |................|
00000040  05 00 00 00 05 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 61 2e  74 78 74 50 4b 05 06 00  |......a.txtPK...|
00000060  00 00 00 01 00 01 00 33  00 00 00 2a 00 00 00 00  |.......3...*....|
00000070  00                                                 |.|
```

That's 113 bytes. Everything the ZIP parser needs. Local file header
with a tiny payload, central directory pointing back to it, EOCD
tying it all together. When the fuzzer mutates compressed_size at
offset 0x12, or flips the compression method at offset 0x08, it's
hitting fields that directly control parser behaviour.

#### Minimal Valid PE (DOS header + PE header + one section)

```
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 80 00 00 00  |................|
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          e_lfanew at offset 0x3C = 0x80 (points to PE signature)

00000080  50 45 00 00 4c 01 01 00  00 00 00 00 00 00 00 00  |PE..L...........|
          ^^^^^^^^^^ PE\0\0 sig   ^^^^ i386
00000090  00 00 00 00 e0 00 02 01  0b 01 0e 00 00 02 00 00  |................|
                                   ^^^^ PE32 magic
000000a0  00 02 00 00 00 00 00 00  00 10 00 00 00 10 00 00  |................|
000000b0  00 00 00 00 00 00 40 00  00 10 00 00 00 02 00 00  |......@.........|
```

The `MZ` at offset 0 and `PE\x00\x00` at offset 0x80 are the two
magic sequences. Without both, mpengine's PE parser won't engage.
One section header, no imports, no exports, minimal optional header.
Under 1KB total. Every byte is parser-relevant.

#### Minimal RAR5 Archive

```
00000000  52 61 72 21 1a 07 01 00  33 92 b5 e5 0a 01 05 06  |Rar!....3.......|
          ^^^^^^^^^^^^^^^^^^^^^^
          RAR5 signature (7 bytes + \x00)
00000010  00 05 01 01 80 80 00 a4  83 78 b0 0a 03 02 80 80  |.........x......|
00000020  00 08 00 80 80 00 00 80  80 00 41 41 41 1d 77 56  |..........AAA.wV|
00000030  51 03 05 04 00                                     |Q....|
```

RAR signature at byte 0: `52 61 72 21 1a 07 01 00`. That's the
minimum magic sequence for the RAR5 format handler. The archive
header, file header, and minimal file data follow.

#### Minimal CAB Archive

```
00000000  4d 53 43 46 00 00 00 00  59 00 00 00 00 00 00 00  |MSCF....Y.......|
          ^^^^^^^^^^^
          CAB signature "MSCF"
00000010  2c 00 00 00 00 00 00 00  03 01 01 00 01 00 00 00  |,...............|
00000020  00 00 00 00 41 00 00 00  01 00 00 00 05 00 00 00  |....A...........|
00000030  00 00 00 00 00 00 4c cc  a4 56 00 00 61 2e 74 78  |......L..V..a.tx|
00000040  74 00 81 2c 0e 42 f6 f0  05 00 05 00 41 41 41 41  |t..,.B......AAAA|
00000050  41 d1 5f cd 63 a2 85 e9  c1                        |A._.c....|
```

`MSCF` at offset 0. Cabinet file header version 3.1, one folder,
one file. Under 100 bytes.

### Where To Get Seeds

Ranked from best to worst:

1. **Build by hand** (best): You control every byte. Minimal by
   construction. You understand the structure because you wrote it.
   Use the format specs and the Python struct module.

2. **Extract from test suites**: Fuzzing projects maintain seed
   corpora. Check:
   - AFL's `testcases/` directory (ships with the tool)
   - Google's fuzzer test corpus: `github.com/google/fuzzing/tree/master/corpus`
   - Format-specific test suites (e.g., PDF test files from pdf.js)

3. **Minimize real-world files**: Take a real PDF, real ZIP, real PE.
   Run it through `afl-cmin` and `afl-tmin` to strip it down to the
   minimum that maintains coverage. Acceptable but slower than
   building by hand.

4. **Random downloads** (worst): Grabbing files off the internet.
   You get bloated, redundant seeds that waste fuzzer cycles. Last
   resort only.

---

## Corpus Minimization — Strip The Fat

### afl-cmin: Remove Redundant Seeds

You've got 500 PDF seeds from various sources. Most of them exercise
the same code paths. Running the fuzzer on all 500 wastes cycles on
redundant coverage. `afl-cmin` solves this.

`afl-cmin` runs every seed through the instrumented target, records
which code paths each seed exercises, and keeps only the MINIMUM SET
of seeds that covers all observed paths. If seeds A, B, and C all hit
the same 47 basic blocks, it keeps one and throws out two.

```bash
# Minimize a corpus directory
afl-cmin -i corpus_raw/ -o corpus_min/ -t 5000 -- \
    ./harness @@

# -i: input directory (your raw seed collection)
# -o: output directory (minimized corpus)
# -t: timeout per execution in ms
# @@: placeholder for input filename
```

Real example for mpengine:

```bash
# Minimize PDF seeds against the mpengine harness
afl-cmin -i seeds/pdf_raw/ -o seeds/pdf_min/ -t 10000 -- \
    ./mpengine_harness @@

# Before: 347 PDF files, 42MB total
# After:  23 PDF files, 890KB total
# Coverage: identical (same basic blocks hit)
```

347 seeds → 23 seeds. Same coverage. The fuzzer now spends its
cycles mutating 23 meaningful seeds instead of re-treading the same
code paths through 347 redundant ones.

### afl-tmin: Minimize Individual Seeds

`afl-cmin` removes redundant seeds from a SET. `afl-tmin` minimizes
a SINGLE seed to its smallest form that maintains its unique coverage
contribution.

```bash
# Minimize a single seed file
afl-tmin -i seed.pdf -o seed_min.pdf -t 5000 -- \
    ./harness @@

# Before: seed.pdf = 14,392 bytes
# After:  seed_min.pdf = 312 bytes
# Coverage: identical for this seed's unique paths
```

`afl-tmin` works by iteratively removing bytes and checking if
coverage changes. If removing bytes 500-600 doesn't change which
basic blocks are hit, those bytes are gone. The result is a seed
where every remaining byte contributes to reaching some code.

Run `afl-cmin` FIRST (remove redundant seeds), then `afl-tmin` on
each surviving seed (shrink individuals). Order matters — minimizing
500 seeds individually is a waste of time when only 23 are needed.

```bash
# Full minimization pipeline
# Step 1: Remove redundant seeds
afl-cmin -i seeds/raw/ -o seeds/dedup/ -t 10000 -- ./harness @@

# Step 2: Minimize each surviving seed
mkdir -p seeds/min/
for f in seeds/dedup/*; do
    name=$(basename "$f")
    afl-tmin -i "$f" -o "seeds/min/$name" -t 10000 -- ./harness @@
done
```

---

## Dictionaries — Teaching The Fuzzer The Language

### What A Dictionary Is

A fuzzer mutates by flipping bits, inserting random bytes, and
splicing inputs together. These are DUMB mutations. Powerful because
of volume, but dumb. The fuzzer doesn't know that `%PDF` means
something. It doesn't know that `endobj` is a token. It doesn't know
that `PK\x03\x04` is a magic signature.

A dictionary teaches it.

A dictionary is a file containing tokens — byte sequences that have
special meaning in the target format. When the fuzzer mutates an
input, it can INSERT dictionary tokens at random positions, REPLACE
existing bytes with dictionary tokens, or COMBINE tokens with random
mutations.

This is the difference between a soldier who speaks the enemy's
language and one who doesn't. Both can fight. The one who speaks the
language infiltrates deeper.

### Dictionary File Format

AFL/LibFuzzer dictionaries use the same simple format:

```
# PDF dictionary for mpengine fuzzing
# Each line: "token_name" = "byte_sequence"
# Hex bytes use \xNN notation

# Magic / signature
pdf_magic="%PDF-"
pdf_eof="%%EOF"

# Object delimiters
obj_start="obj"
obj_end="endobj"
stream_start="stream"
stream_end="endstream"
xref="xref"
trailer="trailer"
startxref="startxref"

# Dictionary delimiters
dict_open="<<"
dict_end=">>"
array_open="["
array_close="]"

# Key names (high-value targets for the parser)
type="/Type"
pages="/Pages"
page="/Page"
catalog="/Catalog"
length="/Length"
filter="/Filter"
kids="/Kids"
count="/Count"
mediabox="/MediaBox"
contents="/Contents"
resources="/Resources"

# Filters (trigger decompression code paths)
flatedecode="/FlateDecode"
asciihex="/ASCIIHexDecode"
ascii85="/ASCII85Decode"
lzw="/LZWDecode"
dct="/DCTDecode"
ccitt="/CCITTFaxDecode"
jbig2="/JBIG2Decode"
jpx="/JPXDecode"

# Stream types that trigger deep parsing
javascript="/JavaScript"
js="/JS"
openaction="/OpenAction"
embeddedfile="/EmbeddedFile"
launch="/Launch"

# Cross-reference streams (different code path than table xref)
xref_stm="/XRef"

# Interesting integers (edge cases for size fields)
int_zero="0"
int_max_16="\xff\xff"
int_max_32="\xff\xff\xff\xff"
int_negative="-1"
int_overflow="2147483647"
int_overflow2="4294967295"
```

Save that as `pdf.dict` and pass it to the fuzzer:

```bash
# AFL++ with dictionary
afl-fuzz -i corpus/ -o output/ -x pdf.dict -- ./harness @@

# LibFuzzer with dictionary
./harness_libfuzzer -dict=pdf.dict corpus/
```

### Format-Specific Dictionaries

#### ZIP Dictionary

```
# ZIP format tokens
zip_local="\x50\x4b\x03\x04"
zip_central="\x50\x4b\x01\x02"
zip_eocd="\x50\x4b\x05\x06"
zip_data_desc="\x50\x4b\x07\x08"
zip64_eocd="\x50\x4b\x06\x06"
zip64_locator="\x50\x4b\x06\x07"

# Compression methods
store="\x00\x00"
deflate="\x08\x00"
bzip2="\x0c\x00"
lzma="\x0e\x00"

# Version values
ver_20="\x14\x00"
ver_45="\x2d\x00"
ver_63="\x3f\x00"

# Flag bits
encrypted="\x01\x00"
data_descriptor="\x08\x00"
utf8="\x00\x08"

# Dangerous sizes (integer overflow candidates)
size_zero="\x00\x00\x00\x00"
size_max="\xff\xff\xff\xff"
size_7f="\xff\xff\x7f\x00"
size_80="\x00\x00\x80\x00"
size_negative="\xff\xff\xff\x7f"
```

#### PE Dictionary

```
# PE format tokens
mz_magic="MZ"
pe_sig="PE\x00\x00"

# Machine types
i386="\x4c\x01"
amd64="\x64\x86"

# Section names (.text, .data, .rsrc, .reloc)
sec_text=".text\x00\x00\x00"
sec_data=".data\x00\x00\x00"
sec_rsrc=".rsrc\x00\x00\x00"
sec_reloc=".reloc\x00\x00"

# Optional header magic
pe32="\x0b\x01"
pe32plus="\x0b\x02"

# Data directory entries trigger different parsers
import_dir="\x00\x00\x00\x00\x00\x00\x00\x00"
export_dir_rva="\x00\x10\x00\x00"
resource_rva="\x00\x40\x00\x00"
clr_header="\x00\x20\x00\x00"

# Interesting characteristics flags
dll_flag="\x00\x20"
exe_flag="\x00\x00"
no_reloc="\x01\x00"

# Sizes that trigger edge cases
sec_align="\x00\x10\x00\x00"
file_align="\x00\x02\x00\x00"
```

#### RAR Dictionary

```
# RAR5 signature
rar5_sig="\x52\x61\x72\x21\x1a\x07\x01\x00"

# RAR4 signature (legacy, different parser path)
rar4_sig="\x52\x61\x72\x21\x1a\x07\x00"

# Header types
rar_main="\x01"
rar_file="\x02"
rar_service="\x03"
rar_encrypt="\x04"
rar_end="\x05"

# Compression methods
rar_store="\x00"
rar_fast="\x01"
rar_normal="\x02"
rar_good="\x03"
rar_best="\x04"
```

### Building Dictionaries From Reversing

The most valuable dictionaries come from the target binary itself.
When you reversed mpengine.dll in Ch08, you found string constants
in the parser functions. Those strings ARE your dictionary.

In Ghidra:

1. Open the Strings window (Window → Defined Strings)
2. Filter to the address range of the parser you care about
3. Export strings that look like format tokens

In practice:

```bash
# Extract strings from mpengine.dll (quick and dirty)
strings -n 3 mpengine.dll | sort -u > mpengine_strings.txt

# Filter for PDF-related strings
grep -iE 'pdf|endobj|stream|xref|trailer|flate|catalog|pages' \
    mpengine_strings.txt > pdf_strings_raw.txt

# Filter for ZIP-related strings
grep -iE 'zip|deflat|inflate|central|local.header|end.of' \
    mpengine_strings.txt > zip_strings_raw.txt
```

Then manually convert the interesting strings to dictionary format.
Not every string is useful. You want tokens the PARSER checks for —
magic bytes, delimiters, keywords that trigger code path decisions.
Ignore logging strings, error messages, and UI text.

The best approach: cross-reference the strings with the functions
from your reversing notes. If a string appears in a comparison
instruction inside the PDF parser's dispatch function, it's a
high-value dictionary token. If it appears in an error logging
function, skip it.

---

## Corpus Evolution During Campaign

### How The Corpus Grows

You start your campaign with 23 minimized seeds. After 24 hours of
fuzzing, you have 2,847 files in the corpus. What happened?

Coverage-guided evolution:

```
Hour 0:    23 seeds, 1,247 basic blocks covered
Hour 1:    189 seeds, 3,891 basic blocks covered
Hour 4:    612 seeds, 5,234 basic blocks covered
Hour 8:    1,453 seeds, 6,102 basic blocks covered
Hour 24:   2,847 seeds, 6,441 basic blocks covered
Hour 48:   3,102 seeds, 6,489 basic blocks covered  ← plateau
```

Every time the fuzzer mutates a seed and the result triggers a NEW
basic block (one never seen before), that mutant is saved to the
corpus. It becomes a new seed for future mutations. The corpus grows
organically toward maximum coverage.

The growth curve ALWAYS looks like this:
- **Explosive growth** in the first hours (easy paths, low-hanging fruit)
- **Diminishing returns** as the easy paths are all found
- **Plateau** where new coverage trickles to near-zero

The plateau is important. It tells you the corpus (and the fuzzer's
mutation strategy) have exhausted what they can find. Time for
intervention.

### Coverage Plateau — When The Machine Stalls

When you see fewer than 1 new basic block per hour for 8+ hours,
the campaign has plateaued. The fuzzer is churning but not finding
new code. Options:

1. **Add new seed types**: If you've been fuzzing PDFs, add a PDF
   with cross-reference streams (different code path). Add one with
   embedded JavaScript. Add one with JBIG2-compressed images.

2. **Improve the dictionary**: Add tokens you missed. Extract more
   strings from the target binary. Add format-specific edge values.

3. **Switch mutation strategies**: If using AFL, enable MOpt
   (mutation scheduling optimization). Try different power schedules
   (`-p fast`, `-p explore`, `-p exploit`).

4. **Target a different format**: Maybe the PDF parser is well-fuzzed
   but the RAR parser hasn't been touched. Rotate targets.

5. **Use the reversing**: Go back to Ghidra. Find the cold code
   paths (blocks with zero hits). Figure out what input conditions
   reach them. Craft a seed that exercises those conditions.

Option 5 is the most effective and the most work. This is where
reversing pays dividends — you're not guessing what might help,
you're SEEING what code is unreached and engineering a seed to
reach it.

### Corpus Pruning

The evolved corpus has redundancy. Many seeds cover the same paths
but arrived via different mutation chains. Periodically prune:

```bash
# Re-minimize the grown corpus
afl-cmin -i output/default/queue/ -o corpus_pruned/ -t 10000 -- \
    ./harness @@

# Before: 2,847 seeds in the evolved corpus
# After:  156 seeds with identical total coverage
```

The pruned corpus is your new starting point for the next campaign
phase. Faster cycle time, same coverage, more efficient mutation.

### Corpus Distillation

After an initial fuzzing run, the grown corpus contains the fuzzer's
"discoveries" — inputs that found new code paths. These are gold.
Distill them:

```bash
# Step 1: Prune (remove redundant seeds)
afl-cmin -i output/default/queue/ -o distilled/phase1/ -t 10000 -- \
    ./harness @@

# Step 2: Minimize each survivor
for f in distilled/phase1/*; do
    name=$(basename "$f")
    afl-tmin -i "$f" -o "distilled/phase2/$name" -t 10000 -- \
        ./harness @@
done

# Step 3: Use distilled corpus as seeds for next campaign
afl-fuzz -i distilled/phase2/ -o output_v2/ -x combined.dict -- \
    ./harness @@
```

This is the campaign cycle:

```
Initial seeds → FUZZ → Grown corpus → DISTILL → Better seeds → FUZZ → ...
```

Each cycle starts with a better corpus than the last. The fuzzer
goes deeper each round. This is iterative refinement — the same
principle that makes machine learning work. Feed the machine its
own output, filtered through quality.

### Cross-Pollination

Here's a dirty trick: seeds from one format parser can sometimes
trigger bugs in another.

Polyglot files. A file that is simultaneously valid as two formats.
A file that starts with `%PDF-1.4` but contains a ZIP local file
header embedded in a stream object. mpengine parses it as PDF.
The PDF parser extracts the stream. The extracted stream gets
re-scanned. The re-scan triggers the ZIP parser. A mutation in
the ZIP portion overflows a buffer in the ZIP parser, but the
delivery mechanism was PDF.

This is recursion, and recursive parsers are a goldmine for bugs.
mpengine scans archives recursively — it extracts files from ZIPs
and scans each extracted file. A ZIP containing a RAR containing a
CAB containing a PE with a corrupted resource section... that's four
levels of parser invocation from a single input file.

Build some polyglot seeds:

```bash
# ZIP containing a minimal PE
zip polyglot_zip_pe.zip minimal.pe

# RAR containing a minimal PDF (use rar command or Python rarfile)
# PDF with embedded ZIP in a stream object (manually construct)
```

Nesting. Recursion. Multiple parser invocations from a single
seed. This is how you find the bugs that single-format fuzzing misses.

---

## Advanced Corpus Techniques

### Grammar-Based Generation

For structured formats, randomly mutating bytes is inefficient. The
parser rejects most mutations because they violate the format's
STRUCTURE, not its VALUES. You want to generate files that are
structurally valid but have semantically insane values.

Grammar-based generation uses a formal grammar to produce files:

```python
# Simplified PDF grammar-based generator
import random

def gen_pdf():
    objects = []
    obj_id = 1

    # Catalog (always object 1)
    catalog = f"{obj_id} 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    objects.append(catalog)
    obj_id += 1

    # Pages
    page_count = random.choice([0, 1, 2, 255, 65535, -1])
    kids = " ".join(f"{i} 0 R" for i in range(3, 3 + max(0, min(page_count, 3))))
    pages = f"{obj_id} 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {page_count} >>\nendobj\n"
    objects.append(pages)
    obj_id += 1

    # Pages (1-3 page objects with weird MediaBox values)
    for _ in range(random.randint(0, 3)):
        x = random.choice([0, -1, 99999, 0x7FFFFFFF])
        y = random.choice([0, -1, 99999, 0x7FFFFFFF])
        page = f"{obj_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {x} {y}] >>\nendobj\n"
        objects.append(page)
        obj_id += 1

    # Optional: stream object with random filter
    if random.random() > 0.5:
        filter_name = random.choice([
            "/FlateDecode", "/ASCIIHexDecode", "/LZWDecode",
            "/GARBAGE", "/A" * 256, ""
        ])
        data = bytes(random.randint(0, 255) for _ in range(random.randint(0, 100)))
        length = random.choice([len(data), 0, len(data) + 100, -1, 0x7FFFFFFF])
        stream_obj = (
            f"{obj_id} 0 obj\n"
            f"<< /Length {length} /Filter {filter_name} >>\n"
            f"stream\n"
        ).encode() + data + b"\nendstream\nendobj\n"
        objects.append(stream_obj)
        obj_id += 1

    # Build xref and trailer
    body = b""
    offsets = [0]  # object 0 is free
    for obj in objects:
        offsets.append(len(body) + 15)  # approximate header offset
        if isinstance(obj, str):
            body += obj.encode()
        else:
            body += obj

    header = b"%PDF-1.4\n"
    xref_offset = len(header) + len(body)

    xref = f"xref\n0 {obj_id}\n"
    xref += "0000000000 65535 f \n"
    running_offset = len(header)
    for obj in objects:
        xref += f"{running_offset:010d} 00000 n \n"
        running_offset += len(obj) if isinstance(obj, str) else len(obj)

    trailer = f"trailer\n<< /Size {obj_id} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"

    return header + body + xref.encode() + trailer.encode()

# Generate 100 grammar-fuzzed PDFs
for i in range(100):
    with open(f'gen/pdf_{i:04d}.pdf', 'wb') as f:
        f.write(gen_pdf())
```

The structure is always valid PDF. The VALUES are insane — negative
page counts, massive MediaBox coordinates, wrong stream lengths,
garbage filter names. This gets past structural validation and hits
the deep parser code that processes the values.

### Splicing

Take the interesting PARTS of two seeds and combine them. The fuzzer
does this automatically (AFL's splice mutation), but you can do it
strategically:

```python
# Splice: take the header from seed A and the body from seed B
with open('seed_a.pdf', 'rb') as f:
    data_a = f.read()
with open('seed_b.pdf', 'rb') as f:
    data_b = f.read()

# Find the first 'stream' keyword in each
split_a = data_a.find(b'stream')
split_b = data_b.find(b'stream')

if split_a > 0 and split_b > 0:
    spliced = data_a[:split_a] + data_b[split_b:]
    with open('spliced.pdf', 'wb') as f:
        f.write(spliced)
```

Header from one file, body from another. The parser might handle
the header fine, then choke on the mismatched body because internal
offsets and lengths no longer agree. That disagreement is where
buffer overflows and heap corruptions live.

### Radamsa — The Mad Mutator

Radamsa is a standalone mutator. Not a fuzzer — it doesn't execute
targets or measure coverage. It just takes an input and produces
mutated outputs. Brilliantly effective at generating weird edge cases
that AFL's built-in mutators miss.

```bash
# Install radamsa
git clone https://gitlab.com/akihe/radamsa.git
cd radamsa && make install

# Generate 100 mutants from a single seed
radamsa -n 100 -o mutant_%n.pdf seed.pdf

# Generate mutants from multiple seeds (picks randomly)
radamsa -n 1000 -o gen/mutant_%n.zip seeds/zip/*.zip
```

Radamsa's mutations are more creative than AFL's defaults. It does
recursive mutations, token-level mutations, format-specific
mutations. Use radamsa to GENERATE seeds, then feed those seeds
into AFL for coverage-guided evolution.

```bash
# Pipeline: Radamsa generates, AFL evolves
# Step 1: Generate diverse mutants
mkdir -p radamsa_seeds/
radamsa -n 500 -o radamsa_seeds/mut_%n.pdf seeds/pdf_min/*.pdf

# Step 2: Minimize (remove redundant)
afl-cmin -i radamsa_seeds/ -o radamsa_min/ -t 10000 -- ./harness @@

# Step 3: Merge into main corpus
cp radamsa_min/* corpus/
```

### Structure-Aware Fuzzing

The holy grail. A mutator that understands the TARGET FORMAT's
structure and mutates intelligently within that structure.

LibFuzzer supports custom mutators:

```cpp
// Custom mutator for ZIP format
// Knows about ZIP structure, mutates WITHIN fields
extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed
) {
    // Parse the ZIP structure
    if (Size < 30) return Size;  // too small for local header

    // Verify it starts with PK signature
    if (Data[0] != 'P' || Data[1] != 'K') return Size;

    // Target specific fields for mutation
    std::mt19937 rng(Seed);
    int target = rng() % 5;

    switch (target) {
        case 0:
            // Mutate compressed_size (offset 18-21)
            if (Size >= 22) {
                uint32_t val = rng();
                memcpy(Data + 18, &val, 4);
            }
            break;
        case 1:
            // Mutate uncompressed_size (offset 22-25)
            if (Size >= 26) {
                uint32_t val = rng();
                memcpy(Data + 22, &val, 4);
            }
            break;
        case 2:
            // Mutate compression method (offset 8-9)
            if (Size >= 10) {
                uint16_t method = rng() % 20;  // known + unknown methods
                memcpy(Data + 8, &method, 2);
            }
            break;
        case 3:
            // Mutate filename_length (offset 26-27)
            if (Size >= 28) {
                uint16_t len = rng();
                memcpy(Data + 26, &len, 2);
            }
            break;
        case 4:
            // Mutate version needed (offset 4-5)
            if (Size >= 6) {
                uint16_t ver = rng() % 100;
                memcpy(Data + 4, &ver, 2);
            }
            break;
    }

    return Size;
}
```

This mutator KNOWS that bytes 18-21 are the compressed size field.
It mutates that field as a unit rather than flipping individual bits.
It knows offset 8-9 is the compression method and tries values that
might be valid, invalid, or boundary cases.

Structure-aware fuzzing finds bugs that random mutation takes days
to stumble into. The cost is writing the custom mutator. Worth it
for high-priority targets.

---

## Measuring Corpus Quality

### Code Coverage Is King

The whole point of the corpus is to maximize code coverage in the
target. More basic blocks hit = more code tested = higher probability
of finding a bug in that code.

Measure coverage with:

```bash
# AFL++ coverage map (during fuzzing)
# Check the fuzzer stats:
cat output/default/fuzzer_stats

# Key fields:
#   paths_total:     number of unique paths found
#   bitmap_cvg:      percentage of the coverage bitmap used
#   stability:       how deterministic the target is (want >90%)

# For detailed coverage analysis, use afl-showmap:
afl-showmap -i corpus/ -o coverage_map.txt -- ./harness @@

# Or use LLVM source coverage (if you have source):
# Compile with -fprofile-instr-generate -fcoverage-mapping
# Run seeds, merge profdata, generate HTML report
llvm-profdata merge -sparse *.profraw -o merged.profdata
llvm-cov show ./harness -instr-profile=merged.profdata \
    -format=html -output-dir=coverage_html/
```

For closed-source targets like mpengine.dll, you can't get source
coverage. You rely on:

- **AFL's bitmap**: basic block edge coverage via DynamoRIO or
  Intel PT instrumentation
- **DynamoRIO's drcov**: records which basic blocks are executed
- **Lighthouse** (IDA/Ghidra plugin): visualizes drcov data on
  the disassembly, shows green (covered) and red (uncovered) blocks

```bash
# Collect coverage with DynamoRIO
drrun -t drcov -- ./harness seed.pdf

# Output: drcov.harness.xxxxx.proc.log
# Load in Lighthouse (IDA plugin) to see coverage on the disassembly
```

### Heat Maps — Where Is Your Corpus Hitting?

Coverage isn't binary. Some code regions get hammered by every seed
(HOT). Others get touched by one seed and never again (WARM). Others
are never reached (COLD).

```
COVERAGE HEAT MAP (conceptual)

   PDF PARSER                 ZIP PARSER              RAR PARSER
   ██████████ header check    ██████████ sig check    ░░░░░░░░░░
   ██████████ obj parse       ████████░░ inflate      ░░░░░░░░░░
   ████████░░ xref parse      ██████░░░░ multi-file   ░░░░░░░░░░
   ██████░░░░ stream decode   ████░░░░░░ zip64        ░░░░░░░░░░
   ████░░░░░░ JS eval         ██░░░░░░░░ encryption   ░░░░░░░░░░
   ██░░░░░░░░ embedded files  ░░░░░░░░░░ split arch   ░░░░░░░░░░
   ░░░░░░░░░░ AcroForm        ░░░░░░░░░░ self-extract  ░░░░░░░░░░

   ██ = hot (many seeds)   ░░ = cold (no seeds)
```

The cold zones are where the bugs are hiding. Nobody's testing
that code. The fuzzer hasn't reached it. Your job is to figure out
WHY it's cold and build seeds that turn it hot.

Cold code is cold for a reason:
- **Feature gating**: the parser only enters that code when a
  specific feature flag is set in the input (e.g., encryption,
  ZIP64 mode, AcroForm)
- **Deep nesting**: the code is 5 function calls deep from the
  entry point — random mutations corrupt the outer structure before
  reaching the inner code
- **Rare value checks**: the code only triggers when a field has a
  specific value (e.g., compression method = 99, version = 63)

Solution for each:
- **Feature gating** → build a seed with that feature enabled
- **Deep nesting** → use a grammar-based generator to produce
  structurally valid deeply-nested inputs
- **Rare value checks** → add the specific value to your dictionary

### Coverage Plateau Detection

Track new basic blocks over time. Graph it:

```
New blocks/hour:
Hour 1:   ████████████████████████████████████████  847
Hour 2:   ████████████████████████                  412
Hour 4:   ████████████████                          289
Hour 8:   ██████████                                156
Hour 12:  ████                                       67
Hour 24:  ██                                         23
Hour 36:  █                                           8
Hour 48:  ░                                           2
```

When the rate drops below ~5 new blocks per hour and stays there,
you've plateaued. The fuzzer has exhausted what the current corpus
and dictionary can find. Time to:

1. Check the heat map for cold regions
2. Build targeted seeds for those regions
3. Expand the dictionary with tokens from cold code paths
4. Distill the corpus and restart

This is the CAMPAIGN CYCLE. Not "start fuzzer, come back in a week."
Active management. Monitor. Analyse. Intervene. Restart. Repeat.

---

## Putting It All Together — Campaign Corpus Pipeline

### Phase 1: Initial Corpus Build

```bash
# Create directory structure
mkdir -p corpus/{pdf,zip,pe,ole,rar,cab,7z,iso}
mkdir -p corpus/minimized
mkdir -p dicts/

# Build minimal seeds (by hand or with generators)
python gen_minimal_pdf.py > corpus/pdf/minimal.pdf
python gen_minimal_zip.py > corpus/zip/minimal.zip
# ... one generator per format

# Gather seeds from test suites
cp /path/to/afl/testcases/archives/zip/* corpus/zip/
cp /path/to/afl/testcases/archives/rar/* corpus/rar/

# Build dictionaries
# Copy from AFL's dict/ and add custom tokens
cp /path/to/afl/dictionaries/pdf.dict dicts/
cat custom_pdf_tokens.dict >> dicts/pdf.dict
```

### Phase 2: Minimization

```bash
# Minimize per-format corpus
for fmt in pdf zip pe ole rar cab 7z iso; do
    afl-cmin -i "corpus/$fmt/" -o "corpus/minimized/$fmt/" \
        -t 10000 -- ./harness @@
done

# Then minimize individual seeds
for fmt in pdf zip pe ole rar cab 7z iso; do
    mkdir -p "corpus/final/$fmt/"
    for f in "corpus/minimized/$fmt/"*; do
        name=$(basename "$f")
        afl-tmin -i "$f" -o "corpus/final/$fmt/$name" \
            -t 10000 -- ./harness @@
    done
done
```

### Phase 3: Fuzzing Campaign

```bash
# Launch fuzzers (one per format for targeted campaigns)
# Master instance
afl-fuzz -M master -i corpus/final/pdf/ -o output/pdf/ \
    -x dicts/pdf.dict -- ./harness @@

# Secondary instances (different mutation strategies)
afl-fuzz -S slave1 -i corpus/final/pdf/ -o output/pdf/ \
    -x dicts/pdf.dict -p fast -- ./harness @@
afl-fuzz -S slave2 -i corpus/final/pdf/ -o output/pdf/ \
    -x dicts/pdf.dict -p explore -- ./harness @@
```

### Phase 4: Monitor and Intervene

```bash
# Watch coverage growth
watch -n 60 'cat output/pdf/master/fuzzer_stats | grep paths_total'

# When plateau detected (no new paths for 8+ hours):

# 1. Distill the grown corpus
afl-cmin -i output/pdf/master/queue/ -o corpus/distilled/pdf/ \
    -t 10000 -- ./harness @@

# 2. Add new seed types (grammar-generated, polyglots)
python gen_pdf_grammar.py --count 50 --output corpus/distilled/pdf/

# 3. Restart campaign with enriched corpus
afl-fuzz -M master -i corpus/distilled/pdf/ -o output/pdf_v2/ \
    -x dicts/pdf_expanded.dict -- ./harness @@
```

### Phase 5: Crash Seeds

When the fuzzer finds crashes, those crash inputs go into a
separate directory for triage (Ch06). But they're ALSO corpus
candidates — a crash input exercises a code path that leads to a
bug. Nearby code paths might have DIFFERENT bugs.

```bash
# Minimize crash inputs
for f in output/pdf/master/crashes/*; do
    name=$(basename "$f")
    afl-tmin -i "$f" -o "crashes/minimized/$name" -t 10000 -- \
        ./harness @@
done

# Add minimized crash seeds to corpus for next campaign phase
# (the fuzzer will mutate near the crash path, finding related bugs)
cp crashes/minimized/* corpus/distilled/pdf/
```

---

## The Ammunition Checklist

Before you launch a fuzzing campaign, verify your supply chain:

```
CORPUS CHECK:
[ ] At least 1 seed per target format
[ ] Each seed is MINIMAL (< 1KB for simple formats, < 10KB for complex)
[ ] Seeds exercise DIFFERENT code paths (diversity)
[ ] Corpus has been minimized with afl-cmin
[ ] Individual seeds minimized with afl-tmin
[ ] No duplicate/redundant seeds

DICTIONARY CHECK:
[ ] Magic bytes / signatures for the target format
[ ] All format-specific tokens (delimiters, keywords, type names)
[ ] Integer edge values (0, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF, -1)
[ ] Tokens extracted from target binary's string constants
[ ] Dictionary file passes syntax validation (no format errors)

CAMPAIGN INFRASTRUCTURE:
[ ] Harness compiled with instrumentation
[ ] Coverage measurement configured
[ ] Monitoring scripts in place (coverage growth, crash count)
[ ] Plateau detection threshold defined (blocks/hour)
[ ] Corpus distillation pipeline scripted
[ ] Crash triage pipeline ready (Ch06)
```

If any box is unchecked, you're not ready. Fix the supply chain
before you pull the trigger.

---

## Summary — Key Takeaways

- **The corpus is your ammunition.** Garbage corpus = garbage results.
  No amount of fuzzer sophistication compensates for bad inputs.

- **Minimality is everything.** Smallest valid file that exercises
  the target code path. Every byte should matter to the parser.
  10 minimal seeds > 10,000 bloated ones.

- **Diversity means different code paths**, not different files.
  Each seed should trigger a different parser branch, feature, or
  format variant. Redundant seeds waste cycles.

- **Build seeds by hand when possible.** You control every byte,
  you know the structure, you can target specific code paths. Use
  the format specification and Python's struct module.

- **Minimize aggressively.** `afl-cmin` removes redundant seeds.
  `afl-tmin` shrinks individuals. Run cmin first, then tmin.
  Order matters.

- **Dictionaries are force multipliers.** Format-specific tokens
  let the fuzzer insert meaningful byte sequences instead of random
  garbage. Build them from format specs AND from reversing the target
  binary's string constants.

- **The corpus evolves.** The fuzzer grows it through coverage
  feedback. Periodically distill the grown corpus and restart.
  Each cycle starts deeper than the last.

- **Monitor coverage actively.** Watch the growth curve. When it
  plateaus, intervene — new seeds, expanded dictionary, grammar
  generation, polyglot files. Never "set and forget."

- **Cross-pollination finds deep bugs.** Polyglot files and nested
  archives trigger recursive parsing paths. ZIP containing RAR
  containing PE = three parser invocations from one seed.

- **Cold code is where the bugs hide.** Use coverage heat maps to
  find untested code. Build seeds that specifically target those
  cold regions. This is where reversing knowledge pays off.

- **Campaign cycle: Build → Fuzz → Distill → Rebuild → Fuzz.**
  Corpus design isn't a one-time task. It's continuous refinement
  for the entire campaign duration. The ammunition supply chain
  never stops.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Seed corpus** | Collection of initial input files used as starting points for mutation-based fuzzing |
| **Corpus minimization (afl-cmin)** | Process of removing redundant seeds that don't contribute unique code coverage |
| **Seed minimization (afl-tmin)** | Process of shrinking an individual seed to the smallest size that maintains its unique coverage |
| **Dictionary** | File containing format-specific tokens (magic bytes, keywords, delimiters) that the fuzzer inserts during mutation |
| **Coverage plateau** | State where the fuzzer stops discovering new basic blocks, indicating the corpus and strategy are exhausted |
| **Corpus distillation** | Full pipeline: prune redundant seeds (cmin) + minimize individuals (tmin) to produce an optimal corpus |
| **Polyglot file** | A file that is simultaneously valid in two or more formats, triggering multiple parser paths |
| **Grammar-based generation** | Creating test inputs from a formal grammar of the target format, producing structurally valid but semantically extreme files |
| **Cross-pollination** | Using seeds from one format to discover bugs in another format's parser, typically via recursive scanning |
| **Structure-aware fuzzing** | Fuzzing with a custom mutator that understands the target format's field layout and mutates fields as semantic units |
| **Coverage heat map** | Visualization showing which code regions are heavily tested (hot) vs untested (cold) in the target binary |
| **Corpus evolution** | The automatic growth of the seed corpus as coverage-guided fuzzing discovers inputs that trigger new code paths |
| **Magic bytes** | Fixed byte signature at a known offset that identifies a file's format (e.g., PK\x03\x04 for ZIP, %PDF for PDF, MZ for PE) |
| **Radamsa** | Standalone mutation tool that generates diverse file mutants without requiring target instrumentation or coverage feedback |
