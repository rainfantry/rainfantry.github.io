# Chapter 14 — Case Studies: CVEs That Changed The War

**VADER-RCE Field Manual**
**Prerequisite**: Volumes I-III
**Drill**: N/A — study and analysis

---

## Why Study Old Kills

You can build tools all day. You can fuzz for a thousand hours. But if
you don't study the kills that came before you, you're reinventing every
mistake and missing every shortcut.

Every CVE in this chapter is a LESSON. Not ancient history — a tactical
debrief. Each one shows you HOW a real vulnerability was found, WHAT made
it exploitable, and WHY it mattered. The pattern that emerges across all
of them will tell you exactly where to point your own campaign.

These are not theoretical bugs. These are bugs that gave attackers SYSTEM
shells on every Windows machine on earth. Through email. Through a
downloaded file. Through a network share that Defender decided to scan.
Zero-click. No user interaction. No authentication. Just a malformed file
landing in the right place at the right time.

Every single one of them is in mpengine.dll. Your target.

The same DLL. The same service. The same privilege level. The same attack
surface you're staring at right now in Ghidra.

Pay attention.

---

## How To Read Each Case Study

Every case study below follows the same five-phase structure:

1. **CONTEXT** — What component, what parser, what the code was supposed
   to do. You need to understand what the developer INTENDED before you
   can see what went wrong.

2. **DISCOVERY** — How the bug was found. Fuzzing? Code review? Variant
   analysis? The method matters because it tells you what works against
   this target.

3. **EXPLOITATION** — How the bug was turned from a crash into a weapon.
   The primitives used, the mitigations bypassed, the chain assembled.

4. **IMPACT** — What happened in the real world. CVSS score. Scope.
   Whether it was exploited in the wild. What got patched.

5. **LESSONS** — What you take away for YOUR campaign. What class of bug,
   what attack surface, what technique.

Read these like after-action reports. Not news articles. The goal is to
extract operational intelligence you can apply directly.

---

## Case Study 1: CVE-2021-1647 — The Off-By-One That Gave You SYSTEM

### Context

Windows Defender's mpengine.dll doesn't just scan files for known
signatures. It UNPACKS them. When a file is packed with a protector like
AsProtect — a commercial binary packer that wraps executables in layers
of anti-debugging and compression — Defender needs to get at the
underlying PE file to scan it. So mpengine.dll contains an AsProtect
unpacker.

The AsProtect unpacker has to parse the PE section table of the packed
binary. A PE file's section table describes memory regions — .text,
.data, .rdata, .rsrc — each with a virtual address, size, raw data
pointer, and various flags. The unpacker reads these sections to
understand the layout of the packed executable before extracting the
original payload.

This parsing code ran inside MsMpEng.exe, which runs as
NT AUTHORITY\SYSTEM. No sandbox. No reduced privileges. SYSTEM.

### Discovery

Google's Project Zero, led by researchers who had been systematically
auditing Defender's parser code, found this bug through targeted code
review. They were already looking at AsProtect handling — this was not
random fuzzing. They knew complex unpackers were where the bugs lived
and they went hunting.

The bug was an off-by-one error in a bounds check during section table
parsing. The code validated that a section index was less than the
maximum count:

```
if (index < section_count) {
    // process section
}
```

But the logic required `<=` (less than or equal to), or alternatively
needed an explicit check for the boundary case. The code checked `<`
but not `==`. When the index was EXACTLY equal to section_count, it
passed the check and processed one section beyond the allocated buffer.

One. Single. Section. Beyond the boundary.

### Exploitation

The section beyond the boundary was heap memory. The parser wrote
section header data into this overflow region, corrupting adjacent
heap allocations. This was a classic heap buffer overflow — controlled
data written past the end of a heap buffer.

The attack vector was beautifully simple: craft a PE file packed with
AsProtect that has a section table triggering the off-by-one. Deliver
it to the target. Email attachment. Downloaded file. Network share.
Web page. Doesn't matter — Defender scans it automatically.

When Defender's Real-Time Protection kicks in and decides to unpack
the AsProtect-protected binary, the parser processes the malformed
section table, walks one entry past the end of its buffer, and
corrupts the heap.

From heap corruption to code execution is a known path for skilled
attackers. Overwrite a function pointer. Corrupt a vtable. Hijack
a lookaside list entry. The specifics depend on the heap layout, but
the primitive — controlled out-of-bounds write to heap — is one of
the most exploitable bug classes in existence.

### Impact

**CVSS 7.8.** Remote code execution as SYSTEM. Microsoft confirmed this
was exploited in the wild before the patch was released — a genuine
zero-day that was being used by attackers against real targets.

The attack required zero user interaction. The victim didn't need to
open the file. They didn't need to click anything. The file just needed
to EXIST somewhere that Defender would scan — their Downloads folder,
an email attachment in their inbox, a file on a mounted network share.
Defender's real-time protection would scan it automatically, trigger
the AsProtect unpacker, and the bug would fire.

The fix was surgical. Microsoft added one `else` branch to handle the
boundary case that the original code missed. Literally one conditional
block. The entire CVE — the zero-day, the in-the-wild exploitation,
the emergency patch — all of it existed because a single comparison
operator was `<` instead of `<=`.

### Lessons

**The most dangerous bugs are the simplest.** This wasn't a complex
race condition. It wasn't a multi-step chain of type confusions. It
was one missing comparison operator. Off-by-one. The kind of bug you
learn about in your first week of C programming.

**Unpackers are high-value targets.** AsProtect, UPX, Themida, VMProtect
— every commercial packer that Defender supports requires an unpacker
in mpengine.dll. Each unpacker is a complex parser that must handle
adversarial input. And each one runs as SYSTEM with no sandbox.

**File delivery is trivial.** The hardest part of most exploits is
getting the payload to the target. With Defender bugs, the delivery
mechanism is built into the operating system. Email it. Drop it on a
share. Host it on a web server. The target's own security software
brings the malicious file into the vulnerable parser.

---

## Case Study 2: CVE-2021-31985 — The Full Chain From Heap Spray to SYSTEM

### Context

Same component. Same year. Same researcher group. Different bug.

This CVE hit the AsProtect unpacker code in mpengine.dll again — a
different code path in the same parser that CVE-2021-1647 lived in.
The PixiePoint research team published a complete exploitation chain,
turning a heap buffer overflow into full code execution against
Defender.

The fact that it was the same component matters. CVE-2021-1647 had
already been patched. The AsProtect unpacker had already been in the
spotlight. Microsoft had already fixed ONE bug in this code. And
there was another one sitting right next to it.

### Discovery

Variant analysis. Once CVE-2021-1647 demonstrated that the AsProtect
unpacker was vulnerable, researchers went back and audited the
surrounding code. Different function, different allocation, different
bounds check failure — but the same root cause: the AsProtect section
processing code was not properly validating buffer boundaries.

This is the power of variant analysis. When you find one bug in a
component, you don't celebrate and go home. You tear the entire
component apart looking for siblings. Bugs cluster. If the developer
made one mistake in bounds checking, they probably made two. Or five.
Or ten.

### Exploitation

The PixiePoint team published a COMPLETE exploitation chain. This is
rare and invaluable — most CVEs get a one-paragraph advisory and a
patch. This one got a full walkthrough:

**Step 1: Heap Spray.** The attacker controls the contents of the
malicious PE file being parsed. By carefully crafting the file's
contents, they can influence what data ends up on the heap before
and after the vulnerable buffer. This is heap grooming — arranging
the heap layout so that the overflow hits a useful target.

**Step 2: Out-of-Bounds Write.** The heap buffer overflow in the
AsProtect section processing writes controlled data past the end of
the allocated buffer. With heap grooming, this overwrites a specific
adjacent structure.

**Step 3: VMM Struct Corruption.** The adjacent structure they targeted
was related to Defender's internal virtual machine monitor (VMM) —
mpengine.dll contains an emulation engine that can execute code in a
sandboxed environment to observe malware behaviour. The VMM structures
control this emulation. Corrupting them gives the attacker influence
over the emulation engine's behaviour.

**Step 4: Arbitrary Read/Write.** By corrupting the VMM structures,
the attacker gained the ability to read and write arbitrary memory
addresses within the MsMpEng.exe process. This is the holy grail
of exploitation primitives — once you have arbitrary read/write, you
control the process.

**Step 5: Write Shellcode to JIT Buffer.** MsMpEng.exe has memory
regions that are both writable and executable — JIT compilation
buffers used by the emulation engine. The attacker used their
arbitrary write primitive to write shellcode directly into one of
these RWX buffers.

**Step 6: SYSTEM.** Redirect execution to the shellcode. Game over.
The shellcode runs as NT AUTHORITY\SYSTEM because MsMpEng.exe runs
as SYSTEM.

### Impact

Full remote code execution. Zero-click. SYSTEM privilege. The
published chain proved it was not just a crash — it was a weaponizable
vulnerability with a working exploitation path from bug trigger to
code execution.

The CVSS score was high, and the detailed exploitation chain meant
that anyone with the technical skill to follow the writeup could
reproduce the attack. Public full-chain exploits for SYSTEM-level
bugs don't appear every day.

### Lessons

**Same component, same class, different path.** This is the argument
for variant analysis. CVE-2021-1647 was fixed. The code was reviewed.
And CVE-2021-31985 was sitting right there in the same parser. If
you find one bug in a parser, KEEP LOOKING.

**Complex internal structures are exploitation goldmines.** The VMM
structures inside mpengine.dll gave the attacker an exploitation
path from heap corruption to arbitrary read/write. The more complex
the internal state of a process, the more options an attacker has for
turning a crash into a chain. mpengine.dll is ENORMOUSLY complex —
it contains parsers, emulators, JIT compilers, and signature engines.
That complexity is your friend.

**JIT buffers are the endgame.** If a process has RWX memory — memory
that is simultaneously writable and executable — the attacker doesn't
need to chain ROP gadgets or bypass CFG. They just write shellcode
directly into executable memory. MsMpEng.exe had JIT buffers for its
emulation engine. That's a massive exploitation enabler.

**Published chains raise the bar for defenders.** Before PixiePoint
published their chain, Microsoft could argue that Defender heap
overflows were "theoretical" risks. After the chain was public, that
argument died. A full chain from trigger to SYSTEM forces the vendor
to take the bug class seriously.

---

## Case Study 3: CVE-2018-0986 — The RAR Parser That Scored 9.8

### Context

mpengine.dll doesn't just parse PE files. It parses EVERYTHING. ZIP
archives, RAR archives, 7z archives, CAB files, ISO images, VHD
containers, Office documents, PDFs, RTF files — the list goes on for
pages. Every file format that could conceivably contain malware, Defender
has a parser for it.

The RAR archive format is particularly interesting. RAR is a proprietary
format with a complex specification — variable-length headers, multiple
compression algorithms, solid archives where files are compressed
together, multi-volume archives split across files, encrypted archives
with different encryption modes. Parsing all of this correctly is hard.
Parsing it securely against adversarial input is VERY hard.

In 2018, a memory corruption vulnerability was found in mpengine.dll's
RAR extraction logic.

### Discovery

The specifics of the discovery method for this CVE point to a
combination of fuzzing and code analysis. RAR parsing code is a prime
fuzzing target — the format is complex, the parser is large, and there
are thousands of potential edge cases in header parsing, decompression,
and extraction.

Archive format fuzzers work by taking valid RAR files and mutating
them — flipping bits in headers, truncating compressed data, corrupting
length fields, nesting archives inside archives. The mutations that
reach deep into the parsing code without being rejected by initial
format checks are the ones that find bugs.

### Exploitation

The vulnerability was a memory corruption bug in the RAR extraction
logic. The specific corruption mechanism allowed an attacker to craft
a RAR file that, when parsed by Defender, would corrupt memory in the
MsMpEng.exe process.

The attack vector is identical to the AsProtect bugs: deliver the
malicious RAR file to the target via any channel that triggers a
Defender scan. Email attachment with a .rar extension. Downloaded
file. File on a network share. Zip the RAR inside another archive.
Embed it in a document. The delivery options are endless because
Defender recursively unpacks containers — it will open a ZIP to find
a RAR to find a PE, scanning at every level.

Recursive unpacking means the attack surface MULTIPLIES. You don't
just get one shot at hitting a parser bug. The file passes through
the ZIP parser, THEN the RAR parser, THEN the PE parser. Each layer
is a separate attack surface. Each layer runs the same SYSTEM-privilege
code.

### Impact

**CVSS 9.8.** That's not a typo. Nine point eight out of ten. This
is about as severe as a vulnerability gets without being rated a
perfect 10.

The scoring breaks down:
- **Attack Vector**: Network (remote, no physical access needed)
- **Attack Complexity**: Low (no special conditions)
- **Privileges Required**: None (no authentication)
- **User Interaction**: None (zero-click)
- **Scope**: Changed (breaks out of the component's security scope)
- **Confidentiality**: High
- **Integrity**: High
- **Availability**: High

Remote. No auth. No user interaction. Full compromise of
confidentiality, integrity, and availability. As SYSTEM.

That's a 9.8. The only reason it's not a 10.0 is the specific
scoring mechanics of CVSS v3 — practically speaking, this is as
bad as it gets.

### Lessons

**Archive parsers are goldmines.** ZIP, RAR, 7z, CAB, ISO, VHD, VHDX,
WIM, TAR, GZIP, BZIP2, XZ, LZ4, ZSTD — mpengine.dll has parsers for
ALL of these. Each one is a separate attack surface. Each one has its
own allocation patterns, its own bounds checks, its own decompression
logic. The RAR parser gave us a 9.8. What does the ISO parser give?
The VHD parser? The CAB parser?

**CVSS 9.8 means the industry agrees this is catastrophic.** When your
target consistently produces vulnerabilities that score in the 9.x
range, you're not chasing minor bugs. You're working on one of the
most dangerous attack surfaces in all of Windows. That's validation of
your target selection.

**Recursive unpacking multiplies attack surface.** Defender doesn't
just parse the outer container. It parses every layer. A RAR inside
a ZIP inside an ISO hits THREE different parsers. Each layer is a
chance to trigger a bug. Nest your malformed files inside valid
containers and you multiply your chances.

**Format complexity correlates with bug density.** RAR is more complex
than ZIP. RAR had the 9.8. Simpler formats with shorter parsers are
less likely to contain bugs — but they're also less likely to have
been fuzzed. There's a sweet spot between "complex enough to have
bugs" and "obscure enough that nobody's fuzzed it yet."

---

## Case Study 4: CVE-2026-45584 — The One They're Exploiting RIGHT NOW

### Context

This one is not history. This is happening now.

CVE-2026-45584 was disclosed in May 2026. It is a heap buffer overflow
in mpengine.dll. It was added to CISA's Known Exploited Vulnerabilities
(KEV) catalogue, which means the US government has confirmed it is being
actively exploited by threat actors in the wild.

Not "could theoretically be exploited." IS being exploited. Right now.
Against real targets. By real attackers.

Fixed in engine version 1.1.26040.8.

### Discovery

The discovery details are limited — this is a fresh CVE and the full
technical writeup hasn't been published. What we know:

- It's a heap buffer overflow (same bug class as CVE-2021-1647,
  CVE-2021-31985, and countless others in mpengine.dll)
- It was significant enough to warrant immediate patching and KEV
  listing
- Attackers found it before (or around the same time as) defenders

Whether it was found through fuzzing, code review, or reverse
engineering the patch of a previous CVE — the result is the same.
Another heap overflow. Another SYSTEM-level bug. Another emergency
patch.

### Exploitation

The specifics of the in-the-wild exploitation haven't been fully
disclosed, but the bug class tells us what the chain looks like:

1. Craft a file that triggers the heap buffer overflow in mpengine.dll
2. Deliver the file to the target (email, web, network share, USB)
3. Defender's real-time protection scans the file automatically
4. The heap overflow fires in MsMpEng.exe (running as SYSTEM)
5. Heap corruption is leveraged into code execution using whatever
   exploitation technique the attacker has in their toolbox

The attackers who are using this in the wild have a working exploit.
They've solved the heap grooming. They've dealt with ASLR. They've
built a chain that works reliably enough to deploy operationally.

### Impact

**CVSS 8.1.** High severity. Actively exploited. CISA KEV listed.

The CVSS score is slightly lower than CVE-2018-0986's 9.8, likely
due to specific scoring factors — perhaps higher attack complexity
or specific preconditions. But "actively exploited" trumps any CVSS
number. A 7.0 that's being used in the wild is more dangerous than
a 9.8 that's theoretical.

Government agencies were ordered to patch immediately. Enterprise
security teams scrambled to verify their Defender engine versions.
And somewhere, the attackers moved to their next zero-day.

### Lessons

**mpengine.dll is STILL producing heap overflows in 2026.** This is
the most important takeaway in this entire chapter. The bug class
that gave us CVE-2021-1647 (off-by-one in AsProtect), CVE-2021-31985
(heap overflow in AsProtect), and CVE-2018-0986 (RAR parser) is still
alive and producing new CVEs five to eight years later.

The attack surface has not been cleaned up. Microsoft has not rewritten
the parser code in a memory-safe language. They have not added
comprehensive bounds checking. They have not sandboxed the parser
effectively enough to make these bugs unexploitable. They patch them
one at a time as they're found.

**There are more where this came from.** If the same bug class keeps
appearing in the same DLL year after year, the probability of more
undiscovered instances is high. mpengine.dll is over 100MB of native
C/C++ code containing parsers for hundreds of file formats. The idea
that all heap overflows have been found and fixed is delusional.

**Active exploitation means the barrier to weaponisation is known.**
Someone out there has a working heap overflow exploit for mpengine.dll
in 2026. They've solved the modern mitigations. They've dealt with
CFG, ASLR, and whatever heap protections MsMpEng.exe has. The
exploitation techniques work against current builds. That means the
problem is solvable.

---

## Case Study 5: Tavis Ormandy's NScript Campaign — The Interpreter Inside the Parser

### Context

In 2017, Tavis Ormandy of Google's Project Zero went looking for bugs
in Windows Defender. What he found was not just a bug — it was an
entire attack surface that nobody had examined.

mpengine.dll contained a full JavaScript interpreter called NScript.

Read that again. The malware scanning engine — the DLL that parses
untrusted files — contained a JAVASCRIPT INTERPRETER. It was there
so that Defender could analyse JavaScript-based malware by actually
executing (emulating) the JavaScript code in a controlled environment.

The theory was sound: if malware uses JavaScript for its payload or
dropper logic, understanding the JavaScript requires executing it.
Static signatures can't catch obfuscated JavaScript that decodes
itself at runtime. So Microsoft built an interpreter into the engine.

The practice was catastrophic.

### Discovery

Tavis didn't find NScript by accident. He was systematically auditing
mpengine.dll — specifically looking at what the engine does with
different file types. When he discovered that the engine contained
a JavaScript interpreter, he knew immediately what he was looking at.

An interpreter is the MOST complex type of code you can put in a
parser. It has to handle:
- Lexing and tokenisation
- Parsing and AST construction
- Type system and type coercion
- Memory management (garbage collection or manual)
- Built-in functions and standard library
- Object model and prototype chain
- String handling and encoding
- Regular expressions (another interpreter INSIDE the interpreter)
- Error handling and exception propagation

Every single one of those subsystems is a potential bug source. And
NScript had them all.

Worse: NScript ran WITHOUT sandboxing. No separate process. No
reduced privileges. No restricted token. It ran directly inside
MsMpEng.exe with full SYSTEM privileges. And it had no ASLR — the
module was loaded at a predictable address.

Tavis found a type confusion vulnerability in the NScript interpreter.
Type confusions occur when the interpreter treats an object of one
type as a different type — for example, treating a string object as
an array object, reading fields at the wrong offsets, and accessing
memory that doesn't belong to the object. In a JavaScript interpreter,
type confusions are endemic because JavaScript's dynamic type system
requires constant type checking and coercion.

### Exploitation

The exploitation was elegant in its simplicity:

1. **Craft a JavaScript payload** that triggers the type confusion in
   NScript. This isn't complex — JavaScript type confusions are well
   understood and the techniques for triggering them are documented
   in the browser exploitation literature.

2. **Embed the JavaScript in a file** that Defender will scan. An HTML
   file. An email with inline JavaScript. A PDF with embedded JavaScript.
   Any container that holds JavaScript.

3. **Deliver the file.** Email it. Host it on a web page. Drop it on
   a share. The usual channels.

4. **Defender scans the file**, detects the JavaScript, and passes it
   to NScript for analysis.

5. **NScript executes the JavaScript** and hits the type confusion.
   The interpreter processes the malformed type operations and
   corrupts its internal state.

6. **No ASLR means predictable addresses.** NScript's code was at a
   known location in memory. The attacker doesn't need an info leak —
   they already know where everything is.

7. **No sandbox means SYSTEM.** The code execution happens directly
   in MsMpEng.exe. No sandbox escape needed. You're already SYSTEM.

8. **No CFG means easy control flow hijacking.** Control Flow Guard
   wasn't protecting NScript's function pointers. Overwrite a function
   pointer and redirect execution anywhere.

The combination of no ASLR, no sandbox, and no CFG meant that
exploiting NScript was EASIER than exploiting a modern web browser.
In 2017, Chrome had multiple layers of sandboxing, full ASLR, CFG,
and site isolation. NScript had none of that. The antivirus engine
was less secure than the browser it was supposed to protect.

### Impact

Remote code execution as SYSTEM. Zero-click. Via email.

Send someone a message with JavaScript in it. Their antivirus scans
it. The scan executes the JavaScript in an unprotected interpreter.
The attacker gets SYSTEM on the victim's machine. The victim never
opened the email. Never clicked a link. Never ran an attachment.
Defender did the exploitation FOR the attacker.

The irony was devastating. The security product — the tool specifically
designed to PROTECT against malicious code — was the attack vector.
Users who had Defender enabled were MORE vulnerable than users who had
it disabled. Installing the security product INCREASED the attack
surface.

Tavis's disclosure sparked a genuine crisis at Microsoft. This wasn't
a single bug — it was an architectural problem. The entire concept of
running a JavaScript interpreter inside an unsandboxed SYSTEM-level
process was the vulnerability.

### Aftermath

Microsoft responded with multiple layers of remediation:

1. **Sandboxing.** MsMpEng.exe gained sandbox support. The process
   could be run with reduced privileges rather than full SYSTEM.
   (Though enabling the sandbox was opt-in for a long time.)

2. **ASLR enforcement.** NScript and other internal components got
   ASLR support, removing the predictable address advantage.

3. **CFG deployment.** Control Flow Guard was applied to protect
   function pointers from hijacking.

4. **NScript deprecation.** Over time, Microsoft reduced NScript's
   role and eventually deprecated it, moving JavaScript analysis
   to better-protected environments.

These mitigations didn't happen overnight. And they didn't eliminate
the attack surface — they just raised the exploitation bar. The
parsers still run. The code is still native C/C++. The bugs are
still there. They're just harder to exploit.

### Lessons

**When you find an interpreter inside a parser, you've found a
treasure vault.** Interpreters are the most complex code in any
system. They have the widest internal attack surface — types, memory
management, string handling, object models. Finding an interpreter
embedded inside a privileged process is the equivalent of finding
an unguarded vault in a bank.

**Missing mitigations multiply severity.** NScript without ASLR was
like a door without a lock. The type confusion was serious. The
type confusion PLUS no ASLR PLUS no sandbox PLUS no CFG was
catastrophic. When you're assessing a target, check what mitigations
are present. Absent mitigations don't just mean "easier to exploit"
— they mean "trivially exploitable."

**The defender IS the attack surface.** This is the philosophical
foundation of the entire VADER-RCE campaign. Security products that
parse untrusted input are attack surfaces. Antivirus that executes
untrusted code is an attack vector. The tool meant to protect the
system becomes the tool used to compromise it. This inversion is not
a flaw in the concept of antivirus — it's an inherent tension in any
security product that must UNDERSTAND malicious input to detect it.

**Type confusions in interpreters are systematic.** This wasn't a
one-off bug. JavaScript interpreters have produced hundreds of type
confusion CVEs in browsers (V8, SpiderMonkey, JavaScriptCore). The
bug class is inherent to the architecture of dynamic type systems.
If you find another interpreter inside mpengine.dll (or inside ANY
privileged parser), type confusion is your first line of attack.

---

## Pattern Analysis — What All These CVEs Have In Common

Stop looking at individual bugs. Look at the PATTERN.

### Common Thread 1: File Format Parsers

Every single CVE in this chapter is a bug in a file format parser:

| CVE | Parser |
|-----|--------|
| CVE-2021-1647 | AsProtect PE unpacker |
| CVE-2021-31985 | AsProtect PE unpacker |
| CVE-2018-0986 | RAR archive extractor |
| CVE-2026-45584 | Undisclosed (heap overflow) |
| NScript (2017) | JavaScript interpreter/analyser |

Parsers. Parsers. Parsers. The core scanning logic — the signature
matching engine — is not where the bugs are. The bugs are in the
code that UNPACKS, DECOMPRESSES, and INTERPRETS file contents.

### Common Thread 2: Heap Memory Corruption

| CVE | Bug Class |
|-----|-----------|
| CVE-2021-1647 | Heap buffer overflow (off-by-one) |
| CVE-2021-31985 | Heap buffer overflow |
| CVE-2018-0986 | Memory corruption (heap) |
| CVE-2026-45584 | Heap buffer overflow |
| NScript (2017) | Type confusion (heap object corruption) |

Every single one is heap-class memory corruption. Not stack overflows.
Not integer overflows (though integers may contribute to the root
cause). Not logic bugs. Heap corruption.

This is because parser code is fundamentally about dynamic memory:
allocate a buffer based on a header field, read data into it, process
the data, allocate more buffers based on the processed data. Every
step involves the heap. Every step is an opportunity for the size
calculation to be wrong, for the bounds check to be missing, for the
type to be confused.

### Common Thread 3: Remote Trigger Via File Delivery

| CVE | Trigger |
|-----|---------|
| CVE-2021-1647 | Malformed PE file |
| CVE-2021-31985 | Malformed PE file |
| CVE-2018-0986 | Malformed RAR archive |
| CVE-2026-45584 | Malformed file (specific format undisclosed) |
| NScript (2017) | JavaScript in any container |

All remotely triggerable. No authentication required. No user
interaction required. Just deliver a file — email, web download,
network share, USB drive, cloud sync. Defender's real-time
protection does the rest.

### Common Thread 4: SYSTEM Privilege

MsMpEng.exe runs as NT AUTHORITY\SYSTEM. Every bug in mpengine.dll
is a potential SYSTEM-level compromise. Not user-level. Not admin.
SYSTEM — the highest privilege level on a Windows machine.

This hasn't changed. MsMpEng.exe still runs as SYSTEM in 2026.
The sandbox was added as an optional layer, but the base process
privilege hasn't been downgraded.

### Common Thread 5: Discoverable Via Known Methods

| CVE | Discovery Method |
|-----|-----------------|
| CVE-2021-1647 | Targeted code review |
| CVE-2021-31985 | Variant analysis |
| CVE-2018-0986 | Fuzzing + code review |
| CVE-2026-45584 | Unknown (likely fuzzing or reversing) |
| NScript (2017) | Targeted code review |

No exotic techniques. No zero-day markets. No nation-state resources
required. Code review and fuzzing. The two methods you're learning
in this manual.

---

## What This Means For Your Campaign

The pattern is clear. Here's how to apply it.

### Target The Less-Fuzzed Parsers

The AsProtect unpacker has been hammered. RAR parsing has been
audited. JavaScript analysis was deprecated. But mpengine.dll
adds new parser code regularly. Every time Microsoft adds support
for a new file format, container type, or packer, they add new
attack surface.

Focus your fuzzing on:
- **ISO image parsing** — ISO 9660 and UDF format handling
- **VHD/VHDX container parsing** — Virtual hard disk format
- **CAB archive parsing** — Windows Cabinet format, complex internals
- **WIM image parsing** — Windows Imaging Format
- **Modern container formats** — AppX, MSIX, OneNote, newer Office
  container variants
- **Newer packer support** — whatever packers have been added recently

The more recently a parser was added, the less time it's had to be
audited. The more obscure the format, the less likely a researcher
has fuzzed it. Find the parsers that nobody's looking at.

### Heap Overflow Is Your Primary Bug Class

Four out of five case studies are heap overflows. This is not
coincidence — it's a structural property of parser code. Your
fuzzing harness should be optimised for detecting heap corruption:

- **Use AddressSanitizer (ASan)** in your harness builds. ASan
  detects out-of-bounds heap accesses immediately, not just when
  they happen to cause a visible crash.
- **Use HeapAlloc/HeapFree hooks** to track allocation patterns
  and detect overflows that ASan might miss.
- **Focus your seed corpus on files with unusual size fields.**
  Heap overflows in parsers almost always come from a mismatch
  between a size field read from the file and the actual data
  available. Mutating size fields is your highest-yield strategy.
- **Monitor allocation sizes.** When your fuzzer triggers a crash,
  check the allocation size vs. the write offset. If the write
  goes past the end of the allocation, you've got a heap overflow.

### Don't Just Fuzz The Top-Level Parser

CVE-2021-1647 and CVE-2021-31985 were not in the top-level PE
parser. They were in the ASPROTECT UNPACKER — a sub-parser that
only fires when the PE file is detected as AsProtect-packed.

This means your fuzzer needs to reach the sub-parsers:

- **Generate seed files that trigger unpacker code paths.** Take a
  legitimate PE file, pack it with AsProtect/UPX/Themida, and use
  THAT as your fuzzing seed. The mutations will then test the
  unpacker, not just the outer PE parser.
- **Layer your test files.** Put a malformed PE inside a ZIP inside
  an ISO. This forces Defender to recurse through three parsers,
  tripling your effective attack surface per test case.
- **Trace code coverage through sub-parsers.** If your fuzzer
  reports coverage, make sure it's showing coverage of the
  unpacker and decompressor code, not just the format detector.

### Every New Format Is New Attack Surface

When Microsoft adds support for scanning a new file format in
Defender, they're writing a new parser. That parser handles untrusted
input. It runs as SYSTEM. It's new code that hasn't been fuzzed by
anyone except maybe Microsoft's own SDL team.

Monitor Defender update notes for new format support. When a new
format appears, build seed files for it and start fuzzing immediately.
You'll be among the first to test that code path.

### The Dollar Value Of A Defender RCE

Consider what these bugs are worth:

- **Bug bounty**: Microsoft's Security Response Center pays up to
  $100,000 for critical Windows vulnerabilities. Defender RCEs
  with working exploits are at the top of that scale.
- **ZDI (Trend Micro)**: Zero Day Initiative purchases exploits
  and reports for disclosure. Defender RCEs command premium prices.
- **MSRC acknowledgment**: Your name in the Security Update Guide.
  A line on your CV that says you found a SYSTEM-level RCE in
  Windows Defender.

This is not hypothetical value. The researchers behind the CVEs in
this chapter built careers on this work. Project Zero researchers,
PixiePoint analysts, independent security consultants — they all
parlayed Defender research into professional credibility.

Responsible disclosure is the path. Find the bug, report it through
MSRC, get credited, get paid. The skills you build doing this are
the same skills used offensively — you just choose the ethical
deployment.

---

## The Strategic Implications

### mpengine.dll Is A Permanent Target

This DLL has been producing critical CVEs since at least 2017 (and
likely earlier). In 2026, it's still producing them. The architecture
of the problem — native C/C++ code parsing untrusted input at SYSTEM
privilege — has not changed.

Microsoft has added mitigations (sandbox, ASLR, CFG). They have not
SOLVED the problem. Solving the problem would require:

- Rewriting parser code in a memory-safe language (Rust, etc.)
- Running all parsing in a fully sandboxed process with minimal
  privileges
- Reducing the number of supported formats to reduce attack surface

None of these have been done comprehensively. Until they are,
mpengine.dll will keep producing CVEs.

### The Bug Density Is Too High For Microsoft To Win

mpengine.dll supports hundreds of file formats. Each format requires
a parser. Each parser is written in C/C++. Each parser handles
untrusted input. The combinatorial explosion of formats × edge cases
× code paths means that bugs will always exist faster than they can
be found and fixed.

Microsoft can patch individual bugs. They cannot patch the
architecture. As long as the architecture remains "native code
parsing adversarial input at maximum privilege," the bugs will
continue.

### Your Competitive Advantage Is Automation

The researchers who found the CVEs in this chapter used some
combination of:
- Manual code review (expensive in time, high in precision)
- Targeted fuzzing (automated, scales horizontally)
- Variant analysis (finding siblings of known bugs)

You can do all three. Your harness provides the fuzzing. Ghidra
provides the code review capability. And the CVE database provides
the known bugs for variant analysis.

The researchers who found these bugs didn't have better tools than
you have. They had domain knowledge, persistence, and a systematic
approach. You're building the same thing.

---

## Summary — Key Takeaways

- **CVE-2021-1647**: Off-by-one in AsProtect unpacker. One missing
  comparison operator. Zero-day exploited in the wild. Fixed with
  one `else` branch. The simplest bugs are the deadliest.

- **CVE-2021-31985**: Full exploitation chain published. Heap spray →
  OOB write → VMM struct corruption → arbitrary R/W → JIT shellcode →
  SYSTEM. Same component as 1647, different code path. Variant
  analysis finds siblings.

- **CVE-2018-0986**: RAR parser memory corruption. CVSS 9.8. Archive
  parsers are goldmines — every format is a separate attack surface.

- **CVE-2026-45584**: Actively exploited in 2026. Heap overflow in
  mpengine.dll. The same bug class, the same DLL, still producing
  CVEs. The attack surface is not exhausted.

- **NScript Campaign**: Full JavaScript interpreter inside the scan
  engine. No ASLR, no sandbox, no CFG. Interpreters inside parsers
  are treasure vaults. The defender IS the attack surface.

- **The pattern**: File format parsers → heap corruption → remote
  trigger → SYSTEM. This pattern has held for nearly a decade.

- **Your focus**: Less-fuzzed parsers, heap overflow detection,
  sub-parser coverage, new format support monitoring.

- **mpengine.dll will keep producing CVEs** until Microsoft rewrites
  it in a memory-safe language or fully sandboxes parsing. Neither
  has happened. The campaign continues.

- **Responsible disclosure** is the deployment model. MSRC reports,
  bug bounty payouts, professional credibility. The same skills,
  the ethical path.

---

*Volume IV continues: Chapter 15 — Building Your Own Lab*
