# Chapter 14 — Reverse Engineering: Ghidra, x64dbg & Disassembly

**VADER-RCE Field Manual**
**Prerequisite**: Ch06 Crash Triage, Ch07 Exploit Primitives, Ch08 Target Reversing
**Drill**: DRILLS/14_reverse_engineering/

---

## Why You Need This

The fuzzer crashed something. You have a binary. You need to know WHY
it crashed, WHERE the bug is, and HOW bad it is.

Or: the IR team handed you a suspicious DLL. No source code. No symbols.
Just a blob of bytes claiming to be a Windows service. Your job is to
read it like a book.

Reverse engineering is the skill that sits behind every other skill in
this manual. Crash triage depends on it — you need to read disassembly to
understand the fault context. Exploit development depends on it — you
need to understand the code to build a reliable payload. Implant development
depends on it — you need to understand what defenders detect before you
can evade them.

Two tools. One workflow. Everything else is application.

**Ghidra**: static analysis — read the binary without running it. Decompile,
annotate, map the code structure, understand what it does conceptually.

**x64dbg**: dynamic analysis — run the binary under a debugger. Watch it
execute, set breakpoints, inspect state at specific moments, observe
runtime behaviour that static analysis can't reveal (self-modifying code,
anti-debug tricks, runtime decryption).

Both tools are necessary. Neither is sufficient alone. Know when to use which.

```
STATIC ANALYSIS (Ghidra)        DYNAMIC ANALYSIS (x64dbg)
─────────────────────────────   ─────────────────────────────
No code runs. Safe.             Code actually executes. Contained.
Full binary visible.            See runtime state: registers, memory.
Cross-references across binary. Defeats runtime decryption.
Fast for large binaries.        Required for anti-debug analysis.
Misses runtime behaviour.       Limited to what you run.
Packed code = unreadable.       Can unpack and dump packed code.
```

---

## Section 1 — Static Analysis Workflow

Static analysis is your first pass. Before you run anything, understand
what you're dealing with. Identify the format, identify key functions,
build a map.

### PE File Structure

Every Windows binary (EXE, DLL, SYS) is a PE (Portable Executable) file.
The PE format describes how the binary loads into memory. Understanding
it tells you what a binary can do before you read a single instruction.

```
PE FILE STRUCTURE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MZ Header (DOS stub):
  Offset 0x00: 4d 5a ("MZ") ← magic bytes identifying a PE file
  Offset 0x3c: e_lfanew     ← offset to PE header (typically 0x80 or 0x100)

PE Header (IMAGE_NT_HEADERS):
  Signature: 50 45 00 00 ("PE\0\0")
  IMAGE_FILE_HEADER: machine type, section count, timestamp, characteristics
  IMAGE_OPTIONAL_HEADER:
    Magic: 0x10b (PE32) or 0x20b (PE32+ / 64-bit)
    AddressOfEntryPoint  ← where execution begins (RVA)
    ImageBase            ← preferred load address (0x400000 for EXEs, 0x10000000 for DLLs)
    SizeOfImage          ← total size in memory
    Subsystem            ← 2=GUI, 3=console, 1=native (driver)
    DllCharacteristics   ← flags: ASLR, NX, CFG, etc.

Section Table (IMAGE_SECTION_HEADER × N):
  .text    EXECUTE|READ       ← code
  .data    READ|WRITE          ← initialised data
  .rdata   READ                ← read-only data (strings, constants, import table)
  .bss     READ|WRITE          ← uninitialised data
  .rsrc    READ                ← resources (icons, manifests, embedded files)
  .reloc   READ                ← relocation table (for DLLs)

Import Table (IMAGE_IMPORT_DESCRIPTOR):
  Located in .rdata
  Lists DLLs the binary imports from
  Lists function names/ordinals from each DLL
  → This is your first behavioural fingerprint

Export Table (IMAGE_EXPORT_DIRECTORY):
  For DLLs: lists functions the DLL exposes
  Name, ordinal, RVA for each exported function
```

**Quick PE analysis before touching Ghidra:**

```
# Windows built-in:
dumpbin /headers malware.dll
dumpbin /imports malware.dll
dumpbin /exports malware.dll

# PE-bear (GUI, free): https://github.com/hasherezade/pe-bear
# CFF Explorer (GUI, free): https://ntcore.com/?page_id=388

# Check DllCharacteristics flags (critical for exploit dev):
# 0x0020 = HIGH_ENTROPY_VA (64-bit ASLR)
# 0x0040 = DYNAMIC_BASE    (ASLR enabled)
# 0x0100 = NX_COMPAT       (DEP enabled)
# 0x4000 = GUARD_CF        (Control Flow Guard)
# 0x0080 = FORCE_INTEGRITY (code signing required)
```

**The import table tells you what a binary does before you read a line:**

```
IMPORT TABLE QUICK TRIAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Networking capabilities:
  ws2_32.dll → WinSock (TCP/UDP network)
  winhttp.dll / wininet.dll → HTTP/S
  dnsapi.dll → DNS resolution

Privilege / token manipulation:
  advapi32.dll → OpenProcessToken, AdjustTokenPrivileges, LogonUser

Process injection:
  kernel32.dll → VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
              → OpenProcess (with PROCESS_ALL_ACCESS)

Registry:
  advapi32.dll → RegCreateKeyEx, RegSetValueEx, RegOpenKeyEx

Credential access:
  samlib.dll, lsasrv.dll → SAM/LSA credential functions (Mimikatz territory)
  vaultcli.dll → Windows Credential Vault

Shellcode / self-modification:
  kernel32.dll → VirtualProtect (changing memory permissions at runtime)
  ntdll.dll → NtAllocateVirtualMemory, NtProtectVirtualMemory (direct syscalls)

Anti-analysis:
  kernel32.dll → IsDebuggerPresent, CheckRemoteDebuggerPresent
  ntdll.dll → NtQueryInformationProcess
```

### Strings Analysis (Pre-Ghidra)

Before opening Ghidra, run strings. It's the fastest recon you have.

```
# Extract ASCII and Unicode strings:
strings -a -n 6 target.exe > strings_ascii.txt
strings -a -n 6 -e l target.exe > strings_unicode.txt

# Hunt for indicators:
grep -iE "https?://|\.onion|\.ru|\.cn" strings_ascii.txt
grep -iE "cmd\.exe|powershell|wscript|mshta" strings_ascii.txt
grep -iE "password|passwd|secret|token|apikey|credential" strings_unicode.txt
grep -iE "HKEY|CurrentVersion\\\\Run|AppInit" strings_ascii.txt
grep -iE "VirtualAlloc|CreateRemoteThread|WriteProcess" strings_ascii.txt

# If NO readable strings — packed or encrypted binary. Go dynamic first.
# If MANY readable strings — unobfuscated, static analysis will be productive.
```

---

## Section 2 — Ghidra Workflow

Ghidra is NSA's open-source reverse engineering framework. Free.
Better decompiler than IDA Free. Used by NSA researchers for years
before release. Use it.

```
# Download: https://ghidra-sre.org/
# Requires Java 17+: https://adoptium.net/

# Launch:
# Windows: ghidraRun.bat
# Linux: ./ghidraRun

# Create a new project, import the binary, accept defaults
# Then: CodeBrowser window opens → Analysis → Auto Analyze → run it
# Wait for analysis to complete (symbol resolution, function detection,
# data type propagation, call graph construction)
```

### Import and Initial Analysis

```
GHIDRA ANALYSIS STEPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. File → Import File → select binary
   Format: Portable Executable (PE)
   Architecture: auto-detected (x86/x64)

2. Analysis → Auto Analyze
   Enable all options, especially:
   - GCC Exception Handlers
   - Shared Return Calls
   - Non-Returning Functions
   - Stack Analysis
   - Decompiler Parameter ID

3. After analysis: Window → Symbol Tree
   - Functions listed by discovered name
   - Imports listed under "Imports"
   - Exports under "Exports"

4. Check the Imports list first:
   - Every imported function is a possible hook point
   - Interesting imports: see import table triage above
```

### Navigation and Disassembly View

```
GHIDRA KEYBOARD SHORTCUTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

G           → Go to address (type RVA or VA)
L           → Label/rename current item
F           → Find (search for string, bytes, or pattern)
Ctrl+F      → Find in decompiler
Right-click → References → Show References (show cross-references)
X           → Cross-references TO current item
Ctrl+I      → Import comment dialog
Ctrl+E      → Edit comment at current location
P           → Create function at current address
U           → Undefined (un-define current item)
```

### Decompiler View

The decompiler converts disassembly to approximate C code. Not perfect.
Not source code. But FAR faster to read than raw assembly for logic
comprehension.

```
# Open decompiler: Window → Decompiler
# Or: double-click a function name

# What the decompiler produces (example):
void FUN_00401234(LPVOID lpParam)
{
  HANDLE hFile;
  DWORD dwBytesWritten;
  
  hFile = CreateFileA("C:\\Users\\Public\\payload.exe",
                       0x40000000,   // GENERIC_WRITE
                       0,            // no sharing
                       NULL,
                       2,            // CREATE_ALWAYS
                       0x80,         // FILE_ATTRIBUTE_NORMAL
                       NULL);
  WriteFile(hFile, &DAT_00405000, 0x4800, &dwBytesWritten, NULL);
  CloseHandle(hFile);
  // ...
  CreateProcessA(NULL, "C:\\Users\\Public\\payload.exe", ...);
  return;
}
```

That's a dropper. It writes embedded data to disk and executes it.
`DAT_00405000` is the embedded payload. Go to that address. Mark it
as the next thing to analyse.

**Rename aggressively:**

```
# Bad name (Ghidra default):   FUN_00401234
# After you understand it:     drop_and_execute_payload

# Rename: click function name → L → type new name → Enter
# Retype parameters: right-click parameter → Retype → enter type

# Add comments throughout:
# → right-click address → Comments → Set Pre Comment
```

The more you rename and annotate, the faster the next function becomes
readable. Context propagates. Once you rename one struct, Ghidra shows
that name everywhere that struct is used.

### Function Call Graphs

```
# View call graph of a function:
# Right-click function → References → Show References To
# Or: Window → Function Call Graph

# The call graph answers:
# - What calls this function? (callers)
# - What does this function call? (callees)
# - Where is this function called in the chain?
```

Call graphs reveal the control flow architecture. Find `main()` or the
DLL entry point (`DllMain`). Walk forward through the call graph. Each
function you trace adds to your understanding of the whole binary.

### Cross-References

```
# Find all places a string or address is used:
# Click on the string or address
# Press X (or right-click → References → Show References To)

# Example:
# You find the string "C2_DOMAIN_HERE" in .rdata at 0x00407890
# Press X → list of all instructions that reference 0x00407890
# Navigate to each → understand how the C2 domain is used
```

Cross-references are the primary way you trace data flow. You find
a suspicious string, find where it's used, find the function using it,
understand what that function does.

---

## Section 3 — x64dbg Workflow

x64dbg is the standard debugger for Windows malware analysis. Free,
open source, plugin-rich. Better than OllyDbg. Comparable to WinDbg
for user-mode analysis but more accessible.

```
# Download: https://x64dbg.com/
# Two binaries: x32dbg (32-bit) and x64dbg (64-bit)
# Use x64dbg for 64-bit targets, x32dbg for 32-bit

# Plugins to install immediately:
# ScyllaHide (anti-anti-debug): https://github.com/x64dbg/ScyllaHide
# xAnalyzer: automatic analysis annotations
# Ret-Sync: Ghidra-x64dbg synchronisation
```

### Loading a Target

```
LOAD METHODS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Load fresh process:
  File → Open → select EXE
  x64dbg breaks at the entry point automatically

Attach to running process:
  File → Attach → select from list
  x64dbg breaks at current execution point
  USE THIS: when the target is already running and you want to inspect live state

Restart with command-line arguments:
  File → Open → EXE → then set arguments in bottom bar before running
```

### Breakpoints

```
BREAKPOINT TYPES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Software Breakpoint (INT3, 0xCC):
  F2 at an instruction → sets INT3 breakpoint
  When RIP hits the address, execution breaks
  VISIBLE: modifies byte at address. Some anti-debug checks detect INT3 patches.
  bp <address> (command bar syntax)
  bp <module.function> (breaks when function is called)

Hardware Breakpoint (DR0-DR3):
  Right-click instruction → Breakpoint → Hardware → Execute
  Uses debug registers — does NOT modify code bytes
  INVISIBLE to most anti-debug checks (no byte modification)
  Only 4 at a time
  bph <address> x (hardware execute breakpoint)
  bph <address> rw 4 (hardware read/write on 4-byte region)

Memory Breakpoint:
  Right-click in memory dump → Set Memory Breakpoint
  Breaks when the memory range is accessed (read/write/execute)
  Used to catch when specific data is accessed or modified
```

### Stepping Controls

```
STEP CONTROLS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

F8    Step Over       — execute current instruction; if it's a CALL,
                        execute the ENTIRE called function and stop after it
                        Use this for: library calls you trust (WinAPI)

F7    Step Into       — execute current instruction; if it's a CALL,
                        enter the called function and stop at first instruction
                        Use this for: suspicious functions you want to trace inside

F4    Run to cursor   — run until the selected address, then break
                        Fast way to get to a specific instruction

F9    Run             — continue execution until next breakpoint
                        Use this to let the program run between breakpoints

Shift+F9  Step past exception — when an exception fires, step past it
                                  without the debugger catching it
                                  Needed for anti-debug tricks that throw
                                  exceptions intentionally
```

### Register and Memory Inspection

```
# Registers visible in top-right panel:
# RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, RIP — general purpose
# RFLAGS — ZF (zero flag), CF (carry), SF (sign), OF (overflow)
#           used by conditional jump instructions (JE, JNE, JG, etc.)

# Memory inspection:
# Memory Map tab — shows all virtual memory regions (similar to VAD)
# Go to memory: Ctrl+G → enter address → view hex dump
# Follow in dump: right-click register or value → Follow in Dump

# Watch a register value change:
# Right-click register → Watch (adds to Watch tab)

# String at address:
# In dump panel, right-click → Follow in Disassembler (treats as code)
# Or: right-click → Follow in Dump (treats as data)
```

### Stack Inspection

```
# Stack is visible in bottom-right panel
# Shows current stack contents from RSP upward
# Local variables, function arguments, return addresses all here

# At a function call, before the CALL executes:
# RSP-8:  return address (will be pushed by CALL)
# RSP-16: first argument (if x64 Windows ABI: RCX carries it, but stack shows spill)

# x64 Windows calling convention (Microsoft ABI):
# RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
# Additional args: pushed on stack (right to left after 4th)
# RAX = return value

# After CALL executes, inside the called function:
# [RSP+0]:  return address
# [RSP+8]:  home space for RCX (callee may spill RCX here)
# [RSP+16]: home space for RDX
# [RSP+24]: home space for R8
# [RSP+32]: home space for R9
# [RSP+40]: first stack argument (if >4 args)
```

---

## Section 4 — Recognising Common Patterns

These are the code patterns you'll see over and over in malware.
Learn them. Pattern recognition is the skill that separates fast
reversers from slow ones.

### Anti-Debug Tricks

Malware checks if it's being debugged. When it detects a debugger,
it changes behaviour — exits, enters a fake code path, corrupts itself.

**Pattern 1 — IsDebuggerPresent:**

```asm
; Simple and common:
call IsDebuggerPresent
test eax, eax
jnz  exit_or_alternate_path   ; if EAX != 0, debugger detected

; In Ghidra decompiler:
if (IsDebuggerPresent() != 0) {
    ExitProcess(0);
}
```

**Bypass**: Patch `IsDebuggerPresent` to always return 0. In x64dbg:
go to `IsDebuggerPresent` in kernel32.dll, find where it reads the
`BeingDebugged` flag from the PEB, patch the instruction to always
return 0. Or use ScyllaHide plugin — it patches this automatically.

**Pattern 2 — CheckRemoteDebuggerPresent:**

```asm
; More thorough check:
push 0                          ; output buffer (boolean)
push -1                         ; -1 = current process handle
call CheckRemoteDebuggerPresent
; checks [output buffer] for TRUE
```

**Pattern 3 — NtQueryInformationProcess:**

Direct syscall to check debugger from kernel. More stealthy than
the user-mode functions. Checks `ProcessDebugPort` (returns non-zero
if debugged) or `ProcessDebugFlags` (returns 0 if debugged, note
the INVERSION).

```c
// Decompiler output:
HANDLE hProcess = GetCurrentProcess();
DWORD debugPort = 0;
NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, 4, NULL);
if (debugPort != 0) {
    // being debugged — take evasion path
}
```

**Pattern 4 — Timing checks:**

Debuggers cause execution to slow down dramatically. Malware measures
time between two points. If the delta is too large, a debugger is
stepping through the code.

```c
// Timing check pattern:
DWORD start = GetTickCount();
// ... some code ...
DWORD end = GetTickCount();
if ((end - start) > THRESHOLD_MS) {
    // too slow — debugger detected
    ExitProcess(0);
}
```

**Bypass**: Patch the conditional jump to NOT exit. Or patch THRESHOLD_MS
to `0xFFFFFFFF`. Or use x64dbg's time-warp plugin to fake time values.

**Pattern 5 — Exception-based anti-debug:**

```c
__try {
    __asm int 3    // INT3 — breakpoint exception
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // exception was caught — no debugger (debugger consumed the exception)
    goto legitimate_code;
}
// execution falls through here if debugger consumed the INT3:
goto malicious_code;
```

**Bypass**: `Shift+F9` in x64dbg passes the exception to the application
instead of the debugger, bypassing the detection.

### String Decryption Loops

Malware rarely stores strings in plaintext. They're XOR-encrypted, RC4,
or base64. The decryption loop runs at startup.

```asm
; XOR decryption loop pattern:
mov  rsi, encrypted_blob_address   ; pointer to encrypted data
mov  rcx, blob_length              ; loop counter
mov  bl, 0x42                      ; XOR key byte

decode_loop:
xor  byte [rsi], bl               ; decrypt one byte
inc  rsi                           ; advance pointer
dec  rcx                           ; decrement counter
jnz  decode_loop                   ; loop until counter = 0
```

**How to break it**: Set a hardware breakpoint on the string buffer
(memory read/write). When the decryption loop finishes, execution will
access the decoded string. Break there. The buffer now contains the
decrypted content.

```
# In x64dbg:
# 1. Find the encrypted buffer address (from Ghidra analysis)
# 2. In memory dump, navigate to that address
# 3. Right-click → Hardware Breakpoint → Read/Write (size = blob_length)
# 4. F9 to run
# 5. Break fires when decryption accesses the buffer
# 6. Inspect the buffer — now decrypted
```

### API Hashing

Instead of importing functions by name (visible in the import table),
malware resolves API addresses at runtime by hashing function names
and comparing against a stored hash table. The import table shows
nothing useful — just `LoadLibraryA` and `GetProcAddress`.

```c
// API hashing pattern (decompiler output):
HMODULE hKernel = GetModuleHandleA("kernel32.dll");
// custom hash function iterates over export table:
FARPROC pVirtualAlloc = ResolveByHash(hKernel, 0xA123B456);  // hash of "VirtualAlloc"
FARPROC pCreateThread = ResolveByHash(hKernel, 0xC789D012);  // hash of "CreateThread"
```

**How to break it**: The resolved function ADDRESS is used immediately
after `ResolveByHash` returns. Set a breakpoint AFTER the call. RAX
contains the resolved function pointer. Or: set a breakpoint on
`GetProcAddress` — even hash-based resolvers often call GetProcAddress
internally.

Better: identify the hash function in Ghidra. Calculate the hash for
every function in kernel32.dll. Match hashes to your constant table.
You now know what the malware is calling even without running it.

### Packer Stubs

Packed executables contain an encrypted/compressed payload and a
small stub that decrypts and executes the real code at runtime.
Static analysis of the packed file shows only the stub.

```
PACKER RECOGNITION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VISUAL INDICATORS:
  - High entropy sections (above 7.0) → encrypted/compressed data
  - Very small .text section, large .data or unnamed section
  - Import table with only: LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualProtect
  - Entry point in non-.text section
  - Section names like .UPX0/.UPX1, .packed, .enigma

BEHAVIOURAL INDICATORS (dynamic):
  - Entry point code immediately calls VirtualAlloc (allocates new memory)
  - Then copies or decrypts data into that memory
  - Then calls VirtualProtect to make the region executable
  - Then JMPs or CALLs into the new region
  - The JMP target is the real entry point

IDENTIFY THE PACKER:
  # ExeinfoPE: https://github.com/ExeinfoASL/Exeinfo_PE
  # Detect-It-Easy (DIE): https://github.com/horsicq/Detect-It-Easy
  ExeinfoPE target.exe     → shows packer name if recognised
  die target.exe           → comprehensive packer/compiler detection
```

**Unpacking strategy:**

```
1. Load packed binary in x64dbg
2. Set breakpoint on VirtualProtect (common stub completion marker)
3. F9 to run — execution hits VirtualProtect when stub marks region as executable
4. After VirtualProtect returns, the real code is now in that region
5. In memory map: find the new executable region (the unpacked code)
6. Right-click region → Dump to file
7. Open the dumped file in Ghidra — this is the actual malware

# Fix IAT (Import Address Table) after dump:
# Use Scylla (built into x64dbg): Plugin → Scylla → IAT Autosearch → Get Imports → Fix Dump
# This reconstructs the import table for the dumped binary
```

---

## Section 5 — Binary Patching

Sometimes you don't want to analyse — you want to CHANGE the binary.
Patch out anti-debug checks. Force a branch to take a specific path.
Disable integrity checks.

### Patch with x64dbg

```
# Patch an instruction:
# 1. Navigate to the instruction you want to change
# 2. Select it → right-click → Assemble
# 3. Type the replacement instruction:
#    e.g., change JNZ (conditional jump) to NOP (no operation)
#    or change JNZ to JMP (unconditional jump — always takes branch)
# 4. Confirm → instruction is patched in memory

# NOP out instructions:
# Select multiple instructions → right-click → Patch → NOP Selection
# Replaces all selected bytes with 0x90 (NOP)

# Save patched binary:
# File → Patch File → Save to new filename
```

### Common Patches

```
PATCH SCENARIOS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Bypass anti-debug check:
  ORIGINAL:  call IsDebuggerPresent
             test eax, eax
             jnz  malicious_exit
  PATCH:     NOP (the jnz) OR change jnz to jmp and flip target
             → debugger check passes regardless of debugger presence

Force branch to take specific path:
  ORIGINAL:  test eax, eax
             je   normal_path
  PATCH:     xor eax, eax   (force EAX=0 to make je always jump)
  OR:        change je to jmp (always jump)

Bypass licence check / registration:
  ORIGINAL:  call check_licence
             test eax, eax
             jz   unlicensed_path   (if EAX=0, no licence)
  PATCH:     change jz to nop, nop  (never takes unlicensed path)
  OR:        insert mov eax, 1 before the test (force "licensed" result)

Skip integrity check:
  ORIGINAL:  call verify_signature
             test eax, eax
             jnz  tampering_detected
  PATCH:     NOP the jnz (tampering check never triggers)
```

### Patch with Ghidra

```
# Ghidra patch mode:
# 1. Navigate to instruction
# 2. Right-click → Patch Instruction
# 3. Type replacement assembly
# 4. Commit

# Export patched binary:
# File → Export Program → Original File (with patches applied)
```

---

## Section 6 — Full Analysis Workflow (End to End)

The workflow is always the same. The details vary by target.

```
REVERSE ENGINEERING WORKFLOW:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 1 — TRIAGE (5 minutes):
  dumpbin /headers target.exe          → PE characteristics
  dumpbin /imports target.exe          → API fingerprint
  strings -a -n 6 target.exe           → readable content
  ExeinfoPE target.exe                 → packed? which packer?
  sha256sum target.exe                 → check VirusTotal

PHASE 2 — STATIC ANALYSIS (Ghidra):
  Import binary → auto-analyze
  Check imports in Symbol Tree → note suspicious functions
  Find entry point (entry function in Symbol Tree)
  Trace call graph from entry
  Rename functions as you understand them
  Annotate suspicious code with comments
  Find cross-references to interesting strings

PHASE 3 — DYNAMIC ANALYSIS (x64dbg):
  Load in analysis VM (ISOLATED — not production)
  ScyllaHide loaded (defeats common anti-debug)
  bp CreateProcess, VirtualAlloc, VirtualProtect, WriteFile
  F9 to run
  Watch which API calls fire → confirms Ghidra's static analysis
  At VirtualAlloc: note returned address (allocated region)
  At VirtualProtect: the region just became executable → dump it
  At CreateProcess: what process is being launched?
  At WriteFile: what is being written to disk?

PHASE 4 — ITERATE:
  Use dynamic findings to refine static analysis
  Go back to Ghidra: now you know which code path ran
  Trace the specific path that fired in the debugger
  Fill in the gaps

PHASE 5 — REPORT:
  Capabilities: what does this binary do?
  Indicators: file hashes, C2 IPs, mutex names, registry keys
  MITRE ATT&CK mapping: which techniques does it implement?
```

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **PE file** | Portable Executable; Windows binary format for EXE, DLL, SYS files |
| **Import Address Table (IAT)** | Table in PE mapping imported function names to resolved addresses at load time |
| **Export Address Table (EAT)** | Table in DLL listing exported functions with their RVAs |
| **Ghidra** | NSA's open-source reverse engineering framework; static analysis and decompilation |
| **x64dbg** | Open-source Windows debugger for dynamic analysis of binaries |
| **Static analysis** | Analysing a binary without executing it; uses disassembly and decompilation |
| **Dynamic analysis** | Analysing a binary by executing it under a debugger; reveals runtime behaviour |
| **Software breakpoint** | INT3 instruction injected at a code address; modifies the binary in memory |
| **Hardware breakpoint** | Uses CPU debug registers (DR0-DR3); no code modification; anti-debug resistant |
| **Anti-debug** | Techniques malware uses to detect and evade debuggers |
| **Packer stub** | Small decryption/decompression routine in a packed binary that extracts the real code at runtime |
| **API hashing** | Resolving Windows API addresses at runtime by hashing function names; hides imports from static analysis |
| **Cross-reference** | In Ghidra: list of all code locations that access a given address or symbol |
| **Binary patching** | Modifying instructions in a binary to change its behaviour |
| **ScyllaHide** | x64dbg plugin that hides the debugger from common anti-debug techniques |

---

## Drill 14 — Reverse Engineering

Go to `DRILLS/14_reverse_engineering/`. Three binaries are provided:
`sample_a.exe` (easy), `sample_b.exe` (intermediate), `sample_c.exe` (packed).

Your mission:

1. **sample_a.exe** — Static analysis only (Ghidra).
   - What does it do? Write a paragraph.
   - Find the hardcoded C2 IP or domain.
   - Identify the persistence mechanism. What registry key?
   - Map to MITRE ATT&CK techniques.

2. **sample_b.exe** — Combined static and dynamic (Ghidra + x64dbg).
   - It contains anti-debug checks. Identify them. Patch them.
   - It decrypts strings at runtime. Capture the decrypted strings.
   - Trace its network communication. What does it send? To where?
   - What process does it inject into?

3. **sample_c.exe** — Packed binary (dynamic focus).
   - Identify the packer with ExeinfoPE/DIE.
   - Unpack it manually in x64dbg using the OEP-finding technique.
   - Fix the IAT with Scylla.
   - Load the unpacked binary into Ghidra. What is it?

4. **Bonus**: Both sample_b.exe and sample_c.exe use API hashing.
   Write a Python script that brute-forces the API hash function
   and maps all hash constants in sample_b.exe to their WinAPI names.

You don't just run binaries. You read them. Every malware author
is a programmer. Programmers leave fingerprints.

---

— Two tools, one target — until the BINARY yields its secrets
and the decompiler speaks in flawed but readable C
