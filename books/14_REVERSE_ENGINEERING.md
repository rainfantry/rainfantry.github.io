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

## Windows Setup

Every tool mentioned in this chapter, exactly how to install it on Windows 11.
Do this ONCE before any other section. All commands run in PowerShell as Administrator
unless noted.

### Step 0 — Java 17 (Required for Ghidra — do this first)

Ghidra will silently fail to launch without Java 17+. `ghidraRun.bat` opens
and closes instantly with no error message if Java is wrong or missing.
This is the number one reason Ghidra "doesn't work."

```powershell
# Check if Java is already installed and what version:
java -version
# Expected output: openjdk version "17.x.x" or "21.x.x"
# If you see version 11 or lower, or "not recognised", install below.

# Download Java 17 (Temurin — free, no Oracle account needed):
# https://adoptium.net/temurin/releases/?version=17
# Select: Windows x64 → .msi → download and run the installer
# IMPORTANT: during install, tick "Set JAVA_HOME variable" and "Add to PATH"
# Both boxes must be checked or Ghidra still won't find Java.

# After install, open a NEW PowerShell window and verify:
java -version
# Expected: openjdk version "17.x.x" 2023-xx-xx
# Failure: "java is not recognised" means PATH was not set — rerun installer, tick the boxes
```

**Requires admin rights: YES — the MSI installer needs elevation.**

### Step 1 — Ghidra (Static Analysis)

```powershell
# Download from the official NSA GitHub release page:
# https://github.com/NationalSecurityAgency/ghidra/releases
# Download the latest ghidra_XX.X.X_PUBLIC_YYYYMMDD.zip
# Extract to C:\Tools\ghidra\ (create the folder first)

# Verify Java is found before launching:
java -version
# Expected: openjdk version "17..." — if not, fix Java first (Step 0)

# Launch Ghidra:
cd C:\Tools\ghidra
.\ghidraRun.bat
# Expected: Ghidra splash screen appears, then the Project Manager window opens
# Failure: window flashes and closes instantly = Java not on PATH — go back to Step 0
# Failure: "Error: A JVM must be found" = same issue, same fix

# If ghidraRun.bat still fails after fixing Java, set JAVA_HOME manually:
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.x.x.x-hotspot"
.\ghidraRun.bat
```

**Requires admin rights: NO — runs as your normal user. Extraction needs write access to C:\Tools.**

### Step 2 — x64dbg (Dynamic Analysis / Debugger)

```powershell
# Download from official site: https://x64dbg.com/
# Click "Download snapshot" — gets you the latest build as a .zip
# Extract to C:\Tools\x64dbg\

# No install needed. Run directly:
# C:\Tools\x64dbg\release\x64\x64dbg.exe  ← for 64-bit targets
# C:\Tools\x64dbg\release\x32\x32dbg.exe  ← for 32-bit targets

# Verify it opens:
Start-Process "C:\Tools\x64dbg\release\x64\x64dbg.exe"
# Expected: x64dbg UI opens, shows CPU/Log/Breakpoints tabs
# Failure: "missing VCRUNTIME140.dll" = install Visual C++ Redistributable:
# https://aka.ms/vs/17/release/vc_redist.x64.exe
```

**Requires admin rights: YES — debugging other processes requires admin. Right-click x64dbg.exe → Run as administrator.**

### Step 3 — x64dbg Plugins (Install Immediately)

```powershell
# ScyllaHide (hides debugger from anti-debug checks):
# https://github.com/x64dbg/ScyllaHide/releases
# Download ScyllaHide.zip → extract
# Copy ScyllaHide.dp64 to C:\Tools\x64dbg\release\x64\plugins\
# Copy ScyllaHide.dp32 to C:\Tools\x64dbg\release\x32\plugins\
# Restart x64dbg → Plugins menu should show ScyllaHide
# Expected: Plugins → ScyllaHide → HookLibraryx64 option appears
# Failure: plugin folder wrong path — check the plugins\ subfolder exists

# xAnalyzer (auto-annotates API calls in disassembly):
# https://github.com/ThunderCls/xAnalyzer/releases
# Same process: drop .dp64 into plugins\ folder
```

### Step 4 — PE Analysis Tools

```powershell
# dumpbin.exe — already on Windows if Visual Studio is installed
# Check:
dumpbin /?
# Expected: Microsoft COFF Binary File Dumper Version XX.XX
# If missing: install "Desktop development with C++" workload in Visual Studio
# OR install just Build Tools: https://aka.ms/buildtools (free, no full VS needed)

# PE-bear (GUI PE viewer):
# https://github.com/hasherezade/pe-bear/releases
# Download pe-bear_x64.zip → extract → run pe-bear.exe
# No install required
# Expected: PE-bear window opens, drag-drop a .exe to analyse it

# Detect-It-Easy / DIE (packer/compiler detection):
# https://github.com/horsicq/Detect-It-Easy/releases
# Download die_win64_portable.zip → extract → run die.exe
# Expected: DIE window opens — drag-drop a binary, see packer/compiler name
# Failure: "VCRUNTIME140.dll missing" — same fix as x64dbg above

# ExeinfoPE:
# https://github.com/ExeinfoASL/Exeinfo_PE/releases
# Download Exeinfo_PE.zip → extract → run ExeinfoPE.exe
# Expected: GUI opens — drag-drop binary, shows packer name in text box
```

### Step 5 — strings.exe (Sysinternals)

```powershell
# strings is part of Sysinternals Suite:
# https://docs.microsoft.com/en-us/sysinternals/downloads/strings
# Direct download: https://download.sysinternals.com/files/Strings.zip
# Extract strings.exe and strings64.exe to C:\Tools\sysinternals\

# Add to PATH (run once in PowerShell as admin):
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Tools\sysinternals", "Machine")

# Open a NEW PowerShell and verify:
strings /?
# Expected: Strings v2.53 — ... usage info printed
# Failure: "not recognised" = PATH not set or wrong folder
```

### Step 6 — WSL2 (Required for Linux-side analysis tools)

The grep commands shown in this chapter work natively in Git Bash on Windows.
WSL2 is only required if you want native Linux binaries of strings/file/objdump.

```powershell
# Install WSL2 (run in PowerShell as Administrator):
wsl --install
# Reboots the machine. After reboot, Ubuntu installs automatically.
# Set a username and password when prompted.

# Verify WSL2 is running:
wsl --list --verbose
# Expected:
#   NAME      STATE    VERSION
#   Ubuntu    Running  2
# Failure: "WSL 2 requires an update" — run: wsl --update
```

**Requires admin rights: YES — WSL2 installation needs elevation.**

### Tool Summary

| Tool | Location | Admin? | WSL2? |
|------|----------|--------|-------|
| Java 17 (Temurin) | adoptium.net | YES | No |
| Ghidra | C:\Tools\ghidra\ | No | No |
| x64dbg | C:\Tools\x64dbg\ | YES | No |
| ScyllaHide plugin | x64dbg\plugins\ | No | No |
| PE-bear | C:\Tools\pe-bear\ | No | No |
| Detect-It-Easy | C:\Tools\die\ | No | No |
| ExeinfoPE | C:\Tools\ExeinfoPE\ | No | No |
| dumpbin | Via Visual Studio Build Tools | No | No |
| strings | C:\Tools\sysinternals\ | No | No |
| WSL2 + Ubuntu | Built-in (optional) | YES | — |

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

```powershell
# Windows built-in (needs Visual Studio Build Tools installed):
dumpbin /headers malware.dll    # show all PE header fields
dumpbin /imports malware.dll    # show every DLL and function imported
dumpbin /exports malware.dll    # show every function exported (DLLs only)

# PE-bear (GUI, free): https://github.com/hasherezade/pe-bear
# CFF Explorer (GUI, free): https://ntcore.com/?page_id=388

# Check DllCharacteristics flags (critical for exploit dev):
# 0x0020 = HIGH_ENTROPY_VA (64-bit ASLR)
# 0x0040 = DYNAMIC_BASE    (ASLR enabled)
# 0x0100 = NX_COMPAT       (DEP enabled)
# 0x4000 = GUARD_CF        (Control Flow Guard)
# 0x0080 = FORCE_INTEGRITY (code signing required)
```

#### Expected Output

```
# dumpbin /headers malware.dll — success looks like:
Microsoft (R) COFF/PE Dumper Version 14.xx.xxxxx.x
...
FILE HEADER VALUES
             14C machine (x86)
               3 number of sections
        XXXXXXXX time date stamp ...
...
OPTIONAL HEADER VALUES
             10B magic # (PE32)
...
# Key line to check: "DLL characteristics"
#   Dynamic base         ← ASLR enabled
#   NX compatible        ← DEP enabled
#   No SEH               ← no structured exception handler table

# Failure: "dumpbin is not recognised as an internal or external command"
# Means: Visual Studio Build Tools not installed, or developer command prompt not open
# Fix: run from "Developer PowerShell for VS 20xx" shortcut in Start Menu
#   OR install Build Tools from https://aka.ms/buildtools
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

```powershell
# Extract ASCII and Unicode strings (Sysinternals strings.exe):
strings -a -n 6 target.exe > strings_ascii.txt      # all ASCII strings, min 6 chars
strings -a -n 6 -u target.exe > strings_unicode.txt  # Unicode (UTF-16) strings

# Hunt for indicators in Git Bash or PowerShell:
Select-String -Path strings_ascii.txt -Pattern "https?://|\.onion|\.ru|\.cn"
Select-String -Path strings_ascii.txt -Pattern "cmd\.exe|powershell|wscript|mshta"
Select-String -Path strings_unicode.txt -Pattern "password|passwd|secret|token|apikey|credential"
Select-String -Path strings_ascii.txt -Pattern "HKEY|CurrentVersion\\Run|AppInit"
Select-String -Path strings_ascii.txt -Pattern "VirtualAlloc|CreateRemoteThread|WriteProcess"

# If NO readable strings — packed or encrypted binary. Go dynamic first.
# If MANY readable strings — unobfuscated, static analysis will be productive.
```

#### Expected Output

```
# strings target.exe — success looks like:
!This program cannot be run in DOS mode.
.text
kernel32.dll
VirtualAlloc
CreateThread
http://192.168.1.100/gate.php
Mozilla/4.0 (compatible; MSIE 7.0)
...
# Lines of recognisable text — URLs, DLL names, error messages, paths

# Failure: output is mostly garbage characters (Ã¸Ý«...) or nearly empty
# Means: binary is packed or encrypted. Static strings analysis won't help.
# Next step: jump to dynamic analysis (x64dbg) and unpack it first.
```

---

## Section 2 — Ghidra Workflow

Ghidra is NSA's open-source reverse engineering framework. Free.
Better decompiler than IDA Free. Used by NSA researchers for years
before release. Use it.

### Ghidra Interface Orientation (Read This Before Clicking Anything)

When Ghidra opens for the first time, you see two separate windows.
This confuses everyone. Here is what they are:

```
GHIDRA WINDOWS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Window 1 — Project Manager:
  This is the landing screen. It manages collections of binaries (projects).
  You must create a project before you can open a binary.
  File → New Project → Non-Shared Project → pick a folder → name it
  This does NOT close when you open a binary — it stays in the background.

Window 2 — CodeBrowser:
  This is where actual analysis happens.
  It opens when you double-click a binary in the Project Manager.
  It has multiple sub-panels:

  LEFT SIDE:
    Program Trees — sections of the binary (.text, .data, etc.)
    Symbol Tree   — all discovered functions, imports, exports, labels
    Data Type Manager — known struct/type definitions

  CENTER:
    Listing (Disassembly) — the raw assembly instructions, scrollable
    Decompiler — approximate C code (open via Window → Decompiler)

  RIGHT SIDE:
    Register values, cross-reference lists, function signature

  BOTTOM:
    Console — log of what Ghidra is doing
    Bookmarks, Function Graph

FIRST THING TO DO IN CODEBROWSER:
  Analysis → Auto Analyze → Run
  Wait for the progress bar at bottom-right to complete (can take 1-5 mins)
  THEN start navigating. Analyzing before the auto-analysis finishes
  gives you incomplete results.
```

### Installing and Launching Ghidra (Detailed)

```powershell
# STEP 1: Confirm Java 17+ is installed and on PATH
java -version
# Must show: openjdk version "17.x.x" or higher
# If not: install from https://adoptium.net/temurin/releases/?version=17

# STEP 2: Extract Ghidra
# Unzip ghidra_XX.X.X_PUBLIC_YYYYMMDD.zip to C:\Tools\ghidra\

# STEP 3: Launch
cd C:\Tools\ghidra
.\ghidraRun.bat
# Expected: Ghidra splash screen for a few seconds, then Project Manager window

# STEP 4: Create a project
# File → New Project → Non-Shared → Next → pick a folder → name it → Finish
# You only do this once per target group (one project can hold many binaries)

# STEP 5: Import your binary
# File → Import File → select your EXE/DLL
# Accept the auto-detected format (Portable Executable)
# Accept the auto-detected language (x86:LE:64:default or x86:LE:32:default)
# Click OK → a summary dialog shows → click OK again

# STEP 6: Open in CodeBrowser
# Double-click the binary in the Project Manager
# "Analyze?" dialog appears → click YES → wait for analysis to finish
```

#### Expected Output

```
# Successful Ghidra launch:
# Ghidra Project Manager window appears with title "Ghidra: <project name>"
# No errors in console at bottom

# Failure: ghidraRun.bat window flashes and closes instantly
# Means: Java not found on PATH
# Fix: open PowerShell, run: java -version
#   If "not recognised": reinstall Temurin JDK 17, tick "Add to PATH"
#   If shows Java 11 or 8: you need Java 17 specifically
#   After reinstall, open a FRESH PowerShell window and try again

# Failure: "Failed to find a supported JDK" error dialog
# Means: JAVA_HOME is set to wrong Java version
# Fix: set it manually before launching:
#   $env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.x.x.x-hotspot"
#   .\ghidraRun.bat

# Successful auto-analysis:
# Progress bar bottom-right fills up and disappears
# Symbol Tree on left populates with function names
# Functions tab shows named entries like FUN_00401234, main, DllMain
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

```c
// Open decompiler: Window → Decompiler
// Or: double-click a function name in the Symbol Tree
// The decompiler panel appears on the right side of CodeBrowser

// What the decompiler produces (example):
void FUN_00401234(LPVOID lpParam)   // Ghidra auto-names unknown functions FUN_XXXXXXXX
{
  HANDLE hFile;                     // local variable Ghidra inferred from stack usage
  DWORD dwBytesWritten;             // another local variable

  // CreateFileA call — Ghidra resolved the API name from the import table
  hFile = CreateFileA("C:\\Users\\Public\\payload.exe",
                       0x40000000,   // GENERIC_WRITE — Ghidra shows raw hex if no enum loaded
                       0,            // dwShareMode = no sharing
                       NULL,         // no security attributes
                       2,            // CREATE_ALWAYS — overwrites existing file
                       0x80,         // FILE_ATTRIBUTE_NORMAL
                       NULL);        // no template file
  // This writes embedded binary data from the .data section to disk
  WriteFile(hFile, &DAT_00405000, 0x4800, &dwBytesWritten, NULL);
  CloseHandle(hFile);
  // ...
  // After writing, it executes the dropped file — this is a dropper pattern
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
# - Where is this function in the chain?
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

#### Expected Output

```
# Successful load:
# x64dbg opens the binary and breaks at the entry point
# CPU tab shows disassembly starting at the entry point address
# Top-right panel shows registers: RAX, RBX, RCX, RDX... all populated
# Bottom-left shows the stack contents
# Log tab shows: "System breakpoint reached!"
#   followed by the module name and entry point address

# Failure: "Access is denied" when loading
# Means: x64dbg not running as Administrator
# Fix: close x64dbg, right-click x64dbg.exe → Run as administrator

# Failure: binary loads but immediately exits before you can do anything
# Means: target has an early anti-debug check before the entry point
# Fix: enable ScyllaHide first (Plugins → ScyllaHide → HookLibraryx64)
#   then reload the binary
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
call IsDebuggerPresent        ; reads BeingDebugged flag from the PEB (Process Environment Block)
test eax, eax                 ; EAX = 1 if debugger present, 0 if not
jnz  exit_or_alternate_path  ; if EAX != 0, debugger detected — jump to evasion path

; In Ghidra decompiler:
if (IsDebuggerPresent() != 0) {
    ExitProcess(0);           ; clean exit so nothing interesting happens under debugger
}
```

**Bypass**: Patch `IsDebuggerPresent` to always return 0. In x64dbg:
go to `IsDebuggerPresent` in kernel32.dll, find where it reads the
`BeingDebugged` flag from the PEB, patch the instruction to always
return 0. Or use ScyllaHide plugin — it patches this automatically.

**Pattern 2 — CheckRemoteDebuggerPresent:**

```asm
; More thorough check:
push 0                          ; lpbDebuggerPresent — output buffer (boolean result goes here)
push -1                         ; hProcess = -1 means current process handle
call CheckRemoteDebuggerPresent ; returns TRUE if any debugger is attached
; checks [output buffer] for TRUE — if TRUE, takes evasion path
```

**Pattern 3 — NtQueryInformationProcess:**

Direct syscall to check debugger from kernel. More stealthy than
the user-mode functions. Checks `ProcessDebugPort` (returns non-zero
if debugged) or `ProcessDebugFlags` (returns 0 if debugged, note
the INVERSION).

```c
// Decompiler output:
HANDLE hProcess = GetCurrentProcess();  // -1 pseudo-handle for current process
DWORD debugPort = 0;                    // output: 0 = not debugged, non-zero = debugger attached
// ProcessDebugPort = 7 — the information class being queried
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
DWORD start = GetTickCount();   // record timestamp before suspicious region
// ... some code ...
DWORD end = GetTickCount();     // record timestamp after
// if the delta is too large, a human is stepping through with a debugger
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
    __asm int 3    // INT3 — raises a breakpoint exception intentionally
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    // exception was caught by THIS handler — no debugger present
    // (debugger would have consumed the INT3 before it reached here)
    goto legitimate_code;
}
// execution falls through here ONLY if debugger consumed the INT3:
goto malicious_code;  // debugger detected path
```

**Bypass**: `Shift+F9` in x64dbg passes the exception to the application
instead of the debugger, bypassing the detection.

### String Decryption Loops

Malware rarely stores strings in plaintext. They're XOR-encrypted, RC4,
or base64. The decryption loop runs at startup.

```asm
; XOR decryption loop pattern:
mov  rsi, encrypted_blob_address  ; RSI = pointer to encrypted data in memory
mov  rcx, blob_length             ; RCX = loop counter (number of bytes to decrypt)
mov  bl, 0x42                     ; BL = single-byte XOR key (0x42 in this example)

decode_loop:
xor  byte [rsi], bl              ; XOR one encrypted byte with the key — decrypts it in place
inc  rsi                          ; advance RSI to point to the next encrypted byte
dec  rcx                          ; decrement the counter
jnz  decode_loop                  ; if counter != 0, loop back and do the next byte
; after loop: [encrypted_blob_address] now contains the decrypted string
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

#### Expected Output

```
# After hardware breakpoint fires on the decrypted buffer:
# x64dbg pauses — RIP is at the instruction that reads the decrypted data
# In the Dump panel at the buffer address, you now see ASCII text instead of garbage:
# Before: 4F 2B 35 27 41 0A 33 2B 11 ...  ← XOR-encrypted garbage
# After:  68 74 74 70 3A 2F 2F 63 32 ...  ← readable bytes
# Right-click the dump → Copy → String → paste into Notepad to read it
# You should see something like: "http://c2server.evil/gate.php"

# Failure: breakpoint never fires
# Means: you set the hardware breakpoint at the wrong address
# Fix: go back to Ghidra — find the exact address of the encrypted blob (look for
#   the MOV RSI, <address> instruction before the loop), use THAT address in x64dbg
```

### API Hashing

Instead of importing functions by name (visible in the import table),
malware resolves API addresses at runtime by hashing function names
and comparing against a stored hash table. The import table shows
nothing useful — just `LoadLibraryA` and `GetProcAddress`.

```c
// API hashing pattern (decompiler output):
HMODULE hKernel = GetModuleHandleA("kernel32.dll");  // get base address of kernel32 in memory
// custom hash function iterates over export table of hKernel,
// hashes each function name, compares to stored constant:
FARPROC pVirtualAlloc = ResolveByHash(hKernel, 0xA123B456);  // 0xA123B456 = hash of "VirtualAlloc"
FARPROC pCreateThread = ResolveByHash(hKernel, 0xC789D012);  // 0xC789D012 = hash of "CreateThread"
// pVirtualAlloc and pCreateThread now hold function pointers — called directly
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
2. Set breakpoint on VirtualProtect (common stub completion marker):
   bp VirtualProtect        ← in x64dbg command bar at bottom
3. F9 to run — execution hits VirtualProtect when stub marks region as executable
4. After VirtualProtect returns, the real code is now in that region
5. In memory map: find the new executable region (the unpacked code)
6. Right-click region → Dump to file
7. Open the dumped file in Ghidra — this is the actual malware

# Fix IAT (Import Address Table) after dump:
# Use Scylla (built into x64dbg): Plugin → Scylla → IAT Autosearch → Get Imports → Fix Dump
# This reconstructs the import table for the dumped binary so Ghidra can read its imports
```

#### Expected Output

```
# Successful unpack:
# After VirtualProtect breakpoint fires, Memory Map shows a new RWX region
# (red/green colouring — both Writable and Executable at the same time is suspicious)
# Dump that region to a file — open in HxD or PE-bear
# First bytes should be: 4D 5A (MZ) followed by PE signature 50 45 00 00
# That confirms you dumped a valid PE — the real malware
# Load into Ghidra: you now see a full Symbol Tree with meaningful function names

# Failure: MZ header not found at start of dump
# Means: you dumped at the wrong offset — the PE starts mid-region
# Fix: in the dumped file, search for "MZ" bytes (4D 5A) using HxD
#   truncate everything before the MZ header and reimport into Ghidra
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

#### Expected Output

```
# Successful patch:
# After right-click → Assemble → type "nop" → confirm:
# The instruction in the disassembly view changes to: 90 NOP
# If you patched a JNZ to NOP, the conditional branch is now gone
# Run the binary (F9) — it should no longer take the anti-debug exit path

# Failure: "Access violation when writing" during patch
# Means: that memory region is read-only (it's in .text which may have write protection)
# Fix: in Memory Map, find the .text region → right-click → Set Page Rights → add Write
#   Then retry the patch — save the file immediately after

# Failure: patched bytes revert when you re-run
# Means: you patched in-memory but didn't save with File → Patch File
# Fix: always save to a new filename after patching, then run the saved binary
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

## Defender Takeaway

This is what you do Monday morning with everything you just learned. This section
is for the blue team. You understand how attackers reverse and how malware hides —
now use that to harden your environment and catch the same tricks in production.

- **Deploy Sysmon with a quality config and watch Event ID 4688 (Process Creation).** Every time a process is created, 4688 logs the full command line. If you see `cmd.exe` or `powershell.exe` spawned by an unusual parent (Word, Excel, a DLL host), that is injection or a dropper. Download the Sysmon config from SwiftOnSecurity's GitHub as a starting baseline.

- **Alert on VirtualProtect calls that flip memory to executable (RWX).** Legitimate software rarely needs to allocate a chunk of memory, write to it, then mark it executable. This is the packer stub pattern. Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) catch the injection that follows. Configure Elastic/Splunk to alert on any process that calls VirtualProtect with PAGE_EXECUTE_READWRITE on memory it just wrote.

- **Block or audit binaries with no valid Authenticode signature.** In Windows Defender Application Control (WDAC) or AppLocker, require signed binaries in production. Most malware droppers are unsigned. Event ID 3033 (WDAC policy block) fires when an unsigned binary is stopped. This alone kills a significant percentage of commodity malware.

- **Enable Windows Defender Credential Guard.** This moves LSA credential storage into a hypervisor-protected enclave. Even if an attacker gets `lsasrv.dll` imports (Mimikatz territory), they cannot extract NTLM hashes from memory because the credential store is now out of reach of user-mode processes.

- **Monitor for IsDebuggerPresent and NtQueryInformationProcess being called from unexpected processes.** Legitimate desktop applications almost never call these. If your EDR telemetry shows a document or script calling these APIs, something is checking whether it is being analysed — that is a strong malware indicator. Hunt in your EDR for these API calls outside of development tool processes.

- **Run your IR binaries in an isolated VM — never production.** Dynamic analysis means the code actually executes. Set up a dedicated Windows 11 VM in VMware Workstation (snapshot before analysis, revert after). Keep it air-gapped from your real network. Any malware that detects VMware and behaves differently is evading sandbox analysis — that itself is an indicator of sophistication.

- **Check DllCharacteristics on all first-party executables you ship or maintain.** Every EXE or DLL you build should have DYNAMIC_BASE (ASLR), NX_COMPAT (DEP), and GUARD_CF (Control Flow Guard) set. Run `dumpbin /headers yourbinary.exe` and confirm all three flags are present. If they're missing, the binary is missing standard exploit mitigations — rebuild with `/DYNAMICBASE /NXCOMPAT /GUARD:CF` linker flags.

- **Hunt for high-entropy DLLs loaded into trusted processes using Windows Event ID 7 (Sysmon — Image Load).** Packed or encrypted DLLs have entropy above 7.0 (max is 8.0). If a DLL with high entropy is loaded into `svchost.exe`, `explorer.exe`, or `lsass.exe`, that is process injection. Configure Sysmon to log all image loads from temp directories and user writeable paths, then alert on anything with unusual file paths or missing version info.

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
