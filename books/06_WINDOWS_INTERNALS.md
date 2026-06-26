# Chapter 06 — Windows Internals: Memory, Handles, Kernel Objects

**VADER-RCE Field Manual**
**Prerequisite**: Ch01-05 (assembly, debugging basics, stack exploitation)
**Drill**: DRILLS/06_win_internals/

---

## Why You Need This

You cannot exploit what you don't understand.

Every privilege escalation, every token manipulation, every kernel
exploit you will ever run is operating on the structures described
in this chapter. EPROCESS, ETHREAD, _OBJECT_HEADER, the token, the
handle table — these are not academic curiosities. They are the
terrain you manoeuvre through.

When a Potato attack steals a SYSTEM token, it is copying a specific
field from one EPROCESS structure to another. When a kernel exploit
maps shellcode into ring 0, it is manipulating PTE entries in the
page directory. When LSASS stores credentials, it is doing so in
a specific heap structure that Mimikatz knows how to walk.

Understand the internals. Then the attacks are not tricks — they are
logical consequences of how the system works.

---

## WINDOWS SETUP

Every tool used in this chapter. Install all of them before you start Section 1.

### Tools Required

| Tool | Purpose | Where to Get It |
|------|---------|-----------------|
| WinDbg Preview | Kernel debugging, inspecting EPROCESS/ETHREAD/tokens | Microsoft Store (search "WinDbg Preview") |
| Windows SDK / Debugging Tools for Windows | Alternative WinDbg install, includes `kd.exe` | https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/ |
| Process Hacker 2 | User-mode handle/token/module inspector | https://processhacker.sourceforge.io/downloads.php |
| Python 3 (system) | Syscall resolver scripts | Already installed — verify below |
| NASM | Assembler for the PEB walk shellcode examples | https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/nasm-2.16.03-installer-x64.exe |
| MinGW-w64 (gcc) | Compiling C snippets (token checks, handle enumeration) | https://winlibs.com/ → download the Win64 UCRT release zip, unzip to C:\mingw64 |
| Mimikatz | Credential extraction (lab only — read credentials, understand defence) | https://github.com/gentilkiwi/mimikatz/releases |
| Sysinternals Suite | Process Explorer, Handle, Autoruns, AccessChk | https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite |
| VMware Workstation / Hyper-V | Second VM for kernel debugging (debuggee) | VMware: https://www.vmware.com/products/workstation-player.html — Hyper-V is built into Windows 11 Pro |

### Install Commands (PowerShell, run as Administrator where marked)

```powershell
# Verify Python is on PATH — expected output: Python 3.x.x
python --version

# Install NASM — after install, add to PATH manually:
# Control Panel → System → Advanced → Environment Variables → PATH → add C:\Program Files\NASM
# Verify:
nasm -v
# Expected: NASM version 2.16.03

# Add MinGW-w64 gcc to PATH (adjust if you unzipped elsewhere):
[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\mingw64\bin", "User")
# Re-open terminal, then verify:
gcc --version
# Expected: gcc (x86_64-posix-seh-rev0...) 13.x.x

# Install Sysinternals to C:\Tools\Sysinternals (run as Admin):
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "$env:TEMP\sysinternals.zip"
Expand-Archive "$env:TEMP\sysinternals.zip" -DestinationPath "C:\Tools\Sysinternals" -Force
# Verify:
C:\Tools\Sysinternals\handle.exe -accepteula
# Expected: Handle vX.X ... No matching handles found.

# Install WSL2 (required if you want to compile Linux-targeting tools or run gdb):
wsl --install
# This installs Ubuntu by default. Reboot when prompted.
# Verify after reboot:
wsl --list --verbose
# Expected: NAME    STATE    VERSION
#           Ubuntu  Stopped  2
```

### WinDbg Setup — Read This First (30-60 Minute Process, Do It Now)

WinDbg is the hardest tool to set up in this chapter. Follow these steps exactly.

**Step 1 — Install WinDbg Preview from the Microsoft Store.**
Open the Store, search "WinDbg Preview", install it. Free. No account needed.

**Step 2 — Configure symbol path.** Without symbols, WinDbg shows raw addresses instead of readable names like `nt!NtReadFile`. This is what the "30-minute wall" is.

```
# Inside WinDbg, go to: File → Settings → Debugging Settings → Symbol path
# Enter exactly this (it downloads symbols on demand from Microsoft):
srv*C:\Symbols*https://msdl.microsoft.com/download/symbols

# Or set it via environment variable (PowerShell, then restart WinDbg):
[System.Environment]::SetEnvironmentVariable("_NT_SYMBOL_PATH", "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols", "User")
```

**Step 3 — First-time symbol download.** When you first break into a kernel session, type:

```
.reload /f
```

This downloads all kernel symbols (~500MB on first run). You need internet. It takes 5-10 minutes. Only happens once.

**Step 4 — Set up kernel debugging with a VM (two-machine setup).**

The safest approach is a VM on the same machine:

```powershell
# On the DEBUGGEE VM (the VM you want to debug — open elevated PowerShell inside it):
# Enable kernel debugging over network (kdnet):
bcdedit /debug on
bcdedit /dbgsettings net hostip:<YOUR_HOST_IP> port:50000 key:1.2.3.4
# Replace <YOUR_HOST_IP> with your host machine IP (run ipconfig to find it)
# This sets a shared key "1.2.3.4" — change it to something else for real use
# Reboot the VM after this.

# On the DEBUGGER (your host machine) in WinDbg Preview:
# File → Attach to kernel → Net tab
# Port: 50000
# Key: 1.2.3.4
# Click OK — WinDbg waits for the VM to boot and connect
```

**Verify WinDbg is working:** after connecting, press Break (Debug → Break). You should see:

```
Break instruction exception - code 80000003 (first chance)
nt!DbgBreakPointWithStatus:
fffff800`12345678 cc              int     3
0: kd>
```

If you see `0: kd>` you are in. If you see nothing, check the VM network settings — it needs to reach your host IP on port 50000.

**Admin rights required:** WinDbg kernel debugging requires the debuggee VM to have test signing enabled OR you must be debugging a real kernel driver. The symbol download requires internet. Process Hacker requires local admin to see protected processes.

---

## Section 1 — Virtual Memory Layout

### User vs Kernel Space

On a 32-bit Windows system, the 4GB address space splits:

```
VIRTUAL ADDRESS SPACE (32-bit, default split)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

0x00000000 ┌─────────────────────────────────┐
           │                                 │
           │       USER SPACE (2GB)          │
           │                                 │
           │  Process code, stack, heap,     │
           │  loaded DLLs, PEB, TEB          │
           │                                 │
0x7FFFFFFF ├─────────────────────────────────┤
           │   (64KB no-access guard zone)   │
0x80000000 ├─────────────────────────────────┤
           │                                 │
           │       KERNEL SPACE (2GB)        │
           │                                 │
           │  ntoskrnl.exe, drivers,         │
           │  HAL, kernel heap, KPCR,        │
           │  page tables, system cache      │
           │                                 │
0xFFFFFFFF └─────────────────────────────────┘

Note: /3GB boot option shifts the split to user=3GB, kernel=1GB
```

On 64-bit Windows, the address space is 128TB:

```
VIRTUAL ADDRESS SPACE (64-bit Windows 10/11)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

0x0000000000000000 ┌───────────────────────────┐
                   │  User space (~128TB)        │
                   │  0x0000 - 0x7FFF prefix     │
0x00007FFFFFFFFFFF ├───────────────────────────┤
                   │  Non-canonical (invalid)    │ ← canonical hole
0xFFFF800000000000 ├───────────────────────────┤
                   │  Kernel space (~128TB)      │
                   │  0xFFFF prefix              │
                   │                             │
                   │  HAL, ntoskrnl, drivers,    │
                   │  PFN database, hypervisor   │
0xFFFFFFFFFFFFFFFF └───────────────────────────┘
```

User-mode code cannot read or write kernel space — attempting it
triggers an access violation (or a kernel bugcheck if in ring 0).
The boundary is enforced by the CPU's privilege rings and page table
entries.

### Page Protection

Each page (4KB) has protection attributes in its page table entry:

```
Protection flags:
  PAGE_NOACCESS          0x01   — all access denied
  PAGE_READONLY          0x02   — read only
  PAGE_READWRITE         0x04   — read + write
  PAGE_EXECUTE           0x10   — execute only
  PAGE_EXECUTE_READ      0x20   — execute + read
  PAGE_EXECUTE_READWRITE 0x40   — full access (RWX)
  PAGE_GUARD             0x100  — guard page (fires exception on first access)
```

The kernel tracks these in PTE (Page Table Entry) flags. NX (DEP)
sets the No-Execute bit in PTE. VirtualProtect modifies these flags.

### Address Translation

```
VIRTUAL ADDRESS → PHYSICAL ADDRESS translation (x64, 4-level paging)

Virtual address: 0x00007FF712345678

Bits [47:39] → PML4 index  (page map level 4 table)
Bits [38:30] → PDPT index  (page directory pointer table)
Bits [29:21] → PD index    (page directory)
Bits [20:12] → PT index    (page table)
Bits [11:0]  → Page offset (byte within the 4KB page)

CR3 register holds the physical address of the PML4 table.
Each level: 512 entries × 8 bytes = 4KB table.
```

> **DEFENDER CALLOUT — Virtual Memory:** Any page marked `PAGE_EXECUTE_READWRITE` (RWX) is a red flag. Legitimate code is almost never RWX — it's either readable/executable (text section) or readable/writable (data section), never both. Memory scanners like `Get-Process | ForEach { ... VirtualQueryEx }` or Process Hacker's Memory tab will highlight RWX regions. Shellcode injectors create RWX pages — flag them.

---

## Section 2 — Virtual Address Descriptors (VADs)

### What VADs Are

The kernel does not track every page individually in a flat structure.
Instead it uses a VAD tree — a balanced binary tree of Virtual Address
Descriptor nodes, one per contiguous region with the same protection.

Each EPROCESS has a `VadRoot` field pointing to this tree. Walking
the tree gives you the complete memory map for a process.

```
VAD tree node (_MMVAD) key fields:
  StartingVpn      — starting virtual page number
  EndingVpn        — ending virtual page number
  u.VadFlags       — protection, type (private/mapped/image), commit
  Subsection       — for file-backed mappings: pointer to file data
  LeftChild        — lower address subtree
  RightChild       — higher address subtree
```

### Viewing VAD Tree In WinDbg

```
# View VADs for current process:
0: kd> !vad

# Example output (truncated):
VAD  level      start     end  commit
...
00000083`a2c6a5d0 ( 8)  7ff6f560  7ff6f606  58  Mapped  Exe  EXECUTE_WRITECOPY  \Windows\System32\ntdll.dll
00000083`a2c6f3c0 ( 7)  7ff745c0  7ff756bf   0  Mapped  READONLY             \Windows\System32\en-US\ntdll.dll.mui
00000083`a2c6b520 ( 5)  7ffc8480  7ffc8480   1  Private READWRITE

# Full walk:
0: kd> !vad 0xffffc38f123456b0 1    # verbose walk from specific node
```

#### Expected Output

Success looks like a table of memory regions. Each row is one contiguous region. Regions with a file path (e.g. `\Windows\System32\ntdll.dll`) are file-mapped (legit DLLs). Regions marked `Private` with no path are heap, stack, or injected code.

Failure looks like `Unable to read VAD node` — means you have the wrong EPROCESS address or you are not in the right process context. Fix: run `.process /p /r [EPROCESS_addr]` first to switch context.

### Why VADs Matter For Exploitation

- **Hiding injected code**: a reflective DLL appears as an anonymous
  private mapping — no file-backed VAD entry, so it doesn't show up
  in normal module enumeration.
- **ASLR**: the kernel uses VAD entries to track allocated regions and
  ensure randomised base assignments don't collide.
- **Memory forensics**: walking the VAD tree reveals ALL mapped regions,
  including injected code that's invisible to `EnumProcessModules`.

> **DEFENDER CALLOUT — VADs:** Injected shellcode typically shows up as a `Private` VAD region with `EXECUTE` permission and no backing file. Forensic tools like Volatility's `malfind` plugin detect exactly this pattern. On a live Windows system, Process Hacker → right-click any process → Properties → Memory tab → filter for "Private" + "Execute" — any hit that isn't the JIT compiler (e.g. from .NET/JavaScript engines) deserves investigation.

---

## Section 3 — PEB and TEB

### Process Environment Block (PEB)

The PEB is a user-mode structure (in user space, accessible to the
process itself) containing process-wide information. One per process.

```
PEB structure (key fields, 64-bit):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Offset  Field                   Size  Notes
+0x000  InheritedAddressSpace    1     process creation flag
+0x002  BeingDebugged            1     IsDebuggerPresent() reads this
+0x008  ImageBaseAddress         8     base address of the EXE
+0x018  Ldr                      8     pointer to PEB_LDR_DATA
+0x020  ProcessParameters        8     RTL_USER_PROCESS_PARAMETERS (command line, env)
+0x028  SubSystemData            8
+0x060  NtGlobalFlag             4     used by heap/debug detection
+0x068  CriticalSectionTimeout   8
+0x070  HeapSegmentReserve       8
+0x078  HeapSegmentCommit        8
+0x098  NumberOfHeaps            4
+0x0A0  MaximumNumberOfHeaps     4
+0x0A8  ProcessHeaps             8     array of heap handles
+0x110  SessionId                4     Terminal Services session
```

**PEB_LDR_DATA** (pointed to by `Ldr`) contains the loaded module list:

```
PEB_LDR_DATA:
  InLoadOrderModuleList    — DLL list in load order (head = EXE)
  InMemoryOrderModuleList  — DLL list in memory address order
  InInitializationOrderModuleList

Each entry is LDR_DATA_TABLE_ENTRY:
  InLoadOrderLinks     — LIST_ENTRY for load order list
  InMemoryOrderLinks   — LIST_ENTRY for memory order list
  DllBase              — base address of the module
  EntryPoint           — DLL entry point address
  SizeOfImage          — size in bytes
  FullDllName          — full path (UNICODE_STRING)
  BaseDllName          — filename only (UNICODE_STRING)
```

Shellcode commonly walks the PEB_LDR_DATA list to find `kernel32.dll`
(always loaded) and resolve `GetProcAddress`/`LoadLibrary` by hash —
without referencing any hardcoded addresses.

### PEB Walk Shellcode — Full Build Instructions

The following NASM assembly walks the PEB to find kernel32.dll base. Here is how to assemble and inspect it on Windows.

```nasm
; ─────────────────────────────────────────────────────────────────────
; peb_walk.asm — Walk PEB to find kernel32.dll base address (x86)
; Build: nasm -f bin peb_walk.asm -o peb_walk.bin
; Inspect: python inspect_bin.py peb_walk.bin
; ─────────────────────────────────────────────────────────────────────

BITS 32                      ; 32-bit mode (x86 shellcode)

xor ecx, ecx                 ; ECX = 0 (used as base for FS-relative access)
mov eax, fs:[ecx+0x30]       ; EAX = PEB address (FS:0x30 always points to PEB in x86)
mov eax, [eax+0x0c]          ; EAX = PEB.Ldr (offset 0x0C in 32-bit PEB)
mov esi, [eax+0x14]          ; ESI = Ldr.InMemoryOrderModuleList.Flink (first entry)
                             ; First entry in Win10 is ntdll, not the EXE
lodsd                        ; EAX = next LIST_ENTRY (advance past ntdll entry)
                             ; LODSD loads [ESI] into EAX and increments ESI by 4
xchg eax, esi                ; ESI = second LIST_ENTRY pointer
lodsd                        ; EAX = third LIST_ENTRY (this is kernel32.dll on Win10)
                             ; LODSD again: load [ESI] into EAX, ESI += 4
mov ebx, [eax+0x10]          ; EBX = LDR_DATA_TABLE_ENTRY.DllBase (offset 0x10 = base addr)
                             ; EBX now holds kernel32.dll base — use it to find exports
```

**How to assemble this on Windows:**

```powershell
# Step 1 — write the asm to a file (do this in your DRILLS/06_win_internals/ folder)
# (paste the NASM source above into peb_walk.asm)

# Step 2 — assemble to raw binary
nasm -f bin peb_walk.asm -o peb_walk.bin

# Expected: no output, no errors. A file peb_walk.bin appears.
# Failure: "nasm: command not found" — NASM is not on PATH. Add C:\Program Files\NASM to PATH.

# Step 3 — inspect the binary (see the opcodes)
python -c "
data = open('peb_walk.bin','rb').read()
print(f'Size: {len(data)} bytes')
print('Hex:', data.hex())
print('Opcodes:')
for i, b in enumerate(data):
    print(f'  [{i:02d}] 0x{b:02x}')
"
```

#### Expected Output

```
Size: 14 bytes
Hex: 31c964a130000000...
Opcodes:
  [00] 0x31   ← XOR
  [01] 0xc9
  [02] 0x64   ← FS segment prefix
  ...
```

Failure looks like `nasm: fatal: unable to open input file 'peb_walk.asm'` — means you are not in the right directory. Use the full path.

**To run shellcode in a controlled test (Windows, Python):**

```python
# run_shellcode.py — inject and execute raw shellcode in THIS process (test only)
import ctypes

# Read the assembled binary
with open("peb_walk.bin", "rb") as f:
    shellcode = f.read()

# Allocate RWX memory — PAGE_EXECUTE_READWRITE = 0x40
buf = ctypes.windll.kernel32.VirtualAlloc(
    None,              # let Windows choose the address
    len(shellcode),    # size of allocation
    0x3000,            # MEM_COMMIT | MEM_RESERVE
    0x40               # PAGE_EXECUTE_READWRITE — writable AND executable
)

# Copy shellcode bytes into the allocated buffer
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_void_p(buf),     # destination
    shellcode,                # source
    len(shellcode)            # byte count
)

# Create a thread to execute the shellcode
ht = ctypes.windll.kernel32.CreateThread(
    None,              # default security
    0,                 # default stack size
    ctypes.c_void_p(buf),  # start address = our shellcode
    None,              # no argument
    0,                 # run immediately
    None               # don't need thread ID back
)

# Wait for the thread to finish (infinite wait)
ctypes.windll.kernel32.WaitForSingleObject(ht, -1)
print("Shellcode executed (it returned — attach debugger to see EBX = kernel32 base)")
```

#### Expected Output

```
Shellcode executed (it returned — attach debugger to see EBX = kernel32 base)
```

The shellcode does not print anything itself — it puts the kernel32 base in EBX. To see it, attach x32dbg before running and set a breakpoint on the thread start address. Failure looks like a crash / access violation — this means you assembled the wrong bit width. The PEB walk above is x86 (32-bit). Running it in a 64-bit Python process will fault. Use a 32-bit Python for this test, or see the x64 version below.

### Thread Environment Block (TEB)

One TEB per thread. Accessible via `FS` segment register (x86) or
`GS` segment register (x64).

```
TEB key fields (64-bit):
  +0x000  NtTib (NT_TIB)          — exception chain pointer, stack base/limit
  +0x030  EnvironmentPointer
  +0x038  ClientId                — ProcessId + ThreadId
  +0x040  ActiveRpcHandle
  +0x050  ThreadLocalStoragePointer
  +0x060  ProcessEnvironmentBlock — pointer to PEB
  +0x068  LastErrorValue          — GetLastError() reads this
  +0x1748 WowTebOffset            — for 32-bit thread on 64-bit process
```

```nasm
; Access PEB from x64 code (NASM, 64-bit):
; Build: nasm -f win64 get_peb.asm -o get_peb.obj
BITS 64
mov rax, gs:[0x60]       ; RAX = PEB address (GS:0x60 in x64, GS:0x30 in x86)
```

---

## Section 4 — Handle Table and Kernel Objects

### Handle Tables

Every Windows object (file, process, thread, event, mutex, etc.) is
a kernel object. User-mode code accesses them via handles. A handle
is an index into the process's handle table.

```
HANDLE TABLE STRUCTURE:
━━━━━━━━━━━━━━━━━━━━━━━━

Per-process: EPROCESS.ObjectTable → _HANDLE_TABLE

_HANDLE_TABLE:
  TableCode      — pointer to table data (or two-level table)
  QuotaProcess   — process this table belongs to
  HandleCount    — number of open handles

Handle value to table entry mapping:
  Handle[3:0]  = 0 (handles are multiples of 4)
  Handle[31:2] = index into handle table

Each entry (_HANDLE_TABLE_ENTRY, 16 bytes on x64):
  VolatileLowValue  — pointer to OBJECT_HEADER (with attribute flags in low bits)
  HighValue         — access mask granted for this handle
```

### The System Handle Table

The kernel maintains a global handle table for system handles (handle
value with high bit set). You can enumerate all handles across all
processes:

```
# WinDbg: walk system handle table
0: kd> !handle 0 7    # dump all handles with type + name
0: kd> !handle 0 f    # full detail including security descriptor

# From user mode (elevated):
# NtQuerySystemInformation(SystemHandleInformation) returns all system handles
# Used by tools like Process Hacker to show global handle table
```

#### Expected Output

```
# !handle 0 7 output (truncated):
PROCESS ffffc38f01234080
    SessionId: 0  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001aa002  ObjectTable: ffff8e0f01234400  HandleCount: 2789.
    Image: System

Handle table at ffff8e0f01234400 with 2789 entries in use

0004: Object: ffffc38f04567890  GrantedAccess: 001f0003 Entry: ffff8e0f01234410
Object: ffffc38f04567890  Type: (ffffc38f01234080) Thread
...
```

Failure looks like `!handle: Unable to read handle table` — means symbols not loaded. Run `.reload /f` first.

> **DEFENDER CALLOUT — Handle Tables:** Attackers who open LSASS for credential dumping leave a handle open. You can detect this: **Event ID 10** in Sysmon (if installed) or **Event ID 4656** in the Windows Security log records every object open request. Filter for handles to `lsass.exe` from non-system processes. In PowerShell: `Get-WinEvent -LogName Security | Where {$_.Id -eq 4656}` — look for `Object Name` containing `lsass`.

---

## Section 5 — Kernel Objects: EPROCESS, ETHREAD

### EPROCESS

EPROCESS is the kernel's process control block. One per process.
Stored in non-paged pool (kernel memory). Not directly accessible
from user mode — you need a kernel driver or exploit to read/write it.

```
EPROCESS (key fields, Windows 10 x64, offsets vary by build):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

+0x000  Pcb (_KPROCESS)          — kernel process control block (scheduler stuff)
+0x2e0  ProcessLock              — spinlock
+0x388  UniqueProcessId          — PID
+0x390  ActiveProcessLinks       — doubly-linked list of all EPROCESS structs
+0x3b8  Flags2
+0x3c0  Flags
+0x440  ObjectTable              — handle table pointer
+0x4b8  Token                    — EX_FAST_REF to access token
+0x5a0  ImageFileName[15]        — process name (first 15 chars)
+0x5b0  ActiveThreads
+0x7d4  Wow64Process             — 32-bit process on 64-bit OS: points to Wow64 info
```

**Note on offsets:** These offsets are for a specific Windows 10 x64 build. They change between Windows versions and even cumulative updates. Always verify with `dt _EPROCESS` in WinDbg on your actual target. This is not academic caution — if you use the wrong offset in an exploit, you corrupt the wrong memory and BSOD the machine.

**ActiveProcessLinks** — every running process is on this circular
doubly-linked list. Walk it to enumerate all processes:

```
0: kd> !process 0 0     # list all processes
0: kd> dt _EPROCESS     # dump EPROCESS structure definition
0: kd> dt _EPROCESS @$proc   # dump current process EPROCESS
```

#### Expected Output

```
# !process 0 0 output (truncated):
PROCESS ffffc38f01234080
    SessionId: 0  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001aa002  ObjectTable: ffff8e0f00001234  HandleCount: 2789.
    Image: System

PROCESS ffffc38f04561080
    SessionId: 0  Cid: 0088    Peb: 00000000  ParentCid: 0004
    DirBase: 002bb003  ObjectTable: ffff8e0f00002345  HandleCount:  54.
    Image: smss.exe
...
```

Failure looks like `Unable to read EPROCESS` — means your kernel session is not connected or process context is wrong. Press Ctrl+Break in WinDbg to re-break in.

The `Token` field at `+0x4b8` is an `EX_FAST_REF` — the token pointer
with the low 4 bits used as a reference count. Mask those off to get
the real token address:

```
token_addr = EPROCESS.Token & ~0xF
```

This is the field that privilege escalation techniques overwrite to
steal the SYSTEM token.

### ETHREAD

ETHREAD is the kernel's thread control block. One per thread. Lives
in the same non-paged pool as EPROCESS.

```
ETHREAD (key fields):
  +0x000  Tcb (_KTHREAD)           — kernel thread control (registers, stack, priority)
  +0x420  CreateTime
  +0x428  ExitTime
  +0x430  Cid (CLIENT_ID)          — ProcessId + ThreadId
  +0x4c8  Win32StartAddress        — user-mode thread start function
  +0x548  ThreadName               — optional thread name (UNICODE_STRING)
```

The **_KTHREAD** embedded at `+0x000` contains:
- `TrapFrame` — saved user-mode register state (RSP, RIP, etc.)
- `ApcState` — APC queue for this thread
- `PreviousMode` — 0=KernelMode, 1=UserMode (current execution context)
- `StackBase` / `StackLimit` — kernel stack bounds

> **DEFENDER CALLOUT — EPROCESS / ETHREAD:** Token-stealing rootkits (Potato variants, kernel exploits) modify `EPROCESS.Token` directly. This leaves no Win32 API trace — but it does trigger anomalies. **Event ID 4672** (Special Logon) fires when a process acquires special privileges. If you see 4672 for a process that should not have SYSTEM rights, investigate. Windows Defender Credential Guard runs as a VTL1 trustlet specifically to prevent token theft from user-mode SYSTEM processes.

---

## Section 6 — _OBJECT_HEADER

Every kernel object is preceded by an `_OBJECT_HEADER` structure.
This header contains metadata about the object regardless of its type.

```
_OBJECT_HEADER (64-bit):
━━━━━━━━━━━━━━━━━━━━━━━━

+0x000  PointerCount    — number of kernel references (object stays alive)
+0x008  HandleCount     — number of open handles (OR ChainedFree if free)
+0x010  Lock
+0x018  TypeIndex       — index into ObTypeIndexTable (identifies object type)
+0x019  TraceFlags
+0x01a  InfoMask        — which optional headers precede this header
+0x01b  Flags
+0x020  ObjectCreateInfo — pointer to OBJECT_CREATE_INFO (or QuotaBlockCharged)
+0x028  SecurityDescriptor — pointer to SD (low bits = flags, must mask)
+0x030  Body            — the actual object data starts here

Actual object pointer = &_OBJECT_HEADER.Body
_OBJECT_HEADER pointer = object_pointer - 0x30
```

Optional headers (presence indicated by InfoMask bitmask):
```
Bit 0x01: OBJECT_HEADER_CREATOR_INFO  — creator process ID
Bit 0x02: OBJECT_HEADER_NAME_INFO     — object name in object namespace
Bit 0x04: OBJECT_HEADER_HANDLE_INFO   — handle database entry
Bit 0x08: OBJECT_HEADER_QUOTA_INFO    — quota charges
Bit 0x10: OBJECT_HEADER_PROCESS_INFO  — single process ownership
Bit 0x40: OBJECT_HEADER_AUDIT_INFO    — audit flags
Bit 0x80: OBJECT_HEADER_PADDING_INFO  — alignment padding
```

### Object Type: ObTypeIndexTable

`TypeIndex` in the header is an index into `nt!ObTypeIndexTable`.
This table contains `_OBJECT_TYPE` pointers for each object class:

```
0: kd> dd nt!ObTypeIndexTable
# Common types:
#   [2]  Directory
#   [3]  SymbolicLink
#   [4]  Token
#   [5]  Job
#   [6]  Process
#   [7]  Thread
#   [8]  Partition
#   [14] File
#   [17] Section
#   [18] Semaphore
#   [19] Event
#   [20] Mutant
```

#### Expected Output

```
# dd nt!ObTypeIndexTable output:
fffff800`12340000  00000000`00000000 ffffc38f`00001000
fffff800`12340010  ffffc38f`00002000 ffffc38f`00003000
...
# Each 8-byte value is a pointer to an _OBJECT_TYPE structure
# Index [6] = Process type, [7] = Thread type, etc.
```

Failure looks like `Cannot read memory at nt!ObTypeIndexTable` — symbols not loaded. Run `.reload /f`.

---

## Section 7 — Token Structure and Privileges

### The Access Token

Every process and thread has an access token. The token determines
what the process is allowed to do — which users/groups it belongs to,
which privileges it holds, what security level it operates at.

```
TOKEN structure (key fields):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

+0x000  TokenSource          — "User32  " or "NtLmSsp " etc
+0x010  TokenId              — unique LUID
+0x018  AuthenticationId     — logon session LUID
+0x020  ParentTokenId
+0x028  ExpirationTime
+0x030  TokenLock
+0x040  ModifiedId           — bumped on each modification
+0x048  Privileges (_SEP_TOKEN_PRIVILEGES):
         +0x000  Present      — bitmask of privileges assigned
         +0x008  Enabled      — bitmask of currently enabled privileges
         +0x010  EnabledByDefault — default enabled set
+0x058  AuditPolicy
+0x060  SidHash
+0x098  SessionId            — terminal services session
+0x0a0  UserAndGroups        — pointer to SID_AND_ATTRIBUTES array
+0x0a8  UserAndGroupCount
+0x0b0  RestrictedSids
+0x0e8  PrivilegeCount
+0x0f0  SecurityAttributes
+0x100  AuthId
+0x108  IntegrityLevelIndex  — pointer to SID + attributes for integrity level
```

### Privilege Bits

Privileges are a 64-bit bitmask. Each bit position corresponds to a
privilege constant:

```
Privilege constants (luid value → privilege name):
  2   SeCreateTokenPrivilege
  3   SeAssignPrimaryTokenPrivilege
  4   SeLockMemoryPrivilege
  5   SeIncreaseQuotaPrivilege
  6   SeMachineAccountPrivilege
  7   SeTcbPrivilege             — "Act as part of OS" — most powerful
  8   SeSecurityPrivilege
  9   SeTakeOwnershipPrivilege
  10  SeLoadDriverPrivilege      — load arbitrary kernel drivers
  11  SeSystemProfilePrivilege
  12  SeSystemtimePrivilege
  13  SeProfileSingleProcessPrivilege
  14  SeIncreaseBasePriorityPrivilege
  15  SeCreatePagefilePrivilege
  16  SeCreatePermanentPrivilege
  17  SeBackupPrivilege          — bypass file ACLs for backup
  18  SeRestorePrivilege         — bypass file ACLs for restore
  19  SeShutdownPrivilege
  20  SeDebugPrivilege           — open any process (bypass DACL)
  21  SeAuditPrivilege
  22  SeSystemEnvironmentPrivilege
  23  SeChangeNotifyPrivilege
  24  SeRemoteShutdownPrivilege
  25  SeUndockPrivilege
  26  SeSyncAgentPrivilege
  27  SeEnableDelegationPrivilege
  28  SeManageVolumePrivilege
  29  SeImpersonatePrivilege     — impersonate any logged-on user
  30  SeCreateGlobalPrivilege
  31  SeTrustedCredManAccessPrivilege
  32  SeRelabelPrivilege
  33  SeIncreaseWorkingSetPrivilege
  34  SeTimeZonePrivilege
  35  SeCreateSymbolicLinkPrivilege
  36  SeDelegateSessionUserImpersonatePrivilege
```

**SeImpersonatePrivilege** (bit 29) and **SeAssignPrimaryTokenPrivilege**
(bit 3) are the Potato attack entry points — covered in Chapter 08.

**SeDebugPrivilege** (bit 20) lets you call `OpenProcess` on ANY
process regardless of DACL, which is why it's the first thing privilege
escalation checks for and Mimikatz requires.

### Checking Token Privileges

```c
// User mode: check current process token
// Compile: gcc check_token.c -o check_token.exe -ladvapi32

#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hToken;
    // Open the current process's primary token for reading
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    // Buffer to receive privilege list
    TOKEN_PRIVILEGES *pPrivs;
    DWORD dwSize = 0;

    // First call: get required buffer size
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);

    // Allocate buffer
    pPrivs = (TOKEN_PRIVILEGES*)malloc(dwSize);

    // Second call: actually fill the buffer
    GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize);

    // Walk the privilege array
    printf("Privilege count: %lu\n", pPrivs->PrivilegeCount);
    for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
        char name[256];
        DWORD nameLen = sizeof(name);
        // Convert LUID to human-readable privilege name
        LookupPrivilegeName(NULL, &pPrivs->Privileges[i].Luid, name, &nameLen);
        // SE_PRIVILEGE_ENABLED = 0x2, SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        printf("  [%s] Attrs: 0x%lx\n", name, pPrivs->Privileges[i].Attributes);
    }

    free(pPrivs);
    CloseHandle(hToken);
    return 0;
}
```

**Build and run:**

```powershell
# Compile (requires MinGW installed):
gcc check_token.c -o check_token.exe -ladvapi32

# Run:
.\check_token.exe
```

#### Expected Output

```
Privilege count: 5
  [SeShutdownPrivilege] Attrs: 0x0
  [SeChangeNotifyPrivilege] Attrs: 0x3
  [SeUndockPrivilege] Attrs: 0x0
  [SeIncreaseWorkingSetPrivilege] Attrs: 0x0
  [SeTimeZonePrivilege] Attrs: 0x0
```

Running as admin adds `SeDebugPrivilege`, `SeImpersonatePrivilege`, and others. Failure looks like `'gcc' is not recognized` — MinGW not on PATH. Fix the PATH environment variable and reopen the terminal.

```
# Kernel mode (WinDbg):
0: kd> !token            // dump current thread token
0: kd> dt _TOKEN [address]
0: kd> !token [token_address]
```

From a command line (using `whoami`):
```cmd
whoami /priv            ← list all privileges and their state
whoami /groups          ← group membership
whoami /all             ← full token dump
```

> **DEFENDER CALLOUT — Tokens and Privileges:** Audit who holds `SeDebugPrivilege` and `SeImpersonatePrivilege` in your environment. By default only Administrators and LocalSystem have SeDebug. If a service account has it, that is a misconfiguration. Use `whoami /priv` on every service account during hardening. Remove privileges not required for the function via Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment.

---

## Section 8 — Windows API Call Chain

### User Mode to Kernel: The Full Path

A simple `ReadFile()` call traverses multiple layers before a byte
is read from disk. Understanding this path tells you where kernel
exploits intercept it and where user-mode hooks apply.

```
USER MODE:
─────────────────────────────────────────────────────────────────────

Application                     calls
  ReadFile(hFile, buf, size, ...)    ← documented Win32 API
                                          │
kernelbase.dll                     ↓
  reads function from IAT → translates to internal call
                                          │
kernel32.dll                       ↓
  (historically the layer — now thin stub to kernelbase)
                                          │
ntdll.dll                          ↓
  NtReadFile(hFile, ...)             ← native NT API (Nt prefix)
  ZwReadFile(hFile, ...)             ← alias (Zw = zero in kernel, checks mode)
                                          │
  int 0x2e / syscall instruction     ↓   ← transitions to kernel mode
                                          │
─────────────────────────────────────────────────────────────────────

KERNEL MODE:
                                          │
KiSystemCall64()                   ↓   ← kernel system call dispatcher
  (validates syscall number, sets up kernel stack)
                                          │
SSDT lookup                        ↓
  KiServiceTable[syscall_number]         ← SSDT entry for NtReadFile
                                          │
ntoskrnl!NtReadFile()              ↓   ← actual kernel implementation
  → IoCallDriver() → driver stack
  → filesystem driver (ntfs.sys)
  → disk driver (disk.sys, storport.sys)
                                          │
                                          ↓
  returns NTSTATUS to KiSystemCall64
  copies output back to user-mode buffer
  returns to user mode
```

### SSDT — System Service Descriptor Table

The SSDT maps syscall numbers to kernel function addresses.

```
SSDT entry format (Windows 10 x64):
  Entry = (EPROCESS KiServiceTable relative offset) >> 4
  Real address = KiServiceTable + (Entry << 4)

# In WinDbg:
0: kd> dps nt!KiServiceTable L100    # dump first 256 SSDT entries

# Show specific entry (by syscall number):
0: kd> u nt!KiServiceTable + (poi(nt!KiServiceTable + syscall_num*4) >> 4)*4 + nt!KiServiceTable
```

SSDT hooking (patching entries to redirect syscalls) was the classic
rootkit technique on 32-bit Windows. On 64-bit Windows with KPP
(Kernel Patch Protection / PatchGuard), modifying the SSDT trips a
BSOD. Modern rootkits use filter drivers and callbacks instead.

### The Syscall Number — Complete Resolver

Every NT API call has a syscall number. This number varies between
Windows versions. Hardcoded syscall numbers break between builds.
The original chapter had an incomplete snippet. Here is the full resolver:

```python
# syscall_resolver.py — extract syscall numbers from ntdll.dll
# Run from any directory. No dependencies beyond stdlib.
# Usage: python syscall_resolver.py
# Or:    python syscall_resolver.py NtReadFile

import ctypes       # to load ntdll and read memory
import ctypes.wintypes
import struct       # to unpack raw bytes
import sys          # for command-line args

def get_syscall_number(func_name):
    """
    Resolve the syscall number for an NT API function.
    Windows stores it as: MOV EAX, <syscall_num> at the start of each Nt* stub.
    The opcode sequence is: 4C 8B D1 B8 XX XX 00 00  (on Win10 x64)
    Byte at offset 4 = low byte of syscall number.
    """
    # Load ntdll — it is always loaded in every process
    ntdll = ctypes.WinDLL('ntdll')

    # Get the function address as an integer
    try:
        func_addr = getattr(ntdll, func_name)
    except AttributeError:
        return None, f"Function '{func_name}' not found in ntdll"

    # Cast the function to a raw byte pointer so we can read its opcodes
    func_ptr = ctypes.cast(func_addr, ctypes.POINTER(ctypes.c_ubyte))

    # Read the first 8 bytes of the function stub
    raw = bytes([func_ptr[i] for i in range(8)])

    # Expected stub on Windows 10/11 x64:
    # 4C 8B D1     — mov r10, rcx  (save arg1 per syscall ABI)
    # B8 XX 00 00 00 — mov eax, <syscall_number>  (load the number)
    # Check for the expected prefix
    if raw[0] == 0x4C and raw[1] == 0x8B and raw[2] == 0xD1 and raw[3] == 0xB8:
        # Unpack the 4-byte syscall number starting at byte 4 (little-endian)
        syscall_num = struct.unpack_from('<I', raw, 4)[0]
        return syscall_num, None
    else:
        # Unexpected stub format — could be hooked by AV or different Windows version
        hex_bytes = ' '.join(f'{b:02X}' for b in raw)
        return None, f"Unexpected stub bytes: {hex_bytes} — may be hooked or wrong OS version"

def main():
    # If a function name was passed as argument, resolve just that one
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        # Default: resolve a useful set of NT APIs
        targets = [
            'NtReadFile', 'NtWriteFile', 'NtOpenProcess', 'NtAllocateVirtualMemory',
            'NtProtectVirtualMemory', 'NtCreateThreadEx', 'NtQuerySystemInformation',
            'NtReadVirtualMemory', 'NtWriteVirtualMemory', 'NtOpenThread',
        ]

    print(f"{'Function':<40} {'Syscall#':>10}  {'Hex':>8}")
    print("-" * 62)
    for name in targets:
        num, err = get_syscall_number(name)
        if num is not None:
            print(f"{name:<40} {num:>10}  {num:#010x}")
        else:
            print(f"{name:<40}  ERROR: {err}")

if __name__ == '__main__':
    main()
```

**Run it:**

```powershell
python syscall_resolver.py

# Or resolve a specific function:
python syscall_resolver.py NtOpenProcess NtCreateThreadEx
```

#### Expected Output

```
Function                                 Syscall#       Hex
--------------------------------------------------------------
NtReadFile                                     6  0x00000006
NtWriteFile                                    8  0x00000008
NtOpenProcess                                 38  0x00000026
NtAllocateVirtualMemory                       24  0x00000018
NtProtectVirtualMemory                        80  0x00000050
NtCreateThreadEx                             187  0x000000bb
NtQuerySystemInformation                      54  0x00000036
NtReadVirtualMemory                           63  0x0000003f
NtWriteVirtualMemory                          58  0x0000003a
NtOpenThread                                 130  0x00000082
```

Numbers are for Windows 11 23H2 — they will differ on other builds. That is the point. Failure looks like `ERROR: Unexpected stub bytes: E9 XX XX XX XX` — the stub starts with a JMP, meaning an AV/EDR has hooked this function. The resolver detected the hook.

> **DEFENDER CALLOUT — SSDT and Syscalls:** Any process that makes raw syscalls (bypassing ntdll.dll entirely) is attempting to evade user-mode hooks placed by EDR/AV. This is called "direct syscalls" or "syscall stomping" and it is a red flag. Defenders can detect it by monitoring for `syscall` instructions executed from memory regions that do not belong to ntdll.dll — some EDR products (e.g. CrowdStrike, SentinelOne) do exactly this with kernel callbacks.

---

## Section 9 — LSASS and Credential Storage

### What LSASS Is

`lsass.exe` (Local Security Authority Subsystem Service) runs as
SYSTEM and manages:
- Authentication (validates passwords, issues tokens)
- Active Directory operations
- Credential caching

Credentials live in LSASS process memory. Mimikatz works by opening
LSASS (requires SeDebugPrivilege or SYSTEM), reading the memory, and
decrypting the stored credentials.

### Where Credentials Live In Memory

```
LSASS memory credential locations:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Authentication packages (DLLs loaded into lsass):
  wdigest.dll   — stores cleartext credentials (if WDigest auth enabled)
                  Key: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
                       UseLogonCredential = 1 → cleartext stored (old/legacy)
                       Default in modern Windows: 0 (disabled)

  msv1_0.dll    — stores NTLM hashes (always present)
                  _MSV1_0_PRIMARY_CREDENTIAL structure

  kerberos.dll  — stores Kerberos tickets (TGTs and service tickets)
                  LSASS_KERB_CREDENTIAL structure

  lsasrv.dll    — the core LSA server; credential encryption keys here
```

### How Mimikatz Reads Credentials

```
Mimikatz sekurlsa::logonpasswords execution path:
1. OpenProcess(LSASS PID) with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
   (requires SeDebugPrivilege or SYSTEM)
2. Find LogonSessionList in lsasrv.dll via pattern scan
3. Walk the LogonSessionList linked list
4. For each session: call appropriate AP module reader
   - For NTLM: walk MSV credential structures, extract NT hash
   - For WDigest: find encrypted password, use LsaUnprotectMemory to decrypt
   - For Kerberos: walk ticket structures, extract TGT + service tickets
5. Output decoded credentials
```

```cmd
# Classic Mimikatz (requires SYSTEM or SeDebugPrivilege):
privilege::debug
sekurlsa::logonpasswords

# Dump from memory (if lsass dump already obtained):
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords

# Get NT hash only:
sekurlsa::msv
```

#### Expected Output (Mimikatz sekurlsa::logonpasswords)

```
Authentication Id : 0 ; 1234567 (00000000:0012d687)
Session           : Interactive from 1
User Name         : george
Domain            : DESKTOP-ABC123
Logon Server      : DESKTOP-ABC123
Logon Time        : 6/27/2026 8:00:00 AM
SID               : S-1-5-21-...

         msv :
          [00000003] Primary
          * Username : george
          * Domain   : DESKTOP-ABC123
          * NTLM     : aad3b435b51404eeaad3b435b51404ee   ← blank password hash
          * SHA1     : ...
```

Failure looks like `ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory` — means you don't have SeDebugPrivilege. Run Mimikatz from an elevated prompt. If LSASS PPL is enabled you need the driver method.

### LSASS Protected Process (PPL)

Modern Windows (2012R2+) can run LSASS as a Protected Process Light
(PPL). PPL prevents non-PPL processes from opening it with read access,
even as SYSTEM.

```
PPL bypass methods:
1. mimidrv.sys — Mimikatz kernel driver, removes PPL flag from EPROCESS
   ↓ driver signing required unless test signing mode
2. PPLdump — userland PPL bypass via Section and ALPC tricks
3. Duplicate process from another PPL process (requires PPL-level access)
4. Kernel exploit that writes EPROCESS.Flags directly
```

EPROCESS field for PPL:
```
EPROCESS +0x6c0  Protection (_PS_PROTECTION):
  SignatureLevel    — publisher signature level
  SectionSignatureLevel
  Type              — 0=None, 1=Light (PPL), 2=Full (PP)
```

Zeroing `Protection.Type` removes PPL status. Requires kernel write.

**Enable LSASS PPL on your own machine (hardening, not exploitation):**

```powershell
# Enable PPL for LSASS via registry (requires admin, takes effect after reboot):
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord

# Verify after reboot using Process Hacker:
# Find lsass.exe → right-click → Properties → General tab
# Should show "Protection: Windows Light"

# Or verify in WinDbg (kernel debug):
# 0: kd> dt _PS_PROTECTION [LSASS_EPROCESS + 0x6c0]
```

> **DEFENDER CALLOUT — LSASS:** Enable RunAsPPL (above). Also enable Windows Defender Credential Guard if your hardware supports it (requires TPM 2.0 + Secure Boot + UEFI). Credential Guard moves credential secrets into a VTL1 isolated process that SYSTEM cannot read. Monitor **Event ID 4624** (successful logon) and **Event ID 4648** (explicit credential logon) — bulk logon events from a single machine are a lateral movement indicator. Deploy Sysmon and enable Event ID 10 to catch any process that opens lsass.exe with VM_READ access.

---

## Section 10 — Debugging Internals With WinDbg

### Essential Kernel Debugging Commands

```
# Process and thread navigation
0: kd> !process 0 0              # list all processes
0: kd> .process /p /r [EPROCESS] # switch to process context
0: kd> !thread [ETHREAD]         # display thread info
0: kd> !pcr                      # processor control region

# Object inspection
0: kd> !object \                  # list object namespace root
0: kd> !object \Device            # list device objects
0: kd> dt _EPROCESS [address]     # dump EPROCESS structure
0: kd> dt _TOKEN [address]        # dump token
0: kd> !token [token_addr]        # formatted token display

# Memory
0: kd> !pte [virtual_address]     # dump page table entry chain
0: kd> !vtop [cr3] [virt_addr]    # virtual to physical translation
0: kd> !pool [physical_address]   # pool allocation info
0: kd> !poolused                  # pool usage by tag

# System info
0: kd> lm                         # list loaded modules
0: kd> !sysinfo                   # system information
0: kd> !irql                      # current IRQL
```

### Walking EPROCESS ActiveProcessLinks

```
# Find SYSTEM process (PID 4):
0: kd> !process 4 0

# Walk all EPROCESS via ActiveProcessLinks:
0: kd> dt _LIST_ENTRY [EPROCESS + ActiveProcessLinks_offset]

# Or use !process 0 0 shortcut to enumerate all
# Then correlate PID to understand process relationships
```

#### Expected Output

```
# .process /p /r [address] output:
Implicit process is now ffffc38f`04561080
Loading User Symbols
................................................................

# dt _EPROCESS [address] output (truncated):
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x388 UniqueProcessId  : 0x0000000000000004 Void
   +0x390 ActiveProcessLinks : _LIST_ENTRY [ 0xffffc38f`04561270 - 0xffffffff`deadbeef ]
   +0x4b8 Token            : _EX_FAST_REF
   +0x5a0 ImageFileName    : [15]  "System"
```

Failure looks like `dt: _EPROCESS not found` — run `.reload /f` to reload symbols.

---

## DEFENDER TAKEAWAY

These are the Monday-morning actions. Each bullet is something you can do right now to make your environment harder to compromise.

- **Enable LSASS PPL.** Set `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` and reboot. This single registry key stops the majority of credential dumping tools cold. Verify with Process Hacker that lsass.exe shows "Protection: Windows Light" after reboot.

- **Enable Windows Defender Credential Guard** (Windows 11 Pro/Enterprise with TPM 2.0 + Secure Boot). This moves credential secrets into a hardware-isolated partition. Even a SYSTEM-level attacker cannot read them. Enable via: Group Policy → Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security.

- **Audit SeDebugPrivilege holders.** Run `whoami /priv` on every service account. Only Administrators should have SeDebugPrivilege — and even then, consider removing it unless required. Group Policy path: Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Debug programs.

- **Deploy Sysmon and monitor Event ID 10 (Process Access).** Any process opening lsass.exe with `0x1010` access mask (VM_READ + QUERY_INFORMATION) is attempting credential dumping. This fires even before credentials are extracted. Sysmon config: include `<TargetImage>lsass.exe</TargetImage>` in the ProcessAccess rule.

- **Monitor Event ID 4672 (Special Logon) in the Windows Security log.** This fires when a session is created with privileged rights. If a non-administrative user triggers 4672, investigate immediately. Enable via: Group Policy → Audit Policy → Audit special logon → Success.

- **Audit for RWX memory pages.** Shellcode injectors allocate `PAGE_EXECUTE_READWRITE` memory. Legitimate code rarely needs this. Run Process Hacker periodically and filter the Memory tab for "Private" + "Execute" + "Write" regions in processes that should not have them (e.g. Word, Explorer, lsass). Flag any hit.

- **Watch for processes without a file-backed VAD.** Reflective DLL injection loads code from memory with no file on disk. The VAD tree shows a "Private" region with EXECUTE permission and no backing path. Volatility's `malfind` detects this pattern in memory forensics. For live detection, Sysmon **Event ID 8 (CreateRemoteThread)** is a precursor — flag cross-process thread creation from unexpected parents.

- **Disable WDigest cleartext caching.** Verify: `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential`. Should be 0 or absent. If it is 1, change it to 0. Legacy applications that require WDigest should be replaced — no exceptions.

---

## Key Terms

| Term | Definition |
|------|-----------|
| **User space / Kernel space** | Memory split: user-mode code runs in the lower portion, kernel and drivers in the upper (inaccessible from user mode without syscall) |
| **PTE** | Page Table Entry — describes physical address mapping and permissions (read/write/execute/NX) for a 4KB memory page |
| **VAD** | Virtual Address Descriptor — kernel data structure tracking a contiguous memory region's type and protection; stored in a per-process balanced binary tree |
| **PEB** | Process Environment Block — user-mode structure containing module list, process parameters, heap info; accessible via FS/GS segment register |
| **TEB** | Thread Environment Block — per-thread user-mode structure containing stack bounds, thread ID, last error, PEB pointer |
| **EPROCESS** | Executive Process — kernel control block for a process; contains PID, handle table, token, image name, active process list links |
| **ETHREAD** | Executive Thread — kernel control block for a thread; embedded KTHREAD, thread ID, start address, trap frame |
| **_OBJECT_HEADER** | 48-byte prefix on every kernel object; contains type index, ref count, security descriptor, optional headers bitmask |
| **Handle table** | Per-process index mapping handle values to kernel object pointers + granted access masks |
| **Token** | Kernel object encoding a process/thread's security context: user SID, group SIDs, privilege bitmask, integrity level |
| **SeDebugPrivilege** | Privilege granting ability to open any process regardless of DACL; required by Mimikatz and most injection techniques |
| **SeImpersonatePrivilege** | Privilege granting ability to impersonate any logged-on user's token; Potato attack entry point |
| **SSDT** | System Service Descriptor Table — kernel array mapping syscall numbers to function pointers; PatchGuard prevents modification |
| **ntdll.dll** | The user-mode gateway to kernel mode; contains all Nt/Zw API stubs with the syscall instruction |
| **LSASS** | Local Security Authority Subsystem Service — runs as SYSTEM, caches credentials; target of Mimikatz and credential extraction attacks |
| **PPL** | Protected Process Light — LSASS protection mode preventing non-PPL processes from reading its memory even as SYSTEM |
| **KPP / PatchGuard** | Kernel Patch Protection — Windows integrity check that BSODs the machine if critical kernel structures (SSDT, IDT, GDT) are modified |
| **EX_FAST_REF** | A pointer with the low 4 bits repurposed as a reference count; used for EPROCESS.Token — mask off low 4 bits to get real address |
| **Reflective DLL injection** | Technique to load a DLL from memory without touching disk; appears as an anonymous private VAD node with no backing file |
| **Direct syscall** | Calling into the kernel by executing the `syscall` instruction directly, bypassing ntdll stubs and the user-mode hooks EDRs place there |

---

## Drill 06 — Windows Internals Investigation

Go to `DRILLS/06_win_internals/`. Kernel debugging symbols are set up.
A target process is running.

Your mission:

1. Attach WinDbg to the target VM (kernel debug). Run `!process 0 0`.
   Locate the target process EPROCESS. Record the address.

2. From that EPROCESS, manually navigate to the Token. Use `dt _TOKEN`
   to dump the privilege bitmask. Identify which privileges are present
   and enabled. Cross-reference with the privilege list in this chapter.

3. Walk the ActiveProcessLinks list. Count all running processes.
   Identify which have matching PIDs to what Task Manager shows.
   Are there any hidden processes (on the list but not in Task Manager)?

4. Find kernel32.dll in the PEB module list. Walk the PEB_LDR_DATA
   InLoadOrderModuleList manually. For each entry, print DllBase and
   BaseDllName. Verify your results against `lm` in WinDbg.

5. Examine the VAD tree for the target process. Find which VAD node
   covers the kernel32.dll region. Document its protection flags.

6. Trigger an NtReadFile syscall and break on it in WinDbg. Trace the
   call from user mode through ntdll.dll into the kernel. Confirm the
   SSDT lookup resolves to ntoskrnl!NtReadFile.

7. **Bonus — defender drill:** Enable LSASS PPL on the target VM. Attempt
   to run `sekurlsa::logonpasswords` with Mimikatz. Document the error.
   Then try with `mimidrv.sys` loaded (test signing mode required). Document
   both outcomes. Write one paragraph on why PPL matters and one paragraph
   on why it is not a complete solution.

No code injection. No exploit development this drill. This is reconnaissance
of the terrain you will fight on.
