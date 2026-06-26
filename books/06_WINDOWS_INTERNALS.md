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

### Why VADs Matter For Exploitation

- **Hiding injected code**: a reflective DLL appears as an anonymous
  private mapping — no file-backed VAD entry, so it doesn't show up
  in normal module enumeration.
- **ASLR**: the kernel uses VAD entries to track allocated regions and
  ensure randomised base assignments don't collide.
- **Memory forensics**: walking the VAD tree reveals ALL mapped regions,
  including injected code that's invisible to `EnumProcessModules`.

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

```nasm
; Classic PEB walk to find kernel32 base (x86)
; TIB (at FS:[0]) → PEB (FS:[0x30]) → Ldr → InLoadOrderModuleList

xor ecx, ecx
mov eax, fs:[ecx+0x30]   ; PEB
mov eax, [eax+0x0c]      ; Ldr
mov esi, [eax+0x14]      ; InMemoryOrderModuleList (first entry = ntdll in Win10)
lodsd                    ; advance to second entry
xchg eax, esi
lodsd                    ; advance to third entry (kernel32.dll)
mov ebx, [eax+0x10]      ; DllBase = kernel32.dll base
```

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

```
; Access PEB from x64 code:
mov rax, gs:[0x60]       ; PEB address
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

**ActiveProcessLinks** — every running process is on this circular
doubly-linked list. Walk it to enumerate all processes:

```
0: kd> !process 0 0     # list all processes
0: kd> dt _EPROCESS     # dump EPROCESS structure definition
0: kd> dt _EPROCESS @$proc   # dump current process EPROCESS
```

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
HANDLE hToken;
OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
GetTokenInformation(hToken, TokenPrivileges, ...);

// Kernel mode (WinDbg):
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

### The Syscall Number

Every NT API call has a syscall number. This number varies between
Windows versions. Hardcoded syscall numbers break between builds.

```
# Resolve syscall numbers (from ntdll):
python3
>>> import ctypes
>>> ntdll = ctypes.WinDLL('ntdll')
>>> func = getattr(ntdll, 'NtReadFile')
>>> # First bytes of function: 4C 8B D1 B8 XX 00 00 00  (mov eax, syscall_num)
# The byte at offset 4 is the syscall number

# Or use SyscallDumper / NtTracer tooling
```

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

No code injection. No exploit development this drill. This is reconnaissance
of the terrain you will fight on.
