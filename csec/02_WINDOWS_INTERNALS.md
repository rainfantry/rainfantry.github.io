# Windows Internals for Red Team Operations

> **Audience:** Cert IV Cyber Security students who have read the C primer and networking guides  
> **Goal:** Understand how Windows actually works under the hood — processes, memory, security tokens, and the PE format — so you can write tools that operate "as part of the OS"  
> **Prerequisite:** You understand C basics, pointers, and structures

---

## Table of Contents

1. [Windows Architecture Overview](#1-windows-architecture-overview)
2. [The PE (Portable Executable) Format](#2-the-pe-portable-executable-format)
3. [Processes and Threads](#3-processes-and-threads)
4. [Virtual Memory and Address Space](#4-virtual-memory-and-address-space)
5. [Handles and Kernel Objects](#5-handles-and-kernel-objects)
6. [Security Tokens and Access Control](#6-security-tokens-and-access-control)
7. [The Windows Registry](#7-the-windows-registry)
8. [Windows Services Architecture](#8-windows-services-architecture)

---

## 1. Windows Architecture Overview

### User Mode vs Kernel Mode

Windows is divided into two privilege levels:

```
┌─────────────────────────────────────────────────────────────┐
│                        USER MODE                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Applications│  │   DLLs      │  │  Subsystem DLLs     │ │
│  │  (your code)│  │(kernel32.dll│  │(user32, gdi32, etc)│ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│  ┌──────┴────────────────┴─────────────────────┴──────┐    │
│  │              NTDLL.DLL (Native API)                 │    │
│  └──────────────────────┬──────────────────────────────┘    │
└─────────────────────────┼───────────────────────────────────┘
                          │  System Call (syscall)
┌─────────────────────────┼───────────────────────────────────┐
│                       KERNEL MODE                            │
│  ┌──────────────────────┴──────────────────────────────┐    │
│  │              NTOSKRNL.EXE (Executive)                │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │    │
│  │  │  Memory  │ │  Process │ │   I/O    │            │    │
│  │  │ Manager  │ │ Manager  │ │ Manager  │            │    │
│  │  └──────────┘ └──────────┘ └──────────┘            │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │        Kernel (scheduler, interrupts, SMP)          │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │    Hardware Abstraction Layer (HAL)                 │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**User Mode:**
- Your application code runs here
- Cannot directly access hardware
- Cannot directly access kernel memory
- Crashes here only kill your process

**Kernel Mode:**
- The operating system core runs here
- Direct hardware access
- Shared address space (a crash here = Blue Screen of Death)
- Entry via **system calls** (syscalls) from user mode

> **Red Team relevance:** Most malware runs in user mode and uses documented APIs to interact with the kernel. Advanced malware (rootkits, kernel drivers) runs in kernel mode.

### The Native API (NTDLL)

Every Windows API function you call (`CreateFile`, `OpenProcess`, `VirtualAlloc`) eventually calls a function in `ntdll.dll` — the **Native API** — which then issues a **system call** into the kernel.

```
Your Code
    ↓
CreateProcessA() in kernel32.dll
    ↓
NtCreateUserProcess() in ntdll.dll
    ↓
SYSCALL into kernel
    ↓
NtCreateUserProcess() in ntoskrnl.exe
```

**Why this matters:**
- `ntdll.dll` is the lowest layer of user-mode code
- Some malware bypasses `kernel32.dll` and calls `ntdll.dll` directly to evade API hooking
- EDR (Endpoint Detection and Response) tools often hook `kernel32.dll` functions to monitor behavior
- Direct syscalls bypass even `ntdll.dll` — this is an advanced evasion technique

---

## 2. The PE (Portable Executable) Format

### What is a PE File?

Every `.exe`, `.dll`, `.sys` (driver), and `.ocx` on Windows is a **PE file**. It is the container format that tells Windows how to load and execute the code inside.

### PE Structure Overview

```
┌─────────────────────────────┐
│     DOS Header (64 bytes)   │  ← "MZ" magic bytes (legacy MS-DOS)
├─────────────────────────────┤
│     DOS Stub (optional)     │  ← "This program cannot be run in DOS mode"
├─────────────────────────────┤
│     PE Signature "PE\0\0"   │  ← 4 bytes at offset specified by DOS header
├─────────────────────────────┤
│     COFF File Header        │  ← Machine type, number of sections, timestamp
├─────────────────────────────┤
│     Optional Header         │  ← Entry point, image base, subsystem, imports
├─────────────────────────────┤
│     Section Table           │  ← Array of IMAGE_SECTION_HEADER structures
├─────────────────────────────┤
│     .text section           │  ← Executable code
│     .data section           │  ← Initialized global/static variables
│     .rdata section          │  ← Read-only data (constants, import tables)
│     .rsrc section           │  ← Resources (icons, dialogs, version info)
│     ... more sections ...   │
└─────────────────────────────┘
```

### Key PE Fields for Malware Analysis

| Field | Purpose | Red Team Relevance |
|-------|---------|-------------------|
| `AddressOfEntryPoint` | Where execution starts (RVA) | Shellcode injection often overwrites this |
| `ImageBase` | Preferred load address | ASLR randomizes this |
| `Subsystem` | GUI (2) or Console (3) | Determines if a console window appears |
| `Import Table` | DLLs and functions this EXE needs | Replaced in packed malware |
| `Export Table` | Functions this DLL provides | Used for API hashing/resolution |
| `Section Headers` | Name, size, and permissions of each section | `.text` = code, `.data` = writable |

### Sections in Detail

#### `.text` — The Code Section
- Contains the actual machine code (CPU instructions)
- Marked as **READ + EXECUTE** (not writable)
- This is where your `main()` function lives

#### `.data` — Initialized Data
- Global and static variables that have initial values
- Marked as **READ + WRITE**

#### `.rdata` — Read-Only Data
- String literals, constants, import tables
- Marked as **READ only**

#### `.rsrc` — Resources
- Icons, images, dialogs, version information
- Malware sometimes hides data here

> **Red Team relevance:** Packers and crypters encrypt the `.text` section and decrypt it at runtime. This changes the hash of the file and defeats static signature detection.

---

## 3. Processes and Threads

### What is a Process?

A **process** is a container that holds everything a running program needs:

- **Virtual address space** — The memory the process can access
- **Executable code** — Loaded from the `.exe` file
- **Data** — Global variables, heap allocations
- **Handles** — References to kernel objects (files, threads, sockets)
- **Security context** — The token (user identity) of the process
- **Environment variables** — PATH, USERNAME, etc.

```
┌─────────────────────────────────────┐
│            PROCESS                  │
│  ┌───────────────────────────────┐  │
│  │  Virtual Address Space        │  │
│  │  ┌─────────┐ ┌─────────────┐ │  │
│  │  │ .text   │ │   Heap      │ │  │
│  │  │ .data   │ │   Stack     │ │  │
│  │  │ .rdata  │ │   (threads) │ │  │
│  │  └─────────┘ └─────────────┘ │  │
│  └───────────────────────────────┘  │
│  ┌─────────┐ ┌─────────┐           │
│  │ Handle  │ │ Handle  │  ...      │
│  │ Table   │ │ Table   │           │
│  └─────────┘ └─────────┘           │
│  ┌───────────────────────────────┐  │
│  │  Security Token (Identity)    │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### What is a Thread?

A **thread** is the unit of execution within a process. A process has at least one thread (the main thread). Threads share the process's memory but have their own:

- **Stack** — Local variables and function call history
- **Registers** — CPU state (instruction pointer, etc.)
- **Thread Local Storage** — Variables unique to this thread

```c
// Create a thread that runs MyFunction
HANDLE hThread = CreateThread(
    NULL,           // Default security
    0,              // Default stack size
    MyFunction,     // Function to run
    (LPVOID)param,  // Parameter passed to function
    0,              // Run immediately
    NULL            // Don't need thread ID
);
```

### Process Creation Deep Dive

When you call `CreateProcessA()`, Windows does this:

1. **Create the process object** in kernel mode (`NtCreateUserProcess`)
2. **Map the EXE** into the new process's address space
3. **Create the initial thread** with a stack
4. **Load required DLLs** (kernel32, ntdll, etc.) and resolve imports
5. **Start execution** at the EXE's entry point

> **Red Team relevance:** DLL injection works by creating a remote thread in another process that loads your DLL. Process hollowing works by unmapping the legitimate EXE and replacing it with malicious code.

---

## 4. Virtual Memory and Address Space

### Virtual Memory Basics

Every process on Windows has its own **virtual address space** — a 4 GB (x86) or 128 TB (x64) "fake" memory space that the process believes it owns exclusively. The CPU's **Memory Management Unit (MMU)** translates virtual addresses to physical RAM addresses.

```
Process A's View          Physical RAM
┌──────────────┐         ┌──────────────┐
│ 0x00000000   │         │              │
│   (NULL)     │         │  OS Kernel   │
├──────────────┤         │   (shared)   │
│              │         ├──────────────┤
│   .text      │───────►│ Process A    │
│   .data      │        │   Code       │
│   Heap       │───────►│              │
│   Stack      │───────►├──────────────┤
│              │        │ Process B    │
├──────────────┤        │   Code       │
│ 0x7FFFFFFF   │        │              │
└──────────────┘        └──────────────┘
```

### Memory Allocation APIs

| Function | Purpose | Red Team Use |
|----------|---------|-------------|
| `VirtualAlloc` | Reserve or commit memory pages | Allocate space for shellcode |
| `VirtualProtect` | Change memory permissions (RWX) | Make shellcode executable |
| `VirtualFree` | Release allocated memory | Cleanup |
| `HeapAlloc` | Allocate from the process heap | General memory allocation |
| `WriteProcessMemory` | Write to another process's memory | DLL injection, process hollowing |
| `ReadProcessMemory` | Read from another process's memory | Credential dumping, recon |

### Memory Permissions

| Permission | Meaning | Typical Use |
|------------|---------|-------------|
| `PAGE_READWRITE` (RW) | Can read and write | Data, buffers |
| `PAGE_EXECUTE_READ` (RX) | Can read and execute | Code sections |
| `PAGE_EXECUTE_READWRITE` (RWX) | Can read, write, AND execute | Shellcode staging (suspicious!) |
| `PAGE_NOACCESS` | Cannot access at all | Guard pages, protection |

> **Red Team relevance:** Allocating RWX (Read-Write-Execute) memory is a common malware behavior. EDR tools monitor for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`.

### The Stack vs The Heap

**Stack:**
- Automatically managed (grows/shrinks with function calls)
- Fast allocation
- Limited size (default 1 MB on Windows)
- Stores local variables, function parameters, return addresses
- **Overflowing the stack overwrites the return address → exploit development**

**Heap:**
- Manually managed (`malloc`, `HeapAlloc`)
- Slower allocation
- Large (limited only by available RAM)
- Stores dynamically allocated data
- **Heap corruption attacks are complex but possible**

---

## 5. Handles and Kernel Objects

### What is a Handle?

A **handle** is an opaque reference (like a ticket number) to a **kernel object** — a data structure that lives in kernel memory and is managed by the Windows kernel.

Common kernel objects:
- **Process** — A running program
- **Thread** — A unit of execution
- **File** — An open file on disk
- **Event** — A synchronization signal
- **Semaphore** — A counter for resource access
- **Token** — A security identity

```c
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,  // Desired access
    FALSE,               // Don't inherit handle
    1234                 // Target PID
);
// hProcess is now a handle to process 1234
```

### Handle Tables

Each process has a **handle table** — an array of pointers to kernel objects. The handle value (e.g., `0x00000124`) is just an index into this table.

```
Process Handle Table
┌─────────┬──────────────────────┐
│ Handle  │ Kernel Object        │
├─────────┼──────────────────────┤
│ 0x004   │ File (C:\log.txt)    │
│ 0x008   │ Thread (ID 456)      │
│ 0x00C   │ Process (ID 1234)    │
│ 0x010   │ Event (MyEvent)      │
│ 0x014   │ Token (User George)  │
└─────────┴──────────────────────┘
```

> **Important:** A handle is only valid within the process that created it. Process A cannot use Process B's handles directly. However, you can **duplicate** a handle from one process to another using `DuplicateHandle()`.

---

## 6. Security Tokens and Access Control

### What is a Token?

A **token** is a kernel object that represents a user's **security context** — their identity, group memberships, and privileges. Every process has a token that determines what it can and cannot do.

```
TOKEN
├── User SID (e.g., S-1-5-21-...-1001 = George)
├── Group SIDs (Administrators, Users, Everyone)
├── Privileges (SeDebugPrivilege, SeBackupPrivilege, etc.)
├── Session ID
├── Integrity Level (Low, Medium, High, System)
└── DACL (what others can do to this token)
```

### SIDs (Security Identifiers)

A **SID** is a unique identifier for a user or group. It looks like:
```
S-1-5-21-3623811015-3361044348-30300820-1013
└┬┘│ └┬──────────────────────────────┘ └──┬──┘
 │ │  │                                    └── Relative ID (RID) — unique within domain
 │ │  └─────────────────────────────────────── Domain SID
 │ └────────────────────────────────────────── Authority (5 = NT Authority)
 └──────────────────────────────────────────── Revision
```

Well-known SIDs:
| SID | Account |
|-----|---------|
| S-1-5-18 | LOCAL SYSTEM |
| S-1-5-19 | LOCAL SERVICE |
| S-1-5-20 | NETWORK SERVICE |
| S-1-5-32-544 | Administrators |
| S-1-5-32-545 | Users |
| S-1-5-11 | Authenticated Users |

### Privileges

Privileges are system-level capabilities, independent of file permissions:

| Privilege | What It Enables |
|-----------|----------------|
| `SeDebugPrivilege` | Open any process for reading/writing (even SYSTEM) |
| `SeBackupPrivilege` | Read any file, bypassing ACLs |
| `SeRestorePrivilege` | Write any file, bypassing ACLs |
| `SeTakeOwnershipPrivilege` | Take ownership of any object |
| `SeLoadDriverPrivilege` | Load kernel drivers |
| `SeTcbPrivilege` | Act as part of the operating system |

> **Red Team relevance:** `SeDebugPrivilege` is the key to process injection. If you have it (administrators do), you can open any process, read its memory, and write to it.

### Token Impersonation

Windows allows a thread to **impersonate** another user's token. This is how services running as SYSTEM can act on behalf of a logged-in user.

```c
// Open a process, steal its token, then impersonate it
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
HANDLE hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);

HANDLE hDupToken;
DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                 TokenPrimary, &hDupToken);

// Now this thread runs as the user from the stolen token
ImpersonateLoggedOnUser(hDupToken);
```

> **This is exactly what TokenVault.exe does.** It finds a SYSTEM process, opens it, steals the token, and impersonates it.

### Access Control Lists (ACLs)

Every securable object (file, registry key, process, token) has a **DACL** (Discretionary Access Control List) that says who can do what.

```
File: C:\secret.txt
┌─────────────────────────────────────────┐
│  DACL                                   │
│  ┌───────────────────────────────────┐  │
│  │  Administrators: Full Control     │  │
│  │  George: Read, Write              │  │
│  │  Everyone: No Access              │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**ACE (Access Control Entry):** Each line in the DACL is an ACE. It contains:
- A SID (who)
- An access mask (what they can do: read, write, execute, delete)
- A type (allow or deny)

---

## 7. The Windows Registry

### What is the Registry?

The **Registry** is a hierarchical database that stores configuration settings for Windows, hardware, software, and user preferences. It is the "brain" of Windows.

### Registry Hives

| Hive | File on Disk | Contents |
|------|-------------|----------|
| `HKEY_LOCAL_MACHINE (HKLM)` | `SYSTEM`, `SOFTWARE` | System-wide settings |
| `HKEY_CURRENT_USER (HKCU)` | `NTUSER.DAT` | Current user's settings |
| `HKEY_USERS (HKU)` | Multiple `NTUSER.DAT` | All user profiles |
| `HKEY_CLASSES_ROOT (HKCR)` | Merged from HKLM+HKCU | File associations |
| `HKEY_CURRENT_CONFIG (HKCC)` | `SYSTEM` subset | Current hardware profile |

### Registry Keys for Red Team Operations

#### Persistence: Run Keys
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
Programs listed here start automatically when the user logs in.

#### Service Configuration
```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```
Each service has a key here with:
- `ImagePath` — Path to the service executable
- `Start` — Startup type (0=Boot, 2=Auto, 3=Manual, 4=Disabled)
- `Type` — Service type (1=Kernel driver, 16=Own process, 32=Shared process)

#### Defender Exclusions
```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions
```
Adding entries here tells Defender to ignore specific paths or file types.

> **Red Team relevance:** ghost_svc.c (persistence) creates a service registry key. shadow_evasion.c adds Defender exclusions to registry. Both operate directly on these keys.

---

## 8. Windows Services Architecture

### What is a Service?

A **service** is a program that runs in the background, often without user interaction, typically with SYSTEM privileges. Services are managed by the **Service Control Manager (SCM)**.

### Service Types

| Type | Value | Description |
|------|-------|-------------|
| SERVICE_KERNEL_DRIVER | 0x1 | Device driver (runs in kernel mode) |
| SERVICE_FILE_SYSTEM_DRIVER | 0x2 | File system driver |
| SERVICE_WIN32_OWN_PROCESS | 0x10 | Runs in its own process |
| SERVICE_WIN32_SHARE_PROCESS | 0x20 | Shares a process with other services |

### Service Startup Types

| Type | Value | When It Starts |
|------|-------|----------------|
| SERVICE_BOOT_START | 0 | During OS boot (drivers only) |
| SERVICE_SYSTEM_START | 1 | During kernel initialization |
| SERVICE_AUTO_START | 2 | Automatic (during system start) |
| SERVICE_DEMAND_START | 3 | Manual (when started by user/admin) |

---

## 8.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Understanding Windows internals — PE format, processes, memory, tokens — gives you the foundation to write tools that "operate as part of the OS."

**What the lab hides from you:** Modern EDR operates **below** the level this document covers. EDR uses **kernel callbacks** to monitor process creation, **minifilter drivers** to intercept file I/O, and **hypervisor-based isolation** (Credential Guard, HVCI) that this document does not address. Understanding user-mode internals is necessary but not sufficient — the battleground has moved to kernel mode and hypervisor mode.

### How User-Mode Knowledge Dies in Production

| Defense | How It Kills User-Mode Techniques | Your Lab Bypass |
|---------|----------------------------------|-----------------|
| Kernel callbacks | `PsSetCreateProcessNotifyRoutine` monitors all process creation | No kernel-level monitoring |
| Minifilter drivers | File system filters intercept I/O before it reaches user mode | No minifilter in lab |
| HVCI (Hypervisor CI) | Prevents unsigned drivers, protects kernel integrity | Not enabled on lab hardware |
| Credential Guard | Hypervisor-isolated LSASS; token theft yields encrypted data | Not enabled |
| PPL (Protected Process Light) | EDR runs as PPL; cannot be opened from user mode | No third-party EDR |
| ETW (Event Tracing) | Kernel-level logging at hundreds of thousands of events/sec | No ETW collection |

### What a Professional Red Teamer Would Do

**Instead of relying solely on user-mode knowledge, they would:**
- **Study kernel architecture** — understand how EDR registers callbacks, how to bypass them from kernel mode
- **Learn hypervisor fundamentals** — understand how Hyper-V isolates Credential Guard, how HVCI works
- **Master ETW internals** — understand providers, sessions, and how to patch or silence them
- **Understand hardware trust roots** — TPM, Secure Boot, UEFI — the foundation that everything else builds on

**Key difference:** The pro knows that user-mode is the **visible tip of the iceberg**. The real control is in kernel mode, hypervisor mode, and hardware. The pro studies the entire stack.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Windows driver development | Kernel-mode code can bypass all user-mode defenses | Windows Driver Kit (WDK) |
| Hyper-V internals | Understand how virtualization-based security works | "Windows Internals, Part 2" — Chapter 9 |
| ETW architecture | Kernel logging is the backbone of modern EDR | Microsoft Docs: "Event Tracing" |
| UEFI / Secure Boot | Hardware trust root; everything else depends on it | "Rootkits and Bootkits" by Matrosov et al. |

### The Honest Bottom Line

> This internals guide teaches user-mode Windows architecture — PE format, processes, memory, tokens, registry, services. It is **essential foundation** but **not sufficient** for modern red teaming. In the real world, EDR lives in kernel mode and hypervisor mode. The value is understanding the OS from the inside. Learn kernel driver development and hypervisor internals next.

---
| SERVICE_DISABLED | 4 | Cannot be started |

### The Service Control Manager (SCM)

The SCM is a special process (`services.exe`) that:
- Maintains the database of installed services
- Starts and stops services on demand
- Handles service dependencies
- Reports service status

```
Service Control Manager (services.exe)
┌──────────────────────────────────────┐
│  Service Database                    │
│  ┌──────────┐ ┌──────────┐          │
│  │ Service A│ │ Service B│  ...     │
│  │ (running)│ │ (stopped)│          │
│  └──────────┘ └──────────┘          │
└──────────────────────────────────────┘
         │
    StartService()
         │
         ▼
┌──────────────────────────────────────┐
│  Service Process (svchost.exe)       │
│  ┌────────────────────────────────┐  │
│  │  Service DLL / Executable      │  │
│  │  Runs as: SYSTEM / LocalService│  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

### Writing a Windows Service

A service is not a normal program. It must:
1. Call `StartServiceCtrlDispatcher()` to connect to the SCM
2. Register a control handler function
3. Report its status to the SCM via `SetServiceStatus()`
4. Run its main logic in a separate thread

> **This is exactly what ghost_svc.c does.** It creates a service that the SCM can start automatically at boot, running as SYSTEM.

---

## Quick Reference Cheat Sheet

| Concept | One-Liner |
|---------|-----------|
| User Mode | Where applications run; limited privileges |
| Kernel Mode | Where Windows core runs; full privileges |
| NTDLL | The lowest user-mode DLL; gateway to kernel |
| PE File | The container format for EXEs and DLLs |
| `.text` section | Contains executable code |
| Process | Container: memory + handles + token + threads |
| Thread | Unit of execution; has its own stack and registers |
| VirtualAlloc | Allocate memory in a process |
| Handle | Reference to a kernel object |
| Token | Security identity (user + groups + privileges) |
| SID | Unique identifier for a user or group |
| SeDebugPrivilege | Allows access to any process |
| DACL | Who can access an object |
| Registry | Windows configuration database |
| Run Keys | Programs that start at login |
| Service | Background program, often running as SYSTEM |
| SCM | Service Control Manager — manages services |

---

*"To write malware that operates as part of the OS, you must first understand how the OS operates."*
