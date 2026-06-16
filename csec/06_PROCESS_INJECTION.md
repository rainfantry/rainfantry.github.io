# Process Injection Theory and Techniques

> **Audience:** Cert IV Cyber Security students who understand Windows internals  
> **Goal:** Understand the theory behind DLL injection, reflective DLLs, and other code injection methods  
> **Prerequisite:** You have read `windows_internals.md` and understand VirtualAlloc, CreateRemoteThread, and handles

---

## Table of Contents

1. [What is Process Injection?](#1-what-is-process-injection)
2. [Classic DLL Injection](#2-classic-dll-injection)
3. [Reflective DLL Injection](#3-reflective-dll-injection)
4. [Process Hollowing](#4-process-hollowing)
5. [APC Injection](#5-apc-injection)
6. [Thread Hijacking](#6-thread-hijacking)
7. [Detection and Evasion](#7-detection-and-evasion)

---

## 1. What is Process Injection?

**Process injection** is the act of executing arbitrary code inside the address space of another process. It is one of the most powerful techniques in malware because it:

- **Hides inside a legitimate process** (e.g., `explorer.exe`, `notepad.exe`)
- **Inherits the target process's privileges** (inject into SYSTEM process = run as SYSTEM)
- **Bypasses application whitelisting** (the parent process is trusted)
- **Evades process-based detection** (EDR monitors new processes, not injected threads)

```
Before Injection:
┌─────────────────┐    ┌─────────────────┐
│   Malware.exe   │    │  explorer.exe   │
│   (suspicious)  │    │  (trusted)      │
│                 │    │                 │
│  [your code]    │    │  [Explorer code]│
└─────────────────┘    └─────────────────┘

After Injection:
┌─────────────────┐    ┌─────────────────────────────┐
│   Malware.exe   │    │  explorer.exe               │
│   (can exit)    │    │  (trusted — looks normal)   │
│                 │    │                             │
│  (nothing)      │    │  [Explorer code]            │
└─────────────────┘    │  [YOUR INJECTED CODE]  ◄───┘
                       └─────────────────────────────┘
```

---

## 2. Classic DLL Injection

### The Technique

Classic DLL injection is the simplest and most widely used method. It forces a target process to load a DLL from disk.

**Steps:**
1. **Open the target process** with `OpenProcess()`
2. **Allocate memory** in the target with `VirtualAllocEx()`
3. **Write the DLL path** into the target's memory with `WriteProcessMemory()`
4. **Create a remote thread** that calls `LoadLibraryA()` with the DLL path
5. **Windows loads the DLL** into the target process, executing its `DllMain()`

### Why LoadLibraryA?

`LoadLibraryA()` is a Windows API function that loads a DLL into the calling process. Every process already has this function in `kernel32.dll`.

By creating a remote thread that starts at `LoadLibraryA`, you trick the target process into loading your DLL for you.

```
Your Process                    Target Process (e.g., explorer.exe)
┌──────────────────┐           ┌──────────────────────────────────┐
│ 1. OpenProcess() │──────────►│ Gets handle with ALL_ACCESS      │
├──────────────────┤           ├──────────────────────────────────┤
│ 2. VirtualAllocEx│──────────►│ Allocates RW memory for path     │
├──────────────────┤           ├──────────────────────────────────┤
│ 3. WriteProcess  │──────────►│ Writes "C:\evil.dll" to alloc    │
│    Memory()      │           │                                  │
├──────────────────┤           ├──────────────────────────────────┤
│ 4. GetProcAddress│           │                                  │
│    (LoadLibraryA)│           │                                  │
├──────────────────┤           ├──────────────────────────────────┤
│ 5. CreateRemote  │──────────►│ Creates thread starting at       │
│    Thread()      │           │ LoadLibraryA("C:\evil.dll")      │
└──────────────────┘           │                                  │
                               │ LoadLibraryA loads the DLL       │
                               │ and calls DllMain()              │
                               └──────────────────────────────────┘
```

### injector.c — What It Actually Does

The injector in your kill chain uses this exact technique:

```c
// Simplified conceptual flow
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllPathLen,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);

WriteProcessMemory(hProcess, remoteMem, dllPath, dllPathLen, NULL);

// CreateRemoteThread calls LoadLibraryA in the target process
HANDLE hThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
    remoteMem,   // Parameter = address of DLL path string
    0,
    NULL
);
```

### DllMain — The Entry Point

When a DLL is loaded, Windows calls its `DllMain()` function:

```c
BOOL APIENTRY DllMain(HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // The DLL was just loaded into a process
            // THIS IS WHERE YOUR PAYLOAD RUNS
            CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
            // A new thread was created in the process
            break;
        case DLL_THREAD_DETACH:
            // A thread exited
            break;
        case DLL_PROCESS_DETACH:
            // The DLL is being unloaded
            break;
    }
    return TRUE;
}
```

> **Key insight:** `DLL_PROCESS_ATTACH` is your payload trigger. When the injected DLL loads, `DllMain` fires and your code executes inside the target process.

---

## 3. Reflective DLL Injection

### The Problem with Classic Injection

Classic DLL injection writes a **file path** to disk and calls `LoadLibraryA()`. This has problems:

1. **The DLL must exist on disk** — Forensic analysis finds the file
2. **LoadLibraryA is monitored** — EDR hooks this function
3. **The DLL appears in the PEB** — The Process Environment Block lists all loaded DLLs

### The Solution: Reflective Loading

**Reflective DLL injection** loads a DLL **entirely from memory** without calling `LoadLibraryA` and without writing to disk.

**How it works:**
1. Read the DLL file into memory in your own process
2. Allocate memory in the target process
3. **Manually map the DLL** — Parse the PE headers and copy sections to the right places
4. **Manually resolve imports** — Walk the import table and patch function addresses
5. **Manually fix relocations** — Adjust memory addresses for the new base
6. **Call the DLL's entry point** directly

```
Your Process                          Target Process
┌─────────────────────┐              ┌─────────────────────────────┐
│ ReadFile("evil.dll")│              │                             │
│ → DLL in memory     │              │                             │
├─────────────────────┤              ├─────────────────────────────┤
│ Parse PE headers    │              │                             │
│ (find .text, .data) │              │                             │
├─────────────────────┤              ├─────────────────────────────┤
│ VirtualAllocEx()    │─────────────►│ Allocate RWX memory         │
├─────────────────────┤              ├─────────────────────────────┤
│ WriteProcessMemory()│─────────────►│ Write mapped DLL sections   │
├─────────────────────┤              ├─────────────────────────────┤
│ Resolve imports     │              │                             │
│ (patch IAT)         │─────────────►│ Write resolved addresses    │
├─────────────────────┤              ├─────────────────────────────┤
│ Fix relocations     │─────────────►│ Adjust base addresses       │
├─────────────────────┤              ├─────────────────────────────┤
│ CreateRemoteThread()│─────────────►│ Call DllMain() directly     │
│ (address = entry)   │              │ (no LoadLibraryA!)          │
└─────────────────────┘              └─────────────────────────────┘
```

### Why It's Called "Reflective"

The DLL **reflects on itself** — it parses its own PE headers to figure out where to load itself. A reflective DLL contains a small bootstrap function that:
1. Finds its own base address in memory
2. Parses its own PE headers
3. Loads itself into the correct memory layout
4. Calls its own `DllMain()`

> **Red Team relevance:** Reflective injection is the gold standard for stealth. No disk artifact. No `LoadLibraryA` call. The DLL doesn't appear in the normal loaded modules list. Tools like Cobalt Strike and Metasploit use this technique.

---

## 4. Process Hollowing

### The Concept

Process hollowing creates a **legitimate process in a suspended state**, then **replaces its memory with malicious code**, and resumes it. From the outside, it looks like a normal process (e.g., `svchost.exe`) but it's running your code.

**Steps:**
1. Create a legitimate process (e.g., `notepad.exe`) in **SUSPENDED** state
2. **Unmap** (hollow out) the legitimate code from memory (`NtUnmapViewOfSection`)
3. **Allocate new memory** where the legitimate code was
4. **Write malicious code** into the allocated space
5. **Fix the thread context** to point to your entry point
6. **Resume the thread** — the process now runs your code with the legitimate name

```
Step 1: Create Suspended Process
┌─────────────────────────────┐
│  notepad.exe (SUSPENDED)    │
│  ┌───────────────────────┐  │
│  │  Legitimate notepad   │  │
│  │  code in memory       │  │
│  └───────────────────────┘  │
└─────────────────────────────┘

Step 2: Unmap (Hollow Out)
┌─────────────────────────────┐
│  notepad.exe (SUSPENDED)    │
│  ┌───────────────────────┐  │
│  │  (empty — unmapped)   │  │
│  └───────────────────────┘  │
└─────────────────────────────┘

Step 3: Write Malicious Code
┌─────────────────────────────┐
│  notepad.exe (SUSPENDED)    │
│  ┌───────────────────────┐  │
│  │  YOUR MALICIOUS CODE  │  │
│  └───────────────────────┘  │
└─────────────────────────────┘

Step 4: Resume
┌─────────────────────────────┐
│  notepad.exe (RUNNING)      │
│  ┌───────────────────────┐  │
│  │  YOUR MALICIOUS CODE  │  │  ← Process name is still "notepad.exe"
│  └───────────────────────┘  │    Parent is still explorer.exe
└─────────────────────────────┘    Looks 100% legitimate in Task Manager
```

### Why Process Hollowing is Powerful

| Defense Mechanism | How Hollowing Beats It |
|-------------------|----------------------|
| Application whitelisting | The parent process is a trusted executable |
| Parent process monitoring | Parent is legitimate (`explorer.exe` spawning `notepad.exe`) |
| Hash-based detection | The file on disk is the real `notepad.exe` |
| Behavioral analysis | The process name matches expected behavior |

> **Red Team relevance:** Advanced malware (e.g., TrickBot, Dridex) uses process hollowing to hide inside legitimate Windows processes. EDR tools detect it by monitoring `NtUnmapViewOfSection` and `CreateProcess` with `CREATE_SUSPENDED`.

---

## 5. APC Injection

### What is an APC?

An **Asynchronous Procedure Call (APC)** is a function that executes in the context of a specific thread. Windows uses APCs for things like I/O completion callbacks.

### APC Injection

If you can find a thread in **alertable state** (waiting with `SleepEx`, `WaitForSingleObjectEx`, etc.), you can queue an APC to it. When the thread enters alertable state, your APC function executes.

```c
// Find a thread in the target process
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

// Queue an APC that loads our DLL
QueueUserAPC(
    (PAPCFUNC)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"),
    hThread,
    (ULONG_PTR)dllPathInTargetMemory
);

// The next time the thread is alertable, LoadLibraryA executes
```

**The catch:** The thread must be in **alertable state** for the APC to execute immediately. If it's not, the APC is queued but doesn't run until the thread becomes alertable.

> **Red Team relevance:** APC injection is stealthy because it doesn't create a new thread. However, finding an alertable thread is unreliable. Some malware forces threads into alertable state using `NtAlertThread`.

---

## 6. Thread Hijacking

### The Concept

Instead of creating a new thread, you **hijack an existing thread** in the target process:

1. Suspend a running thread with `SuspendThread()`
2. Get its context (CPU registers) with `GetThreadContext()`
3. Change the instruction pointer (`RIP`/`EIP`) to point to your shellcode
4. Resume the thread with `ResumeThread()`

```
Normal Thread Execution:
┌────────────────────────────────────────┐
│ Thread running legitimate code         │
│ [instruction 100] → [101] → [102] ...  │
└────────────────────────────────────────┘

After Hijacking:
┌────────────────────────────────────────┐
│ Thread redirected to shellcode         │
│ [instruction 100] → [SHELLCODE] → ...  │
│     ▲                                  │
│     └── RIP/EIP changed to point here  │
└────────────────────────────────────────┘
```

### The Challenge

The hijacked thread's **stack and registers** are in an unknown state. Your shellcode must:
- Save all registers before executing
- Restore them before returning to normal execution
- Or never return (if the goal is to run a payload and let the thread die)

> **Red Team relevance:** Thread hijacking is advanced and fragile. If the thread was in the middle of a critical section or holding a lock, hijacking it can crash the process. Used primarily in sophisticated malware and game cheats.

---

## 7. Detection and Evasion

### How EDR Detects Injection

| Detection Method | What It Monitors |
|------------------|-----------------|
| **API Hooking** | `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` |
| **ETW (Event Tracing)** | Kernel events for process/thread creation |
| **Behavioral Heuristics** | Cross-process memory writes, thread creation in other processes |
| **Memory Scanning** | RWX memory regions, known shellcode signatures |
| **PEB Walking** | Enumerating loaded DLLs to find unknown modules |

### Evasion Techniques

| Technique | How It Works |
|-----------|-------------|
| **Direct Syscalls** | Bypass hooked APIs by calling kernel directly |
| **DLL Unloading** | After injection, unload the DLL from PEB so it doesn't appear in module lists |
| **Module Stomping** | Overwrite a legitimate loaded DLL in memory instead of loading a new one |
| **Thread Pool Injection** | Use legitimate Windows thread pool APIs instead of `CreateRemoteThread` |
| **Fiber Injection** | Use Windows fibers (lightweight threads) instead of threads |

### Your Injector — A Balanced Approach

The `Injector.exe` in your kill chain uses **classic DLL injection** because:
1. It is reliable and well-understood
2. For a classroom demo, stealth is secondary to demonstration
3. It clearly shows the principle: "I can make another process run my code"

To make it stealthier in a real operation:
1. Use reflective injection (no disk artifact)
2. Inject into a process that commonly loads DLLs (e.g., `explorer.exe`)
3. Time the injection to coincide with legitimate activity
4. Name the DLL something innocuous (e.g., `winhttp.dll` in the wrong directory — DLL search order hijacking)

---

## Quick Reference Cheat Sheet

| Technique | Stealth | Complexity | Best For |
|-----------|---------|-----------|----------|
| Classic DLL Injection | Low | Low | Demonstrations, reliability |
| Reflective DLL Injection | High | High | Real operations, no disk artifact |
| Process Hollowing | High | High | Evading application whitelisting |

---

## 7.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Understanding classic DLL injection, reflective injection, process hollowing, and APC injection gives you a complete toolkit for process injection.

**What the lab hides from you:** EDR has evolved beyond API hooking. Modern EDR uses **kernel callbacks** (`PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`) that cannot be bypassed from user mode. **ETW (Event Tracing for Windows)** logs process, thread, and image load events at kernel speed — hundreds of thousands of events per second. **Memory forensics** (Volatility, Rekall) can detect hollowed processes and injected code by comparing memory to disk. **Control Flow Guard (CFG)** and **ACG (Arbitrary Code Guard)** prevent indirect call targets and dynamic code generation.

### How Injection Dies in Production

| Defense | How It Kills Injection | Your Lab Bypass |
|---------|----------------------|-----------------|
| Kernel callbacks | EDR registers kernel callbacks that log/block injection | No third-party EDR |
| ETW (Event Tracing) | Logs every process/thread/image event at kernel level | No ETW collection |
| CFG / ACG | Prevents execution of dynamically generated code | Not enabled |
| HVCI (Hypervisor CI) | Virtualizes code integrity checks; cannot be patched from OS | Not supported on lab hardware |
| Memory forensics | Volatility detects hollowed processes, injected threads | No memory analysis |
| Behavioral ML | Machine learning models detect anomalous thread behavior | No behavioral analytics |

### What a Professional Red Teamer Would Do

**Instead of user-mode injection, they would:**
- **Kernel driver exploitation** — BYOVD to disable callbacks from kernel mode
- **ETW patching** — silence event providers before injection
- **Legitimate process abuse** — use Windows features like `comsvcs.dll MiniDump` to dump LSASS without injection
- **Hardware-level attacks** — Intel ME, BMC, or UEFI implants (nation-state territory)

**Key difference:** The pro understands that user-mode injection is a **solved problem** for defenders. The battleground has moved to kernel mode, hypervisor mode, and hardware mode.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Windows driver development | Kernel-mode code can disable EDR callbacks | Windows Driver Kit (WDK) documentation |
| ETW provider patching | Silences logging that feeds EDR | MDsec: "ETW Tampering" |
| HVCI bypass | Required for kernel-level persistence | Research: "Hypervisor-Protected Code Integrity" |
| COM hijacking | No injection needed; abuse legitimate COM objects | ired.team: "COM Hijacking" |

### The Honest Bottom Line

> This theory document teaches the taxonomy of injection techniques. It does not teach modern injection evasion. In the real world, every technique listed here is **detectable by default** on a properly configured enterprise endpoint. The value is understanding the attack surface. Learn kernel callback manipulation and ETW tampering next.

---

| API | Purpose |
|-----|---------|
| `OpenProcess` | Get a handle to another process |
| `VirtualAllocEx` | Allocate memory in another process |
| `WriteProcessMemory` | Write data to another process |
| `CreateRemoteThread` | Start a thread in another process |
| `LoadLibraryA` | Load a DLL (used as remote thread start) |
| `NtUnmapViewOfSection` | Unmap memory (used in hollowing) |
| `QueueUserAPC` | Queue a function to a thread |
| `SuspendThread` / `ResumeThread` | Control thread execution |

---

*"The most dangerous code is not the code that runs in its own process. It is the code that runs inside a process you trust."*
