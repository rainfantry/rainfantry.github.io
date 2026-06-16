# Chapter 09 — Harness Engineering: Forging The Weapon

**VADER-RCE Field Manual**
**Prerequisite**: Ch05 (Fuzzing Theory), Ch08 (Target Reversing)
**Drill**: DRILLS/09_harness_engineering/

---

## Why You Need This

Chapter 05 gave you fuzzing theory. Chapter 08 gave you the target's
internals — the parsers, entry points, trust boundaries inside mpengine.dll.
Now you connect the two.

A fuzzer without a harness is a gun without a barrel. WinAFL can mutate
files all day. DynamoRIO can instrument every basic block in the target.
But neither of them knows how to CALL mpengine.dll. Neither of them
knows which function to invoke, what arguments it expects, what state
needs to exist before the first call, or how to reset between iterations.

That's your job. You build the harness.

The harness is the bridge between the fuzzer engine and the target binary.
It loads mpengine.dll into memory, resolves the scan function you
identified during reversing, initializes the engine state (signature
database, scan configuration), and exposes a single fuzz target function
that WinAFL calls millions of times with mutated input.

The TOCTOU campaign was 14 hand-built test programs. Each one was
effectively a harness — it set up conditions, triggered Defender, and
observed the result. But those harnesses were manual. One execution per
test. One input per run.

A WinAFL harness does the same thing but in a loop. Millions of times.
With coverage feedback guiding mutation. The harness IS the weapon.
Everything else — the fuzzer, the corpus, the mutation strategies —
is ammunition. A shit harness with perfect ammo finds nothing. A perfect
harness with mediocre ammo finds crashes in its sleep.

This chapter teaches you to forge the weapon.

---

## WinAFL Architecture

Before you write a harness, you need to understand what's driving it.
WinAFL is a fork of American Fuzzy Lop (AFL) ported to Windows. Where
AFL on Linux uses compile-time instrumentation or QEMU, WinAFL uses
DynamoRIO — a dynamic binary instrumentation framework that injects
coverage tracking into a running process at runtime. No source code
needed. No recompilation. You instrument closed-source DLLs like
mpengine.dll without touching a single byte of their code.

### The Fuzz Loop

```
┌──────────────────────────────────────────────────────┐
│                  WinAFL Process                       │
│                                                       │
│  1. INIT                                              │
│     - Load target DLL                                 │
│     - One-time setup (sigs, config, allocations)      │
│     - Reach the "fuzz target function"                │
│                                                       │
│  2. FUZZ LOOP (repeated N times per process)          │
│     ┌──────────────────────────────────────────┐      │
│     │  a. WinAFL writes mutated file to disk   │      │
│     │  b. Call fuzz target function             │      │
│     │  c. DynamoRIO records edge coverage       │      │
│     │  d. Function returns                      │      │
│     │  e. WinAFL compares coverage to corpus    │      │
│     │  f. If new edges → save input to corpus   │      │
│     │  g. If crash → save input to crashes/     │      │
│     │  h. Reset state, go to (a)                │      │
│     └──────────────────────────────────────────┘      │
│                                                       │
│  3. RESTART (after N iterations or crash)              │
│     - Kill process, restart from INIT                 │
│     - Clears accumulated state pollution              │
└──────────────────────────────────────────────────────┘
```

The critical insight: WinAFL does NOT restart the entire process for
every test case. That would be unbearably slow — process creation on
Windows takes milliseconds, and you want microseconds per iteration.

### Persistent Mode

WinAFL supports two modes:

**Fork mode** (default on Linux AFL, not really applicable on Windows):
Start a new process per test case. Clean state every time. Slow as
death. On Windows this means CreateProcess + DLL loading + engine init
for every single input. Maybe 1-5 executions per second. Useless for
real fuzzing.

**Persistent mode** (`-fuzz_iterations N`):
Call the fuzz target function N times in a loop WITHIN the same process.
No process restart between iterations. The function returns, WinAFL
mutates the input file, the function gets called again. Same process,
same loaded DLLs, same initialized state.

Speed difference: 10x to 100x faster than fork mode. You go from
5 exec/sec to 500+ exec/sec. On a fast target with a tight harness,
1000+ exec/sec is achievable.

The tradeoff: state accumulates. If the target function leaks memory,
modifies global variables, or leaves file handles open, that pollution
builds up across iterations. After N iterations, the process is killed
and restarted fresh. The `-fuzz_iterations` parameter controls N —
higher means faster (fewer restarts) but more state pollution risk.

**You will always use persistent mode.** Fork mode is a fallback for
targets so stateful that persistent mode causes false crashes. For
mpengine.dll, persistent mode works. The scan function was designed
to be called repeatedly — Defender scans thousands of files per hour
in normal operation.

### DynamoRIO Instrumentation

DynamoRIO sits between the CPU and the target code. It rewrites basic
blocks at runtime to insert coverage tracking — every time execution
enters a new basic block, a byte in the coverage bitmap gets incremented.
WinAFL reads this bitmap after each iteration to determine if the
mutated input triggered new code paths.

You don't write DynamoRIO code. You configure it via WinAFL command-line
flags:

```
-D "C:\DynamoRIO\bin64"         # Path to DynamoRIO
-coverage_module mpengine.dll   # Which DLL to instrument
-target_module harness.exe      # Module containing fuzz function
-target_method fuzz_target      # Function WinAFL calls in the loop
-fuzz_iterations 5000           # Iterations before process restart
-nargs 1                        # Number of arguments to fuzz function
```

DynamoRIO instruments ONLY the modules you specify with
`-coverage_module`. This is important — mpengine.dll loads dozens of
helper DLLs. Instrumenting all of them slows the fuzzer to a crawl.
Start with mpengine.dll alone. Add dependent modules only if coverage
plateaus and you suspect interesting parsing happens in a helper DLL.

---

## Harness Design Patterns

A harness is a C program (or DLL) that wraps your target function for
WinAFL. There are four patterns, each suited to different targets.

### Pattern 1: File-Based Harness

The simplest. Your fuzz target reads a file from disk and passes it
to the target function. WinAFL writes mutated data to the file before
each call.

```c
#include <windows.h>
#include <stdio.h>

// Function pointer type for the target's scan function
typedef int (__stdcall *ScanFileFunc)(const wchar_t* filepath, int flags);

ScanFileFunc pScanFile = NULL;
HMODULE hEngine = NULL;

// One-time init — called once when process starts
void init_target(void) {
    hEngine = LoadLibraryW(L"mpengine.dll");
    if (!hEngine) {
        fprintf(stderr, "Failed to load mpengine.dll: %lu\n", GetLastError());
        exit(1);
    }

    pScanFile = (ScanFileFunc)GetProcAddress(hEngine, "MpScanFile");
    if (!pScanFile) {
        fprintf(stderr, "Failed to resolve MpScanFile\n");
        exit(1);
    }

    // Engine-specific init (load signatures, etc.)
    // ... covered in "Building an mpengine.dll Harness" below
}

// Fuzz target — WinAFL calls this in a loop
int fuzz_target(const char* filename) {
    wchar_t wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wpath, MAX_PATH);

    // Call the scan function — this is where crashes happen
    int result = pScanFile(wpath, 0);

    return result;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: harness.exe <input_file>\n");
        return 1;
    }

    init_target();

    // WinAFL instruments this call and loops it
    fuzz_target(argv[1]);

    return 0;
}
```

WinAFL writes the mutated input to a temp file, then calls `fuzz_target`
with the file path. The target reads it from disk. Simple, reliable,
slow — every iteration does a file read. For mpengine.dll this is
acceptable because the real Defender workflow reads from disk anyway.

### Pattern 2: In-Memory Harness

Faster. Instead of reading from disk every iteration, you memory-map
the input file and pass a pointer + size to the target function. This
eliminates filesystem overhead.

```c
#include <windows.h>
#include <stdio.h>

typedef int (__stdcall *ScanBufferFunc)(
    const unsigned char* buffer,
    size_t size,
    int flags
);

ScanBufferFunc pScanBuffer = NULL;

int fuzz_target(const char* filename) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return -1;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return -1;
    }

    const unsigned char* data = (const unsigned char*)MapViewOfFile(
        hMap, FILE_MAP_READ, 0, 0, 0
    );
    if (!data) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return -1;
    }

    // Scan the buffer directly — no disk I/O in the hot path
    int result = pScanBuffer(data, fileSize, 0);

    UnmapViewOfFile(data);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return result;
}
```

This pattern works when the target has a buffer-based API. Not all
targets do. mpengine.dll's primary interface is file-based (it expects
a path), but internal parser functions often take buffer + size once
the file has been read. If you identified a deeper parser function
during reversing — one that takes `(buffer, size)` — this pattern
lets you call it directly and skip the file-reading overhead.

### Pattern 3: Persistent Harness With State Reuse

This is the production pattern. You combine in-memory input with
explicit state management to squeeze maximum performance.

```c
#include <windows.h>
#include <stdio.h>

typedef int (__stdcall *ScanBufferFunc)(
    void* engine_ctx,
    const unsigned char* buffer,
    size_t size
);

typedef void* (__stdcall *InitEngineFunc)(const wchar_t* sig_path);
typedef void  (__stdcall *ResetStateFunc)(void* engine_ctx);

ScanBufferFunc pScan = NULL;
InitEngineFunc pInit = NULL;
ResetStateFunc pReset = NULL;
void* g_ctx = NULL;

void init_once(void) {
    HMODULE h = LoadLibraryW(L"mpengine.dll");

    pInit  = (InitEngineFunc)GetProcAddress(h, "InternalInitEngine");
    pScan  = (ScanBufferFunc)GetProcAddress(h, "InternalScanBuffer");
    pReset = (ResetStateFunc)GetProcAddress(h, "InternalResetState");

    // Init engine once — loads signatures, allocates pools
    g_ctx = pInit(L"C:\\sigs\\");
    if (!g_ctx) exit(1);
}

// Called by WinAFL 5000+ times per process lifetime
int fuzz_target(const char* filename) {
    // Read the mutated file
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0 || size > (10 * 1024 * 1024)) {  // Cap at 10MB
        CloseHandle(hFile);
        return 0;
    }

    unsigned char* buf = (unsigned char*)malloc(size);
    DWORD read;
    ReadFile(hFile, buf, size, &read, NULL);
    CloseHandle(hFile);

    // Scan
    int result = pScan(g_ctx, buf, size);

    // Cleanup — critical for persistent mode
    free(buf);

    // Reset engine state for next iteration
    pReset(g_ctx);

    return result;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    init_once();
    fuzz_target(argv[1]);  // WinAFL loops this
    return 0;
}
```

The key elements:
- `init_once()` runs ONCE at process start. Expensive operations
  (LoadLibrary, signature loading) happen here, outside the fuzz loop.
- `fuzz_target()` is called per iteration. It must be fast and clean.
- `pReset()` — if the engine has a state-reset function, call it
  between iterations. This prevents state from iteration N bleeding
  into iteration N+1.
- Size cap: reject inputs over a reasonable max. The fuzzer will
  occasionally generate huge files. Scanning a 500MB mutant wastes
  time and doesn't find new bugs.

### Pattern 4: Network Harness

For targets that read from sockets instead of files. You replace the
socket layer with a buffer read from the fuzzer input file.

```c
// Not relevant for mpengine.dll but included for completeness.
// The pattern: hook recv()/WSARecv() to return data from the
// fuzzer's input file instead of reading from the network.
// Useful for fuzzing HTTP parsers, protocol handlers, etc.
//
// For Defender, the attack surface is FILE parsing, not network
// parsing. Defender doesn't listen on sockets — it reads files
// from disk via the minifilter. Skip this pattern for now.
```

Network harnesses are complex — they require hooking the socket API
or replacing the network stack entirely. You don't need one for
mpengine.dll. If you later fuzz a network-facing target (IIS, SMB
parser, RDP), revisit this.

---

## Building an mpengine.dll Harness

Theory's over. Time to build the real thing.

### Step 1: Load the Engine

mpengine.dll is a massive DLL — 100+ MB depending on the version.
It doesn't just expose a single `Scan()` function. It has an entire
initialization pipeline: loading the VDM signature database, setting
up internal data structures, configuring scan parameters.

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// =====================================================
// TYPE DEFINITIONS
// These come from your reversing work in Chapter 08.
// The exact signatures depend on the mpengine version
// you reversed. These are representative.
// =====================================================

// Opaque engine context
typedef struct _SCAN_ENGINE_CONTEXT SCAN_ENGINE_CONTEXT;

// Scan result codes (from reversing)
#define SCAN_RESULT_CLEAN    0
#define SCAN_RESULT_INFECTED 1
#define SCAN_RESULT_ERROR   -1

// Function pointer types
typedef HRESULT (__stdcall *pfnMpEngineInit)(
    const wchar_t* signaturePath,
    SCAN_ENGINE_CONTEXT** ppContext
);

typedef HRESULT (__stdcall *pfnMpScanFile)(
    SCAN_ENGINE_CONTEXT* pContext,
    const wchar_t* filePath,
    DWORD scanFlags,
    DWORD* pResult
);

typedef void (__stdcall *pfnMpEngineCleanup)(
    SCAN_ENGINE_CONTEXT* pContext
);

// Global state — initialized once, reused across iterations
static HMODULE              g_hEngine  = NULL;
static SCAN_ENGINE_CONTEXT* g_pCtx     = NULL;
static pfnMpEngineInit      g_pfnInit  = NULL;
static pfnMpScanFile        g_pfnScan  = NULL;
static pfnMpEngineCleanup   g_pfnClean = NULL;
```

### Step 2: Resolve Functions

The exact exported function names depend on your mpengine.dll version.
Use `dumpbin /exports mpengine.dll` or your Ghidra analysis from
Chapter 08 to find the right names. Some versions export clean names.
Others export only ordinals — in which case you use `GetProcAddress`
with `MAKEINTRESOURCE(ordinal)`.

```c
int resolve_functions(void) {
    g_hEngine = LoadLibraryW(L"mpengine.dll");
    if (!g_hEngine) {
        fprintf(stderr, "[!] LoadLibrary mpengine.dll failed: %lu\n",
                GetLastError());
        return 0;
    }

    // Try named exports first
    g_pfnInit = (pfnMpEngineInit)GetProcAddress(g_hEngine, "MpEngineInit");
    g_pfnScan = (pfnMpScanFile)GetProcAddress(g_hEngine, "MpScanFile");
    g_pfnClean = (pfnMpEngineCleanup)GetProcAddress(g_hEngine, "MpEngineCleanup");

    // If named exports don't exist, fall back to ordinals
    // you identified in Ghidra
    if (!g_pfnInit) {
        // Example: ordinal 2 from your export analysis
        g_pfnInit = (pfnMpEngineInit)GetProcAddress(
            g_hEngine, MAKEINTRESOURCE(2)
        );
    }
    if (!g_pfnScan) {
        g_pfnScan = (pfnMpScanFile)GetProcAddress(
            g_hEngine, MAKEINTRESOURCE(5)
        );
    }

    if (!g_pfnInit || !g_pfnScan) {
        fprintf(stderr, "[!] Failed to resolve engine functions\n");
        fprintf(stderr, "    Init: %p  Scan: %p  Cleanup: %p\n",
                g_pfnInit, g_pfnScan, g_pfnClean);
        return 0;
    }

    fprintf(stderr, "[+] Engine functions resolved\n");
    return 1;
}
```

### Step 3: Initialize the Engine

This is the expensive part. Signature loading can take seconds. It
happens ONCE, before the fuzz loop starts. If you put this inside
the fuzz target function, you'll get 0.5 exec/sec and find nothing.

```c
int init_engine(void) {
    // Signature database path — you need the VDM files
    // Copy them from C:\ProgramData\Microsoft\Windows Defender\Definition Updates\
    // to a local directory. The fuzzer needs read access.
    const wchar_t* sig_path = L"C:\\fuzzing\\sigs\\";

    HRESULT hr = g_pfnInit(sig_path, &g_pCtx);
    if (FAILED(hr)) {
        fprintf(stderr, "[!] Engine init failed: 0x%08X\n", hr);
        return 0;
    }

    fprintf(stderr, "[+] Engine initialized (ctx: %p)\n", g_pCtx);
    return 1;
}
```

**The VDM files.** mpengine.dll is useless without its signature
database. The engine loads .vdm files (virus definition modules) during
initialization. Without them, it crashes or returns immediately without
scanning anything. Copy the latest VDM files from a Defender installation:

```
C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}\
    mpasbase.vdm     ← antimalware signatures
    mpavbase.vdm     ← antivirus signatures
    mpasdlta.vdm     ← delta updates
    mpavdlta.vdm     ← delta updates
```

Put them in your fuzzing directory. The harness tells the engine where
to find them.

### Step 4: The Fuzz Target Function

This is the function WinAFL calls in a loop. It must:
1. Accept a file path (argv[1] from WinAFL)
2. Call the scan function
3. Return cleanly (no leaks, no dangling state)

```c
// THE FUZZ TARGET
// WinAFL calls this function in persistent mode loop.
// Must be fast. Must be clean. Must not accumulate state.
int fuzz_target(const char* input_file) {
    wchar_t wpath[MAX_PATH];
    int converted = MultiByteToWideChar(
        CP_UTF8, 0, input_file, -1, wpath, MAX_PATH
    );
    if (converted == 0) return 0;

    DWORD scan_result = 0;

    // The actual scan — this is where mpengine.dll parses the file,
    // hits the format dispatchers, enters the parsers you mapped
    // in Chapter 08, and potentially CRASHES on malformed input.
    HRESULT hr = g_pfnScan(g_pCtx, wpath, 0, &scan_result);

    // We don't care about the result. We care about whether it
    // crashed. WinAFL detects the crash via exception handling.
    // A clean return = no bug on this input. Move to next.

    return 0;
}
```

**What happens on a crash:** WinAFL catches the access violation
(or other exception) through its exception handler installed via
DynamoRIO. It saves the input file that caused the crash to the
`crashes/` directory with a filename encoding the exception type
and address. Your harness doesn't need to handle crashes — just
let them happen. That's the point.

### Step 5: Main — Tying It Together

```c
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: harness.exe <input_file>\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "WinAFL harness for mpengine.dll\n");
        fprintf(stderr, "Designed for persistent mode fuzzing.\n");
        return 1;
    }

    // === ONE-TIME INIT (outside fuzz loop) ===
    if (!resolve_functions()) return 1;
    if (!init_engine()) return 1;

    fprintf(stderr, "[+] Harness ready. Target: %s\n", argv[1]);

    // === FUZZ TARGET (WinAFL loops this) ===
    int result = fuzz_target(argv[1]);

    // === CLEANUP (after fuzz loop exits) ===
    if (g_pfnClean && g_pCtx) {
        g_pfnClean(g_pCtx);
    }
    if (g_hEngine) {
        FreeLibrary(g_hEngine);
    }

    return result;
}
```

### Step 6: Compile

```bash
# MSVC (recommended for Windows targets)
cl.exe /O2 /MT harness.c /Fe:harness.exe /link user32.lib

# Or MinGW if you don't have MSVC
x86_64-w64-mingw32-gcc -O2 -o harness.exe harness.c -luser32
```

Use `/O2` optimization. The harness is in the hot path — every
microsecond counts when you're doing 1000 iterations per second.

Use `/MT` (static CRT) so the harness doesn't depend on the MSVC
runtime DLL. One fewer dependency to worry about in the fuzzing
environment.

### Step 7: Run WinAFL

```bash
afl-fuzz.exe -i corpus_dir -o output_dir -t 30000 -D C:\DynamoRIO\bin64 \
    -coverage_module mpengine.dll \
    -target_module harness.exe \
    -target_method fuzz_target \
    -fuzz_iterations 5000 \
    -nargs 1 \
    -- harness.exe @@
```

Flags:
- `-i corpus_dir` — directory of seed files (your initial corpus)
- `-o output_dir` — where WinAFL writes results (crashes, queue, stats)
- `-t 30000` — timeout per iteration in ms (30 seconds; mpengine is slow)
- `-D` — DynamoRIO install path
- `-coverage_module` — DLL to instrument for coverage (mpengine.dll)
- `-target_module` — module containing the fuzz target function
- `-target_method` — name of the function WinAFL loops
- `-fuzz_iterations 5000` — persistent mode iterations before restart
- `-nargs 1` — fuzz target takes 1 argument
- `@@` — placeholder for the input file path

---

## Handling DLL Dependencies

mpengine.dll doesn't exist in isolation. It loads helper DLLs, reads
configuration, and expects a specific environment. Your harness must
provide that environment or the engine crashes before it even starts
scanning.

### The DLL Search Path Problem

When `LoadLibrary("mpengine.dll")` executes, Windows resolves the DLL
using the standard search order. mpengine.dll itself has dependencies
on other Defender DLLs. If those aren't found, LoadLibrary fails.

Solution: set your working directory to the Defender installation path
before loading, or use `SetDllDirectory`:

```c
// Before LoadLibrary
SetDllDirectoryW(
    L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.XXXX.X\\"
);
```

Or copy the entire Defender platform directory to your fuzzing setup.
Cleaner — no dependency on the system Defender installation, which
auto-updates and can break your harness between runs.

### Signature Database Files

Already covered above. The VDM files must be accessible. If the engine
can't load signatures, one of three things happens:
1. It returns an error code without scanning (useless — 100% of
   iterations return immediately, no parser code reached)
2. It crashes during init (harness never enters fuzz loop)
3. It scans but skips all format parsers (no coverage, no crashes)

All three mean zero useful fuzzing. Verify sig loading works BEFORE
running the fuzzer.

### Configuration

Some mpengine versions read configuration from the registry or from
a config file. If the engine expects scan settings, threat actions,
or exclusion lists from a specific location, your harness environment
needs to provide them. During reversing (Chapter 08), note any
registry reads or config file accesses during the init path.

```c
// If the engine reads from registry, create the keys beforehand
// in a setup script or in your harness init:
HKEY hKey;
RegCreateKeyExW(HKEY_LOCAL_MACHINE,
    L"SOFTWARE\\Microsoft\\Windows Defender\\Scan",
    0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
RegSetValueExW(hKey, L"DisableRealtimeMonitoring",
    0, REG_DWORD, (BYTE*)&(DWORD){0}, sizeof(DWORD));
RegCloseKey(hKey);
```

---

## Common Harness Mistakes

You will make these mistakes. Every fuzzer operator does. Learn them
here instead of wasting three days wondering why your campaign produces
zero crashes.

### Mistake 1: State Pollution Between Iterations

The most insidious bug in persistent-mode fuzzing. Iteration N leaves
state behind that affects iteration N+1. Symptoms:

- Crash on iteration 4000 but the crashing input doesn't reproduce
  when run standalone (the crash needed accumulated state from prior
  iterations)
- Coverage numbers grow monotonically even with identical input files
  (unreachable code being "reached" due to corrupted state)
- Exec/sec degrades over time within a process lifetime (memory leaks
  eating available address space)

```c
// BAD — leaks memory every iteration
int fuzz_target(const char* filename) {
    unsigned char* buf = read_file(filename);
    scan(buf);
    // forgot to free(buf)
    return 0;  // 5000 iterations = 5000 leaked buffers
}

// GOOD — clean every iteration
int fuzz_target(const char* filename) {
    unsigned char* buf = read_file(filename);
    scan(buf);
    free(buf);
    return 0;
}
```

For the engine itself: if mpengine.dll maintains internal caches,
detection lists, or scan history, those accumulate across persistent
iterations. The fix: if the engine has a reset/reinit function,
call it after each scan. If it doesn't, reduce `-fuzz_iterations`
to limit accumulation (500 instead of 5000).

### Mistake 2: Missing Initialization

The engine crashes on the first scan because signatures aren't loaded,
or the internal allocator wasn't set up, or a required config value
is missing. Your harness enters the fuzz loop with an engine in a
broken state.

```c
// BAD — no init, engine in undefined state
int main(int argc, char** argv) {
    HMODULE h = LoadLibrary("mpengine.dll");
    ScanFunc scan = GetProcAddress(h, "MpScanFile");
    scan(NULL, argv[1], 0, NULL);  // CRASH — context is NULL
    return 0;
}

// GOOD — proper init sequence
int main(int argc, char** argv) {
    HMODULE h = LoadLibrary("mpengine.dll");
    InitFunc init = GetProcAddress(h, "MpEngineInit");
    ScanFunc scan = GetProcAddress(h, "MpScanFile");

    void* ctx = NULL;
    init(L"C:\\sigs\\", &ctx);  // Load sigs, create context
    if (!ctx) { return 1; }     // Verify init succeeded

    DWORD result;
    scan(ctx, argv[1], 0, &result);  // Now scan with valid context
    return 0;
}
```

**Debug this with -no_fuzz first.** Run your harness through DynamoRIO
without WinAFL fuzzing. If it crashes during init, the fuzzer isn't
the problem — your setup is.

### Mistake 3: Wrong Calling Convention

x86 Windows has multiple calling conventions: `__stdcall`, `__cdecl`,
`__fastcall`, `__thiscall`. Each one handles the stack differently.
If your function pointer type declares `__cdecl` but the actual function
is `__stdcall`, the stack gets corrupted after the call returns.

On x86 (32-bit):
- `__cdecl`: caller cleans the stack
- `__stdcall`: callee cleans the stack
- `__fastcall`: first 2 args in ECX/EDX, callee cleans rest

If you get this wrong, the function executes fine but the return
address is garbage. Your harness crashes AFTER the target function
returns — misleading you into thinking the bug is in the target
when it's in your harness.

```c
// WRONG — cdecl declaration for a stdcall function
typedef int (__cdecl *BadScanFunc)(void* ctx, const wchar_t* path);

// RIGHT — match the actual calling convention from your disassembly
typedef int (__stdcall *GoodScanFunc)(void* ctx, const wchar_t* path);
```

On x64 (64-bit), there's only one calling convention (Microsoft x64).
This problem mostly affects 32-bit harnesses. But mpengine.dll is
64-bit on modern systems, so if you're fuzzing the current version,
calling convention mismatches are rare. If you're fuzzing an older
32-bit version for research purposes, get the convention right.

**How to verify:** In Ghidra, the decompiler annotates function
signatures with the calling convention. IDA does the same. Check
your reversed function signature before declaring the type in your
harness.

### Mistake 4: Harness Too Slow

Your harness works. It finds the function, calls it, returns clean.
But exec/sec is 3. Three executions per second. At that rate, finding
a crash in the combinatorial space of file format parsing will take
geological time.

Common causes:
- **Unnecessary I/O per iteration**: logging to a file on every call,
  reading a config file every time, opening/closing handles that
  could stay open
- **Init code inside the fuzz loop**: loading DLLs, reading signatures,
  or allocating large buffers inside `fuzz_target` instead of `main`
- **Scanning too much data**: no size cap on input, so the fuzzer
  generates a 200MB file and the engine spends 30 seconds parsing it
- **Instrumenting too many modules**: DynamoRIO is tracking coverage
  in mpengine.dll PLUS 15 helper DLLs

```c
// BAD — doing work that belongs in init
int fuzz_target(const char* filename) {
    HMODULE h = LoadLibrary("mpengine.dll");  // EVERY ITERATION
    void* scan = GetProcAddress(h, "Scan");   // EVERY ITERATION
    // ...
    FreeLibrary(h);                           // EVERY ITERATION
    return 0;
}

// GOOD — init once, fuzz function does minimum work
static HMODULE g_h = NULL;
static ScanFunc g_scan = NULL;

void init(void) {
    g_h = LoadLibrary("mpengine.dll");  // ONCE
    g_scan = GetProcAddress(g_h, "Scan");  // ONCE
}

int fuzz_target(const char* filename) {
    // Only the scan call and minimal I/O
    unsigned char* data = read_file(filename);
    g_scan(data);
    free(data);
    return 0;
}
```

### Mistake 5: Target Function Has Side Effects

The target function doesn't just SCAN the file — it takes ACTION on
the result. Quarantine the file. Delete the file. Move the file.
Send a notification to Windows Security Center. Write to an event log.

If your fuzz target function triggers quarantine, the input file gets
moved or deleted between iterations. WinAFL writes a new mutated file,
but the path might be wrong, or the quarantine action itself crashes
because it doesn't have permission in your fuzzing environment.

```c
// BAD — letting the engine take threat actions
DWORD flags = SCAN_FLAG_QUARANTINE | SCAN_FLAG_CLEAN;
g_pfnScan(g_pCtx, wpath, flags, &result);

// GOOD — scan only, no remediation action
DWORD flags = SCAN_FLAG_REPORT_ONLY;  // or 0
g_pfnScan(g_pCtx, wpath, flags, &result);
```

Find the flag values during reversing. There's usually a "report only"
or "detect only" mode that runs the full parser pipeline without
triggering remediation. That's what you want. You want the engine to
PARSE the file (where the bugs are) without trying to CLEAN it.

---

## Harness Optimization

Your harness works. It finds crashes. Now make it faster. Every 2x
speed improvement halves the time to find bugs. Going from 100 exec/sec
to 1000 exec/sec is the difference between a week-long campaign and
an overnight one.

### Minimize File I/O

The biggest bottleneck in most harnesses. Reading from disk is slow.
Writing to disk is slow. CreateFile + ReadFile + CloseHandle per
iteration burns microseconds that compound into hours over millions
of iterations.

```c
// SLOWER — full file I/O per iteration
int fuzz_target(const char* filename) {
    HANDLE h = CreateFileA(filename, GENERIC_READ, ...);
    DWORD size = GetFileSize(h, NULL);
    unsigned char* buf = malloc(size);
    ReadFile(h, buf, size, &bytesRead, NULL);
    CloseHandle(h);

    scan(buf, size);
    free(buf);
    return 0;
}

// FASTER — memory-mapped I/O
int fuzz_target(const char* filename) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ,
                               FILE_SHARE_READ, NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    const unsigned char* data = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    DWORD size = GetFileSize(hFile, NULL);

    scan(data, size);

    UnmapViewOfFile(data);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}
```

Even faster: if you can target a buffer-based internal function instead
of the file-based scan entry point, you eliminate ALL file I/O.
WinAFL can operate in shared-memory mode where it writes mutated
data directly to a memory buffer your harness reads from. Zero disk
involvement. This requires WinAFL's `-s` (shared memory) flag and a
harness that reads from the shared memory region instead of from a
file path.

### Avoid Unnecessary State Reset

If the engine is stateless between scans (each scan is independent),
don't add reset calls that aren't needed. Every function call in the
fuzz loop is overhead.

But be CAREFUL. If you skip the reset and the engine IS stateful,
you get false crashes from state pollution. Test both ways:

1. Run with reset, record crashes over 1 hour
2. Run without reset, record crashes over 1 hour
3. Attempt to reproduce every crash from run 2 standalone
4. If crashes from run 2 reproduce, the engine is stateless enough —
   drop the reset. If they don't reproduce, keep it.

### Profile Before You Optimize

Don't guess where the bottleneck is. Measure.

```bash
# Run the harness once through DynamoRIO without fuzzing
drrun.exe -c winafl.dll -debug -target_module harness.exe \
    -target_method fuzz_target -fuzz_iterations 1 -nargs 1 \
    -- harness.exe test_input.zip
```

The `-debug` flag makes WinAFL log timing information. Check:
- How long does init take? (Acceptable — happens once)
- How long does one fuzz_target call take? (Your per-iteration cost)
- How much of that time is the scan vs. your harness overhead?

If the scan itself takes 50ms and your harness overhead is 1ms, you're
at ~19 exec/sec and the bottleneck is the target, not your code.
Optimize by targeting a deeper, faster parser function.

If the scan takes 1ms and your harness overhead takes 50ms, you're
at ~19 exec/sec and the bottleneck is your harness. Fix the I/O.

### Target The Deepest Parser You Can

This is the highest-impact optimization. Instead of calling the
top-level scan function (which does file type detection, dispatch,
logging, result handling, and THEN calls the parser), call the
parser directly.

```
Top-level scan function (MpScanFile)
  ├── Open file, read magic bytes
  ├── Dispatch to format handler
  │     ├── ZIP parser (ParseZipArchive)     ← TARGET THIS
  │     ├── PDF parser (ParsePdfDocument)    ← OR THIS
  │     ├── PE parser (ParsePeImage)         ← OR THIS
  │     └── ...
  ├── Aggregate results
  ├── Apply threat actions
  └── Return result
```

If you can resolve and call `ParseZipArchive` directly — skipping the
dispatch, file opening, result aggregation, and threat actions — you
eliminate all that overhead. Your harness becomes:

```c
typedef int (__stdcall *ParseZipFunc)(
    void* parser_ctx,
    const unsigned char* data,
    size_t size
);

int fuzz_target(const char* filename) {
    unsigned char* data = read_file(filename);
    size_t size = get_file_size(filename);

    // Call the ZIP parser directly — no dispatch overhead
    parse_zip(g_parser_ctx, data, size);

    free(data);
    return 0;
}
```

The tradeoff: you fuzz ONE format at a time. You need separate harnesses
(or parameterized harnesses) for each parser. But each one runs 3-10x
faster than going through the top-level dispatch.

This is the sniper approach applied to fuzzing. You identified the
parser functions in Chapter 08. Now you aim the fuzzer directly at
them, bypassing all the bureaucratic wrapper code that adds latency
without adding attack surface.

---

## Testing Your Harness

A harness that doesn't work correctly wastes compute and produces
garbage results. Test it BEFORE burning GPU hours on a real campaign.

### Test 1: Known-Crash Reproduction

If you have a crash from prior research (or a known PoC for an older
CVE), run it through your harness. The harness should trigger the same
crash.

```bash
# Run the harness directly, no fuzzer
harness.exe known_crash.zip
```

If it crashes — good, your harness reaches the vulnerable code. If it
doesn't crash, something is wrong: wrong function, wrong flags, missing
initialization, or the crash requires state your harness doesn't set up.

### Test 2: Stability Check (-no_fuzz)

Run WinAFL in dry-run mode. It calls your fuzz target repeatedly with
the same input, without mutations. The harness should survive 10,000+
iterations without crashing.

```bash
afl-fuzz.exe -i corpus -o output -D C:\DynamoRIO\bin64 \
    -no_fuzz \
    -coverage_module mpengine.dll \
    -target_module harness.exe \
    -target_method fuzz_target \
    -fuzz_iterations 10000 \
    -nargs 1 \
    -- harness.exe @@
```

If it crashes during the stability check, your harness has a bug.
State pollution, memory leak, handle leak, or an uninitialized variable
that happens to work on the first call but not the 8000th.

WinAFL reports a stability percentage. Below 95% = your harness is
unreliable. Below 80% = your harness is fucked. Fix it before fuzzing.

**Stability must be verified per input.** A harness might be stable
with a ZIP file but unstable with a PDF because the PDF parser
leaks memory. Test with samples of every format you plan to fuzz.

### Test 3: Coverage Verification

DynamoRIO should report different coverage for different file types.
If you scan a ZIP and a PDF and get identical coverage, your harness
isn't reaching the format-specific parsers. The dispatch function is
failing silently, or the engine isn't loading sigs, or the input files
are being rejected before parsing.

```bash
# Run with debug logging to see coverage
drrun.exe -c winafl.dll -debug \
    -coverage_module mpengine.dll \
    -target_module harness.exe \
    -target_method fuzz_target \
    -fuzz_iterations 1 -nargs 1 \
    -- harness.exe test.zip

# Check the log — look for new basic blocks
# Then run with a different format:
drrun.exe -c winafl.dll -debug \
    -coverage_module mpengine.dll \
    -target_module harness.exe \
    -target_method fuzz_target \
    -fuzz_iterations 1 -nargs 1 \
    -- harness.exe test.pdf

# Compare: different formats should hit different code paths
```

If coverage is zero or near-zero, the engine isn't scanning. Check:
- Are VDM signatures loaded? (engine init must succeed)
- Is the file path reaching the engine correctly? (encoding issues)
- Is the scan function actually being called? (GetProcAddress succeeded?)

### Test 4: Throughput Benchmark

Measure exec/sec before launching a real campaign.

```bash
# Run with a small corpus, watch the exec/sec counter
afl-fuzz.exe -i small_corpus -o bench_output -t 30000 \
    -D C:\DynamoRIO\bin64 \
    -coverage_module mpengine.dll \
    -target_module harness.exe \
    -target_method fuzz_target \
    -fuzz_iterations 5000 \
    -nargs 1 \
    -- harness.exe @@
```

Throughput targets:

| exec/sec | Assessment |
|----------|-----------|
| < 10 | Broken. Something is catastrophically slow. Debug before continuing. |
| 10-50 | Acceptable for complex targets like mpengine.dll. Not great. |
| 50-200 | Good. Production-ready for mpengine.dll campaigns. |
| 200-1000 | Excellent. You're hitting a specific parser with minimal overhead. |
| 1000+ | Outstanding. Usually means you're targeting a small, fast parser function directly. |

**For mpengine.dll specifically:** 50-200 exec/sec is realistic for the
top-level scan function. The engine is massive and scanning involves
significant computation. If you target a specific parser function
directly, 200-500 exec/sec is achievable.

Below 10 exec/sec, stop. Don't burn a week of compute at that speed.
Profile the harness, find the bottleneck, and fix it. The bugs aren't
going anywhere. A fast harness finds them in a day. A slow harness
finds them never.

---

## The Complete Harness Skeleton

Pulling it all together. This is the reference implementation you'll
adapt for each target function.

```c
/*
 * mpengine.dll WinAFL Harness — Skeleton
 *
 * Compile: cl /O2 /MT harness.c /Fe:harness.exe
 * Run:     afl-fuzz.exe -i corpus -o out -t 30000
 *          -D C:\DynamoRIO\bin64
 *          -coverage_module mpengine.dll
 *          -target_module harness.exe
 *          -target_method fuzz_target
 *          -fuzz_iterations 5000
 *          -nargs 1
 *          -- harness.exe @@
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// ============================================================
// CONFIGURATION — adapt these per target
// ============================================================

#define SIG_PATH        L"C:\\fuzzing\\sigs\\"
#define ENGINE_DLL      L"mpengine.dll"
#define ENGINE_DIR      L"C:\\fuzzing\\engine\\"
#define MAX_INPUT_SIZE  (10 * 1024 * 1024)  // 10MB cap

// ============================================================
// TYPES — from your Chapter 08 reversing
// ============================================================

typedef struct _ENGINE_CTX ENGINE_CTX;

typedef HRESULT (__stdcall *pfnInit)(
    const wchar_t* sig_path,
    ENGINE_CTX** ctx
);
typedef HRESULT (__stdcall *pfnScan)(
    ENGINE_CTX* ctx,
    const wchar_t* file_path,
    DWORD flags,
    DWORD* result
);
typedef void (__stdcall *pfnCleanup)(ENGINE_CTX* ctx);

// ============================================================
// GLOBALS — initialized once in main()
// ============================================================

static HMODULE     g_hMod    = NULL;
static ENGINE_CTX* g_ctx     = NULL;
static pfnInit     g_init    = NULL;
static pfnScan     g_scan    = NULL;
static pfnCleanup  g_cleanup = NULL;

// ============================================================
// INIT — runs once before fuzz loop
// ============================================================

static int harness_init(void) {
    // Set DLL search path to find engine dependencies
    SetDllDirectoryW(ENGINE_DIR);

    g_hMod = LoadLibraryW(ENGINE_DLL);
    if (!g_hMod) {
        fprintf(stderr, "[!] LoadLibrary failed: %lu\n", GetLastError());
        return 0;
    }
    fprintf(stderr, "[+] Loaded %ls at %p\n", ENGINE_DLL, g_hMod);

    // Resolve functions — adapt names/ordinals from reversing
    g_init    = (pfnInit)GetProcAddress(g_hMod, "MpEngineInit");
    g_scan    = (pfnScan)GetProcAddress(g_hMod, "MpScanFile");
    g_cleanup = (pfnCleanup)GetProcAddress(g_hMod, "MpEngineCleanup");

    if (!g_init || !g_scan) {
        fprintf(stderr, "[!] Function resolution failed\n");
        fprintf(stderr, "    init=%p scan=%p cleanup=%p\n",
                g_init, g_scan, g_cleanup);
        return 0;
    }
    fprintf(stderr, "[+] Functions resolved\n");

    // Initialize engine — loads signatures
    HRESULT hr = g_init(SIG_PATH, &g_ctx);
    if (FAILED(hr) || !g_ctx) {
        fprintf(stderr, "[!] Engine init failed: 0x%08X\n", hr);
        return 0;
    }
    fprintf(stderr, "[+] Engine initialized (ctx=%p)\n", g_ctx);

    return 1;
}

// ============================================================
// FUZZ TARGET — WinAFL calls this in persistent loop
// ============================================================

__declspec(noinline)
int fuzz_target(const char* input_file) {
    // Convert path to wide string
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, input_file, -1,
                             wpath, MAX_PATH)) {
        return 0;
    }

    // Optional: check file size, reject oversized inputs
    HANDLE hFile = CreateFileA(input_file, GENERIC_READ,
                               FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD size = GetFileSize(hFile, NULL);
        CloseHandle(hFile);
        if (size > MAX_INPUT_SIZE) return 0;
    }

    // The scan — this is where crashes happen
    DWORD result = 0;
    g_scan(g_ctx, wpath, 0 /* REPORT_ONLY */, &result);

    return 0;
}

// ============================================================
// MAIN
// ============================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr,
            "mpengine.dll WinAFL harness\n"
            "Usage: harness.exe <input_file>\n"
        );
        return 1;
    }

    if (!harness_init()) {
        fprintf(stderr, "[!] Init failed. Aborting.\n");
        return 1;
    }

    // WinAFL instruments and loops this call
    fuzz_target(argv[1]);

    // Cleanup (reached after fuzz loop exits)
    if (g_cleanup && g_ctx) g_cleanup(g_ctx);
    if (g_hMod) FreeLibrary(g_hMod);

    return 0;
}
```

Note the `__declspec(noinline)` on `fuzz_target`. This prevents the
compiler from inlining the function, which would break WinAFL's
ability to find it by name. WinAFL needs `fuzz_target` to exist as
a discrete function with a known address. Inlining merges it into
`main()` and the `-target_method` flag fails.

---

## Mapping To The Doctrine

The 0x1security compass applies directly to harness engineering.

**"Search for knowledge, not for 0-days."**

Building the harness forced you to UNDERSTAND the target's initialization
pipeline, scan interface, calling conventions, and state management.
You didn't just copy-paste a template — you reverse-engineered the
engine's API from Chapter 08 analysis and built a bridge to it. Every
harness encodes knowledge about the target. A bad harness reflects
shallow understanding. A good harness proves you KNOW the target.

**"See the paths, see what blocks you, find a substitute way."**

The path: you want to fuzz mpengine.dll's parsers. The block: WinAFL
can't call the engine directly — it doesn't know the API, the init
sequence, or the expected state. The substitute: you build a harness
that handles all of that, presenting a clean `fuzz_target(filename)`
interface to WinAFL. Same doctrine. Applied to tooling instead of
exploitation.

If your first harness is too slow (50ms per iteration), you see the
block and find the substitute: target a deeper parser function, skip
the dispatch overhead, eliminate I/O. If persistent mode causes state
pollution, you find the substitute: add a reset call, or reduce
fuzz_iterations, or isolate the parser into a cleaner wrapper.

**"Crash -> leak memory -> execute arbitrary code."**

The harness is step zero. Before you can crash anything, you need the
weapon that DELIVERS the crash. A well-built harness connected to
WinAFL with a good corpus will fill `crashes/` with inputs that trigger
access violations in the parsers you targeted. Each crash is the
entry point to the exploitation chain from Chapter 07: crash → classify
(Chapter 06) → determine if it gives you a write primitive → build
toward code execution.

The harness doesn't find the exploit. The harness finds the DOOR.
Exploitation walks through it.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Harness** | Custom code that bridges the fuzzer and the target; loads the DLL, resolves functions, calls them in a loop |
| **Persistent mode** | WinAFL mode that calls the fuzz target repeatedly within one process; 10-100x faster than fork mode |
| **Fork mode** | Restarting the entire target process per test case; clean state but extremely slow on Windows |
| **fuzz_iterations** | Number of persistent-mode loop iterations before WinAFL kills and restarts the harness process |
| **State pollution** | Accumulated side effects from prior iterations corrupting current iteration; causes false crashes |
| **DynamoRIO** | Dynamic binary instrumentation framework; injects coverage tracking into binaries at runtime without source |
| **Coverage module** | DLL specified with `-coverage_module` for DynamoRIO to instrument; typically the target DLL only |
| **Target method** | The function WinAFL identifies and calls in the persistent loop; must be `__declspec(noinline)` |
| **VDM files** | Virus Definition Module files; mpengine.dll's signature database, required for scanning to function |
| **Calling convention** | Protocol for passing arguments and cleaning the stack; mismatch = stack corruption after function return |
| **Stability percentage** | WinAFL metric showing how reproducible the harness behavior is; below 95% = unreliable, fix before fuzzing |
| **exec/sec** | Executions per second; primary throughput metric. Below 10 = broken, 50-200 = good for mpengine.dll |
| **Size cap** | Maximum input file size accepted by the harness; prevents the fuzzer from wasting time on oversized mutants |
| **Shared memory mode** | WinAFL mode where mutated input is written to a memory region instead of disk; eliminates file I/O |
| **noinline** | Compiler directive preventing function inlining; required for WinAFL to locate the fuzz target by name |
| **Report-only mode** | Scan flag that runs the full parser pipeline without triggering remediation (quarantine/delete) |

---

## Drill 09 — Harness Engineering

Go to `DRILLS/09_harness_engineering/`. A practice DLL (`vuln_engine.dll`)
is waiting. It simulates a scan engine with:
- An init function that loads a "signature" file
- A scan function that parses input files (ZIP-like format)
- A known heap overflow in the parser (triggered by specific input)
- Internal state that accumulates across calls (testing your reset logic)

Your mission:

1. **Reverse the DLL**: use `dumpbin /exports` or Ghidra to find the
   init, scan, and reset functions. Note calling conventions and
   argument types.

2. **Write the harness**: load the DLL, resolve functions, init the
   engine, implement `fuzz_target`. Don't forget `noinline`.

3. **Test stability**: run with `-no_fuzz` for 10,000 iterations.
   If it crashes, you have a state pollution bug. Fix it.

4. **Verify coverage**: run against the included sample files
   (good.bin, bad.bin, corrupt.bin). Each should produce different
   coverage numbers.

5. **Benchmark throughput**: target 500+ exec/sec on this practice DLL.
   If you're below that, profile and optimize.

6. **Fuzz it**: run WinAFL with the provided seed corpus. The heap
   overflow should be found within 10 minutes. When crashes appear
   in `output/crashes/`, verify they reproduce standalone.

7. **Optimize**: once the basic harness works, try targeting the
   internal parser function directly (bypass the dispatch). Measure
   the exec/sec improvement.

This drill is the graduation exercise for your fuzzing toolchain. After
this, the next chapter points the weapon at mpengine.dll for real.

---

## Summary — Key Takeaways

- **The harness IS the weapon.** WinAFL, DynamoRIO, and the corpus are
  ammunition. Without a correct, fast harness, none of it fires.

- **Persistent mode is mandatory.** Fork mode on Windows gives you
  single-digit exec/sec. Persistent mode gives you hundreds. Use
  `-fuzz_iterations` to balance speed against state pollution.

- **Init once, fuzz many.** LoadLibrary, GetProcAddress, engine
  initialization, signature loading — all of this happens ONCE in
  `main()`. The `fuzz_target` function does the minimum: take input,
  scan, return.

- **State pollution is the silent killer.** If crashes don't reproduce
  standalone, your harness is leaking state between iterations. Add
  reset calls or reduce fuzz_iterations.

- **Calling conventions matter on x86.** Mismatch between your function
  pointer type and the actual function = stack corruption that looks
  like a target bug but is YOUR bug.

- **Disable side effects.** Scan in report-only mode. No quarantine,
  no file deletion, no remediation. You want the parser, not the
  response system.

- **Target the deepest function you can.** Skipping dispatch and
  wrapper overhead can give you 3-10x speed improvement. Your Chapter 08
  reversing identified the parser functions — use them.

- **Test before you fuzz.** Known-crash reproduction, stability check,
  coverage verification, throughput benchmark. In that order. Always.

- **Below 10 exec/sec = stop and fix.** Don't waste compute on a
  broken harness. Profile, find the bottleneck, eliminate it.
