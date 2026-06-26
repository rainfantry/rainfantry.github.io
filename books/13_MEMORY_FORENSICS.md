# Chapter 13 — Memory Forensics: Volatility, EPROCESS & Artefacts

**VADER-RCE Field Manual**
**Prerequisite**: Ch09-12 (especially Ch11 Rootkits, Ch12 Exploit Development)
**Drill**: DRILLS/13_memory_forensics/

---

## Why You Need This

You popped a box. You ran your implant. You moved laterally.
Then the defender pulled the RAM chip out of the server and
handed it to the IR team. Two hours later they've reconstructed
your entire operation from a 32GB memory image.

Memory is the battlefield. Everything running right now lives there.
Processes. Network connections. Registry keys. Credentials in cleartext.
Encryption keys. Injected shellcode. The kernel's list of loaded drivers.
All of it — sitting in RAM, waiting for someone with the right tool
to read it.

This chapter has two audiences. First: you as a defender, or the
forensic analyst handed a memory image and told "find the malware."
Second: you as the attacker, understanding what traces your activity
leaves and how to minimise them.

Both audiences need the same knowledge. The analyst needs to know
what to look for. The attacker needs to know what to hide.

The toolchain is Volatility 3 on the forensic side. The terrain is
the Windows EPROCESS structure on the kernel side. The artefacts
are everything else — memory strings, network sockets, registry hives,
credentials, injected code hiding in VAD nodes.

Learn it as the analyst. Apply it as the attacker. Both roles are yours.

The pipeline:

```
ACQUISITION → ANALYSIS → ARTEFACT IDENTIFICATION → HUNT
```

---

## Section 1 — Memory Acquisition: Getting The Image

You can't analyse what you don't have. Getting the RAM image onto your
analysis box is the first problem. Four primary methods. Each has
tradeoffs in reliability, completeness, and operational noise.

### Method 1 — Live Acquisition with WinPMEM

WinPMEM is the gold standard for live acquisition on Windows. It's a
kernel driver that maps physical memory and streams it to disk.

```
# Download WinPMEM:
# https://github.com/Velocidex/WinPmem/releases

# Run as Administrator — raw format:
winpmem_mini_x64_rc2.exe memdump.raw

# AFF4 format (includes metadata, compression):
winpmem_mini_x64_rc2.exe --format aff4 -o memdump.aff4

# Verify acquisition integrity:
winpmem_mini_x64_rc2.exe --verify memdump.raw

# SHA256 hash immediately after:
certutil -hashfile memdump.raw SHA256
Get-FileHash memdump.raw -Algorithm SHA256
```

**What you get**: Raw physical memory image. Everything — kernel
structures, user-mode process memory, heap contents, registry hive
caches, network state. The most complete acquisition method.

**Limitations**: Requires admin rights. Running the tool creates
artefacts — driver load event ID 7045 in System log, `winpmem`
service entry in registry, process entry in the process list.
On a live system, contents change while you're dumping. Snapshot
of a moving target.

**Detection footprint**: If you're the attacker and you need to know
when you're being imaged — the WinPMEM driver name appears in
`sc query` output and loaded driver lists. The memory dump file
will appear on disk as a multi-gigabyte file. Know the fingerprint.

### Method 2 — hiberfil.sys (Hibernation File)

When Windows hibernates, it writes all RAM contents compressed to
`C:\hiberfil.sys`. This is a complete memory snapshot that already
exists on disk — no driver needed, no admin footprint from acquisition.

```
# hiberfil.sys is locked while Windows is running
# Must access from another boot (forensic boot, secondary OS) or after hibernate

# Volatility 3 can read hiberfil.sys directly — no conversion needed:
python vol.py -f C:\hiberfil.sys windows.pslist

# Or convert to raw first with WinPmem convert mode:
winpmem_mini_x64_rc2.exe --convert hiberfil.sys -o memdump.raw

# hiberfil.sys location:
C:\hiberfil.sys    (requires system access, hidden system file)
```

**What you get**: RAM at the exact moment of hibernation. Complete, no
acquisition noise, disk access only.

**Limitations**: Only available if the machine actually hibernated.
If shut down normally — gone. If the attacker's process ran and exited
before hibernation — not captured. Contents are FIXED at hibernation time,
not current.

**Forensic goldmine**: You have disk access but no live access.
You pulled the drive. Check for hiberfil.sys before setting up anything
more complex. It might already have everything you need.

### Method 3 — Crash Dump (MEMORY.DMP)

Windows generates crash dumps on kernel panic (BSOD). A full crash dump
captures all of RAM. Can also be triggered deliberately for forensic
purposes.

```
# Force a full memory dump via NotMyFault (Sysinternals):
notmyfault64.exe /crash

# Or via kernel debugger:
kd> .dump /f /ma C:\evidence\full.dmp

# Configure automatic full dump permanently:
# System Properties → Advanced → Startup and Recovery
# Write Debugging Information: "Complete memory dump"
# Location: %SystemRoot%\MEMORY.DMP

# Full dump lives at:
C:\Windows\MEMORY.DMP

# Minidumps at:
C:\Windows\Minidump\*.dmp    (per-crash, much smaller, less complete)

# Per-process dump via Task Manager (USER SPACE ONLY, not kernel):
# Right-click process → Create Dump File
# Saves to: %TEMP%\<ProcessName>.DMP
```

**What you get**: All physical RAM at the moment of the crash. Same
completeness as WinPMEM.

**The analyst's windfall**: If a production server crashed during a
compromise and generated a dump automatically, you have a free complete
memory image of the machine at the moment of attack. Check `C:\Windows\MEMORY.DMP`
before doing anything else. It might already be there.

**Limitations**: Crashing the machine is loud and destructive on
production systems. Use deliberate triggering only in forensic VMs or
controlled test environments.

### Method 4 — VM Snapshots

If the target is a virtual machine, the hypervisor can snapshot memory
without touching the guest OS at all. No driver. No footprint. Guest
has no idea it happened.

```
# VMware — suspend the VM, copy the .vmem file:
# The .vmem file IS the raw memory. Volatility reads it directly.
python vol.py -f vm.vmem windows.pslist

# Or copy the .vmss/.vmsn snapshot files:
python vol.py -f snapshot.vmss windows.pslist

# VirtualBox:
VBoxManage debugvm "VM Name" dumpvmcore --filename memdump.core
python vol.py -f memdump.core windows.pslist

# Hyper-V:
# Checkpoint the VM, extract memory from checkpoint directory
# .bin files in the checkpoint folder contain memory
```

**This is gold for red teamers too**: if your implant is running in a
sandboxed analysis VM, the analyst can snapshot and analyse you without
triggering a single in-guest detection evasion hook. The hypervisor
is above you. Act accordingly.

### Live vs Dead Analysis

```
ACQUISITION METHOD COMPARISON:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Method          Source          Footprint     Completeness   When to Use
────────────────────────────────────────────────────────────────────────
WinPMEM (live)  Running system  HIGH          Complete       IR response, active system
hiberfil.sys    Disk (offline)  ZERO          Complete       Disk acquisition, seized hardware
Crash dump      Disk (offline)  Medium        Complete       System already crashed
VM snapshot     Hypervisor      ZERO (guest)  Complete       Virtualised target
Process dump    Running system  Low           Process only   Single-process analysis
```

For most incident response: grab WinPMEM and dump immediately.
For forensic analysis of seized hardware: check for hiberfil.sys and
MEMORY.DMP before touching anything else.

---

## Section 2 — Volatility 3: Core Commands Reference

Volatility 3 is the standard. Python-based, open source, symbol-aware.
Forget Volatility 2 for new Windows targets. Volatility 3 handles symbol
resolution automatically — no manual `--profile` flag.

```
# Install Volatility 3:
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -e .

# Verify:
python vol.py -h

# Base invocation:
python vol.py -f <memory_image> <plugin>

# Windows plugins use windows.* prefix
python vol.py -f memdump.raw windows.pslist

# Output to file:
python vol.py -f memdump.raw windows.pslist > pslist.txt

# JSON output (for scripting):
python vol.py -f memdump.raw windows.pslist --output json > pslist.json

# Get OS info first:
python vol.py -f memdump.raw windows.info
python vol.py -f memdump.raw banners.Banners
```

Volatility auto-downloads Windows symbol packs from Microsoft Symbol Server.
First run on a new Windows build takes a few minutes. After that it's cached
in `~/.cache/volatility3/`.

### Plugin: windows.pslist

Walks the EPROCESS `ActiveProcessLinks` doubly-linked list. This is the
same list the Windows kernel presents to Task Manager and `tasklist`.
Rootkits hide from this by unlinking their EPROCESS entry.

```
python vol.py -f memdump.raw windows.pslist
```

**Sample output:**
```
PID    PPID   ImageFileName   Offset(V)           Threads  Handles  SessionId  Wow64  CreateTime
4      0      System          0xf8015a0c0040       107      0        N/A        False  2024-01-15 09:00:00
88     4      Registry        0xf8015a3f0040       4        0        N/A        False  2024-01-15 09:00:00
500    388    csrss.exe       0xf8015ac60140       10       0        0          False  2024-01-15 09:00:00
672    576    services.exe    0xf8015adf0300       7        0        0          False  2024-01-15 09:00:00
680    576    lsass.exe       0xf8015ae100c0       9        0        0          False  2024-01-15 09:00:00
4928   672    svchost.exe     0xf8015b8a0080       12       0        0          False  2024-01-15 09:00:00
7240   4928   cmd.exe         0xf8015c9f0080       1        0        1          False  2024-01-15 10:23:41
```

**What to look for:**
- `svchost.exe` with PPID other than `services.exe` (PID 672)
- `cmd.exe` or `powershell.exe` spawned from service processes
- Processes with odd names that mimic system processes
- `lsass.exe` with PPID other than `wininit.exe` (PID 576)
- Processes with recent CreateTime in the middle of the night

### Plugin: windows.psscan

Scans physical memory for EPROCESS structures by pool tag (`Proc`).
Finds processes regardless of whether they're linked in ActiveProcessLinks.
This is the rootkit defeater.

```
python vol.py -f memdump.raw windows.psscan
```

**The critical comparison — run this every single time:**

```
python vol.py -f memdump.raw windows.pslist --output csv > pslist.csv
python vol.py -f memdump.raw windows.psscan --output csv > psscan.csv
```

**Process in psscan but NOT pslist = rootkit indicator.**

The EPROCESS structure is in physical memory (psscan found it). But the
kernel's list doesn't include it (pslist didn't walk to it). Something
deliberately unlinked it. That something is a rootkit doing DKOM.

psscan also finds TERMINATED processes. A process that ran and exited
still has its EPROCESS in pool memory until the page is reused. This
catches malware that ran briefly and tried to clean up.

### Plugin: windows.cmdline

Retrieves full command-line arguments for all processes from their
PEB (Process Environment Block). This is how you find encoded payloads.

```
python vol.py -f memdump.raw windows.cmdline

# Filter to specific PID:
python vol.py -f memdump.raw windows.cmdline --pid 7240
```

**Sample suspicious output:**
```
PID     Process         Args
7240    powershell.exe  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                        -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0A...
```

That `-Enc` flag with a base64 payload is encoded PowerShell execution.
Decode it:

```python
import base64

encoded = "JABjAGwAaQBlAG4AdAAgAD0A..."
# PowerShell uses UTF-16-LE encoding
decoded = base64.b64decode(encoded).decode('utf-16-le')
print(decoded)

# Or from command line:
# echo <base64> | base64 -d | iconv -f utf-16le
```

**Flags that trigger an immediate hunt:**
- `-Enc` / `-EncodedCommand` in PowerShell arguments
- `-ExecutionPolicy Bypass` or `-ep bypass`
- `-NonInteractive`, `-WindowStyle Hidden` (hiding execution)
- `IEX` (Invoke-Expression) in command line
- Arguments containing `http://` or `https://`
- Arguments containing `\Temp\` or `\AppData\` paths

### Plugin: windows.netscan

Finds active and recently closed network connections by scanning for
`TcpE` (TCP endpoints), `UdpA` (UDP endpoints), and related structures
in pool memory.

```
python vol.py -f memdump.raw windows.netscan
```

**Sample output:**
```
Offset      Proto   LocalAddr         LocalPort  ForeignAddr       ForeignPort  State          PID    Owner
0xabc12300  TCPv4   192.168.1.100     49231      185.220.101.45    4444        ESTABLISHED    7240   powershell.exe
0xabc99900  TCPv4   192.168.1.100     50100      192.168.1.50      445         ESTABLISHED    7240   powershell.exe
0xabcdef00  TCPv4   0.0.0.0           445        0.0.0.0           0           LISTEN         4      System
```

`powershell.exe` with an ESTABLISHED connection to port 4444 on an
external IP? That's a Meterpreter reverse shell or similar. Log it.

`powershell.exe` with an ESTABLISHED connection to internal host on port 445?
That's SMB-based lateral movement — PsExec, Impacket smbexec, or similar.

**Enrich every foreign IP found:**
```bash
python vol.py -f memdump.raw windows.netscan | awk '{print $5}' | sort -u \
    | grep -v "ForeignAddr\|0.0.0.0\|\*" > foreign_ips.txt

# Check each IP against:
# - VirusTotal: https://virustotal.com/gui/ip-address/<ip>
# - AbuseIPDB: https://www.abuseipdb.com/check/<ip>
# - Shodan: https://shodan.io/host/<ip>
# - ThreatFox: https://threatfox.abuse.ch
```

### Plugin: windows.malfind

Scans process VAD trees for regions that look like injected code:
- Anonymous memory (no file backing — `VadS` tag)
- `PAGE_EXECUTE_READWRITE` permissions
- MZ header or shellcode opcode patterns at the start of the region

This is the primary injection detector. Injected code almost always
appears in anonymous RWX regions.

```
python vol.py -f memdump.raw windows.malfind

# Filter to specific process:
python vol.py -f memdump.raw windows.malfind --pid 848

# Dump suspicious regions:
python vol.py -f memdump.raw windows.malfind --pid 848 --dump
```

**Sample malfind output — reflective DLL injection:**
```
PID: 848   Process: svchost.exe

VAD node @ 0xffffd00012345678
  Start: 0x7ff9a0000000   End: 0x7ff9a000ffff
  Tag: VadS                            ← ANONYMOUS. No file backing.
  Protection: PAGE_EXECUTE_READWRITE   ← RWX. Injected code.

Hexdump:
4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  MZ..............
b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
```

Decoded: `4d 5a` = `MZ`. An MZ header in an anonymous RWX region inside
`svchost.exe` = a PE file was loaded into this process without touching disk.
This is reflective DLL injection.

**Common false positives:**
- .NET JIT-compiled code
- Some Electron apps
- Certain anti-cheat software

Context is everything. `svchost.exe` with an anonymous RWX MZ-header region
is never legitimate. `visual studio devenv.exe` with one might be JIT.

### Plugin: windows.dlllist

Lists DLLs loaded in each process from PEB loader data structures.

```
python vol.py -f memdump.raw windows.dlllist

# Per-process:
python vol.py -f memdump.raw windows.dlllist --pid 848

# Sample output:
Base           Size       Path
0x7ffa12340000 0x1a000    C:\Windows\System32\ntdll.dll
0x7ffa11230000 0x9f000    C:\Windows\System32\kernel32.dll
...
0x7ff900000000 0x4e000    (no path)                          ← REFLECTIVE LOAD
```

DLLs with no path in the output were loaded without touching disk.
The PEB's LDR list shows the module, but there's no disk file to point to.
This is the reflective injection footprint — after the MZ header in malfind,
this is your second confirmation.

**Also hunt for:**
- DLLs loaded from `\Temp\`, `\AppData\Local\`, `\Users\Public\`
- DLLs that impersonate system DLLs but from wrong paths
  (`kernel32.dll` from `C:\Users\Attacker\kernel32.dll`)

### Plugin: windows.handles

Lists open handles for a process — files, registry keys, mutexes, events,
threads, processes. Reveals exactly what the process has open.

```
python vol.py -f memdump.raw windows.handles --pid 7240

# Filter by handle type:
python vol.py -f memdump.raw windows.handles --pid 7240 --types File,Key,Process

# Sample suspicious output:
PID    Process      Type      GrantedAccess   Name
7240   malware.exe  Process   0x1fffff        \Device\...\lsass.exe
```

A process with a handle to `lsass.exe` with access `0x1fffff`
(`PROCESS_ALL_ACCESS`) is credential dumping. This is Mimikatz,
`procdump -ma lsass.exe`, or the `comsvcs.dll MiniDump` technique.

`0x1fffff` = PROCESS_ALL_ACCESS. Maximum. The attacker isn't being subtle.

---

## Section 3 — EPROCESS: The Kernel's Process Representation

Every Windows process has an EPROCESS kernel structure. Understanding
its fields tells you what malware abuses and how to detect it.

### EPROCESS Layout (Windows 10/11, x64)

```
EPROCESS structure (simplified, offsets are build-dependent):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

+0x000  Pcb                    KPROCESS  (CPU scheduling, base)
+0x438  ActiveProcessLinks     LIST_ENTRY ← doubly-linked list, DKOM unlinks here
+0x440  UniqueProcessId        HANDLE    (PID)
+0x448  InheritedFrom...       HANDLE    (PPID)
+0x4b8  ImageFileName[15]      UCHAR     (max 15 chars — TRUNCATED!)
+0x520  Peb                    PVOID     (pointer to PEB in user space)
+0x570  Token                  EX_FAST_REF ← process security token
+0x7d8  VadRoot                RTL_AVL_TREE ← VAD tree
+0x8b0  ObjectTable            HANDLE_TABLE

# Inspect in WinDbg (live system or kernel dump):
dt nt!_EPROCESS
dt nt!_EPROCESS <address>
!process 0 0 lsass.exe
```

### ActiveProcessLinks — The DKOM Target

This doubly-linked list field connects all EPROCESS structures in the
kernel. `NtQuerySystemInformation(SystemProcessInformation)` walks it.
Task Manager, Process Explorer, tasklist — they all use this.

**DKOM rootkit unlink technique:**

```c
// Kernel-mode rootkit code:
PLIST_ENTRY prev = target_eprocess->ActiveProcessLinks.Blink;
PLIST_ENTRY next = target_eprocess->ActiveProcessLinks.Flink;

prev->Flink = next;   // forward traversal skips the target
next->Blink = prev;   // backward traversal skips the target

// target_eprocess->Flink and Blink still point INTO the list
// but the list no longer points BACK to target
// Result: pslist walks the list and never reaches the target
// But: the EPROCESS structure still occupies physical memory
// psscan finds it by scanning for the 'Proc' pool tag
```

The process is invisible to all userspace APIs. Network connections
still work. File handles still work. SYSTEM shell still works.
Nothing visible in Task Manager. psscan defeats it.

### ImageFileName — The 15-Character Lie

The ImageFileName field is limited to 15 characters. Malware exploits
this by naming itself after system processes that fit: `svchost.exe` (10
chars), `lsass.exe` (9 chars), `explorer.exe` (12 chars).

The FULL path is in the PEB, not EPROCESS. Always cross-check:

```
python vol.py -f memdump.raw windows.dlllist --pid <pid>
# The first entry shows the full EXE path from PEB
# Compare against expected system paths:
# Legitimate: C:\Windows\System32\svchost.exe
# Malicious:  C:\Users\Public\svchost.exe
#             C:\Temp\svchost.exe
#             C:\Windows\svchost.exe (note: wrong directory)
```

### Token — Security Context

The security token at `+0x570` determines process access rights. Privilege
escalation implants steal or duplicate tokens from SYSTEM processes.

```
# View privileges for a process:
python vol.py -f memdump.raw windows.privileges --pid 7240

# Dangerous privileges to look for in unexpected processes:
# SeDebugPrivilege   → can open any process, read any memory
# SeImpersonatePrivilege → can steal other users' tokens
# SeLoadDriverPrivilege  → can load kernel drivers (kernel-level access)
# SeTcbPrivilege     → "Act as part of OS" — almost anything

# In WinDbg:
!token (poi(EPROCESS_addr + 0x570) & ~0xf)
```

### Legitimate Process Parent Tree

Parent-child relationships are a primary detection signal. Know the
expected tree. Any deviation is worth investigating.

```
LEGITIMATE WINDOWS PROCESS TREE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
System (PID 4)
└── smss.exe (Session Manager)
    ├── csrss.exe (Client/Server Runtime)
    ├── wininit.exe
    │   ├── services.exe
    │   │   ├── svchost.exe (×many)
    │   │   ├── spoolsv.exe
    │   │   ├── msdtc.exe
    │   │   └── ...
    │   ├── lsass.exe        ← PARENT MUST BE wininit.exe
    │   └── lsm.exe
    └── winlogon.exe
        └── userinit.exe → explorer.exe
            └── (user applications)

VIOLATIONS — always investigate:
  svchost.exe   PPID ≠ services.exe
  lsass.exe     PPID ≠ wininit.exe      ← CRITICAL alert
  cmd.exe       PPID = svchost.exe      ← webshell or exploitation
  powershell.exe PPID = svchost.exe     ← same
  explorer.exe  PPID ≠ userinit.exe     ← explorer hijack
```

---

## Section 4 — VAD Analysis: Detecting Injection

The VAD (Virtual Address Descriptor) tree describes every memory region
in a process address space. Legitimate processes have mostly file-backed
regions (mapped from EXEs and DLLs on disk) with small anonymous regions
(heaps, stacks). Injected code breaks this pattern.

### VAD Region Types

```
python vol.py -f memdump.raw windows.vadinfo --pid 848

# Legitimate DLL VAD entry:
  Start: 0x7ffa12340000   End: 0x7ffa12359fff
  Tag: Vad                     ← file-backed section object
  Protection: PAGE_EXECUTE_READ  ← RX — readable and executable, NOT writable
  FileObject: C:\Windows\System32\kernel32.dll  ← backed by file on disk

# Injected code VAD entry:
  Start: 0x7ff9a0000000   End: 0x7ff9a000ffff
  Tag: VadS                    ← anonymous — NO file backing
  Protection: PAGE_EXECUTE_READWRITE  ← RWX — red flag
  FileObject: (None)           ← nothing on disk
```

The injection signature:
- `VadS` tag (anonymous, private memory)
- `PAGE_EXECUTE_READWRITE` (must be writable to fill, executable to run)
- No FileObject (no disk counterpart)

### Injection Technique Signatures

```
TECHNIQUE → MEMORY SIGNATURE → DETECTION METHOD:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Classic Shellcode Injection:
  VirtualAllocEx(+XW) → WriteProcessMemory(shellcode) → CreateRemoteThread
  SIGNATURE: Small VadS +XW region, no PE header, raw opcodes
  DETECTION: malfind hit, no MZ at start — raw shellcode

Reflective DLL Injection:
  VirtualAllocEx(+XW) → WriteProcessMemory(full DLL) → CreateRemoteThread(reflective_loader)
  SIGNATURE: Large VadS +XW region WITH MZ header — full PE in anonymous memory
  DETECTION: malfind hit WITH MZ header, dlllist shows entry with no path

Process Hollowing (RunPE):
  CreateProcess(SUSPENDED) → UnmapViewOfFile → VirtualAllocEx → WriteProcessMemory → ResumeThread
  SIGNATURE: Process base address region is RWX (should be RX for legitimate EXE)
  DETECTION: PEB image base region has +W permission; hash of in-memory EXE ≠ on-disk EXE

APC Injection:
  OpenProcess → VirtualAllocEx(+XW) → WriteProcessMemory → QueueUserAPC(target_thread)
  SIGNATURE: Same as shellcode injection but no new remote thread created
  DETECTION: malfind — small anonymous +XW region in target process

DLL Search Order Hijack:
  Drop malicious DLL in application directory before system32 DLL
  SIGNATURE: DLL loaded from unexpected path
  DETECTION: dlllist shows DLL from non-System32 location for system DLL name
```

### malfind Output Walkthrough

```
# Run malfind and examine each hit systematically:
python vol.py -f memdump.raw windows.malfind > malfind.txt

# For each hit, answer these questions:

# Q1: Is this process context suspicious?
#     svchost.exe + anonymous RWX = suspicious
#     chrome.exe + anonymous RWX = might be renderer sandbox (verify)
#     notepad.exe + anonymous RWX = very suspicious

# Q2: Does the hex dump start with MZ? (4d 5a)
#     YES → injected PE file. Full DLL in memory.
#     NO  → raw shellcode. Check for common opcode patterns.

# Q3: Common shellcode prologue patterns:
#     fc 48 83 e4 f0        → x64 shellcode alignment (Metasploit/CS/Havoc)
#     e8 ?? ?? ?? ??        → relative call (common in shellcode stubs)
#     60 89 e5 31 d2        → x86 pushad/mov esp shellcode setup

# Q4: Dump and analyse:
python vol.py -f memdump.raw windows.malfind --pid 848 --dump
# Creates: pid.848.vad.0x7ff9a0000000-0x7ff9a000ffff.dmp

# Analyse the dumped file:
file pid.848.vad.*.dmp
strings pid.848.vad.*.dmp | grep -iE "http|cmd|pass|inject|load|download"
# If it's a PE: analyse with Ghidra or Cutter
```

---

## Section 5 — Network Artefacts in Memory

Network state is ephemeral but it lives in kernel memory until the
connection closes and the structures are freed. Memory forensics recovers
active connections, recently closed connections, and listen sockets.

### netscan Deep Dive

```
python vol.py -f memdump.raw windows.netscan

# Columns:
# Offset:       kernel address of connection structure
# Proto:        TCPv4, TCPv6, UDPv4, UDPv6
# LocalAddr:    local IP
# LocalPort:    local port
# ForeignAddr:  remote IP (* = any for listen)
# ForeignPort:  remote port
# State:        LISTEN, ESTABLISHED, CLOSE_WAIT, TIME_WAIT
# PID:          owning process ID
# Owner:        process name
# Created:      connection creation timestamp
```

**C2 beacon patterns:**

```
# Pattern 1: Reverse shell
powershell.exe → 185.220.101.45:4444 ESTABLISHED
# → Active reverse shell. 4444 is the Metasploit default.

# Pattern 2: HTTPS beacon (hard to distinguish from legit)
svchost.exe → 45.77.33.192:443 ESTABLISHED
# → Check: is svchost path legit? Is 45.77.33.192 known hosting?
#   Look up in Shodan — if it's a VPS with no web presence, suspicious.

# Pattern 3: DNS C2 (appears as UDP port 53 traffic)
svchost.exe → 8.8.8.8:53 ESTABLISHED    ← legit (DNS client)
cmd.exe → 1.2.3.4:53 ESTABLISHED         ← cmd has no business doing DNS

# Pattern 4: SMB lateral movement
powershell.exe → 192.168.1.50:445 ESTABLISHED
# → Internal SMB connection from PowerShell = PsExec / Impacket / lateral movement
```

### Named Pipes in Memory

SMB-based C2 and lateral movement uses named pipes. While netscan shows
TCP/UDP, named pipes appear in handles:

```
python vol.py -f memdump.raw windows.handles --pid 7240 --types File \
    | grep -i "\\\\pipe\\\\"
# Named pipes appear as \Device\NamedPipe\<pipename>

# Cobalt Strike default pipes:
# \pipe\msagent_<hex>
# \pipe\postex_<hex>
# \pipe\status_<hex>
# \pipe\mojo.<number>.<number>.<hex>
```

---

## Section 6 — Registry Hives in Memory

Active registry hives are loaded into kernel memory. Volatility can
read them from the memory image without touching on-disk hive files —
critical when an attacker has modified registry-in-memory but not
flushed to disk.

```
# List all loaded hives:
python vol.py -f memdump.raw windows.registry.hivelist

# Output:
# Offset           FileFullPath
# 0xffffd0001234   \REGISTRY\MACHINE\SYSTEM
# 0xffffd0005678   \REGISTRY\MACHINE\SOFTWARE
# 0xffffd0009abc   \REGISTRY\MACHINE\SAM       ← password hash database
# 0xffffd000def0   \REGISTRY\MACHINE\SECURITY
# 0xffffd0001111   \...\Users\victim\NTUSER.DAT

# Query specific key:
python vol.py -f memdump.raw windows.registry.printkey \
    --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

python vol.py -f memdump.raw windows.registry.printkey \
    --key "SYSTEM\CurrentControlSet\Services"

# Hunt persistence keys:
python vol.py -f memdump.raw windows.registry.printkey \
    --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```

**Persistence registry locations to always check:**

```
# Run keys (auto-execute at logon):
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

# Services (executes as SYSTEM on boot):
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>

# Image File Execution Options (debugger hijack):
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>
  Debugger = "C:\malware.exe"    ← malware runs when target binary is launched

# AppInit_DLLs (injected into every process loading user32.dll):
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs

# COM hijacking (user-writable, overrides system COM):
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
```

---

## Section 7 — LSASS Dump Detection

LSASS holds authentication material: NTLM hashes, Kerberos tickets,
cleartext passwords (WDigest enabled). Every credential dumping tool
targets it. As an analyst, you need to know when it was accessed.

```
WHAT LIVES IN LSASS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Credential Type    Location          Extractor
────────────────────────────────────────────────────────────
NTLM hash          MSV1_0 SSP        Mimikatz sekurlsa::msv
Kerberos TGT       Kerberos SSP      Mimikatz sekurlsa::tickets
Kerberos keys      Kerberos SSP      Mimikatz sekurlsa::ekeys
WDigest plaintext  WDigest SSP       Mimikatz sekurlsa::wdigest
DPAPI MasterKey    DPAPI blob        Mimikatz sekurlsa::dpapi
```

**Detecting LSASS credential access:**

```
# Check who has handles to lsass.exe:
python vol.py -f memdump.raw windows.handles | grep -i "lsass"

# A process with PROCESS_ALL_ACCESS (0x1fffff) handle to lsass.exe:
# → Mimikatz, procdump, or comsvcs.dll MiniDump
# Minimum for credential dump: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)

# Check for LSASS dump files on disk (via filescan):
python vol.py -f memdump.raw windows.filescan | grep -i "lsass"
# If you find lsass.dmp or similar in a temp path — it's already been dumped

# Hunt Mimikatz strings in memory:
python vol.py -f memdump.raw windows.memmap --pid <all_pids> --dump
strings *.dmp | grep -iE "sekurlsa|mimikatz|wdigest|lsadump"
```

**The comsvcs.dll MiniDump technique** — signed Microsoft binary, no Mimikatz:

```
# Attacker runs:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\loot\lsass.dmp full

# Detection in cmdline:
python vol.py -f memdump.raw windows.cmdline | grep -i "minidump\|comsvcs"
```

---

## Section 8 — String Extraction

When structured analysis hits a wall, go raw. Malware configurations,
C2 URLs, encryption keys, hardcoded IPs — all can appear as plaintext
in memory.

```
# Extract all strings from raw image:
strings -a -n 8 memdump.raw > strings_ascii.txt
strings -a -n 8 -e l memdump.raw > strings_unicode.txt    # UTF-16 LE

# Per-process via Volatility:
python vol.py -f memdump.raw windows.memmap --pid 7240 --dump
strings pid.7240.*.dmp > pid7240_strings.txt

# Filter for indicators:
grep -iE "https?://[a-zA-Z0-9./_-]+" strings_ascii.txt | sort -u
grep -iE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}" strings_ascii.txt
grep -iE "cmd\.exe|powershell|mshta|wscript|cscript" strings_ascii.txt
grep -iE "password|passwd|token|secret|apikey|bearer" strings_unicode.txt
grep -iE "\\\\pipe\\\\" strings_ascii.txt      # named pipes

# Hunt base64 blobs (encoded payloads, keys):
grep -oE "[A-Za-z0-9+/]{50,}={0,2}" strings_ascii.txt | sort -u > b64_candidates.txt

# Decode candidates:
while IFS= read -r line; do
    decoded=$(echo "$line" | base64 -d 2>/dev/null | strings -n 4)
    [ -n "$decoded" ] && echo "=== $line ===" && echo "$decoded"
done < b64_candidates.txt
```

**What you're hunting:**
- C2 domain names and IP:port combos
- User-Agent strings from malleable C2 profiles
- Mutex names (unique per implant family — searchable in threat intel)
- Encryption keys (32-byte blobs = possible AES-256)
- Hardcoded credentials
- Registry persistence paths
- Staging URLs for second-stage downloads

---

## Section 9 — pslist vs psscan: The Rootkit Gap

This is the single most important indicator in memory forensics.
Automate it. Run it every time. Never skip it.

```
# Generate both lists:
python vol.py -f memdump.raw windows.pslist --output csv > pslist.csv
python vol.py -f memdump.raw windows.psscan --output csv > psscan.csv

# Python comparison script:
import csv

def load_pids(filename):
    pids = {}
    with open(filename) as f:
        reader = csv.DictReader(f)
        for row in reader:
            pid = row.get('PID', '').strip()
            name = row.get('ImageFileName', row.get('Name', '')).strip()
            if pid:
                pids[pid] = name
    return pids

pslist_pids = load_pids('pslist.csv')
psscan_pids = load_pids('psscan.csv')

# Hidden from pslist = in psscan but NOT pslist:
hidden = {pid: name for pid, name in psscan_pids.items() if pid not in pslist_pids}
for pid, name in hidden.items():
    print(f"[HIDDEN] PID {pid} ({name}) — in psscan, NOT pslist → DKOM rootkit suspected")

# In pslist but not psscan (unusual, may indicate corruption):
ghost = {pid: name for pid, name in pslist_pids.items() if pid not in psscan_pids}
for pid, name in ghost.items():
    print(f"[GHOST] PID {pid} ({name}) — in pslist, NOT psscan → investigate")
```

**The three outcomes:**

```
IN pslist    IN psscan   INTERPRETATION
──────────────────────────────────────────────────────────────
    YES          YES     Normal process. OS sees it. Physical memory has it.
    NO           YES     ROOTKIT. EPROCESS is in memory but unlinked from kernel list.
                         Process invisible to Task Manager, tasklist, WinAPI.
                         psscan found EPROCESS by scanning physical memory for 'Proc' tag.
    YES          NO      Rare. Possible: partial EPROCESS corruption, memory smear
                         during acquisition, or extremely unusual synthetic process.
```

**Extend the same logic to drivers and modules:**

```
# Hidden kernel drivers:
python vol.py -f memdump.raw windows.modules > modules.txt
python vol.py -f memdump.raw windows.driverscan > driverscan.txt
# Diff: driver in driverscan not in modules = hidden kernel driver

# SSDT hooks (syscall table manipulation):
python vol.py -f memdump.raw windows.ssdt
# Any SSDT entry pointing outside ntoskrnl.exe or win32k.sys = hook
# A hooked syscall can hide files, processes, network connections, registry keys
```

---

## Triage Sequence (Muscle Memory)

Run this on every memory image. In this order. Every time.

```
# 1. OS identification
python vol.py -f memdump.raw windows.info

# 2. Process list vs pool scan — rootkit check
python vol.py -f memdump.raw windows.pslist > pslist.txt
python vol.py -f memdump.raw windows.psscan > psscan.txt
diff pslist.txt psscan.txt

# 3. Command lines — what was being executed
python vol.py -f memdump.raw windows.cmdline

# 4. Network connections — active C2, lateral movement
python vol.py -f memdump.raw windows.netscan

# 5. Injected code detection — primary injection hunt
python vol.py -f memdump.raw windows.malfind

# 6. Loaded modules — reflective loads, hijacked DLLs
python vol.py -f memdump.raw windows.dlllist

# 7. Handles — LSASS access, suspicious file/pipe handles
python vol.py -f memdump.raw windows.handles | grep -iE "lsass|\\\\pipe\\\\"

# 8. Registry persistence
python vol.py -f memdump.raw windows.registry.printkey \
    --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# 9. Process-specific string extraction on suspects
python vol.py -f memdump.raw windows.memmap --pid <suspicious_pid> --dump
strings pid.<suspicious_pid>.*.dmp | grep -iE "http|cmd|pass|inject" > suspect_strings.txt
```

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **WinPMEM** | Kernel driver for live Windows memory acquisition; creates raw physical memory image |
| **hiberfil.sys** | Windows hibernation file; compressed full RAM snapshot written on hibernate |
| **EPROCESS** | Executive Process structure; kernel object representing every Windows process |
| **ActiveProcessLinks** | Doubly-linked list in EPROCESS; walking this list = pslist; DKOM unlinks from here |
| **DKOM** | Direct Kernel Object Manipulation; rootkit technique to unlink EPROCESS from active list |
| **psscan** | Volatility plugin scanning physical memory for EPROCESS pool tags; defeats DKOM |
| **VAD** | Virtual Address Descriptor; tree structure describing every virtual memory region |
| **VadS tag** | Anonymous (non-file-backed) VAD node; signature of injected shellcode |
| **malfind** | Volatility plugin detecting injected code via anonymous RWX VAD regions |
| **Reflective injection** | Loading a DLL entirely from memory without touching disk |
| **Process hollowing** | Replacing a legitimate process's code with malicious code after creation |
| **LSASS** | Local Security Authority Subsystem Service; primary credential material storage |
| **SSDT hook** | Modification of the System Service Descriptor Table to intercept syscalls |

---

## Drill 13 — Memory Forensics

Go to `DRILLS/13_memory_forensics/`. A memory image from a compromised
Windows 10 host is waiting. Multiple artefacts planted. No hints on
what they are.

Your mission:

1. Run the full triage sequence. Document every hit in a findings log.

2. Find the DKOM-hidden process. Confirm via pslist vs psscan comparison.
   What process name is it using? What EPROCESS offset?

3. Find the injected code. Dump it. Determine: PE or raw shellcode?
   If PE: extract the import address table. What does it import?

4. Trace the network connection. C2 IP, port, owning process.
   Look the IP up in ThreatFox and Shodan. Document what you find.

5. Detect the LSASS access. Which process had a handle?
   What was the access mask? What technique does that match?

6. Extract strings from the suspect process dump. Find the C2 URL,
   the mutex name, and any persistence-related strings.

7. Check registry for persistence mechanism. Document the exact key
   path and value the malware used.

8. Write a one-page IR report: timeline, technique, IOCs, remediation.
   Format it as a SOC handoff document.

Memory doesn't lie. It doesn't delete itself on command. Everything
the attacker did from first access to image time is sitting in there
waiting to be read. Your job is to read it faster than they expected.

---

— Artefacts fade when the lights cut — the patient analyst
HUNTS what the rootkit buried in the electric dark
