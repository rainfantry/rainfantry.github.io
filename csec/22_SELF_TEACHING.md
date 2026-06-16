# Self-Teaching Roadmap: From Cert IV to Professional Red Teamer

> **Purpose:** Turn your kill chain into a curriculum. Every gap is a lesson. Every lesson has a path.
> **Audience:** You, self-teaching, no lecturer, no syllabus.
> **Rule:** No bullshit time estimates. No "just learn Linux." Exact concepts, exact resources, exact order.

---

## How to Use This Document

1. **Start at Level 0** (where you are now)
2. **Pick ONE concept** from the next level
3. **Study it until you can explain it to a wall**
4. **Build something with it**
5. **Move to the next concept**

Do not skip levels. Do not study five things at once. One concept, one build, one level.

---

## Level 0: Where You Are Now

**What you can do:**
- Write C programs using Windows APIs
- Compile with MSVC
- Understand socket programming
- Explain what `CreateProcessA`, `OpenProcess`, `VirtualAllocEx` do
- Build a basic kill chain that works in a lab

**What you understand:**
- Windows processes, threads, handles
- TCP/IP basics
- Service Control Manager
- Registry structure
- Token privileges

**Assessment:** Your CSEC Final chain is proof of Level 0. You are here.

---

## Level 1: Evasion Foundations (1-2 months)

**Goal:** Make your tools survive on a default Windows box with Defender ON.

### 1.1 Windows Internals — The Foundation Everything Builds On

**Concepts to learn:**
- **PE format** — DOS header, NT header, section headers, imports, exports, relocations
- **Memory layout** — virtual address space, pages, committed vs reserved, protection flags
- **System calls** — user mode vs kernel mode, `ntdll.dll`, `Nt*` functions vs `Zw*` functions
- **Processes and threads** — EPROCESS, ETHREAD, TEB, PEB
- **Handles and objects** — object manager, handle table, access masks

**Why:** You cannot evade what you do not understand. EDR lives in kernel mode. You need to know what it sees.

**Resources:**
- *Windows Internals, Part 1* (Russinovich, Solomon, Ionescu) — Chapters 1-5
- *Practical Windows Internals* (Yarden Shafir, Alex Ionescu) — YouTube lectures
- `!peb` and `!teb` in WinDbg — practice on your own machine

**Build project:** Write a program that parses its own PE headers in memory and prints every section name, size, and protection. No libraries — raw pointer arithmetic on `IMAGE_DOS_HEADER`.

---

### 1.2 API Hooking and Unhooking

**Concepts to learn:**
- **IAT (Import Address Table)** — how Windows resolves API calls at load time
- **Inline hooks** — how EDR patches the first bytes of `NtCreateThreadEx` to jump to its own code
- **SSDT (System Service Descriptor Table)** — kernel-level syscall table
- **Unhooking techniques** — reading clean `ntdll.dll` from disk, from KnownDlls, from suspended process

**Why:** EDR hooks `Nt*` functions to monitor your behavior. If you call `CreateRemoteThread`, EDR sees it because it hooked `NtCreateThreadEx`. Unhooking removes the EDR's visibility.

**Resources:**
- "Userland API Hooking and Unhooking" by ired.team
- "Bypassing User-Mode Hooks" by Spotless
- MalwareUnicorn's "Windows API Hooking" workshop

**Build project:** Write a program that:
1. Finds `NtCreateFile` in `ntdll.dll`
2. Checks if the first bytes are hooked (compare to clean copy from disk)
3. If hooked, restores the original bytes
4. Uses the unhooked `NtCreateFile` to write a file

---

### 1.3 Indirect Syscalls

**Concepts to learn:**
- **Direct syscalls** — calling `Nt*` functions by syscall number instead of through `ntdll.dll`
- **Indirect syscalls** — using a trampoline in `ntdll.dll` to avoid direct syscall detection
- **Syswhispers** — tool that generates syscall stubs from Windows headers
- **HellsGate / Halo'sGate** — techniques to find syscall numbers dynamically

**Why:** If EDR hooks `ntdll.dll`, bypass the hook entirely by going straight to kernel mode. Indirect syscalls are the current standard for EDR evasion.

**Resources:**
- "Syswhispers2: Why Direct System Calls Are No Longer Enough" by Jackson T.
- "HellsGate: Hell's Gate Evolved" by am0nsec
- GitHub: `jthuraisamy/Syswhispers2`, `am0nsec/HellsGate`

**Build project:** Rewrite your `shadow_shell.c` to use indirect syscalls for `NtCreateFile`, `NtAllocateVirtualMemory`, `NtCreateThreadEx`. Test it against Windows Defender with Tamper Protection ON.

---

### 1.4 String Encryption and Basic Obfuscation

**Concepts to learn:**
- **XOR encryption** — simple, fast, reversible
- **RC4** — stream cipher, easy to implement
- **AES** — block cipher, use a library (do not implement yourself)
- **String stacking** — building strings at runtime from fragments
- **API hashing** — resolving APIs by hash instead of name (hides imports)

**Why:** Static analysis finds your C2 IP in seconds. Encryption hides it until runtime.

**Resources:**
- "Practical Malware Analysis" (Sikorski, Honig) — Chapter 13: Obfuscation
- GitHub: `mgeeky/ProtectMyTooling` — see how packers work

**Build project:**
1. Write a Python script that XOR-encrypts a string with a random key
2. Embed the encrypted blob and key in your C source
3. Decrypt at runtime before use
4. Verify the string does not appear in the binary (use `strings.exe`)

---

## Level 2: Behavioral Evasion (2-3 months)

**Goal:** Survive behavioral analysis, sandbox detection, and memory scanning.

### 2.1 Sleep Obfuscation

**Concepts to learn:**
- **Ekko / Foliage / AceLdr** — encrypt payload in memory during sleep, decrypt on wake
- **Waitable timers** — `CreateTimerQueueTimer`, `NtWaitForSingleObject`
- **APC (Asynchronous Procedure Call) injection** — queueing APCs to threads
- **Thread pool manipulation** — `TpAllocTimer`, `SetThreadpoolTimer`

**Why:** EDR memory scanners check running processes periodically. If your payload is encrypted in memory during sleep, the scanner sees nothing.

**Resources:**
- "Ekko: Sleep Obfuscation in C" by C5pider (GitHub)
- "Foliage: Another Take on Sleep Obfuscation" by Cracked5pider
- "Sleep Obfuscation: The Current State" by MDsec

**Build project:** Implement Ekko in your `shadow_shell.c`. The shell sleeps for 5 seconds, encrypts itself in memory, wakes up, decrypts, and continues. Verify with Process Hacker that memory is not readable during sleep.

---

### 2.2 Sandbox Detection and Evasion

**Concepts to learn:**
- **VM detection** — CPUID hypervisor bits, registry artifacts, driver checks
- **Timing checks** — `rdtsc`, `QueryPerformanceCounter` to detect emulation
- **Human interaction checks** — mouse movement, foreground window changes
- **Process / module enumeration** — looking for analysis tools (Wireshark, Procmon)
- **Domain / username checks** — common sandbox names ("SANDBOX", "VIRUS")

**Why:** Malware sandboxes run your binary for 30-60 seconds. If you detect the sandbox, you exit cleanly. If you detect a real machine, you execute.

**Resources:**
- "The Art of Malware Analysis" (Dang, Gazet, Bachaalany) — Chapter 8: Anti-Analysis
- GitHub: `a0rtega/pafish` — VM detection techniques in C
- GitHub: `LordNoteworthy/al-khaser` — comprehensive anti-analysis tool

**Build project:** Add sandbox detection to your `spoolsv.exe`. If running in a VM or sandbox, print "OK" and exit. If running on a physical machine, connect to C2. Test in VirtualBox vs your host.

---

### 2.3 Parent Process ID (PPID) Spoofing

**Concepts to learn:**
- **PROC_THREAD_ATTRIBUTE_PARENT_PROCESS** — `UpdateProcThreadAttribute` to fake parent process
- **BlockDLLs** — preventing non-Microsoft DLLs from loading into your process
- **Spoofed command line** — `RtlCreateProcessParametersEx` to hide real arguments

**Why:** EDR correlates parent-child processes. If `explorer.exe` spawns `cmd.exe`, it's normal. If `spoolsv.exe` spawns `cmd.exe`, it's suspicious. PPID spoofing makes your payload appear to be spawned by a legitimate parent.

**Resources:**
- "PPID Spoofing and BlockDLLs" by ired.team
- "The Importance of Parent Process ID Spoofing" by MDSec

**Build project:** Rewrite `shadow_shell.c` to spawn `cmd.exe` with `explorer.exe` as the spoofed parent. Verify in Process Hacker that `explorer.exe` appears as the parent.

---

## Level 3: Network Evasion (2-3 months)

**Goal:** C2 that blends into normal enterprise traffic and survives proxy inspection.

### 3.1 HTTPS C2 with WinHTTP

**Concepts to learn:**
- **WinHTTP vs WinInet** — WinHTTP is better for non-interactive services
- **Certificate pinning** — hardcoding expected server cert to prevent MITM
- **User-Agent rotation** — rotating browser UAs to blend in
- **Domain fronting** — using CDN edge servers to hide true destination

**Why:** Raw TCP on port 8080 is the most detectable thing you can build. HTTPS on 443 looks like normal web traffic.

**Resources:**
- Microsoft Docs: "WinHTTP vs. WinInet"
- "Domain Fronting via CDN" by Vincent Yiu
- GitHub: `mgeeky/RedWarden` — C2 redirector with malleable profiles

**Build project:** Replace your raw socket C2 with WinHTTP HTTPS requests. Host a simple Python Flask server with a self-signed cert. The client polls `/api/v1/status` every 10 seconds and receives commands in JSON. Use certificate pinning.

---

### 3.2 DNS Tunneling and DoH

**Concepts to learn:**
- **DNS tunneling** — encoding data in DNS query names and TXT responses
- **DoH (DNS over HTTPS)** — DNS queries inside HTTPS to `cloudflare-dns.com`
- **DGA (Domain Generation Algorithm)** — generating thousands of candidate domains to prevent takedown

**Why:** Some networks block all outbound except DNS. If you can tunnel over DNS, you have C2 anywhere.

**Resources:**
- "DNS Tunneling: How It Works and How to Detect It" by Unit 42
- GitHub: `yarrick/iodine` — DNS tunneling in C
- GitHub: `BishopFox/sliver` — see DNS C2 implementation

**Build project:** Write a DNS tunnel client that encodes a command in a subdomain query (`base64cmd.yourdomain.com`) and receives output in a TXT record. Use `DnsQuery_A` API.

---

### 3.3 Malleable C2 Profiles

**Concepts to learn:**
- **Malleable C2** — Cobalt Strike's concept of making C2 traffic look like legitimate apps (Gmail, AWS, etc.)
- **JA3 fingerprinting** — TLS client fingerprinting used to detect malware
- **JA3 randomization** — randomizing TLS handshake parameters to evade JA3 detection
- **JARM** — server-side TLS fingerprinting

**Why:** Even HTTPS C2 can be detected by its TLS fingerprint. Malleable profiles randomize the fingerprint to match legitimate software.

**Resources:**
- "Malleable C2 Profiles: A Guide" by Cobalt Strike
- "JA3: A Method for Profiling SSL/TLS Clients" by Salesforce
- GitHub: `salesforce/ja3`

**Build project:** Configure your HTTPS C2 to use a JA3 fingerprint that matches Chrome 120. Test against `ja3er.com` to verify.

---

## Level 4: Advanced Injection (2-3 months)

**Goal:** Inject payload without `CreateRemoteThread` — survive Sysmon Event ID 8.

### 4.1 APC Injection

**Concepts to learn:**
- **APC (Asynchronous Procedure Call)** — kernel mechanism to interrupt a thread
- `QueueUserAPC` / `NtQueueApcThread` — queueing APCs to alertable threads
- **Alertable state** — threads that can receive APCs (`SleepEx`, `Wait`, `ReadFileEx`)
- **Early-bird APC injection** — injecting into a suspended process before it starts

**Why:** `CreateRemoteThread` is logged by Sysmon and EDR. APC injection uses legitimate Windows mechanisms and is harder to detect.

**Resources:**
- "APC Injection: Theory and Practice" by ired.team
- "Early Bird APC Injection" by CyberBit
- GitHub: `Cracked5pider/EarlyBird` — implementation

**Build project:** Rewrite `Injector.exe` to use APC injection instead of `CreateRemoteThread`. Target an alertable thread in `notepad.exe`. Verify the DLL loads successfully.

---

### 4.2 Process Hollowing

**Concepts to learn:**
- **CreateProcess in suspended state** — `CREATE_SUSPENDED`
- **NtUnmapViewOfSection** — unmapping legitimate executable from process
- **VirtualAllocEx + WriteProcessMemory** — writing malicious executable into hollowed process
- **Relocation and import table fixing** — adjusting addresses for new base
- **SetThreadContext + ResumeThread** — redirecting execution to new entry point

**Why:** Instead of injecting into a running process, you replace the entire executable image. The process looks legitimate (signed binary) but executes your code.

**Resources:**
- "Process Hollowing: A Deep Dive" by MalwareTech
- "The Evolution of Process Injection" by Endgame
- GitHub: `m0n0ph1/Process-Hollowing` — reference implementation

**Build project:** Hollow `notepad.exe` to run your `shadow_shell.exe` payload. Verify `notepad.exe` appears in Task Manager but connects to your C2.

---

### 4.3 Mapping Injection (Section Mapping)

**Concepts to learn:**
- **NtCreateSection** — creating a memory section object
- **NtMapViewOfSection** — mapping section into remote process
- **SEC_IMAGE** — mapping a PE file as an executable image
- **Reflective DLL injection** — loading a DLL from memory without `LoadLibraryA`

**Why:** Mapping injection avoids `WriteProcessMemory` + `CreateRemoteThread` — both heavily monitored. It uses legitimate memory sharing APIs.

**Resources:**
- "Reflective DLL Injection" by Stephen Fewer (original paper)
- "Mapping Injection: The Future of Process Injection" by MDsec
- GitHub: `stephenfewer/ReflectiveDLLInjection`

**Build project:** Implement reflective DLL injection. Your DLL loads itself into memory, parses its own imports, and executes without ever calling `LoadLibraryA`. Inject into `explorer.exe`.

---

## Level 5: Credential Theft in Modern Environments (2-3 months)

**Goal:** Steal credentials even when Credential Guard is active.

### 5.1 Kerberos Attacks

**Concepts to learn:**
- **Kerberos authentication flow** — AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ
- **Kerberoasting** — requesting service tickets for SPNs, offline cracking
- **AS-REP Roasting** — requesting tickets for users with "Do not require Kerberos preauthentication"
- **Golden Ticket** — forging a TGT with krbtgt hash
- **Silver Ticket** — forging a TGS with service account hash

**Why:** Credential Guard protects LSASS memory but does not protect Kerberos tickets. If you can get a service ticket, you can crack it offline.

**Resources:**
- "Kerberos Attacks: The Full Guide" by Harmj0y
- "Attacking Kerberos: The Basics" by ired.team
- Impacket: `GetUserSPNs.py`, `GetNPUsers.py`

**Build project:** Set up a Windows Server DC in VirtualBox. Create a user with an SPN. Use Impacket to Kerberoast the account and crack the ticket with Hashcat.

---

### 5.2 Keylogging and Clipboard Theft

**Concepts to learn:**
- **Low-level keyboard hooks** — `SetWindowsHookEx` with `WH_KEYBOARD_LL`
- **Raw input API** — `RegisterRawInputDevices` for keylogging without hooks
- **Clipboard monitoring** — `SetClipboardViewer`, `WM_DRAWCLIPBOARD`
- **Credential Guard bypass** — these techniques do not touch LSASS at all

**Why:** If Credential Guard blocks LSASS dumps, steal credentials at the point of entry — the keyboard.

**Resources:**
- "Windows Keylogging Techniques" by ired.team
- GitHub: `giuliocomi/backdoorplz` — keylogger implementation

**Build project:** Write a keylogger that logs all keystrokes to an encrypted file. Test it on your own machine. Verify it captures passwords typed into Notepad.

---

### 5.3 NTDS.dit Extraction

**Concepts to learn:**
- **NTDS.dit** — Active Directory database containing all domain credentials
- **Volume Shadow Copy** — `vssadmin` to snapshot the database while in use
- **DCSync** — using `DRSGetNCChanges` to replicate password hashes from DC
- **SecretsDump** — Impacket tool for extracting hashes

**Why:** If you have domain admin, you own the domain. NTDS.dit contains every user's hash.

**Resources:**
- "Extracting NTDS.dit" by ired.team
- Impacket: `secretsdump.py`
- Mimikatz: `lsadump::dcsync`

**Build project:** On your lab DC, use `vssadmin` to create a shadow copy, copy `NTDS.dit`, and extract hashes with `secretsdump.py`.

---

## Level 6: EDR Evasion — The Final Boss (3-6 months)

**Goal:** Survive enterprise EDR (CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender for Endpoint).

### 6.1 EDR Architecture Deep Dive

**Concepts to learn:**
- **Kernel callbacks** — `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `CmRegisterCallback`
- **Minifilters** — file system filter drivers that monitor I/O
- **AMSI (Anti-Malware Scan Interface)** — scanning scripts and memory at runtime
- **ETW (Event Tracing for Windows)** — high-speed kernel logging used by EDR
- **PPL (Protected Process Light)** — preventing even admin from terminating EDR processes

**Why:** You cannot evade what you do not understand. EDR is not magic — it is kernel callbacks + userland hooks + cloud correlation.

**Resources:**
- "EDR Internals" by Elastic Security
- "Windows Security Internals" by Matt Graeber
- "AMSI: How It Works and How to Bypass It" by CyberArk

**Build project:** Write a driver (or use a test-signing cert) that enumerates all registered kernel callbacks. Print the addresses and the modules that registered them.

---

### 6.2 Kernel Callback Patching

**Concepts to learn:**
- **Driver development** — WDK, `DriverEntry`, IRP handling
- **Callback removal** — unregistering EDR callbacks from kernel mode
- **BYOVD (Bring Your Own Vulnerable Driver)** — loading a signed vulnerable driver, exploiting it to execute kernel code
- **HVCI (Hypervisor-Protected Code Integrity)** — prevents unsigned drivers from loading

**Why:** If you can remove EDR's kernel callbacks, the EDR goes blind. This is how modern malware survives enterprise EDR.

**Resources:**
- "BYOVD: Bring Your Own Vulnerable Driver" by SentinelOne
- GitHub: `hfiref0x/KDU` — Kernel Driver Utility
- GitHub: `namazso/VulnerableDriver` — practice target

**Build project:** Use KDU to load a vulnerable driver. Use it to patch a test callback you registered yourself. Verify the callback no longer fires.

---

### 6.3 ETW Tampering

**Concepts to learn:**
- **ETW providers** — `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Security-Auditing`
- **ETW sessions** — how EDR subscribes to kernel events
- **Patching ETW** — disabling `EtwEventWrite` in `ntdll.dll`
- **Silencing providers** — unregistering specific providers

**Why:** ETW is the logging backbone of Windows. EDR consumes ETW events. If you silence ETW, EDR sees nothing.

**Resources:**
- "ETW Tampering: The New Normal" by MDsec
- GitHub: `pwn1sher/etw-bypass` — reference implementations

**Build project:** Patch `EtwEventWrite` in your process to return immediately without logging. Verify with `logman` that your process generates no ETW events.

---

## Level 7: Operational Security and C2 Frameworks (Ongoing)

**Goal:** Operate like a professional red teamer, not a script kiddie.

### 7.1 C2 Frameworks

**Concepts to learn:**
- **Cobalt Strike** — industry standard, malleable C2, post-exploitation toolkit
- **Sliver** — open-source alternative to Cobalt Strike
- **Havoc** — modern C2 framework with sleep obfuscation built in
- **Mythic** — collaborative C2 platform with extensive agent support

**Why:** Writing your own C2 is educational. Using a mature framework is operational. Professionals use frameworks because they handle the 90% of edge cases you have not thought of.

**Resources:**
- Cobalt Strike documentation (trial available)
- GitHub: `BishopFox/sliver` — free, open source
- GitHub: `HavocFramework/Havoc` — free, modern

**Build project:** Set up Sliver on a VPS. Generate a beacon. Execute it on your lab VM. Practice all post-exploitation commands (ls, ps, shell, screenshot, keylogger).

---

### 7.2 OPSEC and Tradecraft

**Concepts to learn:**
- **Infrastructure setup** — redirectors, domain fronting, CDN riding
- **Burner infrastructure** — disposable VPS, domains, TLS certs
- ** Attribution avoidance** — never reuse infrastructure, never test from home IP
- **Legal boundaries** — contracts, scope, rules of engagement
- **Reporting** — professional deliverables, risk ratings, remediation advice

**Why:** Technical skill gets you in. OPSEC keeps you out of prison. Professional red teamers are paranoid by design.

**Resources:**
- "Red Team Operations" by SpecterOps
- "The Hacker's Diet" — OPSEC for hackers (blog posts by various authors)
- "Professional Red Teaming" by Wil Allsopp

**Build project:** Set up a complete C2 infrastructure: VPS in EU, CloudFlare redirector, custom domain, valid TLS cert. Document the setup. Then tear it down and rebuild differently.

---

## Study Schedule Template

| Week | Focus | Daily Commitment |
|------|-------|-----------------|
| 1-4 | Level 1.1: Windows Internals | 2 hours |
| 5-6 | Level 1.2: API Hooking | 2 hours |
| 7-8 | Level 1.3: Indirect Syscalls | 2 hours |
| 9 | Level 1.4: String Encryption | 2 hours |
| 10-14 | Level 2.1: Sleep Obfuscation | 2 hours |
| 15-16 | Level 2.2: Sandbox Detection | 2 hours |
| 17-18 | Level 2.3: PPID Spoofing | 2 hours |
| 19-23 | Level 3.1: HTTPS C2 | 2 hours |
| 24-26 | Level 3.2: DNS Tunneling | 2 hours |
| 27-30 | Level 4.1: APC Injection | 2 hours |
| 31-34 | Level 4.2: Process Hollowing | 2 hours |
| 35-38 | Level 4.3: Mapping Injection | 2 hours |
| 39-43 | Level 5.1: Kerberos Attacks | 2 hours |
| 44-47 | Level 5.2: Keylogging | 2 hours |
| 48-52 | Level 6.1: EDR Architecture | 2 hours |
| 53+ | Level 6.2+: Kernel Callbacks | Ongoing |

**Total time to Level 6:** ~12 months at 2 hours/day, 5 days/week.

---

## Rules for Self-Teaching

1. **One concept at a time.** Do not study API hooking and Kerberos in the same week.
2. **Build something every week.** Reading without building is entertainment, not learning.
3. **Test against real defenses.** Set up a VM with Defender ON, ASR enabled, Sysmon logging. If it works there, it might work in the real world.
4. **Document everything.** Write a blog post, a GitHub repo, or a note for every technique you learn. Teaching reinforces learning.
5. **Do not rush.** This is a marathon, not a sprint. Two hours a day for a year beats 12-hour binges that burn you out.
6. **Stay legal.** Every technique in this document has a legitimate defensive purpose. Use them only on systems you own or have explicit written permission to test.

---

## The Bottom Line

**Level 0** (where you are): Cert IV student, basic C, Windows APIs, lab-only kill chain.

**Level 1-2** (1-2 months): Can evade basic AV, survive on default Windows.

**Level 3-4** (4-6 months): Can evade enterprise firewall, inject without detection.

**Level 5** (6-9 months): Can steal credentials in modern environments.

**Level 6** (9-12 months): Can evade enterprise EDR.

**Level 7** (12+ months): Professional red teamer — operational, not just technical.

The gap from your current chain to "real-world viable" is **12 months of focused study**, not a weekend of coding. But every level is achievable. Every concept is documented. Every resource is listed.

Start at Level 1.1. Build the PE parser. Move forward from there.

---

*Document version: 1.0*
*Date: 2026-06-09*
*Classification: Self-teaching curriculum — academic and defensive purposes only*
