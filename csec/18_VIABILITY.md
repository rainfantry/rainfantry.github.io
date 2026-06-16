# Real-World Viability Assessment

> **Question:** Can this kill chain work on a real victim environment?
> **Answer:** Not as-is. Each stage fails against one or more default protections on a modern enterprise Windows machine. This document maps exactly what breaks and why.
> **Purpose:** Honest self-assessment. Know the gap between "lab demo" and "real world."

---

## The Honest Verdict

| Stage | Lab Result | Real-World Result | Why It Dies |
|-------|-----------|-------------------|-------------|
| 1. Evasion | Works | **FAILS** | Tamper Protection is ON by default on every Windows 10/11 install since 1903 |
| 2. Foothold | Works | **CAUGHT** | Behavioral detection flags `socket` → `connect` → `CreateProcessA` with `STARTF_USESTDHANDLES` |
| 3. Persistence | Works | **CAUGHT** | Event ID 7045 fires immediately; EDR correlates service creation from temp path |
| 4. Injection | Works | **BLOCKED** | `CreateRemoteThread` into `explorer.exe` is a textbook EDR alert; Sysmon Event ID 8 |
| 5. Credentials | Works | **FAILS** | Credential Guard (Enterprise) virtualizes LSASS; SAM dumps are encrypted garbage |
| 6. Lateral | Works | **PARTIAL** | SMB still works, but LAPS = unique local admin passwords per machine; no reuse |
| 7. VNC | Works | **BLOCKED** | Outbound 5900 is rarely allowed; NGROK variant might slip through but is noisy |

**Bottom line:** This is a **teaching-grade kill chain**, not a production red-team tool. It demonstrates concepts. It does not bypass modern defenses.

---

## Stage-by-Stage Breakdown

### Stage 1: Evasion — `svchost_update.exe`

**What it does:** Stops Defender services, adds exclusions, corrupts signatures.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **Tamper Protection (default ON)** | Blocks SCM stop of `WinDefend`, blocks registry writes to Defender keys | You turned it OFF |
| **WDAC / AppLocker** | Prevents unsigned/untrusted executables from running | Classroom machine has no app control |
| **PPL (Protected Process Light)** | Defender services run as PPL — cannot be terminated even by Admin | Not enabled in your lab |
| **Cloud-delivered protection** | Even if local engine stops, cloud heuristics still flag files | Internet was on, but cloud protection may not have been active |

**What would be needed to make it real-world viable:**
- A **kernel driver exploit** or **signed driver abuse** to disable Tamper Protection from kernel mode
- A **living-off-the-land** approach using only built-in Windows tools (no dropped binary)
- **BYOVD** (Bring Your Own Vulnerable Driver) — load a known-vulnerable signed driver, exploit it to kill Defender
- A **0-day in Defender** itself (nation-state territory)

**Honest assessment:** Stopping Defender with `OpenSCManagerW` + `ControlService` is 1990s technique. It teaches the APIs. It does not work against a default Windows 11 box in 2026.

---

### Stage 2: Foothold — `spoolsv.exe` (Reverse Shell)

**What it does:** Outbound TCP connect to attacker, spawns hidden `cmd.exe` with socket redirected to stdio.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **Behavioral detection** | `WSAStartup` → `socket` → `connect` → `CreateProcessA` with `STARTF_USESTDHANDLES` is a known malware signature | Defender was stopped |
| **AMSI** | If you tried to run PowerShell or script-based payload, AMSI would catch it | Not applicable (C binary) |
| **Network firewall (enterprise)** | Outbound 8080/8890 blocked; only 80/443 allowed through proxy | Classroom LAN is permissive |
| **ETW (Event Tracing for Windows)** | Every API call is logged; EDR hunts on the sequence | No EDR in lab |

**What would be needed:**
- **HTTPS / DoH (DNS over HTTPS)** tunnel to blend into web traffic
- **Domain fronting** or **CDN riding** to hide C2 behind legitimate infrastructure
- **Process injection** of the shell code into a legitimate browser process (Edge, Chrome) so the connection appears normal
- **Encrypted payload** with runtime decryption to hide the IP/port strings

**Honest assessment:** A raw TCP reverse shell on port 8080 is the most detectable thing you can build. It teaches socket programming. It is not a real-world C2.

---

### Stage 3: Persistence — `SecurityHealthHost.exe`

**What it does:** Installs itself as an auto-start Windows service masquerading as a legitimate security component.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **Event ID 7045** | Windows logs every service creation immediately | No SIEM in lab to see the alert |
| **EDR behavioral rules** | "New service from temp directory" = instant high-severity alert | No EDR |
| **Service signature requirements** | Some hardened environments require signed drivers/services | Test machine has no such policy |
| **AutoRuns / Sysinternals** | Blue teams run `autoruns.exe` regularly; fake service name stands out | No blue team in lab |

**What would be needed:**
- **WMI event subscription** or **scheduled task** (less noisy than service creation)
- **Registry run key** with a legitimate-sounding name
- **DLL hijacking** of a legitimate application (no new service, no new process)
- **Bootkit / UEFI implant** (nation-state, not Cert IV)

**Honest assessment:** Service creation is the loudest persistence technique. It is logged by default. It teaches SCM APIs. It is not how real APTs persist.

---

### Stage 4: Injection — `Injector.exe` + `payload.dll`

**What it does:** Classic remote thread injection using `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` with `LoadLibraryA`.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **Sysmon Event ID 8** | Logs every `CreateRemoteThread` with source/target process | No Sysmon in lab |
| **EDR kernel callbacks** | `PsSetCreateThreadNotifyRoutine` allows security products to block or log remote threads | No EDR |
| **Control Flow Guard (CFG)** | Modern Windows validates indirect call targets; injected thread may fail | Not enabled on lab machine |
| **Microsoft Defender Attack Surface Reduction (ASR)** | Rule "Block process creations originating from PSExec and WMI commands" can block child processes from injected processes | ASR not configured |
| **Child process telemetry** | `explorer.exe` spawning `spoolsv.exe` from `C:\Windows\Temp\c2\` is an instant parent-child anomaly | No telemetry collection |

**What would be needed:**
- **Process hollowing** or **process doppelgänging** (more sophisticated, still detectable)
- **APC injection** or **thread hijacking** (avoids `CreateRemoteThread`)
- **Kernel callback removal** (requires kernel exploit)
- **Early-bird injection** (inject before EDR hooks are established)

**Honest assessment:** `CreateRemoteThread` + `LoadLibraryA` is the first injection technique every student learns. Every EDR detects it. It teaches memory manipulation. It is not a real-world injection method.

---

### Stage 5: Credentials — `TokenVault.exe`

**What it does:** Steals SYSTEM token from `winlogon.exe`, impersonates, dumps SAM hive.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **Credential Guard** | Virtualizes LSASS; SAM dumps contain encrypted hashes useless for pass-the-hash | Not enabled (requires Enterprise/Pro + UEFI) |
| **LSA protection** | `RunAsPPL` registry key prevents non-protected processes from opening LSASS | Not set in lab |
| **EDR LSASS access detection** | Opening `lsass.exe` with `PROCESS_QUERY_INFORMATION` fires alerts | No EDR |
| **SeDebugPrivilege restrictions** | Some environments remove `SeDebugPrivilege` from administrators via GPO | Default config in lab |

**What would be needed:**
- **Mimikatz-style LSASS memory reading** (still detected by Credential Guard)
- **Kerberoasting** or **AS-REP Roasting** (no local admin needed, but requires domain)
- **NTDS.dit extraction** from domain controller (requires DC access)
- **Keylogger** or **clipboard stealer** (avoids Credential Guard entirely)

**Honest assessment:** Token theft + SAM dump is a solid teaching technique. Credential Guard makes it obsolete on any modern Enterprise machine. It teaches token APIs. It is not how real red teams steal creds today.

---

### Stage 6: Lateral Movement — `NetExec.exe`

**What it does:** SMB auth, copy payload, remote service creation.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **LAPS** | Unique local admin password per machine — no password reuse | Not deployed in lab |
| **SMB signing required** | Some environments enforce signing; your tool does not | Not enforced |
| **Windows Firewall** | Blocks SMB (445) between workstations by default | Lab LAN is flat |
| **EDR lateral movement rules** | Correlates SMB auth + service creation + immediate execution | No EDR |
| **Just Enough Administration (JEA)** | Limits admin rights; cannot create remote services | Not configured |
| **Network segmentation** | VLANs isolate workstations; no route to target | Flat network |

**What would be needed:**
- **Valid domain credentials** (phished or kerberoasted)
- **Pass-the-hash** or **Pass-the-ticket** (no plaintext password needed)
- **WMI / PowerShell remoting** (less noisy than service creation)
- **RDP hijacking** or **token impersonation** across sessions

**Honest assessment:** PsExec-style lateral movement still works in poorly segmented networks. It is the most "real-world viable" stage in your chain — but only if you have valid creds AND the network is flat AND LAPS is not deployed. Most enterprise networks fail at least one of those.

---

### Stage 7: VNC Callback

**What it does:** Reverse VNC connection from victim to attacker viewer.

**Why it dies in the real world:**

| Defense | How It Breaks This Stage | Your Lab Bypass |
|---------|-------------------------|-----------------|
| **Egress firewall** | Blocks outbound 5900; only 80/443 allowed | Classroom LAN permissive |
| **Proxy inspection** | Enterprise proxy decrypts and inspects TLS; raw TCP fails | No proxy |
| **NGROK free tier** | Random endpoints, rate limits, easily flagged by threat intel | Used in variant, but still noisy |
| **Screen capture detection** | Some EDR detects screen capture APIs | Not applicable (VNC protocol) |

**What would be needed:**
- **HTTPS tunnel** for VNC over port 443
- **Cobalt Strike / Sliver** beacon with built-in SOCKS proxy (industry standard)
- **RDP over reverse SSH** tunnel
- **Living-off-the-land** using `mstsc.exe` with forwarded ports

**Honest assessment:** Reverse VNC is a teaching tool for GUI access. Real red teams use Cobalt Strike beacons with `rdesktop` or built-in VNC modules tunneled over HTTPS.

---

## What Would Make This Real-World Viable?

To turn this teaching chain into something that works against a modern enterprise endpoint, you would need:

| Gap | What You'd Add | Complexity |
|-----|---------------|------------|
| **Tamper Protection bypass** | BYOVD, kernel driver exploit, or 0-day | Nation-state / advanced |
| **Behavioral evasion** | Indirect syscalls, unhooking, sleep obfuscation | Intermediate |
| **Network evasion** | HTTPS C2, domain fronting, DoH | Intermediate |
| **Injection evasion** | APC injection, thread hijacking, early-bird | Intermediate |
| **Credential evasion** | Kerberoasting, keylogging, clipboard theft | Intermediate |
| **Lateral evasion** | Pass-the-hash, WMI remoting, RDP hijacking | Intermediate |
| **EDR evasion** | EDR userland hook removal, kernel callback patching | Advanced |

**The honest truth:** Each of those "intermediate" items is a multi-week research project. The "advanced" items are full-time red teamer / malware developer territory. Your Cert IV chain is not supposed to be real-world viable — it is supposed to demonstrate that you **understand the concepts** and can **build working code**.

---

## What This Chain IS Good For

| Use Case | Why It Works |
|----------|-------------|
| **Academic demonstration** | Shows complete kill chain from code to execution |
| **Blue team training** | Defenders can see exactly what each stage looks like in logs |
| **Malware analysis practice** | Clean, well-documented code to practice static/dynamic analysis |
| **Interview talking points** | "I built a full kill chain in C using only Windows APIs" |
| **Foundation for advanced study** | Every concept here scales up to real-world techniques |

---

## What This Chain Is NOT

| Claim | Reality |
|-------|---------|
| "Bypasses Defender" | Only with Tamper Protection OFF — a configuration, not a vulnerability |
| "Undetectable" | Every stage has known detection signatures |
| "Production red team tool" | No — it is a learning artifact |
| "0-day" | No vulnerabilities exploited; only documented APIs abused |
| "APT-grade" | APTs use sleep obfuscation, encrypted C2, and EDR evasion — none of which are here |

---

## The One-Liner

> This kill chain works in a **lab with the safeties off**. It dies in the **real world with the safeties on**. That is not a flaw — it is the **expected outcome of a student project**. The value is not in bypassing every defense. The value is in **knowing exactly which defense stops which stage**, and **what you would need to learn next** to get past it.

---

## The Distance: Student Project → Real-World Viable

Straight answer: **You're at "student project." Real-world viable is "professional red teamer." The gap is 1-2 years of dedicated study, not a weekend of coding.**

### What You Have Now (Cert IV Level)

- Understands Windows APIs
- Can compile C
- Knows what a kill chain looks like
- Can explain every line of code

### What Real-World Viable Requires

| Gap | What It Actually Means | Time to Learn |
|-----|----------------------|---------------|
| **Tamper Protection bypass** | Kernel driver development, driver signing abuse, or finding a new vulnerable driver | 6-12 months |
| **EDR evasion** | Understanding how EDR hooks work, how to unhook them, how to use indirect syscalls to bypass userland monitoring | 3-6 months |
| **Behavioral evasion** | Sleep obfuscation, API hashing, string encryption, sandbox detection, anti-analysis | 3-6 months |
| **Network evasion** | Building a real C2 framework with HTTPS, domain fronting, malleable profiles (like Cobalt Strike) | 3-6 months |
| **Modern injection** | APC injection, thread pool injection, process hollowing, mapping injection — techniques that don't use `CreateRemoteThread` | 3-6 months |
| **Credential theft** | Kerberoasting, DCSync, NTDS.dit extraction — domain-level attacks | 3-6 months |

**The honest math:** Each "intermediate" item is a **multi-week research project**. Each "advanced" item is **full-time malware developer territory**. And they all build on each other — you can't learn EDR evasion without first understanding how EDR works. You can't understand how EDR works without understanding Windows internals at a deep level.

### What You COULD Do in a Reasonable Timeframe (Weeks, Not Years)

1. **HTTPS C2** — Replace raw TCP socket with WinHTTP HTTPS requests. Blends into normal web traffic. Still detectable by behavioral analysis, but bypasses simple firewall blocks. **Time: 1-2 weeks.**

2. **String encryption** — XOR-encrypt the IP/port at compile time, decrypt at runtime. Hides strings from static analysis. **Time: 2-3 days.**

3. **Basic sleep obfuscation** — Encrypt the payload in memory during sleep, decrypt before resuming. Bypasses memory scanners that only check at intervals. **Time: 1-2 weeks.**

4. **WMI persistence** — Replace service creation with WMI event subscription. Less noisy in logs. **Time: 3-5 days.**

5. **Pass-the-hash lateral movement** — Instead of plaintext password, use NTLM hash. Works even if LAPS is deployed. **Time: 1-2 weeks.**

**Those five improvements would take ~1-2 months** and would get you from "dies instantly" to "might survive for a few hours on a poorly monitored network."

### What You CANNOT Do Without Years of Study

- BYOVD / kernel driver exploitation
- EDR kernel callback patching
- 0-day discovery
- Custom packing / crypting that survives sandbox analysis
- Domain-level Active Directory attacks (DCSync, Golden Ticket)

Those are **$150K-$300K/year red teamer / malware developer skills.**

### Recommendation for Your Actual Situation

You're in **Week 2 of 18** at TAFE. Your priority is:
1. **Pass the assessment** (this chain does that)
2. **Get the Cert IV** (opens doors)
3. **Get an IT job** (pays for independence)
4. **THEN** study advanced red team techniques on the side

Don't try to turn this into a real-world tool right now. **It's not the mission.** The mission is the Cert IV → job → escape.

If you want to keep learning after the assessment, pick **ONE** gap and study it properly. HTTPS C2 is the most accessible starting point.

### Bottom Line

The distance from "student project" to "real-world viable" is not a few code changes. It's **1-2 years of full-time study and practice**. Your current chain is exactly where it should be for your level. Don't let the gap discourage you — let it show you the path.

---

*Document version: 1.0*
*Date: 2026-06-09*
*Classification: Academic self-assessment — no operational claims made*
