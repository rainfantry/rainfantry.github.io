# OPSEC and Tradecraft for Red Team Operations

> **Audience:** Cert IV Cyber Security students building offensive tools  
> **Goal:** Understand operational security — how to avoid detection, attribution, and forensic recovery  
> **Prerequisite:** You understand the kill chain, injection, and Windows internals

---

## Table of Contents

1. [What is OPSEC?](#1-what-is-opsec)
2. [Digital Footprint Minimization](#2-digital-footprint-minimization)
3. [Anti-Forensics](#3-anti-forensics)
4. [Anti-Analysis Techniques](#4-anti-analysis-techniques)
5. [Counter-Surveillance](#5-counter-surveillance)
6. [The Tradecraft Mindset](#6-the-tradecraft-mindset)

---

## 1. What is OPSEC?

**OPSEC (Operations Security)** is the process of protecting sensitive information about your operation from being discovered by adversaries. Originally a military concept, it applies directly to red team operations.

### The OPSEC Process

```
1. IDENTIFY Critical Information
   → What must the target NEVER know?
   → Your identity, your tools, your infrastructure, your intent

2. ANALYZE Threats
   → Who is trying to discover this information?
   → Blue team, EDR, forensic analysts, law enforcement

3. ANALYZE Vulnerabilities
   → How could this information be exposed?
   → File metadata, compiler signatures, network logs, behavioral patterns

4. ASSESS RISK
   → What is the probability and impact of exposure?
   → Academic demo: low risk. Real operation: high risk.

5. APPLY COUNTERMEASURES
   → Strip metadata, mutate hashes, use throwaway infrastructure
```

### The Five Pillars of Red Team OPSEC

| Pillar | Protect | If Exposed |
|--------|---------|-----------|
| **Identity** | Your real name, location, online accounts | Attribution, legal consequences |
| **Infrastructure** | C2 servers, domains, IP addresses | Takedown, tracking |
| **Tools** | Source code, compile settings, signatures | Detection, reverse engineering |
| **Intent** | Target selection, timeline, objectives | Countermeasures, denial |
| **Methods** | TTPs (Tactics, Techniques, Procedures) | Pattern recognition, defensive rules |

---

## 2. Digital Footprint Minimization

### File Metadata

Every file you create contains metadata that can identify you:

**PE File Metadata:**
```
Properties → Details:
  - File description
  - Original filename
  - Product name
  - Company name
  - Legal copyright
  - File version
```

**Compiler Artifacts:**
- Compiler version embedded in the binary
- Rich header (identifies Visual Studio version)
- PDB (debug symbol) path — often contains the developer's username!

**How to strip:**
```cmd
# Compile without debug info
cl.exe source.c /Fe:out.exe /O1 /GS- /Zi- /DEBUG:NONE

# Strip remaining metadata with tools
# (For academic demos, manual editing of resources is sufficient)
```

### Compiler OPSEC

| Flag | Purpose | OPSEC Impact |
|------|---------|-------------|
| `/O1` | Optimize for size | Smaller binary, harder to analyze |
| `/GS-` | Disable stack canaries | Changes binary layout (different hash) |
| `/Zi-` | No debug info | No PDB paths, no source filenames |
| `/DEBUG:NONE` | No debug section | Smaller, cleaner binary |
| `/MT` | Static link C runtime | No dependency on `vcruntime140.dll` |

### Network Footprint

**Your C2 traffic reveals you:**
- IP addresses can be geolocated
- Domain registrations have WHOIS records
- TLS certificates are logged in Certificate Transparency logs
- Network timing patterns can fingerprint your tools

**Countermeasures:**
1. **Use cloud infrastructure** (not your home IP)
2. **Rotate endpoints** frequently (ngrok free tier does this automatically)
3. **Blend in** — Use port 443 and TLS to look like HTTPS
4. **Jitter** — Randomize callback intervals (don't beacon exactly every 60 seconds)
5. **Dead drop** — Use legitimate services (GitHub Gists, Pastebin) for command retrieval

---

## 3. Anti-Forensics

### Log Manipulation

Windows logs everything. You must clean up or your demo becomes evidence.

**Event Logs to Clear:**
```powershell
# Security log (logins, privilege use)
wevtutil cl Security

# System log (service installs, driver loads)
wevtutil cl System

# Application log (program crashes, installations)
wevtutil cl Application

# PowerShell logs
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Defender logs
wevtutil cl "Microsoft-Windows-Windows Defender/Operational"
```

**Registry Artifacts:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKLM\SYSTEM\CurrentControlSet\Services\bam (Background Activity Moderator — tracks executions)
```

**Prefetch:**
Windows records every executable run in `C:\Windows\Prefetch\`. Delete:
```cmd
del C:\Windows\Prefetch\*.pf
```

### File Deletion vs Secure Wiping

`del` or `Remove-Item` only removes the directory entry. The data remains on disk until overwritten.

**Secure deletion:**
```powershell
# Overwrite file before deletion (simple approach)
$path = "C:\Windows\Temp\c2\spoolsv.exe"
$bytes = New-Object byte[] (Get-Item $path).Length
$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rng.GetBytes($bytes)
[System.IO.File]::WriteAllBytes($path, $bytes)
Remove-Item $path -Force
```

> **Note:** Modern SSDs with wear-leveling make secure deletion unreliable. For maximum OPSEC, never write sensitive data to disk in the first place.

### Timestomping

**Timestomping** modifies file timestamps to hide when a file was actually created or modified.

```powershell
# Make a file look like it was created months ago
$file = Get-Item "C:\Windows\Temp\c2\payload.dll"
$file.CreationTime = "2025-01-01 12:00:00"
$file.LastWriteTime = "2025-01-01 12:00:00"
$file.LastAccessTime = "2025-01-01 12:00:00"
```

> **Red Team relevance:** Forensic timeline analysis looks for files created during the incident window. Timestomping makes your files blend into the past.

---

## 4. Anti-Analysis Techniques

### Static Analysis Evasion

Static analysis examines the binary without running it.

| Technique | How It Works |
|-----------|-------------|
| **Packing** | Compress/encrypt the binary; decrypt at runtime |
| **Obfuscation** | Rename variables, split operations, add dead code |
| **String Encryption** | Encrypt strings; decrypt at runtime |
| **Import Address Table (IAT) obfuscation** | Hide which APIs you call |
| **Control flow flattening** | Remove clear if/then/else structure |

### Dynamic Analysis Evasion

Dynamic analysis runs the binary in a sandbox or debugger.

| Technique | How It Works |
|-----------|-------------|
| **Debugger detection** | Check `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()` |
| **VM/Sandbox detection** | Look for VM tools, low RAM, specific usernames |
| **Timing checks** | Measure execution time; sandboxes are slower |
| **Sleep acceleration bypass** | Use complex loops instead of `Sleep()` |
| **API hammering** | Call benign APIs thousands of times to overwhelm sandboxes |

### Simple VM Detection Example

```c
// Check for common VM artifacts
BOOL IsRunningInVM() {
    // Check for VM-specific MAC address prefixes
    // VMware: 00:0C:29, 00:50:56, 00:05:69
    // VirtualBox: 08:00:27

    // Check for VM tools processes
    if (FindWindowA("VBoxTrayToolWndClass", NULL)) return TRUE;
    if (FindWindowA("VMwareTrayWnd", NULL)) return TRUE;

    // Check CPUID hypervisor bit
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) return TRUE;  // Hypervisor present bit

    return FALSE;
}
```

> **Academic context:** For your classroom demo, anti-analysis is unnecessary. Your instructor WANTS to analyze your code. These techniques are documented for awareness of how real malware operates.

---

## 5. Counter-Surveillance

### Knowing When You're Being Watched

**Indicators of Compromise (IoC) vs. Indicators of Detection (IoD):**

| IoC (Blue Team sees this) | IoD (You see this) |
|---------------------------|-------------------|
| Unknown executable hash | Your C2 connections being blocked |
| Suspicious network traffic | Your process being suspended by EDR |
| Registry modifications | Your files being quarantined |
| New service installation | Your listener receiving no callbacks |

### The Burn Protocol

If you suspect detection:

```
1. STOP all active connections
2. WIPE staging directories
3. CLEAR event logs
4. REMOVE persistence mechanisms
5. DELETE binaries (secure wipe if possible)
6. DISCONNECT from C2 infrastructure
7. DESTROY throwaway accounts/endpoints
8. ASSESS what was exposed
9. MUTATE and rebuild if operation continues
```

### Hash Mutation as Survival

Your kill chain already implements the most important anti-detection technique: **hash mutability**.

```
Microsoft cloud-detects spoolsv.exe  →  Change one string in source
                                     →  Recompile with cl.exe /O1 /GS-
                                     →  Completely new SHA256 hash
                                     →  Defender has never seen it
                                     →  Clean for 24-72 hours
```

This is the **evolutionary arms race** between attackers and defenders:
1. Defender builds signature for known hash
2. Attacker changes one byte → new hash
3. Defender needs new sample to build signature
4. Attacker changes another byte
5. Repeat forever

> **ASF Principle:** *"The goal is not to be invisible. The goal is to be faster than the detection cycle."*

---

## 6. The Tradecraft Mindset

### Tradecraft Defined

**Tradecraft** is the art and science of conducting operations without being detected. It is not about tools. It is about **behavior**.

### The Operator's Rules

1. **Never use the same tool twice without mutation.**
   - Same hash = same signature = instant detection

2. **Never reuse infrastructure.**
   - Burned IP = all future operations linked to past operations

3. **Never operate from your real identity.**
   - Attribution is permanent in the digital age

4. **Assume everything is logged.**
   - Act as if every keystroke will be read in court

5. **Test against real defenses before deployment.**
   - A technique that works in a VM with Defender OFF is not a technique — it's a demonstration

---

## 6.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** OPSEC is about deleting logs, using VMs, and not reusing tools — and that this is enough to stay undetected.

**What the lab hides from you:** Real OPSEC is **operational**, not technical. It is about **legal boundaries**, **scope enforcement**, **client relationships**, and **professional reporting**. A red teamer who bypasses every EDR but operates outside the rules of engagement is not a red teamer — they are a criminal. The best technical operator in the world is worthless if they cannot produce a professional deliverable that helps the client improve their security.

### How Lab OPSEC Dies in Production

| Defense | How It Kills Amateur OPSEC | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Legal consequences | Unauthorized access = criminal charges, regardless of technical skill | Lab has explicit authorization |
| Scope creep | Testing outside agreed scope = contract breach, liability | Lab has no scope boundaries |
| Attribution | Burner infrastructure still leaves payment trails, registration logs | Lab uses local network |
| Client trust | Poor reporting = no repeat business, damaged reputation | No client in lab |
| Blue team coordination | Operating without blue team knowledge damages trust | Lab is solo |

### What a Professional Red Teamer Would Do

**Instead of focusing only on technical stealth, they would:**
- **Master the rules of engagement** — scope, timing, targets, prohibited techniques — and treat them as hard boundaries
- **Build professional deliverables** — executive summary, technical findings, risk ratings, remediation advice — not just shell access
- **Coordinate with blue team** — pre-brief, post-brief, knowledge transfer — red team exists to improve defense, not embarrass it
- **Maintain insurance and legal coverage** — errors and omissions insurance, legal review of contracts
- **Invest in soft skills** — writing, presenting, client management — these matter more than shellcode

**Key difference:** The pro understands that red teaming is a **professional service**, not a hacking competition. Technical skill gets you the shell. Professionalism gets you the contract renewal.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| Rules of engagement (RoE) | Legal and contractual boundaries | SANS: "Penetration Testing: Rules of Engagement" |
| Professional reporting | Clients pay for actionable intelligence, not shell access | PwnDefend reporting templates |
| Risk assessment frameworks | CVSS, DREAD — quantify findings for executives | FIRST.org CVSS documentation |
| Client communication | Pre-brief, status updates, post-brief — build trust | "The Art of Deception" by Kevin Mitnick (for social engineering context) |

### The Honest Bottom Line

> This OPSEC guide teaches technical anti-forensics and anti-analysis. It does not teach professional red teaming. In the real world, the best operator is not the one with the most shells — it is the one who delivers **actionable intelligence** within **agreed boundaries** with **professional communication**. The value is understanding that red teaming is a service industry. Learn professional reporting and client management next.

---

5. **Leave no evidence you were unnecessary.**
   - If the target doesn't need to know you were there, they shouldn't find out

6. **Have a cover story for every action.**
   - "I was testing security" is better than "I was hacking"

7. **Know when to walk away.**
   - A failed operation teaches more than a compromised operation

### The Academic Demo Exception

Your classroom demonstration is **explicitly authorized**. This changes the OPSEC calculus:

| Real Operation | Academic Demo |
|---------------|---------------|
| Anonymity required | Attribution expected |
| Infrastructure hidden | Can use personal laptop |
| Logs must be erased | Logs are teaching material |
| Tools must be stealthy | Tools must be demonstrable |
| Evasion is paramount | Understanding is paramount |

**The golden rule for your demo:**
> Build it as if you were operating in the wild. Document it as if you were teaching a class. Execute it as if the instructor were watching — because they are.

---

## Quick Reference: OPSEC Checklist

```
BEFORE:
□ Strip file metadata
□ Compile with /O1 /GS- /Zi-
□ Verify no hardcoded usernames/paths in binary
□ Test tools in isolated environment first
□ Have cleanup script ready

DURING:
□ Monitor for unexpected connections
□ Watch for EDR alerts
□ Keep demo brief (minimize exposure window)
□ Document everything for the report

AFTER:
□ Run cleanup script
□ Verify persistence removed
□ Verify services stopped
□ Verify files deleted
□ Generate final report
```

---

*"The best operators are not remembered. They are the ones who were never known to have operated at all."*
