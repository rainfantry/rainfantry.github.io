# Tactical Cyber Operations: Expanded Textbook Guide

> **Version:** 2.0 - Integrated with CODE_DOCS  
> **Last Updated:** 2026-06-09  
> **Integration:** Concepts from shadow_shell, shadow_evasion, ghost_svc, injector, payload_dll, shadow_token, shadow_lateral, and supporting documentation

---

## Introduction

Welcome to the Tactical Cyber Operations course. This expanded textbook integrates foundational concepts from the original 6 chapters with practical code-level analysis from the CODE_DOCS series. You cannot understand how to subvert a system if you do not understand how it was built. We begin with raw memory mechanics, move through Windows internals, and bridge into operational techniques.

**Structure:**
- Chapters 1-3: Foundational (Memory, Networking, Exploitation)
- Chapters 4-6: Windows Internals (Architecture, Services, Registry)
- Chapters 7-12: Operational Techniques (Evasion, Injection, Persistence, Credentials, Movement)
- Chapter 13: Defense and Blue Team

---

# PART I: FOUNDATIONS

## Chapter 1: The Foundations of Memory
*(Original Chapter 1 - C Memory Fundamentals)*

### 1.1 The Illusion of Abstraction
Modern programming languages like Python and C# lie to you. They present a world where memory is infinite and automatically managed. Variables spring into existence and vanish without a trace. In cyber operations, this abstraction is a dangerous blind spot. To understand vulnerabilities, we must step down to C.

### 1.2 Pointers: The Map to the Territory
A variable in C holds a value (e.g., `int x = 5;`). A **pointer** is a variable that holds a *memory address* (e.g., `int *p = &x;`). When an attacker achieves execution, they manipulate pointers—redirecting program flow from legitimate code to their payloads.

### 1.3 The Windows API Type System
Windows development introduces platform-specific types that abstract hardware differences:

| Windows Type | C Equivalent | Purpose |
|-------------|-------------|---------|
| `HANDLE` | `void*` | Generic reference to kernel objects (files, processes, threads) |
| `LPVOID` | `void*` | Long Pointer to Void - generic memory pointer |
| `LPCWSTR` | `const wchar_t*` | Wide character string pointer |
| `DWORD` | `unsigned long` | Double Word - 32-bit unsigned integer |
| `BOOL` | `int` | Boolean (0 = FALSE, non-zero = TRUE) |

**Concept:** In shadow_shell.c, `SOCKET` is actually a typedef for `UINT_PTR`. The Windows API wraps raw C types to provide architecture independence (32-bit vs 64-bit) and semantic clarity.

### 1.4 Structs and Memory Layout
Network protocols are strict byte sequences. In C, `structs` define these sequences:

```c
struct TCPHeader {
    uint16_t src_port;  // 2 bytes at offset 0
    uint16_t dst_port;  // 2 bytes at offset 2
    uint32_t seq_num;   // 4 bytes at offset 4
};
```

When loaded into RAM, `src_port` sits at the base address. `dst_port` sits exactly 2 bytes down. `seq_num` sits 4 bytes after. Exploitation relies on knowing exact byte offsets.

---

## Chapter 2: Network Manipulation and Sockets
*(Original Chapter 2 - Socket Programming)*

### 2.1 The Anatomy of a Connection
A network connection is fundamentally an agreement between two endpoints to exchange data. The OS facilitates this via "Sockets." In Windows, the Winsock API (`ws2_32.dll`) provides socket functionality.

### 2.2 Windows Sockets vs UNIX
| Aspect | UNIX | Windows |
|--------|------|---------|
| Header | `<sys/socket.h>` | `<winsock2.h>` |
| Startup | None required | `WSAStartup()` mandatory |
| Cleanup | `close()` | `closesocket()` |
| Library | Built-in | Link `ws2_32.lib` |

**Code from shadow_shell.c:**
```c
WSADATA wsaData;
WSAStartup(MAKEWORD(2, 2), &wsaData);
```

`WSAStartup` initializes the Winsock DLL. The `MAKEWORD(2, 2)` specifies version 2.2. Without this, socket functions fail.

### 2.3 The Reverse Shell Architecture
A reverse shell occurs when a target initiates an *outbound* connection to the attacker:

1. **Connection:** Target uses `socket()` to create endpoint and `connect()` to reach attacker's IP/port
2. **The Pivot:** `dup2()` copies socket file descriptor over STDIN/STDOUT (UNIX) or `CreateProcess` with redirected handles (Windows)
3. **The Shell:** Windows uses `CreateProcess` to spawn `cmd.exe` with inherited socket handles

**Windows Implementation (from shadow_shell.c):**
```c
STARTUPINFO si;
PROCESS_INFORMATION pi;
si.cb = sizeof(si);
si.dwFlags = STARTF_USESTDHANDLES;
si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
```

Key insight: `STARTF_USESTDHANDLES` tells Windows to use the provided handles instead of console. The socket becomes cmd.exe's stdin/stdout.

### 2.4 Port Selection and Evasion
| Port | Service | Detection Risk |
|------|---------|----------------|
| 4444 | Metasploit default | **Critical** - Every IDS flags this |
| 8080 | HTTP Alternate | High - Inspected by proxies |
| 443 | HTTPS | **Lower** - Blends with web traffic |
| 53 | DNS | Moderate - Often unrestricted |

**Real-World Lesson:** Modern enterprise proxies inspect protocol content, not just ports. Raw TCP on 443 without TLS is anomalous. Domain fronting via CDNs (CloudFront, Akamai) hides true destinations behind legitimate infrastructure.

---

## Chapter 3: Memory Corruption and Exploitation
*(Original Chapter 3 - Buffer Overflows)*

### 3.1 Stack Architecture
When a function is called, the OS creates a "Stack Frame" holding:
1. Function arguments
2. **Return Address** - Where CPU returns after function
3. Local variables (buffers)

The stack grows predictably. Local variables sit adjacent to the return address.

### 3.2 Buffer Overflow Mechanism
A buffer overflow occurs when writing more data than a buffer can hold:

```c
char buffer[64];
strcpy(buffer, user_input);  // Dangerous: no bounds checking
```

`strcpy` copies until null terminator, regardless of destination size. Extra bytes spill onto the return address.

### 3.3 Hijacking Execution
Sequence:
1. Overflow the buffer
2. Overwrite Return Address with attacker-chosen address
3. Function returns to corrupted address
4. CPU executes shellcode at that address

**Defensive Countermeasures:**
- ASLR (Address Space Layout Randomization) - Randomizes memory addresses
- DEP/NX (Data Execution Prevention) - Marks stack as non-executable
- Stack Canaries - Values placed before return address, checked before return
- Safe functions: `strncpy`, `strcpy_s` with explicit length limits

---

# PART II: WINDOWS INTERNALS

## Chapter 4: Crossing the Boundary - OS Architecture
*(Original Chapter 4 - Ring 0/3)*

### 4.1 The Privilege Rings
*   **Ring 3 (User Mode):** Normal applications. Limited by OS. Monitored by EDR/AV.
*   **Ring 0 (Kernel Mode):** OS core and drivers. Absolute power. Can read any memory, terminate any process.

### 4.2 Bring Your Own Vulnerable Driver (BYOVD)
Attackers exploit OS trust model:
1. **The Drop:** Bring signed legitimate driver (old graphics, anti-cheat)
2. **The Flaw:** Driver has vulnerable IOCTL endpoint
3. **The Strike:** Send crafted payload from Ring 3 to driver
4. **Result:** Code executes in Ring 0 context

**Modern Note:** Microsoft WHQL signing requirements and HVCI (Hypervisor-protected Code Integrity) make BYOVD harder but not impossible (vulnerable drivers still exist in the wild).

### 4.3 Windows Services Architecture
Services are background programs typically running as SYSTEM. The Service Control Manager (SCM) manages them.

**Service Types:**
| Type | Description |
|------|-------------|
| SERVICE_WIN32_OWN_PROCESS | Runs in separate process |
| SERVICE_WIN32_SHARE_PROCESS | Shares process with other services |
| SERVICE_INTERACTIVE_PROCESS | Can interact with desktop |

**Service Startup:**
| Startup | Trigger |
|---------|---------|
| SERVICE_AUTO_START | System boot |
| SERVICE_DEMAND_START | Manual/admin trigger |
| SERVICE_DISABLED | Cannot start |

### 4.4 Windows Processes and Threads
A **process** is a container: virtual address space, resources, security context. A **thread** is the unit of execution within a process.

**Key APIs:**
- `CreateProcess` - Spawns new process
- `CreateThread` - Creates thread in current process
- `OpenProcess` - Gets handle to existing process
- `VirtualAllocEx` - Allocates memory in another process
- `WriteProcessMemory` - Writes to another process's memory

---

## Chapter 5: The Windows Registry
*(From windows_internals.md)*

### 5.1 Registry Structure
The Registry is Windows' central configuration database:

| Hive | Purpose |
|------|---------|
| `HKLM` | Local Machine - System-wide settings |
| `HKCU` | Current User - User-specific settings |
| `HKCR` | Classes - File associations |
| `HKU` | Users - All user profiles |
| `HKCC` | Current Config - Hardware profiles |

### 5.2 Registry-Based Persistence
**Run Keys (Auto-start):**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Programs listed here execute at user logon. High detection risk - monitored by Autoruns and EDR.

**Modern Alternative: COM Hijacking**
```
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
```

Redirects COM object to malicious DLL. No new process creation. Lower detection surface.

---

# PART III: OPERATIONAL TECHNIQUES

## Chapter 6: Defense Evasion
*(From shadow_evasion.md)*

### 6.1 Evasion Objectives
Evasion techniques aim to blind or cripple security tools:
1. Stop critical services
2. Add path exclusions to bypass scanning
3. Corrupt signature metadata to prevent updates
4. Execute malware from excluded locations

### 6.2 Windows Defender Architecture
**Components:**
- **MsMpEng.exe** - Main engine (runs as PPL - Protected Process Light)
- **NisSrv.exe** - Network Inspection Service
- **Windows Defender Service** - Service control and updates

**Tamper Protection:** Since Windows 10 1903, registry writes to Defender keys and service stops are blocked by kernel, even for Administrators.

### 6.3 Service Control Manager (SCM) Abuse
The SCM manages Windows services via APIs:

```c
SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
SC_HANDLE service = OpenService(scManager, "WinDefend", SERVICE_ALL_ACCESS);
ControlService(service, SERVICE_CONTROL_STOP, &status);
```

**Real-World Limitation:** Tamper Protection blocks this. Modern evasion requires:
- BYOVD (kernel-level bypass)
- Living off the Land (LOLBins like `certutil`, `mshta`)
- ETW patching (Event Tracing bypass)

### 6.4 Registry Manipulation for Exclusions
```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
```

Adding paths here excludes them from real-time scanning. Requires admin + Tamper Protection disabled.

---

## Chapter 7: Process Injection
*(From injector.md and process_injection_theory.md)*

### 7.1 Classic DLL Injection
The "textbook" injection technique:

1. `OpenProcess` - Get handle to target process
2. `VirtualAllocEx` - Allocate memory in target
3. `WriteProcessMemory` - Write DLL path to allocated memory
4. `CreateRemoteThread` with `LoadLibraryA` - Load DLL in target context

**Problem:** This exact API sequence is signatured by every EDR. Sysmon Event ID 8 logs `CreateRemoteThread`. The injected DLL appears in module lists.

### 7.2 Advanced Injection Techniques

**APC Injection:**
```c
QueueUserAPC(loadLibraryAddr, targetThread, dllPathAddr);
ResumeThread(targetThread);
```
No `CreateRemoteThread` event. Uses Alertable Thread state. Lower detection surface.

**Process Hollowing:**
1. Create legitimate process suspended (`CREATE_SUSPENDED`)
2. Unmap (`NtUnmapViewOfSection`) legitimate image
3. Write malicious image at same base address
4. Resume - Process name looks legitimate

**Reflective Injection:**
DLL loads itself without `LoadLibrary` call. Manually maps PE into memory. No module list entry.

### 7.3 Injection Detection
| Method | Detection Vector |
|--------|------------------|
| Classic | Sysmon Event ID 8, module list scanning |
| APC | Alertable thread hunting, APC enumeration |
| Process Hollowing | Memory forensics (image mismatch), PE header analysis |
| Reflective | Memory scanning for PE signatures |

---

## Chapter 8: Persistence Mechanisms
*(From ghost_svc.md)*

### 8.1 Service-Based Persistence
Creating a fake auto-start service:

```c
CreateService(scManager, "ServiceName", DISPLAY_NAME,
    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
    SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
    BINARY_PATH, NULL, NULL, NULL, NULL, NULL);
```

**Execution:** Runs as SYSTEM on boot. Event ID 7045 logs service creation.

**Detection:** 
- Event ID 7045 in System log
- Autoruns service enumeration
- Binary path anomalies (files in Temp, non-standard locations)

### 8.2 Modern Persistence (Low Detection)
| Technique | Detection Difficulty |
|-----------|---------------------|
| Registry Run Keys | High (Autoruns) |
| Services | High (Event ID 7045) |
| Scheduled Tasks | Moderate (Event ID 106) |
| WMI Event Subscriptions | **Low** (No standard events) |
| COM Hijacking | **Low** (Legitimate mechanism) |
| DLL Hijacking | **Low** (No new process) |

**WMI Persistence:**
```powershell
$filter = Set-WmiInstance -Class __EventFilter -Namespace root/subscription
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription
Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}
```

**Why it works:** WMI is Windows Management Instrumentation - a legitimate administrative framework. No obvious "malware" events are generated.

---

## Chapter 9: Token Manipulation and Credentials
*(From shadow_token.md)*

### 9.1 Windows Tokens
A token represents a user's security context:
- Identity (SID)
- Group memberships
- Privileges (SeDebugPrivilege, SeImpersonatePrivilege)
- Logon session

**Token Types:**
- **Primary Token:** Created at logon, attached to process
- **Impersonation Token:** Thread adopts client's security context

### 9.2 Token Theft Technique
```c
// Open target process (e.g., SYSTEM service)
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

// Open token handle
OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);

// Duplicate with impersonation rights
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDup);

// Use token with CreateProcessAsUser
CreateProcessAsUser(hDup, NULL, cmdPath, ...);
```

**Privilege Escalation:** Steal SYSTEM token → Create process as SYSTEM.

### 9.3 Credential Protection
| Feature | Protection |
|---------|-------------|
| Credential Guard | Hypervisor-virtualizes LSASS - tokens encrypted |
| LSA Protection | Prevents non-PPL from opening LSASS |
| WDAG | Application Guard isolates browser credentials |

### 9.4 Modern Credential Theft
Instead of LSASS:
- **Kerberoasting:** Request service tickets offline-crackable
- **DPAPI:** Windows Credential Manager vaults
- **Keylogging:** Capture at input point (bypasses virtualization)
- **Clipboard theft:** Password manager "copy password" interception

---

## Chapter 10: Lateral Movement
*(From shadow_lateral.md)*

### 10.1 The Trust Model
Lateral movement leverages existing authentication relationships:
- Shared local administrator passwords
- Cached domain credentials
- Kerberos tickets (TGTs, service tickets)

### 10.2 Classic Lateral Movement
**SMB/Named Pipes:**
```c
WNetAddConnection2(&res, "\\\\target\\IPC$", password, username);
```

Opens connection to `ADMIN$` share. Copies and executes binaries.

**Limitations:**
- LAPS (Local Admin Password Solution) - unique passwords per machine
- Windows Defender Firewall - blocks SMB between workstations
- Network segmentation - VLAN isolation

### 10.3 Modern Alternatives
| Technique | Advantage |
|-----------|-------------|
| WMI (`Invoke-WmiMethod`) | No Event ID 7045 (no service creation) |
| DCOM (MMC20.Application) | Built-in remote management |
| WinRM | PowerShell remoting, encrypted |
| Pass-the-Ticket | No password needed, just Kerberos tickets |
| RDP Hijacking | Steal existing sessions (no new logon) |

**Kerberos Golden Ticket:**
Forge TGT using domain's KRBTGT hash. Valid for any user, any service, for years.

---

## Chapter 11: Compilation and Build Systems
*(From compilation_advanced.md and c_programming_primer.md)*

### 11.1 The Build Process
1. **Preprocessing:** `#include`, `#define` expansion
2. **Compilation:** C → Object code (.obj)
3. **Linking:** Object files + Libraries → Executable

### 11.2 Compiler Flags
| Flag | Purpose | Security Trade-off |
|------|---------|-------------------|
| `/O1` | Optimize for size | Smaller footprint |
| `/GS-` | Disable stack canaries | Easier exploitation |
| `/MT` | Static CRT linking | No runtime dependencies |
| `/W4` | High warning level | Catches errors |

**Important:** `/GS-` removes stack protection. Makes exploitation easier but is sometimes needed for specific payload behaviors. Defense: always ship with `/GS` enabled.

### 11.3 Import Tables and Static Analysis
The Import Address Table (IAT) lists all DLLs/functions used:
- `ws2_32.dll` + `socket`, `connect`, `send` = Network capability
- `advapi32.dll` + `OpenProcessToken`, `DuplicateTokenEx` = Token manipulation

Static analysis tools (IDA, Ghidra) reconstruct this table to understand malicious capability.

**Modern Evasion:**
- Dynamic API resolution (GetProcAddress at runtime)
- Obfuscated imports
- Position-independent code (PIC) - no imports at all

---

# PART IV: DEFENSE

## Chapter 12: Operational Security (OPSEC)
*(From opsec_tradecraft.md)*

### 12.1 The Tradecraft Mindset
OPSEC is behavior, not tools:
1. **Never use same tool twice** without mutation - same hash = signature
2. **Never reuse infrastructure** - burned IP links past to future operations
3. **Assume everything is logged** - act as if every keystroke will be read in court
4. **Test against real defenses** - lab success ≠ production success

### 12.2 Attribution and Infrastructure
- Burner infrastructure leaves trails (payment methods, registration patterns)
- Cloud metadata APIs leak instance information
- Compromised legitimate accounts blend better than new registrations

### 12.3 Professional Operations
Red teaming is a professional service, not a hacking competition:
- Rules of Engagement define boundaries
- Professional deliverables (executive summaries, risk ratings, remediation advice)
- Coordination with Blue Team (pre/post briefings)
- Legal coverage and insurance

---

## Chapter 13: Defense and Detection - Blue Team Perspective
*(Original Chapter 6 - GeoDefend Integration)*

### 13.1 The Shift in Mindset
Defense assumes breach. Design systems that contain and detect intrusions.

### 13.2 Telemetry and Visibility
Foundation: structured logging to SIEM:
- **Process Lineage:** `wininit.exe` → `services.exe` → `spoolsv.exe` → `cmd.exe` = Suspicious
- **Network Anomalies:** Beaconing DNS to new domains = Potential C2
- **Behavior:** Not signatures, but patterns of activity

### 13.3 Detection Engineering
| Technique | Detection Strategy |
|-----------|-------------------|
| Process Injection | Sysmon Event ID 8, memory scanning |
| Persistence | Autoruns, WMI event subscriptions auditing |
| Credential Theft | LSASS access monitoring, Kerberoasting detection |
| Lateral Movement | SMB session auditing, remote service creation events |

### 13.4 Secure Engineering
1. **Memory Safety:** Replace `strcpy` with `strncpy_s`
2. **Input Validation:** Strict length/type checking
3. **Compile-Time:** Enable ASLR, DEP/NX, CFG
4. **Runtime:** Exploit guard, attack surface reduction rules

### 13.5 The Kill Chain Revisited
Understanding the offensive kill chain enables defensive planning:
1. **Reconnaissance** - Monitor for scanning, OSINT visibility
2. **Initial Access** - Phishing filters, application control
3. **Execution** - AM/PM, application whitelisting
4. **Persistence** - Autoruns monitoring, WMI auditing
5. **Privilege Escalation** - Token monitoring, UAC enforcement
6. **Defense Evasion** - Tamper protection, real-time monitoring
7. **Credential Access** - Credential Guard, LSA protection
8. **Lateral Movement** - SMB inspection, network segmentation
9. **Collection** - DLP, data classification
10. **Exfiltration** - Network monitoring, proxy inspection

---

## Conclusion

By mastering offensive mechanics, you understand the attacker's mindset. This is necessary to engineer effective defenses. The CODE_DOCS series provides line-by-line analysis of real techniques—their operation and their detection.

**Key Takeaway:** Modern defense is not about preventing compromise (impossible) but about rapid detection, containment, and recovery. Understand the attack surface. Minimize it. Monitor the rest.

---

## Appendix A: CODE_DOCS Integration Map

| Textbook Chapter | CODE_DOCS Source | Key Concepts |
|------------------|-------------------|--------------|
| Chapter 2 | shadow_shell.md | Windows sockets, reverse shells, process spawning |
| Chapter 4 | windows_internals.md | Services, processes, handles, registry |
| Chapter 5 | windows_internals.md | Registry structure, persistence locations |
| Chapter 6 | shadow_evasion.md | Tamper Protection, SCM, Defender evasion |
| Chapter 7 | injector.md | Classic injection, APC, Process Hollowing |
| Chapter 7 | process_injection_theory.md | Injection theory, reflective DLL |
| Chapter 8 | ghost_svc.md | Service persistence, SYSTEM execution |
| Chapter 9 | shadow_token.md | Token manipulation, privilege escalation |
| Chapter 10 | shadow_lateral.md | Lateral movement, SMB, NetExec |
| Chapter 11 | compilation_advanced.md | Compiler flags, linking, imports |
| Chapter 11 | c_programming_primer.md | Windows types, API patterns |
| Chapter 12 | opsec_tradecraft.md | Professional operations, attribution |
| All | payload_dll.md | DLL architecture, reflective loading |
| All | networking_concepts.md | Protocols, ports, tunneling |

---

**Document Status:** Ready for integration with practical exercises from CSEC_Final_Complete codebase.
