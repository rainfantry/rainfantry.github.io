# Enterprise Threat Emulation & Defense Guide
**Scenario: Corporate Red Team Operations vs. Enterprise Defense (Semester 2)**

This document is designed for security students and role-play corporate scenarios. It breaks down four advanced Windows vulnerabilities into business concepts. It defines exactly what a student must study to master the exploit, how an Enterprise Red Team would test the corporate environment to prove the vulnerability exists, and how the Company (Blue Team) can determine if their infrastructure is at risk.

---

## 1. Operation REDSUN (Defender TOCTOU Junction Abuse)

### The Concept (For the Company)
Anti-virus solutions (like Windows Defender) are highly privileged. When they detect a threat, they often move or restore files. **Operation RedSun** proves that if the AV relies on the file's original path without verifying it at the exact millisecond of writing, an attacker can swap the original folder with a "Junction" (a shortcut) pointing to `C:\Windows\System32`. The AV will then accidentally write the attacker's payload directly into the protected system folder, granting the attacker full control of the machine.

### Student Study Requirements
To complete this task and understand the codebase, the student must learn:
1.  **NTFS Reparse Points & Junctions:** How to programmatically create Mount Points using `DeviceIoControl` and `FSCTL_SET_REPARSE_POINT`.
2.  **Time-of-Check to Time-of-Use (TOCTOU):** The concept of exploiting the microsecond delay between a program checking a file and acting upon it.
3.  **EICAR Strings:** How AVs use signatures to immediately flag test files.

### Red Team Testing Methodology (Proof of Concept)
1.  Create a temporary staging directory (e.g., `C:\Temp\Bait`).
2.  Drop a dummy executable containing an `EICAR` string into the folder.
3.  Trigger the AV by attempting to execute the dummy file.
4.  Immediately script a loop that attempts to delete `C:\Temp\Bait` and replace it with an NTFS Junction pointing to a protected target (e.g., `C:\Windows\System32`).
5.  Wait for the AV cloud-remediation to trigger.
6.  **Verification:** Check if the dummy file was successfully written into `C:\Windows\System32`. If yes, the company is vulnerable to arbitrary file overwrites.

### Company Vulnerability Assessment (Blue Team)
*   **Vulnerable if:** The EDR/AV solution does not use "Safe File Handles" or fails to perform path resolution checks (Impersonation) prior to remediation writes.
*   **Detection:** Monitor Event Logs (Sysmon Event ID 11 & 15) for sudden creation of NTFS Junctions in `Temp` or `AppData` directories immediately following a malware detection event.

---

## 2. Operation GREENPLASMA (Object Manager Hijacking)

### The Concept (For the Company)
Windows uses an internal "Object Manager" to keep track of shared resources (like memory sections and events) in a folder called `\BaseNamedObjects`. **Operation GreenPlasma** proves that if a highly privileged process (like the Windows input loader, `ctfmon.exe`) doesn't properly secure its shared memory, a standard user can create a fake "symbolic link" in that folder. When `ctfmon` tries to create its memory, the link redirects it to a location the attacker controls, allowing the attacker to read/write memory meant only for `SYSTEM`.

### Student Study Requirements
To complete this task and understand the codebase, the student must learn:
1.  **Windows Object Manager:** Use the Sysinternals tool `WinObj` to visualize `\BaseNamedObjects` and `\Sessions`.
2.  **Native APIs (NTAPI):** Specifically `NtCreateSymbolicLinkObject`, `NtOpenSection`, and `NtMapViewOfSection`.
3.  **Process Security Descriptors (DACLs):** Understanding how `SYSTEM` processes dictate who can read or write to their mapped memory.

### Red Team Testing Methodology (Proof of Concept)
1.  Query the current user's Session ID.
2.  Use `NtCreateSymbolicLinkObject` to pre-create a symbolic link at `\Sessions\<ID>\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon<ID>`.
3.  Point this link to a custom namespace (e.g., `\BaseNamedObjects\RedTeam_Hijack`).
4.  Trigger `ctfmon.exe` to spawn as SYSTEM (e.g., by invoking a UAC elevation prompt).
5.  **Verification:** Attempt to open the memory section at `\BaseNamedObjects\RedTeam_Hijack` using `NtOpenSection` with `SECTION_MAP_WRITE` access. If the handle is successfully acquired, the company is vulnerable to Privilege Escalation via memory manipulation.

### Company Vulnerability Assessment (Blue Team)
*   **Vulnerable if:** Applications running as `SYSTEM` create named objects in user-accessible namespaces without strictly defining explicit Security Descriptors (passing `NULL` for security attributes).
*   **Detection:** It is difficult to detect Object Manager manipulation via standard logs. Advanced EDR must hook `NtCreateSymbolicLinkObject` and flag anomalous symbolic link creations in the `\BaseNamedObjects` path by standard user processes.

---

## 3. Operation MINIPLASMA (Cloud Filter TOCTOU / Registry DACL)

### The Concept (For the Company)
Windows includes a driver (`cldflt.sys`) to handle files stored in the cloud (like OneDrive). **Operation MiniPlasma** exploits a known race condition in how this driver handles canceling ("aborting") a file download. By racing the system and swapping symbolic links at the exact right millisecond, an attacker can trick the driver into stripping the security protections (DACLs) off critical Windows Registry keys.

### Student Study Requirements
To complete this task and understand the codebase, the student must learn:
1.  **Cloud Filter API (`CfApi`):** How Windows uses placeholders and hydration to fetch cloud files.
2.  **Registry Hardlinks:** How native APIs can link one registry key to another.
3.  **Race Condition Exploitation (C#):** How to use multi-threading in C# to precisely time an API call (`CfAbortOperation`) while simultaneously swapping a link.

### Red Team Testing Methodology (Proof of Concept)
1.  Register a fake Cloud Sync Root using `CfRegisterSyncRoot`.
2.  Create a placeholder file.
3.  Initiate a read on the placeholder to trigger the hydration (download) process.
4.  In parallel threads: 
    *   Thread A: Rapidly calls `CfAbortOperation`.
    *   Thread B: Rapidly swaps a registry symlink to point to a highly sensitive key (e.g., `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`).
5.  **Verification:** Run a script as a standard user attempting to write a new value to the targeted `HKLM` key. If the write succeeds, the TOCTOU race was won, the DACL was reset, and the system is compromised.

### Company Vulnerability Assessment (Blue Team)
*   **Vulnerable if:** The OS is missing the specific patches for `cldflt!HsmOsBlockPlaceholderAccess` (or if the patch was regressed, as the scenario suggests).
*   **Detection:** Monitor for Sysmon Event ID 12 or 13 (Registry Event) showing unexpected modification of critical `HKLM` Security Descriptors by standard user processes, or anomalies involving `cldflt.sys` operations.

---

## 4. Operation BLUEHAMMER (RPC Endpoint & SAM Manipulation)

### The Concept (For the Company)
Remote Procedure Calls (RPC) allow programs to request services from other programs, often crossing privilege boundaries. **Operation BlueHammer** proves that if a privileged RPC service (like Windows Defender's backend) fails to validate the data sent to it, an attacker can crash or manipulate it. Furthermore, the scenario demonstrates using elevated context to interact directly with the Security Account Manager (SAM) to change passwords without knowing the original credentials.

### Student Study Requirements
To complete this task and understand the codebase, the student must learn:
1.  **RPC Architecture:** Understanding Interface Definition Language (IDL) files, RPC Stubs, and how to analyze an RPC endpoint using tools like `RpcView`.
2.  **Memory Corruption (Basic):** Understanding how providing incorrect sizes or malformed data to an RPC stub causes server-side crashes or logic bypasses.
3.  **LSA & SAM APIs:** Studying `SamOpenDomain`, `SamOpenUser`, and `SamiChangePasswordUser` to understand how Windows manages local authentication.

### Red Team Testing Methodology (Proof of Concept)
1.  Analyze the `windefend.idl` to find the vulnerable RPC function signature.
2.  Write a client application that binds to the local RPC endpoint using `RpcBindingFromStringBinding`.
3.  Send a specially crafted payload (e.g., an array with a manipulated length field) to bypass the server-side validation.
4.  Assume the context of the crashed/exploited service.
5.  Use `LsaLookupNames` to resolve the SID of the local Administrator account.
6.  **Verification:** Execute `SamiChangePasswordUser` via the elevated context. If the Administrator's NTLM hash/password is successfully overwritten, the vulnerability is confirmed.

### Company Vulnerability Assessment (Blue Team)
*   **Vulnerable if:** Internal RPC services rely on client-side validation rather than rigorously checking buffer bounds and pointer validity on the server side.
*   **Detection:** 
    *   Monitor for service crashes (Event ID 7034) related to the targeted RPC service.
    *   Monitor Security Event ID 4661 (A handle to an object was requested) targeting the SAM database, particularly from unusual processes.
    *   Monitor Security Event ID 4724 (An attempt was made to reset an account's password) originating from non-standard administrative tools.