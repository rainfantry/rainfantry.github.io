# GLOSSARY — MILITARY-TO-TECHNICAL FIELD REFERENCE

> **FIELD REFERENCE CARD — OPERATION VADER.**
> Print this. Tape it to your monitor. Reference while coding.

---

## WEAPONS & AMMUNITION

| Military Term | Technical Equivalent |
|---|---|
| **Magazine** | Buffer — stores data before firing. You load it, you seat it, then you send it. |
| **Rounds** | Data bytes loaded into the magazine. Each byte is a round in the mag. |
| **Propellant charge** | Path data that drives the redirect. The energy behind the projectile. |
| **Trigger pull** | `DeviceIoControl()` call — sends the loaded magazine downrange to the kernel. |
| **Warhead** | IOCTL code — different warhead = different operation, same launcher platform. |
| **Blank round / EICAR** | EICAR test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) — a 68-byte standard AV test pattern recognised by every antivirus on Earth. Not malware. Exists specifically so operators can trigger AV scans without real payloads. Draws the same response as live ordnance — Defender scrambles to quarantine it. The muzzle flash that gives away the enemy's position. |
| **Camo / concealment** | XOR encoding — hides the blank round in transit so the enemy doesn't spot it early. |
| **Weapon system** | The compiled exploit binary. Everything assembled, ready to deploy. |
| **Primary weapon** | `CreateFileW()` — the universal tool. Every engagement starts here. |
| **Weapon malfunction** | `INVALID_HANDLE_VALUE` return — your weapon just failed to cycle. |
| **Functions check** | Error checking after every `CreateFile` call. You ALWAYS check. Always. |
| **Fire discipline** | Handle management — close at the right time, not before, not after. Premature close = negligent discharge. Late close = resource leak. |
| **Misfire** | `DeviceIoControl()` failure — trigger pulled, nothing happened. |
| **Dry fire drill** | Test programs in `TESTS/` — drill the mechanics without live rounds. |
| **Live fire** | Running the actual exploit against a real target. |
| **Policing brass** | `free()` / `CloseHandle()` cleanup after engagement. Leave no trace on the ground. |

---

## GRIP & CONTROL

| Military Term | Technical Equivalent |
|---|---|
| **Grip** | Handle — your hold on a kernel object. No grip, no control. |
| **Drawing a weapon** | Opening a handle via `CreateFile()`. Weapon comes out of the rack and into your hands. |
| **Holstering** | `CloseHandle()` — releasing the grip. Weapon goes back. |
| **Armoury** | Kernel object table — where all weapons are racked and tracked. |
| **Armoury tag** | Handle value — the number stamped on your weapon that references it in the rack. |
| **Exclusive grip** | `dwShareMode = 0` — nobody else touches this weapon while you hold it. |
| **Weapon rack** | Per-process handle table — your section's personal armoury. |
| **Clearance level** | `dwDesiredAccess` (`READ`, `WRITE`, `DELETE`) — what you're authorised to do with this weapon. |

---

## EXPLOSIVE ORDNANCE & TRIPWIRES

| Military Term | Technical Equivalent |
|---|---|
| **Claymore** | Batch oplock — **FRONT TOWARD ENEMY.** Directional. Devastating. Patient. |
| **Tripwire** | Oplock trigger mechanism — the enemy walks through it, the claymore fires. |
| **Arming the claymore** | `FSCTL_REQUEST_BATCH_OPLOCK` — device armed, safety off, waiting for contact. |
| **Detonator** | `OVERLAPPED` struct + event — the firing circuit that connects tripwire to explosive. |
| **Radio detonator** | `FILE_FLAG_OVERLAPPED` (async mode) — remote initiation, you don't have to be standing next to it. |
| **CONTACT** | `WAIT_OBJECT_0` — tripwire triggered. Enemy in the kill zone. Execute. |
| **Kill zone** | The directory where the bait sits. Everything that enters this space is already dead. |

---

## COMMUNICATIONS & SURVEILLANCE

| Military Term | Technical Equivalent |
|---|---|
| **Radio receiver** | `OVERLAPPED` struct — your comms hardware for receiving signals from the kernel. |
| **Tuning the frequency** | `CreateEvent()` — setting up the channel before you can receive anything. |
| **Listening post (LP)** | `WaitForSingleObject()` call — you're dug in, silent, watching the lane. |
| **Manning the LP** | Thread blocked waiting for signal — one soldier committed, eyes on, no movement. |
| **Standing watch** | Synchronous / blocking I/O — you stand there until something happens or you're relieved. |
| **Radio signal** | Event signaled state — the message came through. Act on it. |
| **Flooding the net** | Polling loop (`Sleep` + check) — wastes bandwidth, broadcasts your position. Undisciplined. |
| **Noise discipline** | Event-based waiting — zero CPU burn, instant response. Professional. Silent. Lethal. |
| **Battlefield chronograph** | `QueryPerformanceCounter()` — nanosecond-precision timing. Knows exactly when the round left the barrel. |

---

## TERRAIN & NAVIGATION

| Military Term | Technical Equivalent |
|---|---|
| **Reparse point** | Filesystem marker on a directory's MFT entry — a hidden IED that says "when you hit this point, change direction." Junctions and symlinks are both types of reparse points. The mechanism that makes the road sign swap possible. |
| **Road sign** | NTFS junction — a sign that tells traffic where to go. |
| **Swapping the signs** | Creating a junction via `FSCTL_SET_REPARSE_POINT` — redirecting the enemy's convoy into your kill zone. |
| **Crossroads** | Directory that becomes a junction — the intersection where the swap happens. |
| **Convoy route** | File path being resolved — the route the enemy's logistics follow. |
| **Civilian address** | DOS path (`C:\Windows\System32`) — the address civilians use. |
| **Military grid reference** | NT path (`\??\C:\Windows\System32`) — the real coordinates. No ambiguity. |
| **Fortified position** | `System32` / protected directory — the enemy's hardened compound. |
| **Area of Operations (AO)** | Working directory (`C:\Temp\...`) — your operational sandbox. |
| **Staging area** | Temp directory where bait is deployed — forward operating base before the assault. |
| **Kill zone** | Junction directory that redirects the enemy — they walk in thinking it's safe. It's not. |

---

## ENEMY FORCE

| Military Term | Technical Equivalent |
|---|---|
| **Enemy** | Windows Defender — the force you're operating against. |
| **Enemy commander** | `MsMpEng.exe` (scan engine) — the brain making decisions. |
| **Forward sentry** | `WdFilter.sys` (minifilter driver) — the tripwire at the perimeter. Sees everything that moves on the filesystem. |
| **Patrol** | RealTime Protection scan — the enemy actively sweeping the AO. |
| **Guard rotation** | RTP scan schedule — when the patrols cycle. Predictable patterns are exploitable. |
| **Defence in depth** | Detection layers (hash → signature → behavioral → cloud) — multiple defensive lines. You need to defeat all of them. |
| **Wanted poster** | Published exploit signature — the enemy knows what you look like. Change your appearance. |
| **Detention procedure** | Quarantine process — captured, isolated, neutralised. What happens if they catch your payload. |
| **QRF (Quick Reaction Force)** | Defender's quarantine thread — fast-response element that moves to neutralise detected threats. |

---

## OPERATIONS & TACTICS

| Military Term | Technical Equivalent |
|---|---|
| **OPORD** | Operations Order — the full exploit sequence, start to finish. Every phase planned. |
| **Kill chain** | The 4-phase exploit sequence — each phase feeds the next. Break one link, mission fails. |
| **Ambush** | The TOCTOU exploit pattern — let the enemy come to you, then strike in the gap between their check and their action. |
| **Recon** | Defender's initial file check — the enemy scans the bait. They flag it as hostile and call in the QRF (quarantine). The gap between recon and the QRF arrival is the kill window. |
| **Main body** | Defender's quarantine operation — the follow-up force that moves on the file after recon clears it. |
| **Fast air insertion** | Raw Win32 API calls (~0.2ms) — surgical, direct, no wasted movement. |
| **Moving by convoy** | Shell commands (slow, milliseconds) — loud, visible, predictable. Avoid in combat. |
| **Scorched earth** | Delete bait + remove directory before junction — deny the enemy any ground to stand on. |
| **Exfil** | Cleanup after successful exploitation — get out clean. No evidence. |
| **Battle Damage Assessment (BDA)** | Verify payload landed in `System32` — confirm the rounds hit the target. |
| **AO sanitised** | All temp files and handles cleaned up — the area looks like nobody was ever there. |
| **Clean extraction** | No traces left behind — forensically invisible. Ghost protocol. |

---

## DOCTRINE

| Military Term | Technical Equivalent |
|---|---|
| **TOCTOU** | Time-of-Check to Time-of-Use — the ambush doctrine. The enemy checks the ground, decides it's safe, then moves through. In the gap between checking and moving, you swap the terrain. |
| **Race condition** | The fundamental timing problem the ambush exploits — two forces competing for the same ground at the same time. |
| **Deterministic engagement** | Oplock-controlled timing — guaranteed engagement window. The claymore doesn't miss. |
| **Blind ambush** | Racing without oplocks — no tripwire, no guarantee. You're just hoping the enemy walks through at the right time. Unprofessional. |
| **Re-engagement protocol** | Retry loop — first attempt failed, cycle the action, try again. Persistence kills. |
| **Mission abort** | Timeout / cleanup on failure — know when to break contact. Fighting a lost engagement gets you killed. |

---

## SIGNALS INTELLIGENCE & COUNTER-INTELLIGENCE

| Military Term | Technical Equivalent |
|---|---|
| **EICAR** | European Institute for Computer Antivirus Research test string — a 68-byte standardised pattern that every AV on Earth detects on purpose. The industry's official blank round. Not malware, never was. |
| **XOR encoding** | Single-byte XOR (key 0x42) applied to the EICAR string. Camouflage — hides the blank round inside the binary so the enemy doesn't intercept it during transit. Reversible: apply the key once to encode, again to decode. |
| **MAPS** | Microsoft Active Protection Service — Defender's satellite uplink. Sends file metadata/samples to Microsoft's cloud for verdict. Adds latency to the scan pipeline, which paradoxically WIDENS the TOCTOU window. |
| **Cloud Block at First Sight** | Defender holds a suspicious file for up to 60 seconds while waiting for a cloud verdict. The hold extends the gap between check and use — more time for the junction swap. |
| **Sysmon** | System Monitor — the enemy's surveillance camera network. Event IDs 11 (FileCreate), 15 (FileCreateStreamHash), 23 (FileDelete) are the ones that see junction operations. Not installed by default on consumer Windows. |
| **ETW** | Event Tracing for Windows — passive wire taps baked into the OS kernel. The `Microsoft-Windows-Kernel-File` provider logs all filesystem operations including junction creation. Always on, but nobody's listening unless they set up a trace. |
| **AMSI** | Antimalware Scan Interface — script and memory scanning layer. Does NOT cover filesystem-level TOCTOU attacks. Not our problem. |
| **RPC** | Remote Procedure Call — the enemy's internal radio network. Defender exposes 236 procedures via UUID `c503f532-443a-4c69-8300-ccd1fbdb3839`. We intercepted the frequency list. |
| **IDL** | Interface Definition Language — the captured enemy codebook. Maps every RPC procedure number to its function signature. |
| **Tamper Protection** | Encrypted enemy comms — prevents modification of Defender settings. Guards the config, NOT the scan-to-quarantine pipeline. |
| **Detection footprint** | Your signature on the battlefield — what the enemy's surveillance network can see. Junction creation + file deletion + immediate recreation = a recognisable pattern if they're watching. |

---

> This is YOUR language. When the code stops making sense, come back here.
> Every line of C maps to something you already know from section attacks
> and fire-and-manoeuvre. The skill transferred — you just didn't know it yet.
