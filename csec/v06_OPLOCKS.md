# Chapter 6 — Oplocks: The Claymore

## What Is an Oplock?

An **opportunistic lock** (oplock) is a caching mechanism built into NTFS.
Its original purpose is a field cache — a supply dump that lets applications
stash file data locally and only sync with disk when another process needs
the file. Performance logistics.

But from an exploit perspective, an oplock is a **claymore mine**. You plant
it on a file with the tripwire facing the enemy, and the instant another
process touches that file, you get the radio signal from your listening post
BEFORE the enemy's operation completes. FRONT TOWARD ENEMY.

It's not a lock in the traditional sense (it doesn't deny the enemy passage).
It's an early warning system — a signal from the LP that contact is imminent.

## Types of Oplocks

We have several munitions in the armoury. We only care about one:

| Type | Purpose | For Exploit? |
|------|---------|--------------|
| Level 1 (Exclusive) | One reader, no other access | No — too restrictive |
| Level 2 (Shared) | Multiple readers, breaks on write | No — breaks too late |
| **Batch** | Like Level 1 but breaks on ANY open | **YES — this is ours** |
| Filter | Similar to batch but for filter drivers | Sometimes used |
| R/RH/RW/RWH | Modern lease-based oplocks | Overkill for this |

### Why Batch Oplocks?

A **batch oplock** is a command-detonated claymore. It fires when ANY
process calls `CreateFile` on the locked file — not on read, not on
write — on the OPEN itself. But you keep your hand on the detonator.
You get the signal, you decide when to release.

This is exactly the ambush we need:
1. We plant the claymore (batch oplock) on `bait.exe`
2. Defender's WdFilter rolls up to the wire — calls `CreateFile` to scan `bait.exe`
3. NTFS detects the tripwire and holds Defender in the kill zone
4. NTFS sends the radio signal to our position — CONTACT
5. We react (swap the junction)
6. We release the firing mechanism — NTFS lets Defender proceed
7. Defender follows the junction into our ambush, scanning the wrong directory

The key insight: between steps 4 and 6, we have a **guaranteed window**.
The kernel holds the enemy in the kill zone until we give the word.
This is a command-detonated ambush, not a hope-for-the-best IED.

## How Oplock Breaking Works

The fire mission inside the kernel:

```
┌─── YOUR PROCESS ───┐        ┌─── NTFS DRIVER ───┐        ┌─── DEFENDER ───┐
│                     │        │                    │        │                │
│ RequestBatchOplock  │───────►│ Register oplock    │        │                │
│ returns PENDING     │◄───────│ on file inode      │        │                │
│                     │        │                    │        │                │
│ WaitForSingle...    │        │                    │        │ CreateFile     │
│ (sleeping)          │        │                    │◄───────│ (wants to      │
│                     │        │ Check: oplock?     │        │  open file)    │
│                     │        │ YES → break it     │        │                │
│                     │        │                    │        │ (PAUSED)       │
│ Event fires!        │◄───────│ Signal the event   │        │ (waiting)      │
│                     │        │                    │        │ (can't         │
│ *** REACT HERE ***  │        │                    │        │  proceed yet)  │
│ close handle        │───────►│ Oplock released    │        │                │
│ swap junction       │        │                    │        │                │
│                     │        │ Resume Defender's   │───────►│ CreateFile     │
│                     │        │ CreateFile          │        │ completes      │
│                     │        │                    │        │ (follows       │
│                     │        │                    │        │  junction!)    │
└─────────────────────┘        └────────────────────┘        └────────────────┘
```

The critical detail: NTFS **holds Defender in the kill zone** until we
release the detonator. This isn't a fire-and-hope engagement where we
pray we're faster — the kernel literally pins the enemy in place until
we complete our manoeuvre. Command-detonated. Controlled. Lethal.

There IS a timeout — the kernel has a configurable oplock break timeout,
typically seconds. If we take too long, NTFS will let the enemy through
anyway. But we only need <1ms. The swap happens faster than a trigger
pull. We'll never hit the timeout.

## Setting a Batch Oplock (Code)

```c
// 1. Open the file — MUST use FILE_FLAG_OVERLAPPED
HANDLE hFile = CreateFileW(
    L"C:\\Temp\\bait.exe",
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,   // Required for async oplock
    NULL
);

// 2. Set up the OVERLAPPED event
OVERLAPPED ov = {0};
ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

// 3. Request the oplock
DeviceIoControl(
    hFile,
    FSCTL_REQUEST_BATCH_OPLOCK,
    NULL, 0, NULL, 0, NULL,
    &ov
);
// Returns FALSE with ERROR_IO_PENDING — that's correct

// 4. Wait for the break
DWORD wait = WaitForSingleObject(ov.hEvent, 30000);
if (wait == WAIT_OBJECT_0) {
    // OPLOCK BROKEN — someone opened the file
    // React NOW
}
```

## Oplock Sharing Requirements — Leaving the Gate Open

For the claymore to work, you MUST leave the gate open so the enemy can
approach the wire. If you open the file with `dwShareMode = 0` (exclusive),
other processes can't open the file — you've barricaded the approach and
the enemy will never reach the kill zone. The tripwire sits there forever,
never triggered.

We use `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` — the
gate is wide open. All approaches clear. Defender can open, read, write,
and delete the file. Every one of those movements trips the wire and
sends the radio signal back to our position first.

## What Triggers an Oplock Break?

For a batch oplock — what trips the wire — any enemy movement on the
approach:

- `GENERIC_READ` → CONTACT
- `GENERIC_WRITE` → CONTACT
- `DELETE` → CONTACT
- Any `CreateFile` call → CONTACT

Any attempt to open the file trips the wire. The claymore doesn't
discriminate — any movement in the kill zone fires the signal.
Defender's scan always starts with a `CreateFile`. Perfect.

## Oplock Caveats

### Friendly Forces Don't Trip It
YOUR process opening the file again doesn't break your own oplock.
Blue-on-blue is filtered out — the claymore knows the difference between
friendly and hostile movement.

### One Claymore Per Position
Only one batch oplock on a file at a time. If two processes request a
batch oplock on the same file, the second request fails. You can't
stack claymores on the same approach.

### Release the Detonator to Let Them Through
After the oplock breaks (CONTACT), you MUST close the file handle (or
call `DeviceIoControl` with a special response) to release the oplock
and let the other process proceed. Release the firing mechanism — let
the enemy walk into the ambush position. In our exploit, we close the
handle as part of the junction swap sequence.

### Keep Your Hand on the Detonator
If you close the oplock handle before it breaks, the claymore is disarmed.
The tripwire goes dead. The handle must remain open (and the OVERLAPPED
event must be valid) for the entire time you're on overwatch.

## Oplocks vs. File Locking

Don't confuse the claymore with a roadblock:

| Feature | Oplock | File Lock |
|---------|--------|-----------|
| Purpose | Notification | Access control |
| Blocks others? | Temporarily (during break) | Yes (permanently) |
| User mode? | Needs no privileges | Needs no privileges |
| Granularity | Whole file | Byte range |
| For exploit? | **YES** | No |

A file lock is a roadblock — nobody gets through. An oplock is a
claymore — everyone gets through, but you know exactly when and you
control what happens next. We want early warning, not denial.

## Key Takeaways

- Batch oplocks fire when ANY process opens the file — CONTACT
- NTFS holds the enemy in the kill zone until we acknowledge the break
- This gives us a guaranteed, kernel-enforced timing window — command-detonated, not luck
- Must use `FILE_FLAG_OVERLAPPED` + `OVERLAPPED` structure
- Must leave the gate open (`FILE_SHARE_*`) or the claymore is useless
- Close the handle after break to release the firing mechanism — let them proceed into the ambush
- This is not a "hope we're fast enough" race — the kernel holds the enemy at the wire

## Test Program

Compile and run `TESTS/test06_oplock.c` to plant a claymore and trigger
it from another terminal window.
