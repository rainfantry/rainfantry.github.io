# Chapter 4 — DeviceIoControl: The Fire Command

## What Is DeviceIoControl?

`DeviceIoControl` is the fire command. It sends a **control code** to a
device driver — a direct order from your user-mode program (your .exe)
to a kernel-mode driver (the filesystem, disk, network) to execute a
special mission that normal read/write operations don't cover.

`ReadFile`/`WriteFile` are normal comms — routine radio traffic up and
down the chain of command. `DeviceIoControl` is the fire mission. You're
not passing data through the mailbox. You're calling in ordnance on a
grid reference. Different intent, different authority, different result.

```c
BOOL DeviceIoControl(
    HANDLE hDevice,          // Handle to the device/file/directory
    DWORD dwIoControlCode,   // WHAT to do (the command)
    LPVOID lpInBuffer,       // Input data for the command (can be NULL)
    DWORD nInBufferSize,     // Size of input data
    LPVOID lpOutBuffer,      // Buffer for output data (can be NULL)
    DWORD nOutBufferSize,    // Size of output buffer
    LPDWORD lpBytesReturned, // How many bytes the driver wrote back
    LPOVERLAPPED lpOverlapped // For async I/O (can be NULL for sync)
);
```

## IOCTLs: The Warheads

Each command is called an **IOCTL** (I/O Control Code). Think of them as
different warheads for the same launcher — same firing mechanism, but
what you load into the tube determines what happens at the target. Two
matter for us:

### FSCTL_SET_REPARSE_POINT — "Plant the Junction"

```
Value: 0x000900A4
Meaning: "Stamp a reparse point (junction/symlink) onto this file/directory"
Used in: Building Block 1 (junction creator)
```

This is the "plant the junction" fire command. You send this IOCTL to a
directory handle along with a magazine containing the reparse data — the
payload that tells NTFS where the junction should redirect to. The NTFS
driver receives the payload, validates the ordnance, and writes the
reparse point into the MFT entry.

```c
// Create a junction: send reparse data to the directory
DeviceIoControl(
    hDirectory,                  // Handle to the empty directory
    FSCTL_SET_REPARSE_POINT,     // "Make this a junction"
    reparseBuffer,               // Points to target path in NT format
    bufferSize,                  // Size of the reparse data
    NULL, 0,                     // No output
    &bytesReturned,              // Ignored for this call
    NULL                         // Synchronous — no OVERLAPPED needed
);
```

After this fire command lands, the directory IS a junction. Any path
resolution through it gets redirected. It's instant and invisible — like
planting a claymore on a trail. Anyone who walks through follows your
redirect, not their original heading.

### FSCTL_REQUEST_BATCH_OPLOCK — "Arm the Tripwire"

```
Value: 0x00090014
Meaning: "Give me a batch oplock on this file — notify me when someone opens it"
Used in: Building Block 2 (oplock listener)
```

This is the "arm the tripwire" fire command. You send this IOCTL to a
file handle. The NTFS driver registers an oplock — a tripwire — on the
file. When another process opens that file, the driver fires the break
notification before letting the intruder proceed. You get advance warning
of contact.

```c
// Set an oplock: async — needs OVERLAPPED
DeviceIoControl(
    hFile,                       // Handle to the file (must be OVERLAPPED)
    FSCTL_REQUEST_BATCH_OPLOCK,  // "Set a tripwire on this file"
    NULL, 0,                     // No input data needed
    NULL, 0,                     // No output data needed
    NULL,                        // Bytes returned — not used for async
    &overlapped                  // The async notification struct
);
// Returns FALSE with GetLastError() == ERROR_IO_PENDING
// That's SUCCESS for async — "roger, tripwire armed, standby for contact"
```

## The IOCTL Number System

IOCTL values aren't random serial numbers. They're constructed from four
fields — like a military grid reference that encodes sector, unit type,
and mission code in one string:

```
Bits 31-16: Device Type    (e.g., 0x0009 = FILE_DEVICE_FILE_SYSTEM)
Bits 15-14: Required Access (0=any, 1=read, 2=write, 3=read|write)
Bits 13-2:  Function Code  (the specific command)
Bits 1-0:   Transfer Method (how data is passed)
```

You don't need to decode these yourself — just use the named constants.
But knowing the structure explains why `FSCTL_*` codes all start with
0x0009 — they're all filesystem fire commands, same unit designation.

### Decode It Yourself — Hands On

Pull apart our two IOCTLs manually. Open `cmd.exe` or a calculator in
programmer mode and verify:

```
FSCTL_SET_REPARSE_POINT = 0x000900A4

  Hex:    0x 0009 00A4
  Binary: 0000 0000 0000 1001 0000 0000 1010 0100

  Bits 31-16 (Device Type):    0x0009 = FILE_DEVICE_FILE_SYSTEM  ✓
  Bits 15-14 (Required Access): 00    = FILE_ANY_ACCESS
  Bits 13-2  (Function Code):  0000 0000 1010 01 = 0x29 = 41
  Bits 1-0   (Transfer Method): 00    = METHOD_BUFFERED

FSCTL_REQUEST_BATCH_OPLOCK = 0x00090014

  Bits 31-16: 0x0009 = FILE_DEVICE_FILE_SYSTEM  ✓  (same unit)
  Bits 15-14: 00     = FILE_ANY_ACCESS
  Bits 13-2:  0000 0000 0101 = 0x05 = 5
  Bits 1-0:   00     = METHOD_BUFFERED
```

Function code 41 vs function code 5 — different warheads, same launcher,
same unit. Every `FSCTL_*` you'll ever encounter has `0x0009` in the
upper word. If you see `0x002D` up there instead, that's a disk IOCTL
(`FILE_DEVICE_MASS_STORAGE`) — different unit, wrong fire command for
a filesystem target.

`FSCTL` = File System ConTroL
`IOCTL` = I/O ConTroL (the general category)

## Direct Fire vs Indirect Fire

DeviceIoControl operates in two modes of engagement:

### Direct Fire (Synchronous — You See the Impact)
```c
// Last parameter is NULL — no OVERLAPPED
DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, buf, size,
                NULL, 0, &returned, NULL);
// ^^^ Thread holds position until the junction is planted
// Returns TRUE on impact confirmed, FALSE on misfire
```

Direct fire. You pull the trigger, you see the round impact, you get
immediate confirmation. This is fine for quick operations like planting
a junction. Completes in microseconds — holding position for a
microsecond costs nothing.

### Indirect Fire (Asynchronous — Wait for the Spotter)
```c
// Last parameter is &overlapped — indirect fire mode
OVERLAPPED ov = {0};
ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

DeviceIoControl(hFile, FSCTL_REQUEST_BATCH_OPLOCK,
                NULL, 0, NULL, 0, NULL, &ov);
// ^^^ Returns immediately — "roger, fire mission received, standby for effect"
// The event ov.hEvent will be signaled when the tripwire fires
```

Indirect fire. You send the fire mission, but you can't see the target
from your position. The round's in the air, you're waiting for the
forward observer's radio call. Required for oplocks because we don't know
WHEN the tripwire will be triggered. Could be 5 milliseconds. Could be
30 seconds. Could be never (if nobody walks through the kill zone). You
call it in and wait for the spotter.

## How the Payload Moves

For `FSCTL_SET_REPARSE_POINT` — loading and firing the magazine:
```
Your program                         Kernel (NTFS driver)
───────────                          ─────────────────────
Load the magazine
  (reparse buffer with
   target path)      ───────────────►  Receives payload
                                       Validates the ordnance
                                       Writes to MFT record
                   ◄───────────────  Returns TRUE (impact confirmed)
```

For `FSCTL_REQUEST_BATCH_OPLOCK` — arming the tripwire and waiting:
```
Your program                         Kernel (NTFS driver)
───────────                          ─────────────────────
Send tripwire order ──────────────►  Arms the oplock
                   ◄───────────────  Returns ERROR_IO_PENDING
                                     ("roger, tripwire armed, standby")

  ... silence on the wire ...

                                     Enemy process opens the file
                                     NTFS sees the tripwire
                                     Signals your event ──────────►  CONTACT!
                                                                     WaitForSingleObject returns
```

## Error Handling

DeviceIoControl returns TRUE/FALSE. But for indirect fire missions,
FALSE with `ERROR_IO_PENDING` actually means the fire mission was
received — the forward observer is in position:

```c
BOOL result = DeviceIoControl(..., &overlapped);
if (!result) {
    DWORD err = GetLastError();
    if (err == ERROR_IO_PENDING) {
        // GOOD — fire mission received, standing by for effect
        // Wait for the event to be signaled
    } else {
        // ACTUAL misfire
        printf("[-] DeviceIoControl failed. Error: %lu\n", err);
    }
}
```

Common error codes — your battle damage assessment:
- `ERROR_IO_PENDING` (997) — fire mission received, standby (this is SUCCESS for async)
- `ERROR_INVALID_FUNCTION` (1) — wrong warhead for this launcher, driver doesn't support this IOCTL
- `ERROR_ACCESS_DENIED` (5) — you don't have the clearance on this handle
- `ERROR_INVALID_PARAMETER` (87) — malformed payload, bad magazine size or contents

## Key Takeaways

- `DeviceIoControl` sends fire commands (IOCTLs) to kernel-mode drivers
- `FSCTL_SET_REPARSE_POINT` plants junctions (direct fire, instant impact)
- `FSCTL_REQUEST_BATCH_OPLOCK` arms file tripwires (indirect fire, wait for contact)
- Indirect fire mode: returns FALSE + ERROR_IO_PENDING = "roger, standing by" — that IS success
- Direct fire mode: returns TRUE = impact confirmed, FALSE = misfire
- The handle MUST have been opened with the right access and flags — wrong clearance, no fire mission

## Test Program

Compile and run `TESTS/test04_ioctl.c` to see DeviceIoControl in action
with a simple synchronous call.
