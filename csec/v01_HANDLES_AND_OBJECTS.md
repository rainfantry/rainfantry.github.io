# Chapter 1 — Handles: Your Grip on the Weapon

## What Is a Handle?

A handle is a **number**. That's it. An integer — like 0x0044 or 0x00B8.

But this number is your **grip** on something the Windows kernel is managing
for you. When you open a file, Windows doesn't hand you the actual file.
It creates an internal data structure (a "kernel object") representing that
open file, and hands you back a number — the handle — that refers to it.

Think of it like a weapons rack at the armoury. You request a rifle. The
armourer doesn't let you walk into the cage — he hands you the weapon with
a tag number. When you return it, you hand back the tag. The armourer finds
the weapon. You never go into the cage yourself.

```
Your program                    Windows kernel (the armourer)
─────────────                   ─────────────────────────────
"Open C:\test.txt"  ──────────► Creates File Object (racks the weapon)
                    ◄──────────  Returns handle 0x0044 (your tag)

"Read handle 0x0044" ─────────► Looks up 0x0044 in YOUR process's rack
                                Finds the File Object
                    ◄──────────  Returns the file contents

"Close handle 0x0044" ────────► Destroys the entry (weapon returned)
                                Cleans up the File Object
```

## Why Handles Exist

Security. If Windows just gave you a raw pointer to the kernel's internal
data, you could corrupt it. Crash the system. Read other people's files.
Instead, handles are validated by the kernel on every use — like a sentry
checking credentials:

- Does this handle exist in YOUR process's rack? (Not someone else's)
- Does this handle have the right ACCESS? (Are you cleared for READ or WRITE?)
- Is this handle the right TYPE? (Is it a file handle, not a process handle?)

Every Win32 function that operates on a resource takes a handle as its
first argument. Like every weapon drill starts with "grip the weapon":
`ReadFile(handle, ...)`, `WriteFile(handle, ...)`,
`DeviceIoControl(handle, ...)`, `CloseHandle(handle)`.

## The Handle Table (Your Personal Armoury)

Every process has its own handle table. A private weapons rack
managed by the kernel:

```
Process A's rack:
  0x0004 → File Object (C:\test.txt, READ access)
  0x0008 → File Object (C:\log.txt, WRITE access)
  0x000C → Event Object (manual-reset, not signaled)

Process B's rack:
  0x0004 → File Object (D:\data.bin, READ|WRITE access)  ← DIFFERENT weapon!
  0x0008 → Process Object (pointing to Process C)
```

Handle 0x0004 in Process A is **completely different** from handle 0x0004
in Process B. They're tags into different racks. This is why you can't
just pass a handle number to another process and expect it to work — it'd
be like handing someone YOUR armoury tag at a DIFFERENT base.

## Types of Kernel Objects (The Arsenal)

Almost everything in Windows is a kernel object accessed through a handle:

| Weapon Type | Issued By | Used For |
|-------------|-----------|----------|
| File | `CreateFile()` | Reading/writing files AND directories |
| Event | `CreateEvent()` | Radio signals between threads ("CONTACT!") |
| Process | `OpenProcess()` | Controlling other processes |
| Thread | `CreateThread()` | Running code on parallel — like splitting the section |
| Mutex | `CreateMutex()` | Ensuring only one operator does something at a time — Defender uses these internally to coordinate scan threads |
| Section | `CreateFileMapping()` | Sharing memory between processes — how Defender shares signature data between `MsMpEng.exe` and `WdFilter.sys` |

For our exploit, we care about **File handles** (grips on files and directories)
and **Event handles** (radio receivers for tripwire notifications). Mutex and
Section are listed because you'll encounter them if you inspect Defender's
process in tools like Process Explorer — knowing the handle types prevents
confusion when you see unfamiliar entries in the rack.

## CreateFile: Drawing Your First Weapon

`CreateFile` is the Win32 function that opens files (and directories) and
returns a handle. Despite its name, it can also OPEN existing files, not
just create new ones. It's the universal weapon of file operations.

```c
HANDLE h = CreateFile(
    "C:\\test.txt",     // Target to engage
    GENERIC_READ,       // Access mode: what can we DO with this grip?
    0,                  // Sharing: can other operators use it simultaneously?
    NULL,               // Security: who can inherit this grip?
    OPEN_EXISTING,      // Disposition: create new or draw existing?
    FILE_ATTRIBUTE_NORMAL, // Flags: special mods?
    NULL                // Template: ignore this
);
```

This returns a handle — your grip. WITH that grip, you can:
- `ReadFile(h, ...)` — read the file's contents (intel gathering)
- `WriteFile(h, ...)` — write data to the file (plant payload)
- `DeviceIoControl(h, ...)` — send fire commands to the driver
- `CloseHandle(h)` — release the grip (return the weapon)

## INVALID_HANDLE_VALUE (Weapon Malfunction)

If `CreateFile` fails, it returns `INVALID_HANDLE_VALUE` (which is -1).
You MUST check for this. Every. Single. Time. Like a functions check
before every patrol.

```c
if (h == INVALID_HANDLE_VALUE) {
    printf("[-] Weapon malfunction. Error: %lu\n", GetLastError());
    return 1;
}
```

`GetLastError()` returns a number that tells you WHY the malfunction:
- 2 = target not found (file doesn't exist)
- 5 = access denied (you're not cleared)
- 32 = weapon in use by another operator (file locked)
- 183 = target already exists

## CloseHandle: Returning the Weapon

When you're done with a handle, you MUST close it. This is like returning
your weapon to the armoury after a patrol. If you don't:

- The kernel keeps the object alive (resource leak — wasted kit)
- The file stays "in use" (other operators can't access it)
- If you close the wrong handle, you might break your own program

```c
CloseHandle(h);
```

In our exploit, handle management is critical — like fire discipline.
We need to close the oplock handle at EXACTLY the right moment — too
early and the tripwire disarms, too late and we miss the window.

## How This Matters for the Exploit

1. **File handles**: We grip the bait file with `CreateFile` to arm the
   tripwire. The flags we pass determine whether the radio receiver works.

2. **Directory handles**: We grip the directory with `CreateFile` (yes,
   `CreateFile` opens directories too — with `FILE_FLAG_BACKUP_SEMANTICS`)
   to plant the junction reparse point.

3. **Event handles**: We create a radio receiver with `CreateEvent` for the
   async tripwire notification. When the claymore fires, Windows signals
   this event — CONTACT on the radio.

4. **Handle lifecycle**: The exploit's timing depends on releasing grips in
   the right order. Close the tripwire handle → destroy the position →
   plant the junction. All within microseconds. Fire discipline.

## Key Takeaways

- A handle is a number — your grip on a kernel object (your tag from the armoury)
- Every process has its own rack — handles are private to your operation
- `CreateFile` returns grips for files AND directories
- Always check for `INVALID_HANDLE_VALUE` (functions check)
- Always `CloseHandle` when done (return the weapon)
- `GetLastError()` tells you why the malfunction occurred (AAR)
- Handle timing is critical in race condition exploits — fire discipline wins wars

## Test Program

After reading this chapter, compile and run `TESTS/test01_handles.c`.
It demonstrates drawing weapons, inspecting grips, and understanding
access clearances. Dry fire drill — no live rounds.
