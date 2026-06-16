# Chapter 3 — CreateFile: The Primary Weapon System

## Why a Whole Chapter on One Function?

Because `CreateFile` is the most critical weapon in the Windows armoury,
and you'll draw it in 5 different configurations during the exploit. Each
combination of flags is a different fire mode — same weapon platform,
completely different effect on target.

```c
HANDLE CreateFileW(
    LPCWSTR lpFileName,            // What to open
    DWORD dwDesiredAccess,         // What you want to DO with it
    DWORD dwShareMode,            // Can others use it simultaneously?
    LPSECURITY_ATTRIBUTES lpSA,   // Who can inherit this handle (usually NULL)
    DWORD dwCreationDisposition,   // Create new? Open existing? Both?
    DWORD dwFlagsAndAttributes,    // The magic flags
    HANDLE hTemplateFile           // Almost always NULL
);
```

We use the `W` version (wide/Unicode) because Windows paths are UTF-16
internally. The `A` version converts your ASCII string to UTF-16 anyway —
cut out the rear echelon and go direct.

## Parameter 1: lpFileName — The Target Designation

This is the file or directory path. Straightforward grid reference, except:

- Use `\\` in C strings because `\` is the escape character
  - `"C:\\Temp\\test.txt"` = the path `C:\Temp\test.txt`
- For wide strings, prefix with `L`:
  - `L"C:\\Temp\\test.txt"` = wide string (UTF-16)
- Maximum path length is 260 characters (MAX_PATH) unless you use `\\?\` prefix

## Parameter 2: dwDesiredAccess — Rules of Engagement

This determines what operations the handle authorises you to execute — your
clearance level for that target.

| Value | Meaning | When We Use It |
|-------|---------|----------------|
| `GENERIC_READ` | Read the file's contents | Oplock handle — we only need eyes on target |
| `GENERIC_WRITE` | Write/modify the file | Junction handle — we need to stamp reparse data |
| `GENERIC_READ \| GENERIC_WRITE` | Both | Deploying the bait file |
| `DELETE` | Delete the file | Policing brass |

You can combine them with `|` (bitwise OR). The kernel checks this against
the file's security descriptor — if your user account doesn't have write
permission, `GENERIC_WRITE` will fail with error 5 (ACCESS_DENIED).
Denied at the checkpoint. No clearance, no entry.

## Parameter 3: dwShareMode — Fire Discipline

This is the one that catches blokes out. It controls what OTHER operators can
do with the target while YOUR grip is active — who else gets to touch the
weapon while you're holding it.

| Value | Meaning |
|-------|---------|
| `0` | Exclusive grip — nobody else lays a hand on this target |
| `FILE_SHARE_READ` | Others can observe (read) |
| `FILE_SHARE_WRITE` | Others can modify (write) |
| `FILE_SHARE_DELETE` | Others can destroy/rename the target |
| All three combined | Open slather — anyone can do anything |

**For the exploit:**
- Oplock handle: `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`
  We WANT Defender to approach the target — that's what trips our claymore.
  If we lock it down with `0` (exclusive), Defender gets ACCESS_DENIED and
  never enters the killzone.
- Junction handle: `0` (exclusive) — nobody else touches the objective
  while we're planting the charge on the reparse point.

## Parameter 5: dwCreationDisposition — Assault or Occupy?

| Value | Meaning |
|-------|---------|
| `CREATE_NEW` | Fail if position already held. Deploy only to empty ground. |
| `CREATE_ALWAYS` | Always deploy. Overwrite whatever's dug in there. |
| `OPEN_EXISTING` | Fail if nothing's there. Occupy existing position only. |
| `OPEN_ALWAYS` | Occupy if held, deploy if empty. |
| `TRUNCATE_EXISTING` | Occupy and strip it bare. Fail if position is empty. |

**For the exploit:**
- Bait file: `CREATE_ALWAYS` (fresh deployment each assault)
- Oplock handle: `OPEN_EXISTING` (bait must already be in position)
- Junction directory: `OPEN_EXISTING` (staging area must already be prepared)

## Parameter 6: dwFlagsAndAttributes — Weapon Attachments

This is where the weapon becomes mission-specific. These flags change how
the handle operates at a fundamental level — barrel attachments, optics,
and fire selectors bolted onto the rail.

### FILE_ATTRIBUTE_NORMAL
Standard-issue. No attachments, no modifications. Iron sights on a
regular file.

### FILE_FLAG_OVERLAPPED
**Critical for oplocks.** This attachment switches the handle to
asynchronous fire mode.

Without it: `DeviceIoControl` locks your trigger finger until the operation
completes. Your entire section freezes in the open until the oplock breaks.
Can't manoeuvre, can't react, nothing.

With it: `DeviceIoControl` fires and returns immediately with `ERROR_IO_PENDING`.
When the oplock breaks, Windows sends the signal to your OVERLAPPED struct —
like a squawk on the radio net. You're free to manoeuvre in the meantime.

```c
// WITHOUT OVERLAPPED — your section is frozen in the open
DeviceIoControl(hFile, FSCTL_REQUEST_BATCH_OPLOCK, ...);
// ^^^ doesn't return until oplock breaks. Could be minutes. Or never.

// WITH OVERLAPPED — fire and move
DeviceIoControl(hFile, FSCTL_REQUEST_BATCH_OPLOCK, ..., &overlapped);
// ^^^ returns FALSE with ERROR_IO_PENDING
// Later: WaitForSingleObject(overlapped.hEvent, timeout);
```

### FILE_FLAG_BACKUP_SEMANTICS
**Required for breaching directories.** Normally `CreateFile` only grips files.
This flag says "I'm authorised to enter rooms, not just pick up objects on
the ground."

Any user can attach this flag. Despite the name suggesting you need special
privileges, it doesn't require elevated clearance on directories you already
have access to. The name is a decoy — ignore it, strap it on.

```c
// Breach a directory (for planting junction reparse point)
HANDLE hDir = CreateFileW(
    L"C:\\Temp\\work",
    GENERIC_WRITE,
    0, NULL,
    OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS,  // ← without this, CreateFile bounces off dirs
    NULL
);
```

### FILE_FLAG_OPEN_REPARSE_POINT
Normally, when you open a junction, Windows follows the redirect and sends
you to the TARGET — like a signpost routing you to a different building.
This flag says "grip the signpost itself, don't follow it."

We use this when SETTING the junction — we need the handle on the junction
directory, not on System32 at the other end of the redirect.

```c
// Without FLAG_OPEN_REPARSE_POINT:
//   CreateFile("C:\Temp\junction") → opens C:\Windows\System32 (the target)
//
// With FLAG_OPEN_REPARSE_POINT:
//   CreateFile("C:\Temp\junction") → grips the junction directory itself
```

### Combining Attachments
Flags are combined with `|` (bitwise OR) — stacking attachments on the rail:

```c
// Breach a directory + don't follow reparse redirects
FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT

// Async fire mode
FILE_FLAG_OVERLAPPED
```

## The Five CreateFile Draws in Our Assault

Here's every `CreateFile` we'll fire and why — the full battle order:

### 1. Deploy the bait (write EICAR)
```c
CreateFileW(baitPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
```
Standard deployment. Write the EICAR string, drop the weapon immediately.

### 2. Arm the claymore (oplock handle)
```c
CreateFileW(baitPath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
```
Async handle for the tripwire. Share everything so Defender walks right in.

### 3. Grip the directory for junction (in the oplock callback)
```c
CreateFileW(dirPath, GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            NULL);
```
Exclusive grip on the breach point. Lock out all other operators while we
plant the reparse charge.

### 4-5. Various cleanup handles
Delete operations, directory demolition. Policing brass after the contact.

## Error Handling Pattern (Weapon Safety Check)

Every `CreateFile` in the exploit follows this drill:

```c
HANDLE h = CreateFileW(path, access, share, NULL, disp, flags, NULL);
if (h == INVALID_HANDLE_VALUE) {
    printf("[-] Failed to grip %ls. Error: %lu\n", path, GetLastError());
    // Safety any handles already drawn
    return FALSE;
}
// Engage with the handle...
CloseHandle(h);  // Holster the weapon
```

## Key Takeaways

- `CreateFile` draws handles for files, directories, and devices — one weapon, many targets
- `dwDesiredAccess` controls your ROE clearance (read, write, delete)
- `dwShareMode` controls what OTHER operators can do while you're gripping the target
- `FILE_FLAG_OVERLAPPED` switches to async fire mode (required for tripwires)
- `FILE_FLAG_BACKUP_SEMANTICS` lets you breach directories
- `FILE_FLAG_OPEN_REPARSE_POINT` grips the junction itself, not its redirect target
- Always do a weapon safety check with `INVALID_HANDLE_VALUE` and always `CloseHandle` — holster every weapon you draw

## Test Program

Compile and run `TESTS/test03_createfile.c` to experiment with different
flag configurations and observe how they affect your grip. Dry fire drill —
no live rounds, full muscle memory.
