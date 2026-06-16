# Chapter 2 — The Filesystem and How Paths Work

## What Happens When You Open a File?

When you type `notepad C:\Temp\test.txt`, here's the full chain of
command that fires inside Windows. This matters because our exploit
attacks this chain — we're disrupting the convoy mid-route.

```
1. Application calls CreateFile("C:\Temp\test.txt")
                    │
2. Win32 subsystem converts to NT path: \??\C:\Temp\test.txt
                    │
3. Object Manager resolves \??\ → DOS device namespace
   Finds C: → \Device\HarddiskVolume3 (your actual disk partition)
                    │
4. Path becomes: \Device\HarddiskVolume3\Temp\test.txt
                    │
5. I/O Manager sends IRP_MJ_CREATE to the filesystem driver stack
                    │
6. ┌─ MINIFILTER DRIVERS ─┐ (this is where Defender lives!)
   │  WdFilter.sys         │ ← Defender's file scan filter
   │  checks the file      │
   │  before NTFS sees it  │
   └───────────────────────┘
                    │
7. NTFS driver processes the request
   - Walks the directory tree: root → Temp → test.txt
   - At each directory, checks for REPARSE POINTS (junctions!)
   - If it hits a reparse point, it RESTARTS resolution from the new target
                    │
8. File is opened, handle returned to the application
```

Step 6 is Defender's checkpoint — the sentry post where every file gets
searched. Step 7 is where junctions redirect, like swapping a road sign
after the patrol has already cleared the intersection. Our exploit lets
Defender inspect at step 6, then we swap the road signs at step 7 before
Defender comes back for the follow-up operation.

## Two Path Namespaces

Windows has TWO coordinate systems for locating a file on disk. This
fucks with everyone, like having two separate map grids for the same AO.

### DOS Paths (What You Normally Use)

```
C:\Windows\System32\cmd.exe
D:\Projects\code.py
\\server\share\file.txt
```

These are the paths you use day-to-day — in Explorer, cmd, PowerShell.
They use drive letters (C:, D:) and backslashes. Think of them as the
grid references on a civilian road map.

### NT Paths (What the Kernel Uses)

```
\??\C:\Windows\System32\cmd.exe
\Device\HarddiskVolume3\Windows\System32\cmd.exe
\??\D:\Projects\code.py
```

The `\??\` prefix means "resolve this through the DOS device namespace."
It's how the kernel translates drive letters to physical devices —
the MGRS coordinates that the artillery actually fires on, not the
town names the civvies use.

**Why this matters**: NTFS junctions store their target as an NT path.
When you create a junction, you write `\??\C:\Windows\System32` into
the reparse data buffer. This is not optional — junctions won't work
with plain DOS paths.

### Try This in Your Terminal

Open `cmd.exe` and run these. See the two coordinate systems in action:

```cmd
:: See what your C: drive letter actually points to:
fsutil fsinfo volumeinfo C:

:: Create a junction and inspect its reparse data:
mkdir C:\Temp\test_junction_target
mkdir C:\Temp\test_junction_link
mklink /J C:\Temp\test_junction_link C:\Temp\test_junction_target
fsutil reparsepoint query C:\Temp\test_junction_link

:: You'll see the NT path in the output:
::   Substitute Name: \??\C:\Temp\test_junction_target
:: That's the kernel's grid reference — what CreateJunction() writes.

:: Clean up:
rmdir C:\Temp\test_junction_link
rmdir C:\Temp\test_junction_target
```

Now in PowerShell, see the device namespace:

```powershell
# List all drive letter → device mappings:
Get-WmiObject Win32_Volume | Select DriveLetter, DeviceID | Format-Table

# You'll see something like:
#   C:    \\?\Volume{GUID}\
# That GUID maps to \Device\HarddiskVolumeN in kernel space.
# When our junction says \??\C:\Windows\System32, the kernel resolves
# C: through this exact mapping to reach the physical partition.
```

This is not abstract theory. Your junction code writes `\??\` paths.
If you don't understand what that prefix resolves to, you can't debug
a junction that points to the wrong target.

## NTFS: The Filesystem

NTFS (New Technology File System) is the terrain your C: drive operates
on. Every file and directory is a registered entry in the Master File
Table (MFT) — the garrison's personnel manifest. Key properties:

### Everything Is a Record

Files aren't just raw payload sitting on disk. Each file is an MFT
record — a full dossier that contains:
- Filename
- Timestamps (created, modified, accessed)
- Security descriptor (who has clearance to access it)
- Data streams (the actual file content)
- **Reparse data** (if it's a junction/symlink)

### Directories Are Just Files

A directory in NTFS is a file whose data content is a muster roll of
other files. That's it. There's no special "directory" fortification —
it's just a file that happens to contain a roster of filenames.

This is why `CreateFile` can open directories — because to NTFS, a
directory IS a file with the `FILE_ATTRIBUTE_DIRECTORY` flag set.

### Reparse Points

This is the crucial one — the ambush mechanism. Any NTFS entry (file
or directory) can have a **reparse point** — a set of embedded orders
that says "when you encounter this path, reroute instead of proceeding
along the original bearing."

Types of reparse points:
- **Mount points / Junctions** (`IO_REPARSE_TAG_MOUNT_POINT`): redirect
  a directory to another path. THIS IS WHAT WE USE.
- **Symbolic links** (`IO_REPARSE_TAG_SYMLINK`): like junctions but
  work for files too. Require admin to create (unless developer mode).
- **Cloud files** (`IO_REPARSE_TAG_CLOUD`): OneDrive, Dropbox placeholders.

When the NTFS driver advances down a path and hits a reparse point, it:
1. Halts the advance
2. Reads the reparse data (the reroute orders)
3. Passes the orders back to the I/O Manager
4. I/O Manager restarts path resolution from the NEW target

The application that opened the path **never knows it got redirected**.
It called for fire on `C:\Temp\work\file.exe` and got a file back. It
has no idea the rounds actually landed in `C:\Windows\System32\`.

## The Filter Driver Stack

Between an application and the actual filesystem, there's a layered
defence in depth — a stack of **filter drivers**. These are the
sentries at a multi-layered checkpoint. Every file operation marches
through every position in the stack before reaching its objective.

```
Application
    │
    ▼
┌──────────────────────────┐
│ I/O Manager              │ Creates I/O Request Packets (IRPs)
├──────────────────────────┤
│ Filter Driver: WdFilter  │ ← Windows Defender scans here
├──────────────────────────┤
│ Filter Driver: Others    │ ← Antivirus, encryption, backup software
├──────────────────────────┤
│ NTFS Driver              │ ← Actual filesystem
├──────────────────────────┤
│ Volume Manager           │
├──────────────────────────┤
│ Disk Driver              │ ← Physical hardware
└──────────────────────────┘
```

Defender's `WdFilter.sys` is a **minifilter driver** — a forward
observer embedded in the convoy route — that registers for specific
operations:
- `IRP_MJ_CREATE` — file opens
- `IRP_MJ_WRITE` — file writes
- `IRP_MJ_SET_INFORMATION` — file moves/renames

When it spots a suspicious file (by content or name), it calls in a
scan. The scan happens INLINE — meaning the application's file open
is HALTED while Defender searches the payload. The convoy stops dead
at the checkpoint while the sentry inspects.

**That halt is the gap we exploit. The kill window.**

## Path Resolution Step by Step

Let's trace the full engagement when Defender scans
`C:\Temp\work\bait.exe`:

```
1. WdFilter sees IRP_MJ_CREATE for C:\Temp\work\bait.exe
2. WdFilter reads the file content → matches EICAR signature
3. WdFilter decides to quarantine the file
4. WdFilter needs to RE-OPEN the file for quarantine
   (this is a separate operation from the scan)
                    │
   ──── OUR WINDOW ────
   │                    │
   │ Between the scan and the re-open, we:
   │  a) Delete C:\Temp\work\  (the directory)
   │  b) Create C:\Temp\work\ as a junction → C:\Windows\System32
   │                    │
   ──── END WINDOW ────
                    │
5. WdFilter re-opens C:\Temp\work\bait.exe
6. NTFS resolves C:\Temp\work\ → hits junction → resolves to System32
7. WdFilter is now operating on C:\Windows\System32\bait.exe
8. WdFilter runs as SYSTEM → has write access to System32
9. Our payload lands in System32
```

Between steps 4 and 5, the sentry has already cleared the vehicle and
waved it through — but we swap the road signs while he walks back to
the guardhouse for the quarantine paperwork. When he follows the same
road name again, the signs now point into the fortified compound. He's
got SYSTEM-level clearance, so the gates open for him. Our payload
rides his credentials straight into the armoury.

## Key Takeaways

- Paths march through multiple layers of defence in depth before reaching the actual file
- NT paths (`\??\C:\...`) are the real grid coordinates — what the kernel and junctions use internally
- NTFS reparse points can silently reroute path resolution, like swapped road signs in a kill zone
- Junctions redirect directories — completely invisible to the application following them
- Defender is a sentry post embedded in the filter driver stack, between the application and NTFS
- The scan-then-act gap in Defender is the TOCTOU window — the moment the sentry's back is turned

## Test Program

After reading this, compile and run `TESTS/test02_paths.c`.
It shows how to query file attributes, detect reparse points, and
understand path resolution.
