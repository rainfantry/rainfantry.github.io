# Chapter 0 — Operation VADER: Mission Brief

## The One-Sentence OPORD

We are building a weapon that tricks Windows Defender into writing a file
wherever WE choose — including fortified system directories — by exploiting
a race condition in how Defender scans and quarantines files.

## The Vulnerability We're Exploiting

Windows Defender runs as **SYSTEM** — the highest clearance level on a
Windows machine. It's the base commander. When it quarantines a malicious
file, it follows standard operating procedure:

1. **Recon** — checks the file's location (e.g., `C:\Temp\work\malware.exe`)
2. **Approach** — opens the file at that path
3. **Engage** — reads/moves/deletes the file

Between step 1 and step 2, there is a **gap**. A tiny one — 15-50
milliseconds. But that's an eternity in computer terms. That's our window.

In that gap, we **swap the road signs**. We replace `C:\Temp\work\` with a
junction (a filesystem redirect) that points to `C:\Windows\System32\`.

Now when Defender does step 2, it thinks it's approaching `C:\Temp\work\malware.exe`,
but it's actually marching straight into `C:\Windows\System32\malware.exe`. And
because Defender runs as SYSTEM, it has **full access to System32**. A standard
user (us) doesn't. We redirected the enemy's own fire onto their own position.

This is called a **TOCTOU** vulnerability: **Time-of-Check to Time-of-Use**.
The enemy checked the route, we changed it, they walked into our ambush.

## Training Syllabus

To build this weapon, you need to understand these concepts. Each gets its own chapter:

| # | Chapter | What It Teaches | Why You Need It |
|---|---------|----------------|-----------------|
| 1 | Handles & Objects | How Windows tracks grips on open files/resources | Everything in Win32 uses handles — your grip on the weapon |
| 2 | Filesystem & Paths | How `C:\Temp\file.txt` becomes a real file | Understanding the patrol route = understanding the redirect |
| 3 | CreateFile Deep Dive | The most versatile weapon in Win32 | You'll fire it 5+ times in the exploit |
| 4 | DeviceIoControl | How to send fire commands to the kernel | Junctions and oplocks both use this trigger |
| 5 | Async I/O | Setting up a radio receiver instead of standing watch | Oplocks require async comms to work |
| 6 | Oplocks | The tripwire/claymore mechanism | How we detect the exact moment the enemy enters the kill zone |
| 7 | NTFS Junctions | The road-sign swap mechanism | How we redirect the enemy patrol |
| 8 | Defender Architecture | How the enemy operates | Know your enemy's SOP |
| 9 | TOCTOU Theory | Race condition fundamentals — the ambush doctrine | The vulnerability class we're exploiting |
| 10 | The Chain | Full kill chain — all BBs combined | The complete operations order |
| 11 | RPC Attack Surface | Defender's 236-procedure RPC interface | Enemy comms intercepted — unexplored terrain |
| 12 | Reverse Shell | Winsock callback mechanism | The payload phones home |
| 13 | Beyond TOCTOU | Rootkit-phase discoveries — HWBP, phantom DLLs, service ACLs | What else is broken on the box |

## How to Use This Manual

1. **Read chapters 1-5 first.** These are basic training. Skip nothing.
2. **Run the test programs** in `TESTS/` after each chapter. Fire them yourself.
3. **Read chapters 6-9.** These build on basic training — advanced tactics.
4. **Read chapter 10.** This is the full operations order.
4b. **Read chapter 11.** Enemy comms intelligence — Defender's RPC attack surface.
4c. **Read chapter 12.** Reverse shell — the callback mechanism.
4d. **Read chapter 13.** Beyond TOCTOU — rootkit-phase escalation vectors.
5. **Study the annotated building blocks** in `BUILDING_BLOCKS/`. Answer key.
6. **Write your own versions** in `LIVE/`. Live fire exercise.

The test programs are dry fire drills. The building blocks are complete weapon
systems. Your live code is the real engagement. Each layer builds on the last.

## The Kill Chain (Preview)

```
┌─────────────────────────────────────────────────────────────┐
│                    OPERATION VADER — KILL CHAIN              │
│                                                             │
│  1. Stage the AO              C:\Temp\work\                 │
│  2. Drop the bait             C:\Temp\work\bait.exe         │
│  3. Arm the tripwire          (oplock = claymore planted)   │
│  4. Enemy patrol arrives      → tripwire fires!             │
│  5. Scorched earth            C:\Temp\work\ destroyed       │
│  6. Plant the junction        C:\Temp\work\ → System32     │
│  7. Enemy resumes patrol      opens "C:\Temp\work\X"        │
│  8. Junction redirects        actually enters System32\X    │
│  9. Enemy writes as SYSTEM    payload lands behind the wire │
│                                                             │
│  Steps 5-6 happen in ~0.2ms. (fast air insertion)           │
│  Enemy gap between 4 and 7 is ~15-50ms. (convoy speed)     │
│  We have 30-250x time advantage.                            │
└─────────────────────────────────────────────────────────────┘
```

## Area of Operations

- **Build machine**: Your Windows 11 laptop (this one — the armoury)
- **Target machine**: REDACTED test laptop (Windows 11 Home 24H2, standard user, RTP enabled, Tamper Protection OFF, HVCI on but user-mode ACB off)
- **Compiler**: `cl.exe` via Visual Studio Developer Command Prompt
- **No admin required**: The entire operation runs as a standard user. No escalation needed to launch.

## Compile Commands (Weapons Assembly)

Every source file in this repo assembles the same way:

```cmd
:: First, open Developer Command Prompt or run:
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

:: Then assemble any weapon:
cl.exe filename.c /Fe:output.exe /O1 /GS-
```

`/O1` = optimise for size (smaller profile, fewer signatures — like stripping serial numbers)
`/GS-` = disable stack buffer security checks (reduces detectable patterns — less noise)
