# MODULE 00 — START HERE

**22nd Survey Division | Offensive Security Course**
**Prerequisite: None. This is where everyone starts.**

---

You paid $497 to learn this from scratch. That means you get the unfiltered version — no handholding fluff, but also no skipping the foundations. Every expert you've seen online who makes this look easy spent years building the mental model you're about to get in one chapter.

Read everything. Do every exercise. Don't skip ahead.

---

## 0.1 — What Is a Computer, Actually?

Before you can break something, you need to know what it is.

A computer has three main parts that matter for this course:

**CPU — the worker.**
The CPU (Central Processing Unit) is the brain. It executes instructions one at a time, incredibly fast. It can only do one thing: read an instruction, execute it, move to the next. The CPU doesn't store anything permanently — it's a worker who only holds what's in their hands right now.

**RAM — the desk.**
RAM (Random Access Memory) is your workspace. When you open a program, it gets loaded onto the desk. The worker (CPU) reads from the desk and writes to the desk. RAM is fast. RAM is temporary — when you turn the power off, everything on the desk disappears.

**Disk — the filing cabinet.**
Your hard drive or SSD is the filing cabinet. Everything that needs to survive a reboot lives here — your photos, your programs, your documents. The filing cabinet is slow compared to the desk, but it persists.

**The process of running a program:**
1. You double-click a program.
2. Windows reads the program's file from the filing cabinet (disk).
3. Windows copies it onto the desk (RAM).
4. The worker (CPU) starts reading instructions from the desk and executing them.

**Why this matters for security:**

When a program is running, it lives in RAM. Its code is in RAM. Its data is in RAM. Its secrets — passwords, encryption keys, authentication tokens — are in RAM.

If you can READ another program's RAM, you can steal its secrets.
If you can WRITE to another program's RAM, you can change what it does.

This is not theoretical. Windows provides functions that let one process read and write another process's memory. Those functions are legitimate, authorised Windows features. That's what makes them so dangerous.

You will use `ReadProcessMemory` and `WriteProcessMemory` in Module 09. Right now, know they exist and know WHY they matter.

---

## 0.2 — What Is a Process?

Every running program is a **process**.

Not just the programs you open yourself — every piece of software running on your machine is a process. Windows itself is made of dozens of processes. Your antivirus is a process. The thing managing your printer is a process.

**What a process has:**
- Its own chunk of RAM (its "memory space" — other processes can't touch it without special access)
- A **PID** — Process ID, a number Windows assigns to identify it
- A parent process that spawned it
- Threads (but don't worry about those yet)

**Parent and child processes:**
When a process starts another process, the first is the parent and the second is the child. Open PowerShell from the Start menu — Windows Explorer is the parent, PowerShell is the child.

**The Windows process tree — memorise this:**

```
System (PID 4)
└── smss.exe          — Session Manager. First user-mode process.
    └── csrss.exe     — Client/Server Runtime. Manages console windows.
    └── wininit.exe   — Windows Initialisation.
        └── services.exe    — Service Control Manager. Manages Windows services.
            └── svchost.exe — Generic service host. Runs multiple services.
            └── svchost.exe
            └── svchost.exe  (there are many)
        └── lsass.exe       — Local Security Authority. Handles logins, stores credentials.
```

**Why svchost.exe matters:**

`svchost.exe` is a generic Windows process that hosts multiple Windows services. There are always several of them running. They're signed by Microsoft. They're expected. They're trusted.

If you inject your malicious code into a `svchost.exe` process, your code is now running inside a process that:
- Is signed by Microsoft
- Is expected to be running
- Has a legitimate network footprint (some svchost instances connect to Microsoft servers)
- Will confuse analysts who see network traffic coming from "svchost.exe"

This technique is called **process injection**. You'll build it in Module 10.

**EXERCISE 0.2**

1. Press `Ctrl + Shift + Esc` to open Task Manager.
2. Click the **Details** tab.
3. Scroll until you find `svchost.exe`. There will be many — pick any one.
4. Right-click it → **Properties**.
5. Look at the path in the General tab.

**Expected result:** `C:\Windows\System32\svchost.exe`

If you see a `svchost.exe` at any other path — that's not Windows. That's malware pretending to be Windows. Remember this.

---

## 0.3 — What Is Memory?

Memory means RAM. But RAM isn't one flat pool — it's organised. The two structures you need to understand are the **stack** and the **heap**.

**The Stack**

The stack is temporary working space. Every time a function runs, Windows gives it a chunk of stack space to store:
- Local variables (variables declared inside the function)
- The return address (where the CPU goes when the function finishes)
- Function arguments

The stack grows downward in memory — each new function call adds a frame at a lower address. When the function returns, that frame is gone.

Think of the stack as a notepad. You jot down working notes while you're solving a problem. When you're done, you tear off the page and throw it away.

**The Heap**

The heap is dynamic memory — memory your program explicitly requests at runtime. In C, you ask for heap memory with `malloc()`. In C++, you use `new`. The heap grows upward.

Think of the heap as a whiteboard. You write on it when you need to, and you erase specific sections when you're done. If you forget to erase (free the memory), it builds up — that's a memory leak.

**Buffers**

A buffer is a chunk of memory with a fixed size. You declare a buffer when you know you need to store up to N bytes of something.

```c
char name[64];   // a buffer that holds up to 64 characters
```

This buffer lives on the stack. It's 64 bytes long. No more.

**Buffer Overflow**

Buffer overflows are just writing more data into a box than the box can hold — and the stuff you wrote ends up in memory that belongs to something else.

If you copy 128 characters into a 64-byte buffer, the extra 64 bytes go somewhere. On the stack, "somewhere" is right next to the return address — the value that tells the CPU where to go when the function finishes.

If you control what overwrites the return address, you control where the CPU goes next.

That's a stack buffer overflow. It's been a known vulnerability since 1988. It still works in modern software that doesn't have mitigations enabled.

**EXERCISE 0.3**

1. Open Windows Calculator (`calc.exe`). Just type `calc` in the Start menu.
2. Download **Process Hacker 2** (see Section 0.7 for the link). Open it.
3. Find `Calculator.exe` in the list (it might say `CalculatorApp.exe`).
4. Right-click → **Properties** → **Memory** tab.
5. Look at the **Working set** value.

**Expected result:** Somewhere between 30 MB and 100 MB, depending on your system.

The working set is how much physical RAM the process is currently using. That number represents the desk space Windows has allocated for the calculator. Every byte in that working set is readable with the right access.

---

## 0.4 — What Is an API?

**API** stands for Application Programming Interface. That sounds complicated. It isn't.

An API is a collection of pre-written functions that someone else built, packaged, and made available for you to call.

When you write a program, you don't write code to talk directly to the network card's hardware — that would take thousands of lines and require you to understand electrical signals. Instead, you call an API function like `connect()`, and the API handles all of that for you.

**The Windows API**

Windows provides thousands of functions that programs can call to ask Windows to do things. This collection is called the **Windows API** (sometimes called the Win32 API).

Examples:
- `CreateProcess()` — start a new process
- `VirtualAlloc()` — allocate a chunk of memory
- `WriteProcessMemory()` — write data into another process's memory
- `CreateRemoteThread()` — create a thread in another process
- `RegSetValueEx()` — write to the Windows registry

**Why attackers love the Windows API:**

These functions are legitimate. They're signed. They're authorised. They're the normal, expected way for programs to interact with Windows.

Antivirus software has to allow these functions — if it blocked `VirtualAlloc()`, half of Windows would stop working. So attackers use the legitimate API to do illegitimate things.

`VirtualAlloc()` asks Windows to give your process a chunk of writable, executable memory. Normal programs use this to load plugins. Attackers use it to load shellcode.

`WriteProcessMemory()` lets you write bytes into another process's memory. Normal programs use this in debuggers. Attackers use it to inject code.

The functions aren't malicious. What you write into memory with them might be.

**An API call in plain English:**

```
VirtualAlloc(
    NULL,           // let Windows pick the address
    4096,           // give me 4096 bytes (one page)
    MEM_COMMIT,     // actually allocate the memory now
    PAGE_EXECUTE_READWRITE  // I need to execute code from this memory
)
```

That single call gives you a 4 KB block of memory you can write shellcode into and then execute. You'll write this in Module 09.

---

## 0.5 — What Is a Shell?

A **terminal** is a text-based interface to the operating system. Instead of clicking icons, you type commands. The OS executes them.

On Windows, there are two main shells:

**cmd.exe** — the classic Windows command prompt. Limited. Old. Still works. You'll use it sometimes because targets have it.

**PowerShell** — a more powerful shell. It can call Windows APIs, query system information, download files, and run scripts. Defenders use it. Attackers love it. It's built into every modern Windows machine.

**Bind Shell vs Reverse Shell**

When you compromise a machine, you want a shell — a command prompt on their machine that you control.

**Bind shell:** your code on the target opens a port and waits. You connect TO the target. Problem: corporate firewalls block inbound connections. The defender's firewall kills your bind shell before you can reach it.

**Reverse shell:** your code on the target connects OUT to you. The target calls home. Corporate firewalls almost always allow outbound connections on ports 80 (HTTP) and 443 (HTTPS). The defender's firewall waves it through.

This is why every C2 framework defaults to HTTPS reverse shells on port 443. The firewall sees an HTTPS connection going out. That's normal. That's allowed. Your shell traffic rides inside it.

**EXERCISE 0.5**

Open PowerShell (search "PowerShell" in the Start menu).

Type this exactly:

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Format-Table Name, Id, CPU -AutoSize
```

Press Enter.

**Expected output:** A table showing the 5 processes using the most CPU time, with their name, PID, and CPU seconds. Something like:

```
Name         Id      CPU
----         --      ---
chrome     4821   342.45
svchost    1024   128.33
...
```

You just queried the Windows process list, sorted it, filtered it to the top 5, and formatted the output. That's recon. That's intelligence gathering. You did it with a single line, and it ran inside a process that's already on every Windows machine on the planet.

---

## 0.6 — What Is C?

C is a programming language invented in 1972. It's still one of the most important languages for security work, for reasons that go beyond nostalgia.

**How C works:**

You write C code in a `.c` file — human-readable text. A **compiler** reads that text and translates it into machine code: raw bytes that the CPU executes directly.

No interpreter. No virtual machine. No "runtime" layer between your code and the CPU. You write instructions; the CPU executes them.

**Why attackers use C:**

1. **Small binaries.** A C program compiled for a simple task can be a few kilobytes. Smaller means less to detect, less to transfer, less to hide.

2. **Direct control.** In C, you manage memory yourself. You decide where to allocate it, what to put in it, when to free it. This is what makes buffer overflows possible — and what makes exploits possible.

3. **Direct API access.** You can call Windows API functions directly from C with `#include <windows.h>`. No wrapper. No overhead.

4. **Cross-compilation.** On a Linux machine, you can compile a Windows `.exe` using `mingw-w64`. Your target never runs your compiler — you ship them a finished binary.

**Hello World in C — every line explained:**

```c
#include <stdio.h>   // include the standard input/output library
                     // this gives you access to printf()

int main() {         // main() is the entry point — where the program starts
                     // int means the function returns an integer to the OS

    printf("Hello, World!\n");  // print the text to the terminal
                                // \n means newline (go to the next line)

    return 0;        // return 0 to the OS — means "success, no errors"
                     // return 1 (or anything else) means "something went wrong"
}
```

**Compile it:**

```
x86_64-w64-mingw32-gcc hello.c -o hello.exe
```

Breaking down that command:
- `x86_64-w64-mingw32-gcc` — the cross-compiler (compiles Windows .exe from any OS)
- `hello.c` — your source file
- `-o hello.exe` — name the output file `hello.exe`

**Run it:**

```
./hello.exe
```

**Expected output:**

```
Hello, World!
```

If you see that, your compiler works. If you see an error, check Section 0.7 and make sure MinGW is installed and on your PATH.

Every payload, every injector, every loader you build in this course starts exactly like this. One `main()`. One blank slate. You build up from here.

---

## 0.7 — Setting Up Your Environment

Do not skip this section. Every tool listed here is used somewhere in the course. Install them all now and verify each one before moving on.

---

### Tool 1: MinGW-w64 (C Compiler for Windows)

MinGW-w64 lets you compile C/C++ programs that run on Windows, from Windows (or Linux).

**Install via winget (Windows 10/11):**

Open PowerShell as Administrator and run:

```powershell
winget install -e --id MSYS2.MSYS2
```

After MSYS2 installs, open the MSYS2 terminal and run:

```
pacman -S mingw-w64-x86_64-gcc
```

This installs the 64-bit MinGW GCC toolchain.

**Alternative — direct download:**
Go to `https://github.com/niXman/mingw-builds-binaries/releases` and download the latest `x86_64-posix-seh` build. Extract to `C:\mingw64`. Add `C:\mingw64\bin` to your system PATH.

**Verify:**

Open a new PowerShell window and run:

```
gcc --version
```

**Expected output:**

```
gcc (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 13.x.x
...
```

Any version number is fine. If you get "command not found", your PATH isn't set correctly.

---

### Tool 2: Python 3

Python is used throughout the course for scripting, automation, and building tools.

**Install:**

Go to `https://www.python.org/downloads/` and download the latest Python 3 installer for Windows.

During installation: **check the box that says "Add Python to PATH"**. If you miss this, Python won't work from the terminal.

**Verify:**

```
python --version
```

**Expected output:**

```
Python 3.12.x
```

If you get `Python 2.x`, you have the old version. Make sure Python 3 is what's on your PATH.

---

### Tool 3: Git

Git is version control. You'll use it to pull course materials, manage your code, and push your work.

**Install:**

Go to `https://git-scm.com/download/win` and download the installer. Accept the defaults during installation.

**Verify:**

```
git --version
```

**Expected output:**

```
git version 2.x.x.windows.x
```

---

### Tool 4: VS Code

VS Code is your code editor. It has syntax highlighting, an integrated terminal, and extensions for every language you'll use.

**Install:**

Go to `https://code.visualstudio.com/` and download the Windows installer.

After installation, open VS Code and install these extensions (search in the Extensions sidebar, `Ctrl + Shift + X`):

- **C/C++** by Microsoft
- **Python** by Microsoft
- **GitLens** (optional but useful)

---

### Tool 5: Process Hacker 2

Process Hacker 2 is a free, open-source Windows process monitor. It shows you more than Task Manager: thread stacks, memory maps, handles, network connections, and which DLLs each process has loaded.

**Install:**

Go to `https://processhacker.sourceforge.io/downloads.php` and download **Process Hacker 2** (not 3 — version 3 requires a paid certificate to avoid UAC warnings; version 2 is free and works fine).

Install it. Run it as Administrator for full access.

You'll use Process Hacker in almost every module from 09 onwards.

---

### Tool 6: Wireshark

Wireshark captures and displays network traffic in real time. You'll use it to see what your payloads are actually sending over the network.

**Install:**

Go to `https://www.wireshark.org/download.html` and download the Windows installer.

During installation, install **Npcap** when prompted — this is the packet capture driver. Without it, Wireshark can't capture traffic.

**Verify:**

Open Wireshark. You should see a list of network interfaces with live activity graphs. If you see blank adapters with no activity, Npcap may not have installed correctly — reinstall it from `https://npcap.com/`.

---

### Tool 7: x64dbg

x64dbg is a Windows debugger for 64-bit and 32-bit executables. You'll use it to step through your own code, examine memory at runtime, and reverse engineer targets.

**Install:**

Go to `https://x64dbg.com/` and download the snapshot. It's a ZIP file — extract it to `C:\x64dbg\`.

Inside the extracted folder, you'll find:
- `x64\x64dbg.exe` — for 64-bit programs
- `x32\x32dbg.exe` — for 32-bit programs

You'll mostly use the 64-bit version.

---

### Verification Checklist

Run through this before proceeding to Module 01:

```
[ ] gcc --version          shows a version number
[ ] python --version       shows Python 3.x
[ ] git --version          shows a version number
[ ] VS Code opens          with C/C++ extension installed
[ ] Process Hacker 2       runs and shows processes
[ ] Wireshark              opens and lists network interfaces
[ ] x64dbg                 opens without errors
```

If any of these fail, fix it before moving on. Module 01 assumes all seven tools are working.

---

## 0.8 — What You Will Build By Module 22

This is a full offensive security course. Here's what each module delivers:

**MODULE 01 — Offensive Mindset**
How to think like a security researcher. Attack surface enumeration. Threat modelling. Why defenders fail. The rules that govern legitimate security research.

**MODULE 02 — Recon and Footprinting**
Passive and active reconnaissance. OSINT. Service enumeration. You learn to map a target before you touch it.

**MODULE 03 — Vulnerability Research**
How vulnerabilities are found, classified, and reported. CVE system. CVSS scoring. Reading patch diffs to find the bug.

**MODULE 04 — Windows Defences: ASLR, DEP, Stack Canaries**
How Windows tries to stop you. Address Space Layout Randomisation, Data Execution Prevention, stack cookies. Why each one works — and what it takes to bypass them.

**MODULE 05 — Exploit Development**
Writing your first working exploit. Controlling EIP/RIP. Return-oriented programming (ROP). Building a full exploit chain from crash to code execution.

**MODULE 06 — Fuzzing Theory and Practice**
Automated vulnerability discovery. Corpus generation. Coverage-guided fuzzing with WinAFL. How to find crashes in closed-source software.

**MODULE 07 — Exploit Primitives**
Arbitrary read/write. Type confusion. Use-after-free primitives. How to turn a crash into a reliable exploit.

**MODULE 08 — Privilege Escalation**
From user to Administrator to SYSTEM. Token impersonation. Service misconfiguration. UAC bypass. Kernel exploits.

**MODULE 09 — Malware Development**
Shellcode: writing it, encoding it, executing it. Process injection using VirtualAlloc, WriteProcessMemory, CreateRemoteThread. Your first working dropper.

**MODULE 10 — Code Injection**
DLL injection. Reflective DLL injection. Process hollowing. APC injection. You build four different techniques; you understand why each exists.

**MODULE 11 — Rootkits**
Kernel-mode rootkit fundamentals. DKOM. AMSI bypass. ETW bypass. MSRC-class research: the techniques behind disclosed vulnerabilities in Windows Defender.

**MODULE 12 — Antivirus Evasion**
Beating Kaspersky Premium without a kernel exploit. Signature evasion. Behavioural evasion. Sleep obfuscation. Heaven's gate. PPID spoofing.

**MODULE 13 — Memory Forensics**
Analysing a memory dump. Volatility Framework. Finding injected code. Reconstructing attacker activity from RAM.

**MODULE 14 — Reverse Engineering**
Static and dynamic analysis. x64dbg workflows. IDA Free / Ghidra. Unpacking packers. Reconstructing C from assembly.

**MODULE 15 — Post-Exploitation**
Credential harvesting. Lateral movement prep. Persistence mechanisms. Covering tracks. OPSEC.

**MODULE 16 — Command and Control (CHEYANNE + ECLIPSE)**
Building a working C2 framework from scratch. Listener. Implant. Task queue. Encrypted comms over HTTPS. CHEYANNE is the agent; ECLIPSE is the operator interface.

**MODULE 17 — Network Warfare**
Network sniffing. ARP spoofing. Man-in-the-middle. Traffic injection. Protocol abuse. You build tools, not just run them.

**MODULE 18 — Cryptography and Evasion**
Symmetric and asymmetric crypto. How TLS works. How attackers abuse it. Custom protocol design for C2 comms that blends into normal HTTPS traffic.

**MODULE 19 — Living Off the Land (LOTL)**
Built-in Windows tools as weapons. certutil, wmic, mshta, regsvr32, rundll32. The attacker's toolkit that ships with every Windows machine.

**MODULE 20 — Active Directory**
Domain architecture. Kerberos. Pass-the-hash. Pass-the-ticket. Golden ticket. DCSync. Attacking an enterprise environment.

**MODULE 21 — Android RAT**
Building an Android remote access tool. ADB. APK structure. Permissions abuse. Exfiltration over encrypted channels. StarKiller architecture.

**MODULE 22 — OSINT and Social Engineering**
Open-source intelligence at scale. Building target profiles. Pretexting. Physical pretexting. The human layer of every attack chain.

---

By Module 22, you will have built every tool in the 22nd Survey Division arsenal — from scratch.

---

## 0.9 — How to Use This Course

A few rules that determine whether you get good at this or just think you did:

**Read the chapter. Don't skim.**
Every sentence is load-bearing. If a paragraph seems boring, it's foundational. The details you skip in Module 02 will be the ones that break your exploit in Module 07.

**Every EXERCISE: do it.**
Exercises are marked with **EXERCISE X.X** headers. They are short. They take 2-10 minutes. Do every single one. The goal is to see the concepts live on your machine, not just understand them in the abstract. Security research is empirical — you test things, you observe results.

**Every // DRILL: build it.**
Drills appear in later modules. They're longer coding challenges. You write the code, compile it, run it, and verify the output matches the expected result. If it doesn't match, you debug it. Debugging is 70% of the job. Get comfortable with it early.

**Expected output blocks: your output must match.**
When a section shows you what the output should look like, your output should match — same format, same structure, similar values. If it doesn't, something is wrong with your environment or your code. Fix it before moving on.

**Ask yourself after every section: could I teach this to someone else?**
This is the test. If the answer is no, re-read the section. Understanding means being able to explain. If you can only recognise the concept when you see it, you don't own it yet.

---

That's Module 00.

You now know what a computer is, what a process is, what memory is, what an API is, what a shell is, what C is, and how to set up your environment.

You haven't written any malware. You haven't exploited anything. But you have the mental model that every module from here builds on.

Module 01 is where it gets sharp.

---
