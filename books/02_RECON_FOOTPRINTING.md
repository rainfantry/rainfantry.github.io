# Chapter 02 — Recon & Footprinting: OSINT and Active Recon

**VADER-RCE Field Manual**
**Prerequisite**: Ch01 (Offensive Mindset)
**Drill**: DRILLS/02_recon_footprinting/

---

## Why You Need This

Recon is the phase that determines whether every subsequent phase
succeeds or fails. Operators who rush recon show up at a door
they don't understand, armed with the wrong tools, against
defences they didn't know existed.

Recon has two modes. Passive: zero contact with target systems.
You're reading their digital exhaust — public records, search
engines, code repositories, social media. The target has no
visibility. Zero detection risk. Maximum intelligence with no
exposure.

Active: you interact directly with target systems. Scanning ports,
grabbing banners, probing services. The target may log this.
Detection risk exists and scales with noise level.

The rule: exhaust passive before starting active. Everything you
can learn for free, with zero risk, you should learn before you
take any risk at all.

This chapter covers both modes end to end: what to look for,
what tools to use, how to map an attack surface, and how to
stay invisible while doing it.

---

## WINDOWS SETUP

Every tool in this chapter. Exact install commands. No excuses.

### Tools List and Install Commands

**1. nmap** — port scanner, service version detection, NSE scripts
```powershell
# Download installer from https://nmap.org/download.html#windows
# Direct link: https://nmap.org/dist/nmap-7.95-setup.exe
# Run installer as Administrator (requires admin rights)
# Verification:
nmap --version
# Expected: Nmap 7.95 ( https://nmap.org )
```

**2. Npcap** — packet capture driver required by nmap (bundled in nmap installer)
```powershell
# Installed automatically with nmap. If you need it separately:
# https://npcap.com/#download
# MUST install as Administrator
# Verification: check Add/Remove Programs for "Npcap"
```

**3. theHarvester** — email/subdomain/host enumeration
```powershell
# Requires Python 3.8+ (you already have this)
pip install theHarvester
# OR clone from GitHub for latest version:
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements/base.txt
# Verification:
python theHarvester.py --help
# Expected: usage: theHarvester.py [-h] -d DOMAIN ...
```

**4. Shodan CLI** — command-line interface to Shodan API
```powershell
pip install shodan
# After install, configure with your API key (free account at shodan.io):
shodan init YOUR_API_KEY_HERE
# Verification:
shodan info
# Expected: Query credits available: 100 ...
```

**5. subfinder** — passive subdomain discovery
```powershell
# Download Windows binary from GitHub releases:
# https://github.com/projectdiscovery/subfinder/releases
# Download subfinder_windows_amd64.zip, extract subfinder.exe to C:\Tools\
# Add C:\Tools\ to your PATH in System Environment Variables
# Verification:
subfinder -version
# Expected: subfinder v2.x.x
```

**6. amass** — aggressive subdomain discovery
```powershell
# Download Windows binary:
# https://github.com/owasp-amass/amass/releases
# Download amass_windows_amd64.zip, extract to C:\Tools\
# Verification:
amass -version
# Expected: v3.x.x
```

**7. gobuster** — DNS/directory brute force
```powershell
# Download Windows binary:
# https://github.com/OJ/gobuster/releases
# Extract gobuster.exe to C:\Tools\
# Verification:
gobuster version
# Expected: gobuster v3.x.x
```

**8. masscan** — high-speed port scanner (WSL2 REQUIRED — see below)
```powershell
# masscan does NOT have a working Windows native build.
# Install WSL2 first (requires admin rights, Windows 10 2004+):
wsl --install
# Reboot when prompted, then open Ubuntu from Start Menu:
sudo apt update && sudo apt install masscan -y
# Verification (inside WSL2):
masscan --version
# Expected: Masscan version 1.x.x
```

**9. truffleHog** — git history secret scanner
```powershell
pip install trufflehog
# Verification:
trufflehog --help
# Expected: usage: trufflehog [-h] ...
```

**10. gitleaks** — fast secret scanner for git repos
```powershell
# Download Windows binary:
# https://github.com/gitleaks/gitleaks/releases
# Download gitleaks_windows_x64.zip, extract to C:\Tools\
# Verification:
gitleaks version
# Expected: v8.x.x
```

**11. whatweb** — web technology fingerprinting (WSL2 REQUIRED)
```powershell
# No working Windows native build. Use WSL2:
wsl --install   # if not already installed
# Inside WSL2 Ubuntu:
sudo apt install whatweb -y
# Verification (inside WSL2):
whatweb --version
# Expected: WhatWeb version 0.5.x
```

**12. wafw00f** — WAF detection
```powershell
pip install wafw00f
# Verification:
wafw00f --help
# Expected: Usage: wafw00f url1 [url2 [url3 ...]]
```

**13. Wappalyzer** — browser extension for passive tech fingerprinting
```
# Chrome: https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbllamg
# Firefox: https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
# No install command — add to browser from the link above.
# Verification: browse any website and click the Wappalyzer icon in toolbar.
```

**14. ExifTool** — metadata extraction from files
```powershell
# Download Windows executable:
# https://exiftool.org/  → download "Windows Executable"
# Extract exiftool(-k).exe, rename to exiftool.exe, place in C:\Tools\
# Verification:
exiftool -ver
# Expected: 12.xx
```

**15. dig / nslookup** — DNS query tools
```powershell
# nslookup: already built into Windows, no install needed
nslookup -type=MX google.com
# Expected: Non-authoritative answer: google.com MX preference = ...

# dig: NOT built into Windows natively. Options:
# Option A — install BIND tools for Windows:
# https://www.isc.org/download/ → BIND → Windows installer
# Option B — use nslookup instead (same results, different syntax)
# Option C — WSL2: sudo apt install dnsutils -y
```

**16. curl** — HTTP requests, banner grabbing
```powershell
# Built into Windows 10/11. No install needed.
curl --version
# Expected: curl 7.x.x (Windows) ...
```

**17. gitrob — DEPRECATED. Do not install.**
```
# gitrob is no longer maintained and its GitHub repo is archived.
# Replacement: use truffleHog + gitleaks + manual GitHub dorking.
# truffleHog covers everything gitrob did and is actively maintained.
```

### WSL2 Setup (Required for masscan and whatweb)

```powershell
# Run PowerShell as Administrator:
wsl --install
# This installs WSL2 + Ubuntu 22.04 by default.
# Reboot when prompted.
# After reboot, Ubuntu opens and asks you to set a username/password.
# That's your Linux username — remember it.

# Verify WSL2 is working:
wsl --list --verbose
# Expected:
#   NAME      STATE           VERSION
# * Ubuntu    Running         2
```

**Admin rights required for**: nmap install, Npcap install, WSL2 install.
All other tools run as a normal user after install.

---

## Section 1 — Passive Recon: OSINT

OSINT (Open Source Intelligence) is intelligence gathered from
publicly available sources. No hacking required. No authorisation
needed. It's all sitting there, indexed by search engines,
accessible to anyone who knows how to look.

The volume of information that organisations accidentally expose
is extraordinary. Job postings reveal technology stacks. GitHub
repos leak credentials. LinkedIn reveals org charts and tool
names. Shodan indexes every publicly exposed service on the
internet.

Before you touch a scanner, you should know:
- The organisation's IP ranges and domain names
- What software versions are running on exposed services
- Who the system administrators are (names, emails, LinkedIn)
- What security tools they use (job postings, LinkedIn skills)
- Whether any employee has leaked credentials to a paste site
- Whether any internal code or config has been committed to GitHub

### WHOIS and Domain Registration

Every registered domain has WHOIS records. This data includes:
registrar, registration date, expiry date, and historically,
the registrant's contact information. Privacy protection services
now obscure most personal data, but organisation names, admin
emails, and associated nameservers are frequently still exposed.

```bash
# Basic WHOIS lookup
whois targetcompany.com

# WHOIS on an IP address (reveals the owning organisation)
whois 203.0.113.50

# Dig for nameservers (reveals DNS provider, potentially hosting info)
dig NS targetcompany.com

# WHOIS via web — more detail, some services show history
# https://who.is/
# https://www.whois.com/
# https://centralops.net/co/
```

**Windows alternative — use nslookup (built-in) instead of dig:**

```powershell
# Get nameservers — equivalent to: dig NS targetcompany.com
nslookup -type=NS targetcompany.com

# Get A record (hostname to IP)
nslookup targetcompany.com

# WHOIS on Windows — use the web interfaces above, or PowerShell:
# (No native whois command on Windows — web is your best bet)
```

#### Expected Output

**WHOIS lookup success looks like:**
```
Domain Name: TARGETCOMPANY.COM
Registry Domain ID: 12345678_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: http://www.godaddy.com
Updated Date: 2023-01-15T10:22:00Z
Creation Date: 2010-03-22T18:00:00Z
Expiry Date: 2025-03-22T18:00:00Z
Registrar: GoDaddy.com, LLC
Registrant Organization: Target Company Pty Ltd
Admin Email: admin@targetcompany.com
Name Server: NS1.TARGETCOMPANY.COM
Name Server: NS2.TARGETCOMPANY.COM
```

**Failure looks like:**
```
No match for "TARGETCOMPANY.COM".
```
Means: domain doesn't exist, or you typo'd it.

```
>>> Last update of WHOIS database: 2024-01-15T00:00:00Z <<<
[...redacted by privacy service...]
```
Means: domain has WHOIS privacy protection. You'll still see registrar
and nameservers — just not registrant contact info. That's fine, still useful.

From a WHOIS lookup you can often extract:
- Registered domain names (hunt for adjacent domains)
- Admin contact email (target for phishing, password reset)
- Registrar (informs of potential registrar-level attacks)
- Registration/expiry dates (old domains may have weaker security)
- Name servers (tells you DNS provider, possibly hosting provider)

**WHOIS history** — registrations change. Historical WHOIS records
(available via services like SecurityTrails or DomainTools) can
reveal previously registered IPs and organisational details that
the company has since tried to obscure.

---

### Shodan: The Internet-Wide Scanner

Shodan continuously scans the entire internet and indexes every
service it finds. Search Shodan and you get a map of every
publicly exposed service for a target organisation without
sending a single packet to their network.

```
# Search by organisation name
org:"Target Company Name"

# Search by domain
hostname:targetcompany.com

# Search by IP range
net:203.0.113.0/24

# Find specific software versions
apache 2.4.49

# Find exposed webcams, industrial systems, RDP
product:webcam country:AU
port:3389 country:AU

# Chain filters
org:"Target Company" port:22

# Shodan CLI (requires API key)
shodan search "org:Target Company"
shodan host 203.0.113.50
```

**Windows — Shodan CLI commands:**

```powershell
# Install Shodan CLI (already covered in Windows Setup above)
# Run these in PowerShell or CMD after install:

shodan search "org:Target Company"    # search by org
shodan host 203.0.113.50              # detail on a specific IP
shodan count "org:Target Company"     # how many results before you use credits
shodan download results.json.gz "org:Target Company"  # save results to file
```

#### Expected Output

**`shodan host 203.0.113.50` success looks like:**
```
203.0.113.50
City:                   Sydney
Country:                Australia
Organisation:           Target Company Pty Ltd
Updated:                2024-01-10T08:22:11.414Z
Number of open ports:   3

Ports:
     22/tcp
    443/tcp
   8443/tcp
```

**Failure looks like:**
```
ERROR: No information available for that IP.
```
Means: Shodan hasn't scanned that IP recently, or it's in a range
Shodan can't reach (RFC1918 private IPs won't appear).

```
ERROR: Access denied. Please use a valid API key.
```
Means: run `shodan init YOUR_KEY` first.

What Shodan tells you per result:
- IP address, port, protocol
- Service banner (software name and version)
- SSL certificate details (often contains hostnames, org names)
- Last scan timestamp
- Geographic location

SSL certificates are gold. A certificate for one IP often contains
Subject Alternative Names (SANs) listing every hostname that cert
was valid for — giving you a complete list of subdomains and
internal hostnames without ever touching the target.

```
# Shodan filter for cert SANs
ssl.cert.subject.cn:targetcompany.com

# Gets you everything in that cert including SANs
# Often reveals internal hostnames like vpn.internal.targetcompany.com
```

**Shodan alternatives:**
- Censys (censys.io) — similar capability, often has more recent scan data
- FOFA (fofa.info) — Chinese equivalent, excellent coverage of Asian infrastructure
- ZoomEye — similar to Shodan, different scan coverage

---

### Google Dorking

Google's index contains data organisations didn't intend to expose.
File listings, configuration files, login pages, employee data —
all indexed and searchable with the right operators.

```
# Core Google operators for recon
site:targetcompany.com          # restrict to target domain
filetype:pdf                    # specific file types
intitle:"index of"              # directory listings
inurl:admin                     # admin paths in URLs
intext:"password"               # password in page content

# Compound dorks
site:targetcompany.com filetype:pdf
  → find all indexed PDFs — reports, contracts, internal docs

site:targetcompany.com intitle:"index of"
  → find directory listings with files exposed

site:targetcompany.com filetype:sql
  → database dumps accidentally exposed

site:targetcompany.com inurl:wp-admin
  → WordPress admin panels

site:targetcompany.com "internal use only"
  → documents marked confidential but indexed publicly

site:targetcompany.com filetype:log
  → log files with sensitive data

site:targetcompany.com filetype:bak OR filetype:old OR filetype:backup
  → backup files that shouldn't be public

intext:"targetcompany.com" site:pastebin.com
  → pastes mentioning the target — leaked creds, data dumps

"@targetcompany.com" filetype:xls
  → spreadsheets with employee email addresses
```

**Google Hacking Database (GHDB)** — exploit-db.com/google-hacking-database
— a maintained collection of dorks organised by category. Search
it before building your own dork list. Whatever you're looking for,
someone has already written a dork for it.

---

### GitHub Dorking

Developers commit secrets to GitHub constantly. API keys, database
passwords, internal hostnames, AWS credentials. Not intentionally.
But continuously.

```
# GitHub search operators
"targetcompany.com" password
"targetcompany.com" secret
"targetcompany.com" api_key
"targetcompany.com" BEGIN RSA PRIVATE KEY
"targetcompany.com" AWS_SECRET_ACCESS_KEY

# Look for the company's internal tools accidentally made public
org:targetcompany

# Hunt for config files containing the domain
"targetcompany.com" extension:env
"targetcompany.com" extension:config
"targetcompany.com" filename:.env

# Specific secret patterns
"AKIA" "targetcompany"          # AWS access key prefix
"-----BEGIN" targetcompany.com  # Private keys
```

**Automated tools for GitHub secret hunting:**

```powershell
# truffleHog — scans git history for secrets (Windows, runs natively)
# Scan a GitHub org:
trufflehog github --org=targetcompany

# Scan a specific repo:
trufflehog git https://github.com/targetcompany/someproject

# Scan a local repo you've already cloned:
trufflehog filesystem C:\path\to\cloned\repo
```

```powershell
# gitleaks — fast secret scanner (Windows, runs natively)
# Scan a local repo:
gitleaks detect --source=C:\path\to\repo --verbose

# Scan and output results to JSON:
gitleaks detect --source=C:\path\to\repo --report-path=C:\leaks.json
```

**gitrob is deprecated and must not be used.** The project is archived
and unmaintained. truffleHog v3 + gitleaks together cover everything
gitrob did, with active maintenance and better detection rates.

#### Expected Output

**`trufflehog github --org=targetcompany` success looks like:**
```
Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLE
File: config/deploy.rb
Line: 14
Commit: a3f2b1c...
Repository: targetcompany/infrastructure
```

**Failure looks like:**
```
Error: HTTP 403 - Forbidden
```
Means: you're rate-limited or need a GitHub token. Set one:
```powershell
$env:GITHUB_TOKEN = "ghp_yourtokenhere"
trufflehog github --org=targetcompany
```

```
No results found.
```
Means: either no secrets in that org's public repos, or the org name is wrong.
Check with: `https://github.com/targetcompany` in browser first.

GitHub history matters. Code gets committed, developers realise
it contains a secret, and they remove it in the next commit. But
the secret is in the git history. Tools like TruffleHog scan
the ENTIRE history of a repository, not just the current state.

---

### LinkedIn Intelligence

LinkedIn is an organisational intelligence database that companies
pay to maintain for you. Employees list their roles, tools, and
skills. From LinkedIn you can reconstruct:

- Complete org chart (who reports to whom)
- Tool stack (employees list the software they use)
- Security team members (names, seniority, focus areas)
- Technology vendors (contractors list client names)
- Email format (firstname.lastname@company.com, f.lastname@, etc.)

```
# LinkedIn search approaches
Company page → People tab → filter by department
  → Get a list of employees in a specific department

"[Company Name]" "Security Engineer" site:linkedin.com
  → Google-indexed LinkedIn profiles for security staff

"[Company Name]" "senior sysadmin" site:linkedin.com
  → Find IT admin targets for social engineering

Hunter.io — verify email formats, find email addresses
  https://hunter.io/search/targetcompany.com
  → Lists known emails, shows the format pattern

# Email permutation from known name
  john.smith@targetcompany.com
  jsmith@targetcompany.com
  john_smith@targetcompany.com
  smithj@targetcompany.com
  → Verify with SMTP probe or service like Hunter
```

Job postings are underrated intelligence. A listing for
"Senior Active Directory Administrator" tells you they run AD.
"Experience with CrowdStrike required" tells you their EDR.
"Palo Alto NGFW management" tells you their firewall. The hiring
manager's LinkedIn tells you their name.

---

### Passive Recon Tools: Compiled Toolkit

```
TOOL                PURPOSE
────────────────────────────────────────────────────────
theHarvester        Email, subdomain, host enumeration
                    python theHarvester.py -d targetcompany.com -b all
                    WINDOWS: pip install theHarvester (runs natively)

Maltego             Visual link analysis, entity mapping (paid/free CE)
                    WINDOWS: native Windows installer at maltego.com

SpiderFoot          Automated OSINT, covers 100+ sources
                    spiderfoot -s targetcompany.com -m all
                    WINDOWS: pip install spiderfoot

Recon-ng            Modular recon framework (like Metasploit for recon)
                    recon-ng -w targetcompany
                    WINDOWS: pip install recon-ng (or use WSL2)

FOCA                Document metadata extraction — find author names,
                    internal paths, software versions from PDFs/DOCX
                    WINDOWS: FOCA is Windows-native! Download from
                    https://github.com/ElevenPaths/FOCA/releases

Metagoofil          Extracts metadata from public documents
                    metagoofil -d targetcompany.com -t pdf,docx
                    WINDOWS: pip install metagoofil

Exiftool            Reads metadata from images/documents (GPS coords,
                    camera models, software versions, author names)
                    exiftool document.pdf
                    WINDOWS: native Windows exe at exiftool.org

Intelx.io           Historical WHOIS, leaked database search, pastes
                    WEB ONLY — use in browser

SecurityTrails      DNS history, WHOIS history, subdomain intelligence
                    WEB ONLY — use in browser (securitytrails.com)

Censys              Internet scan data (alternative to Shodan)
                    WEB ONLY — use at censys.io

BuiltWith           Technology fingerprint from web scraping
                    WEB ONLY — use at builtwith.com

Wappalyzer          Browser extension — identifies tech stack passively
                    while browsing target website
                    WINDOWS: Chrome/Firefox extension — see Windows Setup
```

---

## Section 2 — DNS Enumeration

DNS is the phone book of the internet. Enumerated correctly, it
reveals the full map of a target's infrastructure: every subdomain,
every mail server, every CDN, every hosted service.

### Basic DNS Queries

```bash
# Standard A record (hostname to IP)
dig targetcompany.com A

# Mail servers
dig targetcompany.com MX

# Name servers (DNS infrastructure)
dig targetcompany.com NS

# SPF records (reveals email infrastructure and third-party senders)
dig targetcompany.com TXT

# Zone transfer (often blocked, but worth trying)
dig @ns1.targetcompany.com targetcompany.com AXFR

# Reverse DNS (IP to hostname)
dig -x 203.0.113.50

# nslookup alternative
nslookup -type=MX targetcompany.com
```

**Windows equivalents using nslookup (no install needed):**

```powershell
# A record
nslookup targetcompany.com

# MX records (mail servers)
nslookup -type=MX targetcompany.com

# NS records (nameservers)
nslookup -type=NS targetcompany.com

# TXT records (SPF, DKIM, verification tokens)
nslookup -type=TXT targetcompany.com

# Zone transfer attempt
nslookup
  server ns1.targetcompany.com
  set type=AXFR
  targetcompany.com

# Reverse DNS (PTR record)
nslookup 203.0.113.50
```

#### Expected Output

**`nslookup -type=MX targetcompany.com` success looks like:**
```
Server:  UnKnown
Address:  192.168.1.1

Non-authoritative answer:
targetcompany.com       MX preference = 10, mail exchanger = mail.targetcompany.com
targetcompany.com       MX preference = 20, mail exchanger = mail2.targetcompany.com
```

**Failure looks like:**
```
*** UnKnown can't find targetcompany.com: Non-existent domain
```
Means: domain doesn't exist. Check spelling.

```
*** UnKnown can't find targetcompany.com: No response from server
```
Means: DNS server timeout. Try specifying a public DNS: `nslookup -type=MX targetcompany.com 8.8.8.8`

### Zone Transfer

A DNS zone transfer is a mechanism for DNS servers to replicate
their records to secondary servers. If misconfigured, ANY host
can request the full zone and receive every DNS record in one
query.

```bash
# Attempt zone transfer against each nameserver
dig @ns1.targetcompany.com targetcompany.com AXFR
dig @ns2.targetcompany.com targetcompany.com AXFR

# If successful, you receive EVERY DNS record:
# All subdomains, all IPs, all mail servers, all internal hostnames
# This is essentially the full infrastructure map in one query
```

**Windows zone transfer attempt:**

```powershell
# In PowerShell, use nslookup interactive mode:
nslookup
  server ns1.targetcompany.com
  set type=AXFR
  targetcompany.com
  exit

# Or use Resolve-DnsName (PowerShell built-in):
Resolve-DnsName -Name targetcompany.com -Type AXFR -Server ns1.targetcompany.com
```

#### Expected Output

**Zone transfer success (misconfigured server) looks like:**
```
; <<>> DiG 9.11.x <<>> @ns1.targetcompany.com targetcompany.com AXFR
targetcompany.com.         3600  IN  SOA   ns1.targetcompany.com. ...
targetcompany.com.         3600  IN  NS    ns1.targetcompany.com.
mail.targetcompany.com.    3600  IN  A     203.0.113.51
vpn.targetcompany.com.     3600  IN  A     203.0.113.52
dev.targetcompany.com.     3600  IN  A     203.0.113.55
```
That's gold — entire infrastructure in one query.

**Failure looks like (correctly configured server):**
```
; Transfer failed.
targetcompany.com: Transfer not allowed
```
Means: zone transfer is blocked (correct behaviour on their end).
Still worth trying every nameserver — misconfigurations happen.

Most organisations block zone transfers. But "most" is not "all".
Always try. The information is worth the 2 seconds it takes.

### Subdomain Enumeration

Subdomains are separately targetable attack surfaces. mail.,
vpn., dev., staging., api., admin. — each one is a potential
entry point with its own software, patch level, and security
posture.

**Brute force enumeration:**

```bash
# dnsenum — combines DNS brute force and zone transfer attempts
# WINDOWS: use WSL2
dnsenum targetcompany.com

# dnsrecon — comprehensive DNS recon
# WINDOWS: pip install dnsrecon
dnsrecon -d targetcompany.com -t brt -D /usr/share/wordlists/dnsmap.txt

# gobuster DNS mode
# WINDOWS: download gobuster.exe (see Windows Setup)
gobuster dns -d targetcompany.com -w subdomains-top1million-5000.txt

# amass — aggressive subdomain discovery
# WINDOWS: download amass.exe (see Windows Setup)
amass enum -d targetcompany.com

# subfinder — passive subdomain discovery from certificate logs
# WINDOWS: download subfinder.exe (see Windows Setup)
subfinder -d targetcompany.com -all
```

**Windows wordlists** — gobuster and dnsrecon need a wordlist.
SecLists is the go-to collection:
```powershell
# Clone SecLists to your machine (it's large — pick what you need)
git clone https://github.com/danielmiessler/SecLists.git C:\Tools\SecLists

# The subdomain wordlist you'll use most:
# C:\Tools\SecLists\Discovery\DNS\subdomains-top1million-5000.txt

# gobuster with Windows paths:
gobuster dns -d targetcompany.com -w C:\Tools\SecLists\Discovery\DNS\subdomains-top1million-5000.txt
```

#### Expected Output

**`subfinder -d targetcompany.com` success looks like:**
```
               __    _____           __
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/

                projectdiscovery.io

[INF] Loading provider config from /home/user/.config/subfinder/provider-config.yaml
[INF] Enumerating subdomains for targetcompany.com

www.targetcompany.com
mail.targetcompany.com
vpn.targetcompany.com
dev.targetcompany.com
api.targetcompany.com
staging.targetcompany.com

[INF] Found 6 subdomains for targetcompany.com in 12 seconds 3 milliseconds
```

**Failure looks like:**
```
[INF] Found 0 subdomains for targetcompany.com in 5 seconds
```
Means: either no passive data exists for that domain, or you
haven't configured API keys for the passive sources. Add keys
to `C:\Users\YourUser\.config\subfinder\provider-config.yaml`
for Shodan, SecurityTrails, etc. to get more results.

**Certificate Transparency logs:**

Every SSL certificate issued is logged in public Certificate
Transparency (CT) logs. Search these and you get every subdomain
that has ever had a certificate — including dev, staging, and
internal subdomains accidentally issued public certs.

```
# crt.sh — search CT logs
https://crt.sh/?q=%.targetcompany.com

# From command line (Windows PowerShell)
# curl is built into Windows 11 but no jq — use this instead:
```

```powershell
# Query crt.sh from PowerShell and parse results
$domain = "targetcompany.com"
$results = Invoke-RestMethod -Uri "https://crt.sh/?q=%25.$domain&output=json"
$results | Select-Object -ExpandProperty name_value | Sort-Object -Unique

# This often reveals subdomains you can't find by brute force:
# staging.targetcompany.com
# dev.internal.targetcompany.com
# vpn.targetcompany.com
```

#### Expected Output

**crt.sh PowerShell query success looks like:**
```
api.targetcompany.com
dev.targetcompany.com
mail.targetcompany.com
staging.targetcompany.com
vpn.targetcompany.com
www.targetcompany.com
```

**Failure looks like:**
```
Invoke-RestMethod : The remote name could not be resolved: 'crt.sh'
```
Means: DNS issue on your end. Try `nslookup crt.sh` — if that fails,
check your internet connection.

---

## Section 3 — Technology Fingerprinting

Knowing what software a target runs at what version is the
bridge between recon and exploitation. A running service is
just a process. A service at a specific version with a known
CVE is a target.

### Web Technology Fingerprinting (Passive)

```bash
# Wappalyzer — browser extension, passive fingerprinting
# WINDOWS: Add to Chrome/Firefox (see Windows Setup)
# Just browse the site while installed and it identifies:
# CMS, frameworks, CDN, analytics, server software

# builtwith.com — API-driven tech detection
curl "https://api.builtwith.com/free1/api.json?KEY=free&LOOKUP=targetcompany.com"

# whatweb — active web fingerprinting from CLI
# WINDOWS: WSL2 required
whatweb targetcompany.com
whatweb -a 3 targetcompany.com  # aggressive mode

# wafw00f — WAF detection
# WINDOWS: pip install wafw00f (runs natively)
wafw00f targetcompany.com

# Manually check response headers
# WINDOWS: curl is built into Windows 11
curl -I https://targetcompany.com
# Look for: Server:, X-Powered-By:, X-Generator:, X-CMS:
```

**Windows native header inspection:**

```powershell
# PowerShell — fetch headers only (equivalent to curl -I)
$response = Invoke-WebRequest -Uri "https://targetcompany.com" -Method HEAD
$response.Headers

# Or more targeted — just the interesting ones:
$response = Invoke-WebRequest -Uri "https://targetcompany.com" -Method HEAD
$response.Headers["Server"]
$response.Headers["X-Powered-By"]
$response.Headers["X-Generator"]
```

#### Expected Output

**`curl -I https://targetcompany.com` success looks like:**
```
HTTP/2 200
server: Apache/2.4.41 (Ubuntu)
x-powered-by: PHP/7.4.21
content-type: text/html; charset=UTF-8
x-frame-options: SAMEORIGIN
```
Read those headers: Apache 2.4.41 on Ubuntu, PHP 7.4.21.
Now search NVD: `https://nvd.nist.gov/vuln/search/results?query=Apache+2.4.41`

**`wafw00f targetcompany.com` success looks like:**
```
[*] Checking https://targetcompany.com
[+] The site https://targetcompany.com is behind Cloudflare (Cloudflare Inc.) WAF.
```
Or if no WAF:
```
[~] No WAF detected by the generic detection
```

Response headers give you away for free. A header of
`X-Powered-By: PHP/7.4.21` tells you the PHP version.
`Server: Apache/2.4.41 (Ubuntu)` tells you the web server
and OS. These are fingerprints that don't require any additional
scanning.

---

## Section 4 — Active Recon

Active recon means touching the target. From this point, every
action is potentially logged. Calibrate your noise level against
your operational requirements.

### Nmap: The Standard Port Scanner

Nmap is the tool. Learn every flag. Know what traffic patterns
each scan type produces. Know which flags are loud and which
are quiet.

```bash
# Basic TCP SYN scan (requires root/admin)
nmap -sS 203.0.113.0/24

# SYN scan with service version detection and OS fingerprint
nmap -sS -sV -O 203.0.113.50

# All ports (slow but thorough)
nmap -p- 203.0.113.50

# Fast scan — top 1000 ports
nmap -F 203.0.113.50

# Stealth: slow scan with decoys (reduces detection probability)
nmap -sS -T1 --randomize-hosts --data-length 25 203.0.113.50

# Aggressive (loud, fast, comprehensive — not for stealth ops)
nmap -A -T4 203.0.113.50

# UDP scan (slow but reveals non-TCP services: SNMP, DNS, TFTP)
nmap -sU --top-ports 200 203.0.113.50

# Script scan — run NSE scripts against open ports
nmap -sV --script=default 203.0.113.50

# Specific script categories
nmap --script=vuln 203.0.113.50      # vulnerability detection (loud)
nmap --script=safe 203.0.113.50     # safe info-gathering scripts
nmap --script=discovery 203.0.113.50 # discovery-oriented scripts

# Output to all formats simultaneously
nmap -oA target_scan 203.0.113.50
# Creates .nmap (human-readable), .xml, .gnmap
```

**Windows notes for nmap:**

```powershell
# On Windows, SYN scan (-sS) requires admin rights (Npcap needs it).
# Run PowerShell as Administrator, then:
nmap -sS 203.0.113.50

# If you can't run as admin, use TCP connect scan instead (-sT):
# Slightly louder (completes full TCP handshake), but no admin needed.
nmap -sT 203.0.113.50

# Windows path for nmap output files — use a known directory:
nmap -oA C:\Tools\scans\target_scan 203.0.113.50

# View .nmap file after:
Get-Content C:\Tools\scans\target_scan.nmap
```

#### Expected Output

**`nmap -sV 203.0.113.50` success looks like:**
```
Starting Nmap 7.95 ( https://nmap.org ) at 2024-01-15 14:22 AEST
Nmap scan report for targetcompany.com (203.0.113.50)
Host is up (0.042s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
```

**Failure looks like:**
```
Nmap scan report for 203.0.113.50
Host is up (0.042s latency).
All 1000 scanned ports on 203.0.113.50 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)
```
Means: firewall is eating your probes. Try `-Pn` to skip host
discovery: `nmap -sV -Pn 203.0.113.50`

```
Failed to open device eth0
```
Means: SYN scan without admin rights. Either run PowerShell as
Administrator, or switch to TCP connect scan with `-sT`.

### Reading Nmap Output

```
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open     http       Apache httpd 2.4.41
443/tcp  open     ssl/https  Apache httpd 2.4.41
3306/tcp filtered mysql
8080/tcp closed   http-alt

INTERPRETING:
open     → port is accepting connections
closed   → port reachable but nothing listening
filtered → firewall/filter blocking the probe (service may exist)

SERVICE  → nmap's best guess from port number
VERSION  → actual banner-grabbed or probe-response version

ACTION:
22 OpenSSH 8.2p1 → look up CVEs for this version
80/443 Apache 2.4.41 → check for Apache CVEs at this version
3306 filtered → MySQL probably exists but firewalled
               → try from inside if you get access
```

### Masscan: Fast Large-Scale Scanning

Masscan can scan the entire internet in under 6 minutes. For
scanning entire IP ranges, it's faster than nmap by orders of
magnitude. Use it for discovery, then nmap for detail.

```bash
# Scan a range for specific ports
masscan 203.0.113.0/24 -p80,443,22,3389 --rate=10000

# Scan a large range fast
masscan 203.0.0.0/8 -p80 --rate=100000

# Output to file
masscan 203.0.113.0/24 -p80,443 -oX masscan_out.xml

# Typical workflow: masscan for discovery, nmap for detail
masscan 203.0.113.0/24 -p- --rate=10000 -oL live_hosts.txt
# then for each live host:
nmap -sV -sC -p <ports_found> <ip>
```

**Windows: masscan requires WSL2.** Run these inside WSL2 Ubuntu:

```bash
# Open WSL2 (search "Ubuntu" in Start Menu or run: wsl)
# Inside WSL2, masscan needs sudo:
sudo masscan 203.0.113.0/24 -p80,443,22,3389 --rate=10000

# Save output to a Windows-accessible path (WSL2 mounts Windows drives at /mnt/):
sudo masscan 203.0.113.0/24 -p80,443 -oX /mnt/c/Tools/scans/masscan_out.xml

# The file will then be at C:\Tools\scans\masscan_out.xml on Windows
```

#### Expected Output

**`masscan 203.0.113.0/24 -p80,443 --rate=1000` success looks like:**
```
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2024-01-15 05:22:13 GMT
Initiating SYN Stealth Scan
Scanning 256 hosts [2 ports/host]
Discovered open port 443/tcp on 203.0.113.50
Discovered open port 80/tcp on 203.0.113.50
Discovered open port 443/tcp on 203.0.113.51
```

**Failure looks like:**
```
FAIL: failed to detect a network interface
```
Means: masscan can't find a network interface in WSL2. Add
`--interface eth0` or run `ip link` inside WSL2 to find
the correct interface name, then specify it.

```
FAIL: socket(AF_INET, SOCK_RAW, 6): Operation not permitted
```
Means: forgot `sudo`. Masscan needs raw socket access.

### Banner Grabbing

Banner grabbing is connecting to a service and reading what it
announces about itself. Servers are often very talkative.

```bash
# netcat manual banner grab
nc targetcompany.com 22
nc targetcompany.com 80

# HTTP banner grab
curl -I https://targetcompany.com

# Telnet-style banner grab for raw TCP services
echo "" | nc -w 2 203.0.113.50 25

# automated banner grabbing with nmap
nmap -sV --version-intensity 9 203.0.113.50

# grab banners from a list of hosts/ports
nmap -iL targets.txt -sV -oA banners

# SMTP banner grab (often very verbose)
nc targetcompany.com 25
# Response: "220 mail.targetcompany.com ESMTP Postfix (Ubuntu)"
# → Reveals mail server software, version, and hostname
```

**Windows banner grabbing — netcat alternatives:**

```powershell
# Windows doesn't ship with nc (netcat). Options:

# Option A: Use ncat (installed with nmap on Windows):
ncat targetcompany.com 22
ncat targetcompany.com 25

# Option B: PowerShell TCP client for raw banner grab:
$tcp = New-Object System.Net.Sockets.TcpClient("targetcompany.com", 22)
$stream = $tcp.GetStream()
$buffer = New-Object byte[] 1024
$read = $stream.Read($buffer, 0, 1024)
[System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
$tcp.Close()
# Expected: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

# Option C: curl for HTTP banners (built into Windows 11):
curl -I https://targetcompany.com

# Option D: masscan via WSL2 with banner grabbing:
sudo masscan 203.0.113.50 -p22,25,80 --banners --rate=100
```

#### Expected Output

**`ncat targetcompany.com 22` success looks like:**
```
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```
That's the SSH version string. Now look up CVEs for `OpenSSH 8.2p1`.

**`ncat targetcompany.com 25` success looks like:**
```
220 mail.targetcompany.com ESMTP Postfix (Ubuntu)
```
Mail server, software (Postfix), and hostname revealed in one line.

**Failure looks like:**
```
Ncat: Connection refused.
```
Means: nothing listening on that port, or firewall is blocking.

```
Ncat: Connection timed out.
```
Means: firewall is silently dropping your packets (filtered state).

---

## Section 5 — Attack Surface Mapping

All the recon data you've collected is raw material. The output
of this phase is an attack surface map: a structured inventory of
every entry point, ranked by exploitability.

### The Attack Surface Map Structure

```
TARGET: targetcompany.com
DATE: 2024-01-15

DOMAINS & SUBDOMAINS
──────────────────────────────────────────────
targetcompany.com           → 203.0.113.50 (Apache 2.4.41)
www.targetcompany.com       → 203.0.113.50 (same host)
mail.targetcompany.com      → 203.0.113.51 (Postfix 3.4.13)
vpn.targetcompany.com       → 203.0.113.52 (OpenVPN 2.4.7)
dev.targetcompany.com       → 203.0.113.55 (Apache 2.2.34) ← OUTDATED
api.targetcompany.com       → 203.0.113.56 (nginx 1.18.0)
staging.targetcompany.com   → 203.0.113.57 (Apache 2.4.41) ← NO WAF

NETWORK SERVICES
──────────────────────────────────────────────
203.0.113.50   22/tcp OpenSSH 8.2p1
               80/tcp Apache 2.4.41 (redirect to 443)
               443/tcp Apache 2.4.41 + mod_ssl + WordPress 5.8.2
203.0.113.51   25/tcp Postfix 3.4.13
               587/tcp Postfix (STARTTLS)
               993/tcp Dovecot
203.0.113.52   1194/udp OpenVPN
203.0.113.55   22/tcp OpenSSH 7.9p1 (OLDER VERSION)
               80/tcp Apache 2.2.34 (EOL — multiple known CVEs)
203.0.113.56   443/tcp nginx 1.18.0
               8443/tcp nginx (API)

TECHNOLOGY STACK
──────────────────────────────────────────────
CMS: WordPress 5.8.2 (check CVE, check plugins)
PHP: 7.4.21 (X-Powered-By header)
DB: MySQL (port 3306 filtered externally)
Email: Google Workspace (MX records → google.com)
CDN: Cloudflare (main site)
WAF: Cloudflare WAF (main site) — staging has NO WAF

PRIORITY TARGETS (RANKED)
──────────────────────────────────────────────
1. dev.targetcompany.com — Apache 2.2.34 (EOL), no WAF, older SSH
   → Multiple public CVEs for Apache 2.2.x
   → Likely less-maintained than production
   
2. staging.targetcompany.com — Same software as prod but no WAF
   → Better testbed for web application attacks
   → May share credentials with production
   
3. WordPress on main site — version 5.8.2, check plugin CVEs
   → wpscan for plugin enumeration
   
4. VPN endpoint — OpenVPN 2.4.7, potential credential attack vector
   → LinkedIn reveals employee names for credential stuffing
```

This map guides every subsequent phase. You know where the targets
are, what version they run, and which ones are highest priority.

---

## Section 6 — OPSEC During Recon

Recon creates traces. Know what traces each activity creates and
mitigate accordingly.

### Passive Recon OPSEC

Passive recon is inherently low-risk but not zero-risk:

**Search engines**: your queries are logged by the provider.
Google knows you searched for `site:targetcompany.com filetype:sql`
at your IP address. This matters in a legal context, not an
operational one (the target can't see this). Use non-tracking
search engines (DuckDuckGo, Startpage) if the provider logging
concerns you.

**WHOIS lookups**: some registrars log queries and can be
subpoenaed. Use web-based WHOIS services through Tor or a VPN
if attribution is a concern.

**Shodan/Censys**: your searches are logged to your account.
Create a research account that doesn't link to your real identity.
Use an email address and payment method that don't identify you.

**LinkedIn**: LinkedIn shows companies a list of who viewed
their profiles and employees. A research firm with a LinkedIn
profile viewing 50 employees of a target company is detectable.
Use a generic profile or a LinkedIn account not associated with
your identity. Better: use Google-cached LinkedIn data and
intelligence aggregators rather than direct profile views.

### Active Recon OPSEC

Active recon IS detectable. The question is how much.

**Source IP management:**

```
LOUDEST (most attributable)
  Scan from your own IP → logs trace directly to you

BETTER
  Scan from a VPS → logs trace to the VPS provider
  → VPS providers get subpoenas but add a step

BETTER STILL
  Chain through multiple VPSes in different jurisdictions
  → Attribution requires legal process in multiple countries

MOST CAREFUL
  Route through Tor exit nodes
  → Tor is extremely slow for port scans
  → Combine with proxy chains for scanning
  → masscan doesn't support Tor — use nmap via proxychains
```

**Noise level calibration:**

```bash
# Loud (T4-T5) — fast, lots of packets, triggers IDS/IPS
nmap -T4 -A targetcompany.com

# Moderate (T3 default) — reasonable speed, detectable but not aggressive
nmap -sS -sV targetcompany.com

# Quiet (T1-T2) — extremely slow, mimics normal traffic patterns
nmap -T1 --scan-delay 5s targetcompany.com

# Custom timing — control packets per second manually
nmap --max-rate 10 targetcompany.com     # 10 packets per second
masscan --rate 5 203.0.113.0/24          # 5 packets per second
```

**Decoy scanning:**

```bash
# Make scan appear to come from multiple sources
# -D flag: list decoy IPs separated by commas, ME = your real IP
nmap -D 198.51.100.1,198.51.100.2,ME targetcompany.com
# IDS sees packets from 3 sources simultaneously — harder to isolate real attacker
```

**Timing your scans:**

Active scans during business hours blend with legitimate traffic.
Scans at 3am stand out against a quiet baseline. Know the target's
time zone and activity patterns. Schedule accordingly.

**What to avoid:**

```
DON'T scan from the same IP across multiple operations.
DON'T use your personal internet connection for active recon.
DON'T leave scan artifacts (nmap output files) on shared infrastructure.
DON'T log into target-facing services from operational infrastructure
  (your scan VPS should NEVER authenticate to the target).
DON'T reuse tool signatures — default nmap probes have
  known fingerprints. Customise.
```

---

## Reconnaissance Workflow: End To End

This is the complete operational sequence. Execute in order.

```
PHASE 1: PASSIVE RECON (zero risk)
─────────────────────────────────────────────
□ WHOIS — domain registration, registrar, admin contact
□ DNS — A, MX, NS, TXT, attempt zone transfer
□ Shodan/Censys — exposed services, banners, SSL certs
□ Google dorks — leaked files, directory listings, login pages
□ GitHub dorking — leaked credentials, internal config
□ Certificate Transparency — full subdomain list via crt.sh
□ theHarvester — email addresses, subdomains
□ LinkedIn — org chart, tech stack, employee names
□ Job postings — technology stack, vendor names
□ SecurityTrails/DomainTools — DNS history, WHOIS history

PHASE 2: INTELLIGENCE SYNTHESIS
─────────────────────────────────────────────
□ Compile all IP ranges and CIDR blocks
□ List all confirmed subdomains
□ List all services with version numbers
□ Identify highest-priority targets
□ Note any immediately exploitable findings
   (default creds, exposed admin panels, version CVEs)

PHASE 3: ACTIVE RECON (detectable)
─────────────────────────────────────────────
□ masscan — rapid port discovery across IP ranges
□ nmap -sV — service version on confirmed live hosts
□ Banner grabbing — detailed service identification
□ Web technology fingerprinting (whatweb, wafw00f)
□ Directory enumeration on web targets (gobuster, feroxbuster)
□ WordPress/CMS scanning if applicable (wpscan)
□ Subdomain brute force to supplement passive data

PHASE 4: ATTACK SURFACE MAP
─────────────────────────────────────────────
□ Structured inventory: all hosts, all ports, all services, all versions
□ Priority ranking by exploitability
□ CVE lookup for each identified version
□ Chain identification: what sequences lead to the objective?
□ Hand off to Phase 3 of kill chain: Weaponisation
```

---

## DEFENDER TAKEAWAY

You just learned how attackers map your organisation before touching a single
system. Here's what to do on Monday morning to make that map harder to build
and faster to detect.

- **Audit your public DNS records.** Run `nslookup -type=ANY yourdomain.com`
  and crt.sh against your own domain. Every subdomain an attacker finds,
  you should have found first. Dev, staging, and internal subdomains with
  public certs are the ones that get orgs compromised — get them off public
  DNS or behind a VPN.

- **Block zone transfers from unauthorised hosts.** Check your DNS server
  config (Windows DNS Server: DNS Manager → right-click zone → Properties
  → Zone Transfers → allow only to specific secondary DNS IPs).
  Misconfigured zone transfers hand attackers your full infrastructure map
  for free. Event ID 6009 in DNS Server logs indicates a zone transfer.

- **Search your own org on Shodan.** Log into shodan.io, search
  `org:"Your Company Name"` and `hostname:yourdomain.com`. Everything
  it returns is publicly visible to any attacker. Exposed RDP (port 3389),
  management interfaces, and dev boxes with no auth are immediate priorities
  to firewall or shut down.

- **Hunt your own GitHub.** Run truffleHog against every public repo your
  org owns: `trufflehog github --org=yourcompany`. Also search GitHub for
  `"yourcompany.com" extension:env` and `"yourcompany.com" filename:.env`.
  If anything comes back with credentials, rotate those secrets immediately
  and assume compromise. Then set up GitHub secret scanning alerts in your
  org settings (free for public repos).

- **Suppress version banners on internet-facing services.** Web servers
  advertising `Server: Apache/2.4.41` or `X-Powered-By: PHP/7.4.21` hand
  attackers their CVE shortlist. On Apache: `ServerTokens Prod` and
  `ServerSignature Off` in httpd.conf. On nginx: `server_tokens off` in
  nginx.conf. On IIS (Windows): HTTP Response Headers → remove Server header
  in IIS Manager, or use URLScan.

- **Enable Windows DNS Debug Logging to catch recon.** In DNS Manager →
  right-click server → Properties → Debug Logging tab → enable logging.
  A sudden spike in PTR (reverse DNS) queries or ANY-type queries from a
  single external IP is a recon indicator. Event ID 4 in DNS Debug log
  captures zone transfer attempts.

- **Check job postings before they go live.** Before posting a role that
  names your tech stack ("CrowdStrike experience required", "Palo Alto
  NGFW management"), strip specific product names. Replace with generic
  descriptions ("enterprise EDR", "next-gen firewall"). Attackers read
  your job board to build their tooling list.

- **Monitor for port scan activity at your firewall.** Windows Firewall with
  Advanced Security logs blocked inbound connections (enable via: `wf.msc`
  → Properties → Domain/Private/Public Profile → Logging → Log dropped
  packets). Event ID 5152 (firewall blocked packet) in bulk from a single
  external IP over a short period is a scan. Correlate with Event ID 5156
  (allowed connection) to see what got through.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **OSINT** | Open Source Intelligence — intelligence gathered from publicly available sources with no direct target interaction |
| **Passive recon** | Intelligence gathering that does not interact with target systems — zero detection risk |
| **Active recon** | Intelligence gathering via direct interaction with target systems — detectable |
| **WHOIS** | Domain registration records including registrar, dates, and contact information |
| **Shodan** | Search engine for internet-exposed devices and services; indexes banners and service metadata |
| **Google dork** | A targeted Google search query using operators to find specific types of exposed content |
| **Certificate Transparency** | Public logs of all SSL certificates issued; reveals subdomains that have had certificates |
| **Zone transfer** | DNS mechanism that, when misconfigured, reveals all DNS records to any requester |
| **Banner grabbing** | Connecting to a service and reading its self-identification string to determine software and version |
| **Attack surface map** | Structured inventory of all discovered entry points, ranked by exploitability |
| **Subdomain enumeration** | Discovery of all subdomains of a target domain via brute force, CT logs, and passive sources |
| **theHarvester** | OSINT tool for email, subdomain, and hostname enumeration across multiple sources |
| **Masscan** | Asynchronous port scanner capable of scanning large ranges rapidly |
| **Fingerprinting** | Identifying the specific software and version running on a service |
| **Nmap NSE** | Nmap Scripting Engine — Lua scripts that extend nmap's capability to include vulnerability detection and service-specific probing |
| **truffleHog** | Tool that scans git repository history for secrets, credentials, and sensitive strings |
| **gitleaks** | Fast secret scanner for git repositories; replacement for deprecated gitrob |
| **WSL2** | Windows Subsystem for Linux v2 — runs a real Linux kernel inside Windows, required for Linux-native tools |
| **Certificate SAN** | Subject Alternative Name — field in an SSL cert listing all hostnames the cert is valid for; reveals subdomains |
| **wafw00f** | Web application firewall detection tool; identifies WAF vendor from HTTP responses |

---

## Drill 02 — Recon & Footprinting

Go to `DRILLS/02_recon_footprinting/`. A target domain and scope
document are provided. All activity must stay within scope.

Your mission:

1. Complete a full passive recon cycle on the provided target.
   Use theHarvester, Shodan, crt.sh, and Google dorks. Document
   every finding. Time yourself: complete passive recon within 2 hours.

2. Enumerate all subdomains using at least 3 different methods:
   brute force (gobuster/dnsrecon), certificate transparency (crt.sh),
   passive OSINT (subfinder/amass). Compare results. Identify
   subdomains that only appear in one source.

3. For each unique IP discovered, run nmap with -sV. Record every
   open port and service version.

4. Identify every web technology stack on the in-scope hosts.
   Include web server, CMS, backend language, CDN, and WAF
   detection results.

5. Build the attack surface map in the provided template. Rank
   every target by priority. Justify each ranking.

6. For each top-3 ranked target, find at least one publicly known
   CVE for the identified service version. Link the CVE to the
   target.

7. Write the OPSEC log: for each active recon action you took,
   what trace did it create? Where is that trace stored? How would
   a blue team analyst find it?

---

— 
Intelligence GATHERED before the first packet sent —
silence spells the org chart before the scan begins.
