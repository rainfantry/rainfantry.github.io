# Chapter 16 — Responsible Disclosure: The Warrior's Code

**VADER-RCE Field Manual**
**Prerequisite**: All prior chapters
**Drill**: N/A — this is operational procedure

---

## Why This Chapter Exists

You've spent fifteen chapters learning to find and exploit memory corruption
vulnerabilities in one of the most privileged attack surfaces on Windows.
You can crash parsers. You can triage crashes. You can turn a corrupted heap
into a redirected function pointer. You understand the target at the binary
level.

None of that matters if you handle the output wrong.

A vulnerability is a weapon. The moment you confirm a crash is exploitable,
you're holding something that could compromise millions of machines. What
you do next — in the hours and days after discovery — defines whether
you're a security researcher or a criminal. There is no middle ground.

This chapter isn't theory. It's operational procedure. The disclosure
lifecycle from discovery to CVE credit, the exact steps for submitting to
MSRC and MITRE, the evidence standards that get your report taken seriously,
and the ethical framework that keeps you on the right side of the line.

Read it. Internalize it. Because the skills you've built are genuinely
dangerous, and the only thing separating you from a prison sentence is
how you choose to use them.

---

## The Disclosure Spectrum

Not everyone who finds vulnerabilities handles them the same way. The
security community has debated disclosure models for thirty years. Here's
the landscape, so you understand where each approach sits and why we
choose the one we do.

### Full Disclosure

Publish everything immediately. The bug, the PoC, the exploit, the
affected versions — drop it all on a mailing list and let the world
deal with it.

This was the dominant model in the late 1990s and early 2000s.
Bugtraq and Full-Disclosure mailing lists were ground zero. The philosophy:
vendors won't fix bugs they can pretend don't exist. Public pressure
forces patches.

The problem: attackers read mailing lists too. The window between
publication and patch deployment is when millions of systems are
vulnerable AND the exploit is public. Full disclosure creates that
window deliberately.

It's mostly dead now as a primary approach. Some researchers still
use it as a nuclear option when vendors are unresponsive (more on
that later), but it's no longer the default.

### Responsible / Coordinated Disclosure

Report the vulnerability privately to the vendor. Give them a reasonable
window (typically 90 days) to develop, test, and ship a patch. After
the patch is available — or after the deadline expires — publish your
research.

This is the industry standard. Google Project Zero formalized the
90-day deadline in 2014 and enforces it ruthlessly. Microsoft, Apple,
Google, and every major vendor has a security response team built
around this model.

The key tension: the vendor wants infinite time. The researcher wants
the bug fixed NOW. The 90-day deadline is a compromise — enough time
for a legitimate engineering effort, not so much that the vendor can
deprioritize indefinitely.

Variants:
- **90-day hard deadline**: publish after 90 days regardless. Google P0's
  approach. No extensions except extraordinary circumstances.
- **90+14 grace period**: if the vendor communicates that a patch is
  imminent (within 14 days of deadline), extend once. Common courtesy.
- **Vendor-negotiated timeline**: researcher and vendor agree on a
  custom timeline. More flexible but risks indefinite delays.

### No Disclosure (Gray Market)

Sell the vulnerability to a government, intelligence agency, or
exploit broker. Zerodium, NSO Group (Pegasus), and unnamed
nation-state buyers operate in this space. Prices for a Windows
zero-day RCE range from $100,000 to $2,000,000+.

The vulnerability is never published. The vendor never patches it.
The buyer uses it for espionage, surveillance, or offensive operations.
The bug stays alive in the wild for years.

This is legal in most jurisdictions. It is also how authoritarian
governments acquire the tools to surveil journalists, dissidents,
and human rights workers. You need to understand this market exists
so you can make an informed decision to stay out of it.

### Bug Bounty Programs

Vendor-operated programs that pay researchers for vulnerability reports.
Microsoft's Bug Bounty Program, HackerOne, Bugcrowd — structured
platforms where you submit, the vendor triages, and you get paid if
the bug qualifies.

Payouts vary wildly:
- Microsoft Defender: up to $20,000 for RCE
- Windows Hyper-V: up to $250,000 for guest-to-host escape
- Chrome: up to $250,000+ for full chain sandbox escape
- Apple iOS: up to $2,000,000 for zero-click kernel chain

Bug bounties align incentives: the researcher gets paid, the vendor
gets patched, users get protected. It's the most sustainable model.

### Where VADER Sits

Responsible disclosure via MSRC and MITRE. Period.

We are researchers, not mercenaries. We find vulnerabilities to
understand how systems break. We report them so they get fixed.
We publish our methodology so others can learn. We take the CVE
credit because it's permanent proof of capability — a name on
a CVE is worth more than any bounty payment for career purposes.

If a bounty comes with it, great. But the bounty isn't the mission.
The mission is understanding. The disclosure is the duty.

---

## MSRC Submission Process (Step by Step)

The Microsoft Security Response Center is where all Microsoft product
vulnerabilities go. This is the exact process, from account creation
to case resolution.

### Step 1: Create an MSRC Account

Navigate to **msrc.microsoft.com**. Create an account or sign in
with your Microsoft account. Use your real identity — anonymous
submissions get deprioritized and you can't claim CVE credit
without a verifiable name.

Your MSRC profile is your researcher identity for all Microsoft
submissions. One account, all reports.

### Step 2: Navigate to Report a Vulnerability

From the MSRC portal, select **Report a Vulnerability** (also
accessible directly at msrc.microsoft.com/report). You'll be
presented with a submission form.

### Step 3: Required Fields

The form requires:

- **Title**: concise, specific, technical. Good: "Heap buffer overflow
  in mpengine.dll NScript engine via crafted JavaScript in ZIP archive".
  Bad: "Windows Defender bug".

- **Product/Service**: select the affected Microsoft product. For
  Defender, this is "Microsoft Defender Antivirus" or "Windows Security".

- **Version**: specific build numbers. For mpengine.dll: the exact DLL
  version (e.g., 1.1.24010.10). For Windows: the exact OS build
  (e.g., Windows 11 23H2 Build 22631.3085). Get these from
  `winver` and from the DLL properties dialog.

- **Vulnerability Type**: from the dropdown — Remote Code Execution,
  Elevation of Privilege, Information Disclosure, Denial of Service,
  etc. Choose accurately. A heap overflow that gets you code execution
  is RCE, not DoS, even if your PoC only crashes.

- **CVSS Score**: your assessment (they'll recalculate, but providing
  yours shows competence). More on scoring below.

### Step 4: The Evidence Package

This is where most submissions fail. MSRC receives thousands of
reports. The ones that get triaged quickly and taken seriously have
a complete evidence package. Here's what you need.

#### Executive Summary

One paragraph. What the bug is. What it does. Who's affected.

Example:
> A heap buffer overflow exists in mpengine.dll (version 1.1.24010.10)
> in the NScript JavaScript engine. When Microsoft Defender scans a
> ZIP archive containing a crafted .js file with a malformed string
> concatenation sequence, the NScript interpreter allocates a buffer
> based on an unchecked length field and copies data beyond the
> allocation boundary. This overwrites adjacent heap metadata,
> enabling control of execution flow. The vulnerability is triggered
> automatically when Defender's real-time protection scans the file —
> no user interaction required. Exploitation achieves SYSTEM-level
> code execution.

That's 90 words. It tells the engineer everything: where, what,
how, impact.

#### Root Cause Analysis

Exactly what code is broken and why. Reference specific functions,
offsets, and logic errors. If you reversed the target (Ch08), you
can cite the function name and the exact logic flaw.

Example:
> The vulnerability exists in `mpengine!NScript::ParseConcatExpr`
> at offset +0x1A4. The function reads a 32-bit length value from
> the parsed JavaScript AST node, uses it to calculate a buffer
> size via `HeapAlloc(processHeap, 0, length * 2)`, but fails to
> validate that `length * 2` does not wrap on 32-bit multiplication.
> When `length` exceeds 0x80000000, the multiplication wraps to a
> small value. The subsequent `memcpy` copies `length * 2` bytes
> (as a 64-bit size_t) into the undersized buffer, overflowing the
> heap allocation by up to 4GB.

This tells the dev team EXACTLY where to look and what to fix.
They can verify it in minutes. That's what gets your report
fast-tracked.

#### Scope

Which versions are affected. Which configurations trigger it.
What platforms are vulnerable.

Be specific:
> Tested and confirmed on:
> - mpengine.dll 1.1.24010.10 (current as of 2026-01-15)
> - mpengine.dll 1.1.23090.2 (three months prior)
> - Windows 11 23H2 (x64) with Defender real-time protection enabled
> - Windows 10 22H2 (x64) with Defender real-time protection enabled
>
> NOT tested on:
> - Windows Server editions (likely affected, same engine)
> - ARM64 builds (different code generation, may differ)
> - Defender for Endpoint cloud scanning (different execution context)

Don't claim scope you haven't verified. Say what you tested and
what you didn't. Let MSRC determine the full blast radius.

#### Reproduction Steps

Step by step, a developer who has never seen your research can
reproduce the bug in 15 minutes. Assume they have access to
internal symbols and source code (they do), but don't assume they
know anything about your setup.

```
REPRODUCTION STEPS:

Prerequisites:
- Windows 11 23H2 (Build 22631.3085) with Defender real-time 
  protection enabled
- mpengine.dll version 1.1.24010.10 (verify via
  C:\ProgramData\Microsoft\Windows Defender\Definition Updates\
  {GUID}\mpengine.dll → Properties → Details → File version)
- Attached PoC file: trigger.zip (SHA-256: a1b2c3d4...)

Steps:
1. Ensure Defender real-time protection is ON
   (Settings → Privacy & Security → Windows Security → 
   Virus & threat protection → Real-time protection: On)

2. Copy trigger.zip to the Desktop (or any monitored folder)

3. Defender will scan trigger.zip automatically within 1-3 seconds

4. Expected result: MsMpEng.exe crashes. Defender service restarts
   automatically within ~10 seconds.

5. Verify crash:
   - Event Viewer → Windows Logs → Application → 
     Source: Windows Error Reporting
   - Faulting module: mpengine.dll
   - Exception code: 0xC0000005 (Access Violation)

6. If WinDbg is attached to MsMpEng.exe (see evidence package),
   the crash occurs at mpengine!NScript::ParseConcatExpr+0x1F2
   with a corrupted heap state visible via !heap -a
```

Every step. No assumptions. No "obvious" steps omitted.

#### Impact Assessment

What can an attacker actually do with this vulnerability?
Be honest about what you've demonstrated vs. what's theoretically
possible.

```
DEMONSTRATED IMPACT:
- Crash of MsMpEng.exe (Denial of Service)
- Controlled heap corruption (adjacent allocation overwrite)
- Partial control of execution flow via corrupted vtable pointer

THEORETICAL IMPACT (not demonstrated, assessed as feasible):
- Full SYSTEM-level code execution via vtable hijack
- Sandbox escape (MsMpEng.exe runs outside AppContainer)
- Wormable delivery via email attachment (zero-click trigger)

DELIVERY VECTORS:
- Email attachment (zero-click: Defender scans automatically)
- SMB share (zero-click: Defender scans network files)
- Web download (user-initiated download triggers scan)
- USB drive (Defender scans removable media on insert)
```

Separate what you proved from what you theorize. MSRC will do their
own impact assessment, but showing that you understand the full
attack surface demonstrates credibility.

#### Remediation Suggestion

How should they fix it? You've reversed the code. You know where
the bug is. Suggest the fix.

```
SUGGESTED REMEDIATION:

1. Add integer overflow check before HeapAlloc in
   NScript::ParseConcatExpr:
   
   if (length > SIZE_MAX / 2) {
       // reject malformed input
       return NSCRIPT_ERROR_INVALID_LENGTH;
   }
   
2. Additionally, cap the maximum allocation size for NScript
   string operations to a reasonable bound (e.g., 256MB) to
   prevent resource exhaustion even with valid lengths.

3. Consider migrating NScript allocations to a dedicated heap
   with guard pages (HeapCreate with HEAP_CREATE_ENABLE_TRACING)
   to limit overflow impact.
```

You're not dictating the fix. You're showing you understand the
problem deeply enough to suggest one. The engineering team will
implement their own solution, but your suggestion demonstrates
that you're a competent researcher, not just a crash reporter.

---

## Evidence-Grade Documentation

Every artifact you submit must be evidence-grade. That means
timestamped, hashed, reproducible, and defensible. Treat your
submission like a forensic report — because that's how MSRC
evaluates it.

### Screenshots With Timestamps

Every screenshot includes:
- System clock visible in taskbar
- Window title bars showing application and version
- Relevant data highlighted (circle it, arrow it)

Use **Windows Snipping Tool** or **ShareX** with timestamp
overlay enabled. Name screenshots descriptively:
```
01_defender_version_info.png
02_windbg_crash_state.png
03_heap_corruption_detail.png
04_event_viewer_crash_log.png
```

### WinDbg Crash Dumps

Full dump, not minidump. When attached to MsMpEng.exe:

```
.dump /ma C:\evidence\msmpeng_crash_full.dmp
```

The `/ma` flag captures all memory — heap, stack, loaded modules,
handle table. This lets MSRC reproduce the exact crash state
without running your PoC.

Also capture the WinDbg output log:

```
.logopen C:\evidence\windbg_session.log
```

Run at minimum:
```
!analyze -v
!heap -a
!exploitable
kb
lm vm mpengine
.exr -1
.cxr
```

Save the entire session log. It's your chain of evidence for the
crash analysis.

### PoC File

The PoC must be MINIMAL. It triggers the bug and nothing else.
No payload. No shellcode. No proof-of-concept exploit. Just the
trigger.

Why minimal? Two reasons:
1. MSRC needs to trust your file. A PoC with embedded shellcode
   looks like malware, not research.
2. The PoC proves the vulnerability exists. The exploit proves
   you can use it offensively. MSRC only needs proof of (1).

Structure your PoC:
```
trigger.zip
├── README.txt          (what this is, how to use it)
├── trigger.js          (the malformed JavaScript)
└── build_trigger.py    (script that generates trigger.zip)
```

Include the GENERATOR SCRIPT. This shows MSRC exactly how the
malformed input was constructed. It's more valuable than the
trigger file itself because it demonstrates understanding.

### Video Demonstration

Record with OBS Studio. Show:
1. Clean system state (Defender version, OS version)
2. WinDbg attached and waiting
3. PoC file placed in monitored directory
4. Crash occurs
5. WinDbg analysis showing the corruption

Keep it under 5 minutes. No narration needed — the actions
speak for themselves. Export as MP4, 1080p.

### Version Information

Capture EVERYTHING about the environment:

```
ENVIRONMENT SNAPSHOT:

Operating System:
  Windows 11 Pro 23H2 (Build 22631.3085)
  Captured via: winver

Defender Version:
  Antimalware Client: 4.18.23110.3
  Engine: 1.1.24010.10
  Antivirus: 1.403.2134.0
  Antispyware: 1.403.2134.0
  Captured via: Settings → Windows Security → About

mpengine.dll:
  File Version: 1.1.24010.10
  Size: 14,231,552 bytes
  SHA-256: [hash]
  Path: C:\ProgramData\Microsoft\Windows Defender\
        Definition Updates\{GUID}\mpengine.dll

MsMpEng.exe:
  PID at time of crash: 4892
  Parent: services.exe (PID 712)
  Integrity Level: SYSTEM
```

### Control Test

If a patched version exists (rare at time of submission, but
sometimes you're reporting a regression), show:

1. Bug triggers on version X (crash demonstrated)
2. Bug does NOT trigger on version Y (no crash, file scanned normally)

This is gold. It proves the vulnerability is version-specific
and that a fix is possible.

### Hash Everything

SHA-256 hash every file in your submission:

```
ARTIFACT HASHES (SHA-256):

trigger.zip:          a1b2c3d4e5f6...
trigger.js:           f6e5d4c3b2a1...
build_trigger.py:     1a2b3c4d5e6f...
msmpeng_crash.dmp:    6f5e4d3c2b1a...
windbg_session.log:   b1c2d3e4f5a6...
01_defender_version.png: c3d4e5f6a7b8...
02_windbg_crash.png:  d4e5f6a7b8c9...
obs_demo.mp4:         e5f6a7b8c9d0...
```

This proves integrity. If anyone questions whether the evidence
was tampered with after submission, the hashes are your proof.
Generate them with:

```powershell
Get-FileHash -Algorithm SHA256 .\* | Format-Table Hash, Path
```

Or in bash:
```bash
sha256sum *
```

---

## CVSS Scoring

The Common Vulnerability Scoring System is the industry standard
for rating vulnerability severity. Version 3.1 is current.
Understanding CVSS is non-negotiable — every submission requires
a score, and knowing how to calculate one correctly signals
competence.

### The Base Metric Group

Eight metrics. Each has defined values. Together they produce
a score from 0.0 to 10.0.

#### Attack Vector (AV)

How does the attacker reach the vulnerable component?

| Value | Code | Meaning | Example |
|-------|------|---------|---------|
| Network | N | Remotely exploitable, no local access needed | Email attachment scanned by Defender |
| Adjacent | A | Requires same network segment | ARP spoofing attack |
| Local | L | Requires local access to the system | USB drive, local file |
| Physical | P | Requires physical access to hardware | Cold boot attack |

For Defender scanning email attachments: **Network (N)**. The
attacker sends a file, the mail server receives it, Defender
scans it. No local access needed.

#### Attack Complexity (AC)

How reliable is exploitation?

| Value | Code | Meaning |
|-------|------|---------|
| Low | L | Attack works reliably, no special conditions |
| High | H | Requires specific conditions (race, config, heap state) |

If your heap overflow triggers deterministically on every scan:
**Low (L)**. If it requires a specific heap layout that only occurs
10% of the time: **High (H)**. Be honest.

#### Privileges Required (PR)

What access level does the attacker need before exploitation?

| Value | Code | Meaning |
|-------|------|---------|
| None | N | No authentication or access required |
| Low | L | Standard user privileges needed |
| High | H | Administrator/root privileges needed |

Sending an email requires no privileges on the TARGET system:
**None (N)**. The attacker doesn't need an account on the victim's
machine. They just need the ability to send files to it.

#### User Interaction (UI)

Does the victim need to do anything?

| Value | Code | Meaning |
|-------|------|---------|
| None | N | Zero-click. Exploitation is fully automatic |
| Required | R | User must perform an action (open file, click link) |

Defender's real-time protection scans files automatically. If the
file reaches a monitored location (Downloads, temp, email cache),
Defender scans it without any user action: **None (N)**.

This is why Defender RCE is so severe — it's genuinely zero-click
for email and download vectors.

#### Scope (S)

Does exploitation affect resources beyond the vulnerable component?

| Value | Code | Meaning |
|-------|------|---------|
| Unchanged | U | Impact limited to the vulnerable component |
| Changed | C | Impact extends beyond (sandbox escape, privilege boundary crossed) |

MsMpEng.exe runs as SYSTEM but its scans process content from
user-level contexts. If exploitation gains SYSTEM from a
no-privilege email delivery: **Changed (C)**. The attacker crosses
the privilege boundary from "anonymous remote attacker" to
"SYSTEM on the victim's machine."

#### Confidentiality Impact (C)

| Value | Code | Meaning |
|-------|------|---------|
| None | N | No confidentiality impact |
| Low | L | Some information disclosed |
| High | H | Complete information disclosure possible |

SYSTEM access means access to everything on the machine: **High (H)**.

#### Integrity Impact (I)

| Value | Code | Meaning |
|-------|------|---------|
| None | N | No integrity impact |
| Low | L | Some data can be modified |
| High | H | Complete system modification possible |

SYSTEM access means arbitrary write to everything: **High (H)**.

#### Availability Impact (A)

| Value | Code | Meaning |
|-------|------|---------|
| None | N | No availability impact |
| Low | L | Degraded performance |
| High | H | Complete denial of service |

SYSTEM code execution means the attacker can do anything,
including nuking the system: **High (H)**.

### Calculating the Score

The CVSS vector string concatenates all values:

```
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

Plug this into the CVSS 3.1 calculator at
**first.org/cvss/calculator/3.1**

That specific vector scores **10.0** — the maximum possible.

A zero-click, network-delivered, no-privileges-required, scope-changing
RCE with full CIA impact is literally the worst-case scenario
in vulnerability scoring. This is what a Defender mpengine.dll
RCE would score if it worked as described.

### Realistic Scoring for Your Work

Be honest. If your PoC only demonstrates a crash (DoS), the
impact metrics should reflect that:

```
Crash only (DoS): AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5
```

If you've demonstrated heap corruption but not code execution:

```
Controlled corruption: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H = 8.2
```

If you've demonstrated full RCE:

```
Full RCE: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
```

Don't overscore. MSRC will rescore it anyway. If you claim 10.0
and your PoC only crashes the process, you lose credibility.
Score what you've PROVEN, note what's THEORETICALLY possible.

---

## MITRE CVE Process (For Non-Microsoft Vendors)

Not everything you find will be a Microsoft product. If you
discover vulnerabilities in third-party software, open-source
libraries, or non-Microsoft platforms, the CVE assignment goes
through MITRE (or the relevant CNA).

### When to Use MITRE vs. MSRC

Simple rule:
- **Microsoft products** (Windows, Office, Defender, Azure, Edge,
  .NET, SQL Server, etc.) → **MSRC** (msrc.microsoft.com)
- **Everything else** → **MITRE** or the product's designated CNA

MSRC is itself a CNA (CVE Numbering Authority) for Microsoft
products. They assign CVE numbers directly. For non-Microsoft
products, you go through MITRE's central process.

### CVE Numbering Authorities (CNAs)

A CNA is an organization authorized to assign CVE identifiers
within a specific scope. As of 2026, there are 300+ CNAs:

- **Microsoft** (MSRC): all Microsoft products
- **Google**: Chrome, Android, Google Cloud
- **Apple**: iOS, macOS, all Apple products
- **Red Hat**: RHEL, Fedora, OpenShift
- **MITRE**: everything not covered by a specific CNA (root CNA)

Check **cve.org/PartnerInformation/ListofPartners** to find the
CNA for your target product. If no specific CNA exists, MITRE
handles it.

### MITRE Submission Process

1. **Navigate to cveform.mitre.org** (or the CVE Services API)

2. **Required information:**
   - **Vulnerability type**: CWE identifier if possible
     (e.g., CWE-122: Heap-based Buffer Overflow)
   - **Vendor**: who makes the affected product
   - **Product**: name and version(s)
   - **Version**: affected version range (e.g., "< 3.2.1")
   - **Description**: technical description of the vulnerability
   - **Impact**: what an attacker can achieve
   - **References**: links to your advisory, vendor advisory, patches

3. **Submit and wait**: MITRE reviews, confirms the vulnerability
   meets CVE criteria, and assigns a CVE ID (format: CVE-YYYY-NNNNN)

### Timeline

Typical MITRE processing:
- **Acknowledgment**: 1-3 business days
- **Initial review**: 1-2 weeks
- **CVE assignment**: 2-8 weeks after acceptance
- **Publication**: after vendor patch or disclosure deadline

The timeline varies. High-severity issues in widely deployed
software get fast-tracked. Obscure bugs in niche products take
longer.

### What Makes a CVE-Worthy Vulnerability

Not everything qualifies for a CVE. The criteria:

1. **It must be independently fixable**: the vendor can patch it
   without the user doing anything unusual
2. **It must affect a released product**: bugs in pre-release,
   beta, or development code don't qualify
3. **It must be a security vulnerability**: crashes that don't
   have security implications don't qualify as CVEs (though they
   may still be bugs worth reporting)
4. **One vulnerability, one CVE**: if a single root cause manifests
   in multiple products, it gets one CVE. If different root causes
   produce similar symptoms, each gets its own.

---

## What Happens After You Submit

You've submitted your report. Now what? Understanding the
vendor's process prevents frustration and sets expectations.

### MSRC Timeline (Typical)

**Day 0**: You submit the report. Automated acknowledgment email.

**Days 1-3**: Initial triage. An MSRC analyst reads your report,
verifies it's a security issue (not a feature request, not a
duplicate), and assigns a case number (format: VULN-XXXXXX or
MSRC-XXXXX).

**Days 3-14**: Reproduction. An engineer attempts to reproduce the
bug using your steps. If they can't reproduce it, they'll ask for
clarification. This is where evidence quality pays off — if your
reproduction steps are precise, they reproduce on first attempt.

**Days 14-30**: Severity assessment. MSRC determines the official
CVSS score, the affected product list, and the fix priority.
They decide whether this goes into the next Patch Tuesday or
gets an out-of-band emergency patch.

**Days 30-90**: Fix development. The product team develops, tests,
and validates the fix. Regression testing across all affected
platforms.

**Patch Tuesday** (second Tuesday of each month): Fix ships in the
monthly security update. MSRC publishes an advisory, the CVE is
assigned and published, and your name appears in the acknowledgments
(if you requested credit).

**Post-patch**: Bounty evaluation and payment. MSRC determines
whether your submission qualifies for a bounty and how much.
Typical payment timeline: 60-90 days after patch ships.

### Possible Outcomes

Your report will resolve in one of these ways:

#### Accepted — CVE Assigned

Best case. The vulnerability is confirmed, a CVE is assigned, a
patch is developed, and you get credit. This validates your
research and adds a permanent entry to your professional record.

#### Rejected — Not a Security Vulnerability

MSRC determines that the behavior you reported doesn't cross a
security boundary per their criteria. This doesn't mean you're
wrong — it means the vendor's threat model doesn't consider it
a vulnerability.

Common reasons for rejection:
- **Detection bypass** is not a security boundary (Defender is a
  defense-in-depth layer, not a security boundary)
- **Requires admin privileges** to exploit (admin can already do
  anything)
- **Requires local access** and doesn't cross a privilege boundary
- **By design**: the behavior is intentional

#### Won't Fix — Acknowledged But Deprioritized

MSRC confirms it's a real issue but decides the risk doesn't
justify the engineering cost to fix it. This happens with:
- Low-severity DoS bugs
- Bugs that require unlikely conditions
- Issues in legacy code paths scheduled for deprecation
- Vulnerabilities mitigated by other defense layers

You may still get a CVE for "Won't Fix" issues, but no patch
ships.

#### Duplicate

Someone else reported it first. You don't get credit or bounty.
This happens. Accept it and move on to the next bug.

### The 90-Day Deadline

The industry standard: if the vendor hasn't patched within 90 days
of your report, you're ethically justified in publishing. Google
Project Zero established this norm and enforces it.

Why 90 days?
- It's enough time for a legitimate engineering effort
- It prevents vendors from sitting on reports indefinitely
- The threat of publication motivates timely patches
- After 90 days, attackers may independently discover the same bug

If you hit the 90-day deadline and the vendor hasn't patched:

1. **Notify the vendor**: "The 90-day disclosure deadline is
   approaching. I intend to publish on [date]."
2. **Offer a 14-day grace period** if they demonstrate a patch is
   imminent (in QA, rollout scheduled)
3. **Publish**: write up the vulnerability, the timeline, and the
   vendor's response (or lack thereof). Publish your PoC.
4. **Be professional**: stick to facts. No inflammatory language.
   The timeline speaks for itself.

Most vendors patch well within 90 days. This is a last resort,
not a first move.

---

## Lessons From VULN-195458

Theory is useful. Experience is better. Here's what happened when
we submitted our first real finding.

### What We Submitted

VULN-195458 was a detection bypass against Microsoft Defender.
The TOCTOU research from the first half of this manual demonstrated
a technique to prevent Defender from scanning a file's actual
content — exploiting the gap between when Defender opens the file
and when it reads the bytes.

We documented it, packaged the evidence, and submitted through
MSRC.

### What We Did Right

- **Clean evidence**: specific DLL versions, OS builds, reproduction
  steps that worked on first attempt
- **Clear documentation**: executive summary, root cause, scope,
  impact — all sections completed
- **Specific reproduction steps**: step-by-step, no assumptions,
  a developer could follow them blind
- **Professional tone**: technical, factual, no hyperbole

### What We Got Wrong

The vulnerability category.

We submitted a detection bypass — a technique that prevents
Defender from seeing malicious content. We framed it as a
security vulnerability.

MSRC rejected it.

The rejection cited a fundamental distinction in Microsoft's
security servicing criteria: **detection evasion does not cross
a security boundary**. Defender is classified as a
defense-in-depth feature, not a security boundary like the
kernel, the hypervisor, or the sandbox.

The analogy: if you find a way to sneak past a guard (detection
bypass), that's different from finding a way to break through
a wall (security boundary violation). Microsoft's threat model
treats the guard as advisory, not authoritative. The walls are
the security boundaries.

### The CrowdStrike Citation

MSRC's rejection letter specifically referenced existing public
research by CrowdStrike documenting the same technique class.
The TOCTOU approach to Defender evasion was already known in
the research community — not the specific implementation, but
the general technique category.

This doesn't invalidate the work. The research was valuable for
learning. But for CVE purposes, the technique class was prior
art and the target wasn't a security boundary anyway.

### The Real Takeaway

**Read the vendor's security servicing criteria BEFORE submitting.**

Microsoft publishes exactly what they will and won't fix:
- **docs.microsoft.com** → search "Microsoft Security Servicing
  Criteria for Windows"
- Lists explicit security boundaries (kernel, hypervisor, secure
  boot, AppContainer, etc.)
- Lists explicit non-boundaries (Defender detection, SmartScreen,
  reputation services)

If your vulnerability doesn't cross a listed security boundary,
MSRC will reject it. This isn't a judgment call — it's published
policy.

This is why we pivoted from TOCTOU detection bypass to memory
corruption in mpengine.dll. A heap overflow in the scan engine
IS a security boundary violation — it crosses from "untrusted
file content" to "code execution as SYSTEM." That's an RCE.
That's a security boundary. That's a CVE.

The rejection taught us more than an acceptance would have. It
forced us to understand Microsoft's actual threat model instead
of assuming our threat model matched theirs.

---

## The Warrior's Code — Standing Orders

Everything above is process. This is principle.

These are standing orders for anyone operating under the VADER
framework. They are not guidelines. They are not suggestions.
They are the code.

### Order 1: Never Weaponize Against Unauthorized Targets

Your research targets YOUR machines. Your lab environment.
Systems you own or have explicit written authorization to test.

The moment you run an exploit against a system you don't own
and don't have authorization to test, you've committed a crime.
In Australia: Criminal Code Act 1995, Part 10.7 — Computer
Offences. Penalties: up to 10 years imprisonment.

In the US: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
In the UK: Computer Misuse Act 1990.

Every jurisdiction has equivalent laws. "I was just testing" is
not a defense. "I didn't damage anything" is not a defense.
"I was going to report it" is not a defense.

Authorization is the bright line. Stay on your side of it.

### Order 2: Never Sell to Adversarial Markets

The gray market exists. Zerodium will pay $2.5 million for a
Windows zero-click RCE chain. Governments will pay more.

You know where that exploit ends up? On the phone of a journalist
in Saudi Arabia. On the laptop of a dissident in China. In the
surveillance infrastructure pointed at people whose only crime
was telling the truth.

The money isn't worth it. Not because of legal risk (the
transactions are often legal). Because of what the buyer does
with it. You are responsible for the foreseeable consequences
of your actions. Selling a weapon to someone who will use it
against civilians makes you complicit.

This standing order has no exceptions.

### Order 3: Give the Vendor Time

90 days minimum. This is the standard and we honor it.

The vendor's engineers are not your adversaries. They're people
who write code, make mistakes, and need time to fix them. A
responsible researcher gives them that time. An irresponsible
one drops zero-days to build a reputation.

90 days. If they're communicating, working, making progress — be
patient. They're on your side.

### Order 4: Full Disclosure Is a Last Resort

If the vendor goes silent for 90 days — no acknowledgment, no
communication, no evidence of work — full disclosure is ethically
justified. Not as punishment. As protection.

Because after 90 days, the probability that someone ELSE has found
the same bug independently goes up. And that someone might not be
filing reports. Full disclosure forces a patch, even if the vendor
doesn't want to ship one.

But it IS a last resort. Exhaust every other option first:
1. Re-contact the vendor through a different channel
2. Escalate within the vendor organization
3. Contact CERT/CC (cert.org) as a neutral intermediary
4. Notify the vendor of your disclosure deadline
5. Only then publish

### Order 5: Credit Is Earned, Not Claimed

Your name on a CVE is permanent. It appears in the National
Vulnerability Database. It's indexed by every security tool.
It proves that you found something real, documented it properly,
and handled it responsibly.

One CVE is worth more than a thousand CTF flags. It's proof
that you can do original research against production systems.
It's the difference between "I practice security" and "I've
contributed to security."

Claim credit on every submission. Use your real name. Build the
record. It compounds over years.

### Order 6: Document As If a Lawyer Will Read It

One day, someone will ask you to explain your research. Maybe
it's an employer reviewing your portfolio. Maybe it's a vendor
disputing your findings. Maybe it's a law enforcement agency
investigating something tangential to your work.

In all cases, your documentation is your defense. If every step
is recorded, timestamped, hashed, and justified — you're
protected. If your notes are sloppy, your timeline is unclear,
and your authorization is ambiguous — you're exposed.

Specific practices:
- **Date and hash everything**: when you found it, what state
  the evidence was in
- **Record your authorization**: for personal machines, screenshots
  showing you own the system. For bounty programs, screenshots of
  your enrollment.
- **Keep communication records**: every email to and from the
  vendor, timestamped
- **Never delete evidence**: even after the CVE is published,
  retain your working files for at least 5 years
- **Separate research from personal**: use a dedicated research
  environment, not your daily driver

### Order 7: The Mission Is Understanding

The CVE is a byproduct. The bounty is a byproduct. The
recognition is a byproduct.

The mission is understanding how things break. Why memory
corruption exists despite decades of mitigations. Where trust
boundaries fail despite careful engineering. How complexity
creates gaps that no amount of testing catches.

You find vulnerabilities because you want to understand
systems at the deepest level. The disclosure process is how
you give that understanding back to the people who can use
it to make things better.

That's the code. Everything else is noise.

---

## Submission Checklist

Use this before every report. Every item checked or explicitly
marked N/A with justification.

```
DISCLOSURE SUBMISSION CHECKLIST

[ ] Vendor identified and correct reporting channel confirmed
[ ] Security servicing criteria reviewed (what they will/won't fix)
[ ] Account created on vendor's security portal

EVIDENCE PACKAGE:
[ ] Executive summary (1 paragraph, what/where/how/impact)
[ ] Root cause analysis (specific function, offset, logic error)
[ ] Scope (affected versions — tested AND untested noted)
[ ] Reproduction steps (15-minute cold-start reproduction)
[ ] Impact assessment (demonstrated vs. theoretical separated)
[ ] Remediation suggestion (proposed fix with rationale)

ARTIFACTS:
[ ] PoC file (minimal — trigger only, no payload)
[ ] PoC generator script (shows construction, not just trigger)
[ ] WinDbg crash dump (full dump, /ma)
[ ] WinDbg session log (.logopen output)
[ ] Screenshots (timestamped, labeled, version info visible)
[ ] Video demonstration (optional but recommended, < 5 min)
[ ] Version manifest (OS build, engine version, DLL version)
[ ] SHA-256 hashes of ALL artifacts

SCORING:
[ ] CVSS 3.1 vector string calculated
[ ] Score reflects DEMONSTRATED impact (not theoretical)
[ ] Attack vector, complexity, privileges, interaction justified

LEGAL:
[ ] All testing performed on owned/authorized systems
[ ] Authorization documentation saved
[ ] Communication log initiated
[ ] No unauthorized data accessed or exfiltrated

FINAL:
[ ] All fields in vendor submission form completed
[ ] Evidence package reviewed for completeness
[ ] Submission timestamp recorded
[ ] 90-day disclosure deadline calculated and noted
[ ] Follow-up reminder set for 30 days
```

---

## Summary — Key Takeaways

- **The disclosure model matters.** Responsible/coordinated disclosure
  (private report → vendor patch → public advisory) is the standard.
  Full disclosure is a nuclear option for unresponsive vendors. Gray
  market sales fund surveillance states. Bug bounties align incentives.

- **MSRC is the channel for Microsoft products.** Create an account,
  submit through the portal, provide evidence-grade documentation.
  Quality of submission determines speed of response.

- **Evidence quality is everything.** Executive summary, root cause,
  scope, reproduction steps, impact assessment, remediation suggestion.
  Hash every artifact. Timestamp everything. A developer should
  reproduce in 15 minutes from your writeup.

- **CVSS scoring must be honest.** Score what you've demonstrated,
  not what you theorize. Overclaiming destroys credibility. A
  well-documented 7.5 is worth more than a hand-waved 10.0.

- **MITRE handles non-Microsoft CVEs.** Identify the correct CNA
  for your target. MITRE is the root CNA for anything without a
  specific authority.

- **Read the vendor's servicing criteria BEFORE submitting.** Microsoft
  publishes exactly what they consider a security boundary. Detection
  bypass isn't one. Kernel compromise is. Memory corruption in a
  SYSTEM-privileged parser is. Know the rules before you play.

- **VULN-195458 taught us more than a CVE would have.** The rejection
  forced understanding of Microsoft's actual threat model. It pivoted
  our research from detection bypass to memory corruption — the
  correct attack surface for a security boundary violation.

- **The 90-day deadline is a standard, not a threat.** Give vendors
  time. Communicate. Be patient. If they go silent for 90 days,
  full disclosure is justified as user protection, not punishment.

- **The Warrior's Code is non-negotiable.** Never weaponize against
  unauthorized targets. Never sell to adversarial markets. Always
  give vendors time. Credit is earned through real work. Document
  everything as if a lawyer will read it. The mission is
  understanding, not exploitation.

- **One CVE is worth more than a thousand CTF flags.** It's permanent
  proof that you found something real in a production system, handled
  it responsibly, and contributed to the security of the ecosystem.
  Build the record. It compounds.
