# Chapter 01 — Offensive Mindset: Attacker Psychology & Kill Chain

**VADER-RCE Field Manual**
**Prerequisite**: None — this is the entry point
**Drill**: DRILLS/01_offensive_mindset/

---

## Why You Need This

Before you touch a tool, before you run a scan, before you write a
single line of exploit code — you need to think like an attacker.

Not like a penetration tester following a checklist. Not like a
developer auditing their own code. Like someone who wants in,
has no legitimate path, and will take as long as needed to find
the one unguarded door.

The technical skills come later. All of them depend on this
foundation: the psychology, the doctrine, the kill chain. Get
this wrong and you're a script kiddie with a fancy toolset.
Get it right and every technique in this manual assembles into
a coherent operation.

This chapter doesn't teach exploits. It teaches how to think
before you exploit. How adversaries think. How defenders think.
Where the gaps are. Why operators fail. Why OPSEC is a survival
skill, not an afterthought.

Read it. Internalise it. Every chapter after this one assumes
you have.

---

## Section 1 — Attacker Psychology

### The Asymmetry Doctrine

The defender has to protect everything, all the time. The attacker
only has to find one path in. That asymmetry is not a detail —
it is the fundamental condition of offensive security.

Defenders build walls. Attackers find the gate that was left open,
or the window on the third floor, or the employee who'll click
anything. One unpatched service. One misconfigured permission. One
developer who hardcoded a credential. That's all it takes.

The attacker's advantage:

```
DEFENDER                        ATTACKER
──────────────────────────────────────────
Must defend every surface       Must compromise ONE surface
Must be correct always          Must be correct once
Operates under time pressure    Operates on their own schedule
Resources constrained           Unlimited time budget
Knows the rules                 Makes the rules
```

Operating with this mindset does not mean arrogance. It means
patience. Real threat actors don't hurry. They recon for weeks.
They sit in a network for months before acting. They fail a hundred
times in ways that leave no trace before they find the one approach
that works.

Speed is for getting out. Patience is for getting in.

---

### The Attacker's Goal Hierarchy

Attackers have objectives. The objectives vary but the hierarchy
doesn't change:

```
TIER 1 — ACCESS
  Get a foothold on the target system.
  Any access. Unprivileged. Constrained. Whatever opens the door.

TIER 2 — PERSISTENCE
  Make the access survive reboots, log-offs, and basic incident response.
  One shell that dies when the user logs out is not a foothold.

TIER 3 — PRIVILEGE
  Elevate from user to admin/SYSTEM/root.
  Full control of the machine is required for most objectives.

TIER 4 — LATERAL MOVEMENT
  From one machine to others in the environment.
  One computer is rarely the target. The target is deeper.

TIER 5 — OBJECTIVE
  Whatever the mission is: data exfiltration, ransomware deployment,
  persistent backdoor, destruction, espionage.
```

Every technique you learn in this manual serves one of these tiers.
When you encounter a new exploit or tool, immediately classify it:
which tier does this enable? Which tier does it require as a
prerequisite?

A privilege escalation exploit is useless without initial access.
An exfil technique is useless without persistence. Know which rung
of the ladder you're on before you reach for the next.

---

### Thinking Like An Adversary

Real adversaries spend more time thinking than acting. Before any
technical operation, they answer these questions:

**What am I targeting?**

Specific host? Service? User? Data? The tighter the target
definition, the more efficient the operation. "Compromise the
company" is not a target. "Read emails on the CFO's workstation"
is a target.

**What do I know about it?**

Architecture, software stack, patch level, network location.
Every assumption about the target that is WRONG will generate
noise and failed attempts. False starts burn time and risk exposure.

**What are my constraints?**

Detection risk, time window, available tooling, skills. A noisy
scan that trips an IDS is not necessarily a failed operation —
unless the constraint is staying undetected. Know your constraints
before you start. Don't discover them mid-operation.

**What's the simplest path?**

Not the most technically impressive path. Not the most educational
path. The simplest path. Complexity is an enemy. Every additional
technique is another opportunity for failure, noise, or detection.

If you can social engineer a password out of a help desk employee,
you don't need a zero-day. If a default credential works, you
don't need a brute force. If a public exploit exists for the
target's version, you don't need to write your own.

The chain that wins is the chain that works, not the chain that
demonstrates skill.

---

## Section 2 — Threat Modelling From The Attacker's POV

### What Is Attack Surface?

Attack surface is everything the target exposes that an attacker
can interact with. Not just the obvious stuff.

```
DIGITAL SURFACE
─────────────────────────────────────────────
Network services: open ports, protocols, APIs
Web applications: login pages, upload forms, APIs
Email: phishing entry, credential harvest via reset
Public code: GitHub repos, pastebin, job listings
Third-party services: software supply chain

PHYSICAL SURFACE
─────────────────────────────────────────────
Physical access to hardware
USB drops in parking lots
Building access, tailgating

HUMAN SURFACE
─────────────────────────────────────────────
Employees: credentials, access, social engineering
Contractors: same access, weaker vetting
IT help desk: password resets, account recovery
LinkedIn: org chart, tool stack, employee names
```

Threat modelling from the attacker's perspective is the process
of enumerating the target's full attack surface, then ranking
paths by ease of exploitation and value of outcome.

### Threat Modelling Process (Attacker's Version)

This is NOT the defender's STRIDE model. This is the attacker's
version:

**1. ENUMERATE**

What is exposed? Every service, every URL, every person with
a LinkedIn title that tells you what software the company runs.
Cast wide. Nothing is irrelevant at this stage.

**2. FINGERPRINT**

What specifically is running? Version numbers, OS, software stack.
A "web server" is not a target. "Apache 2.4.49 on Ubuntu 20.04,
CVE-2021-41773 path traversal, unpatched" is a target.

**3. RANK**

Of everything exposed, which path offers the highest probability
of success with the lowest detection risk? Stack-rank it. Work
the top of the list first.

**4. CHAIN**

Rarely does a single vulnerability give you the full objective.
Map out the chain: initial access → privilege escalation → lateral
movement → objective. Identify which links are known-good and
which are uncertain. The uncertain links need contingencies.

**5. VALIDATE**

Before executing the real operation, validate your assumptions
wherever possible. Test credentials on non-critical systems first.
Confirm the service version on a non-production endpoint. Every
assumption you can validate before going live reduces operational
risk.

---

## Section 3 — The Kill Chain

The kill chain is the sequence of stages from first contact to
mission complete. Understanding it is essential whether you're
executing the attack or building the defense. Defenders use it
to identify detection opportunities. Attackers use it to identify
where they're most exposed.

The model comes from Lockheed Martin's original paper. The
structure here is adapted for technical operations.

```
PHASE 1: RECONNAISSANCE
  Gather intelligence on the target.
  Passive: no direct interaction with target systems.
  Active: direct interaction begins.

PHASE 2: WEAPONISATION
  Assemble the attack tools.
  Choose exploit, configure payload, build the delivery vehicle.

PHASE 3: DELIVERY
  Get the weapon to the target.
  Email attachment, drive-by download, web app vulnerability,
  physical USB, supply chain compromise.

PHASE 4: EXPLOITATION
  The weapon executes on the target.
  Vulnerability triggered, code runs.

PHASE 5: INSTALLATION
  Establish persistence.
  Backdoor, scheduled task, registry key, service — something
  that survives the user session ending.

PHASE 6: COMMAND & CONTROL (C2)
  Establish a channel back to you.
  Outbound beacon, reverse shell, C2 framework.
  The foothold becomes interactive.

PHASE 7: ACTIONS ON OBJECTIVE
  The actual mission.
  Exfil data, deploy ransomware, move laterally, achieve
  whatever the target was.
```

### Using The Kill Chain As An Operator

For every operation you run, know which phase you are in at all
times. This matters because:

**Detection risk is not uniform across phases.**

Reconnaissance (passive) has near-zero detection risk. Exploitation
has high detection risk if done noisily. Post-exploitation (C2,
lateral movement) is where most operations get burned — not during
the initial exploit, but during the post-exploitation activity
that trips EDR or anomaly detection.

**Failure modes differ by phase.**

A failed delivery (phishing email blocked) doesn't burn you — the
target may not even know an attempt was made. A failed exploitation
(crash, error, IDS alert) may trigger active incident response.
Know the consequences of failure at each stage and plan accordingly.

**Recovery differs by phase.**

If recon fails (bad intelligence), you iterate. If exploitation fails
cleanly, you try another vector. If post-exploitation fails (C2
detected, persistence removed), your access is gone and the target
may be hardened. The later in the chain you fail, the harder the
recovery.

### Phase Detail: Reconnaissance

Reconnaissance is the phase most operators rush. That is a mistake.
Incomplete reconnaissance leads to wrong assumptions. Wrong
assumptions lead to failed operations.

Reconnaissance divides into two modes:

**Passive recon**: intelligence gathered without directly touching
target systems. WHOIS lookups, Shodan queries, LinkedIn, GitHub,
Google dorking, job postings. The target has no visibility into
this. Zero detection risk.

**Active recon**: direct interaction with target systems. Port
scans, banner grabs, web spider, directory brute-force. The target
MAY have logging that captures this. Detection risk increases
with noise level.

Always exhaust passive recon before moving to active. Everything
you can learn passively is free — no detection risk, unlimited
time. Everything you do actively is a signal that can be recorded.

Chapter 02 of this manual covers recon in full operational detail.

### Phase Detail: Weaponisation

You have a target and a vulnerability. Weaponisation is the
configuration work: choosing the right exploit, building the
payload, assembling the delivery vehicle.

Key decisions in weaponisation:

**Exploit selection**: public PoC vs custom? Public exploits are
detectable (signatures exist). Custom exploits take time to build
but evade detection. For red team ops, the sophistication of the
target's EDR dictates which you need.

**Payload selection**: what runs after exploitation? Reverse shell,
staged loader, in-memory execution, fileless techniques. The payload
must survive the target's defences. A Meterpreter binary dropped
to disk will be caught by Defender. In-memory shellcode using
API unhooking might not.

**Delivery vehicle construction**: how is the payload getting to
the target? Phishing email with attachment, malicious document,
web drive-by, supply chain inject. Each has different success rates
against different targets.

### Phase Detail: Actions On Objective

The kill chain ends at the objective, not at the shell. Operators
who get excited about popping a shell and forget to execute the
actual mission objective are not completing operations — they're
demonstrating access.

Define the objective before the operation starts. The objective
should be specific and verifiable:

```
BAD OBJECTIVE: "compromise the company"
GOOD OBJECTIVE: "extract the credentials database from DB-01 and
                 maintain persistence for 30 days undetected"

BAD OBJECTIVE: "get domain admin"
GOOD OBJECTIVE: "access the HR share on FILE-01 containing
                 employee salary data"
```

The objective drives every other decision. Delivery method,
persistence mechanism, lateral movement path — all of it is
optimised for reaching the objective with minimum exposure.

---

## Section 4 — Red Team vs Blue Team Mindset

### The Red Team Mindset

Red team thinking is adversarial. The goal is to find a path in,
regardless of what the defender intended.

Core traits:

**Assume success is possible.** Defenders make mistakes. Code has
bugs. Systems are misconfigured. People click things they shouldn't.
The red team's job is to find these realities, not confirm the
defender's assumptions.

**Think in chains, not single exploits.** Almost no single
vulnerability gives you the objective. The chain from initial
access to data exfiltration might be four vulnerabilities and
three misconfigurations linked together. Each link looks minor
in isolation. Together, they're a full compromise.

**Value stealth over speed.** A fast operation that triggers alerts
and gets remediated accomplishes nothing. A slow operation that
achieves the objective and leaves no trace is the goal. If the
blue team doesn't know it happened, it succeeded.

**Document everything.** Professional red teams document every
step taken, every command run, every credential captured. Not
for the report (though that matters) — for repeatability and
legal cover. If the client disputes what you did, your logs are
your proof.

### The Blue Team Mindset

Blue team thinking is defensive. The goal is to detect, contain,
and eradicate. Understanding it makes you a better attacker.

Core traits:

**Think in IoCs and TTPs.** Indicators of Compromise (file hashes,
IP addresses, domain names) are easy to change. Tactics, Techniques,
and Procedures (how an attacker operates) are hard to change.
Good blue teams look for TTPs, not just IoCs. Good red teams
vary their TTPs to avoid signature-based detection.

**Assume breach.** Modern blue teams don't build walls and hope
nothing gets through. They assume something already has. The
question is finding it. This is threat hunting — active searching
for evidence of compromise rather than waiting for alerts.

**Log everything.** Blue teams can only detect what they have
evidence for. Comprehensive logging (endpoint, network, application)
is the foundation. Attackers who understand what gets logged can
operate in the gaps — paths that don't generate log entries.

**Response speed matters.** The faster the blue team detects and
contains, the smaller the blast radius. An attacker who pops a
shell at 2am on a Friday has potentially 60 hours before business-
hours detection. An attacker who pops a shell during an active
security monitoring window has minutes.

### Switching Between Mindsets

The best operators can flip between both. When planning an attack,
think red: what's the path in? When assessing whether your operation
will be detected, think blue: what log entry would this generate?
What alert would this trigger?

```
EXAMPLE — LATERAL MOVEMENT DECISION

Red team view:
  Target: FILE-01, holds the data we need.
  Path: Pass-the-hash with captured NTLM credential.
  Feasibility: Yes, if SMB is accessible from current host.

Blue team overlay:
  Pass-the-hash = Event ID 4624 (logon type 3, NTLM auth)
  SMB to FILE-01 during off-hours = anomaly
  Mimikatz execution = LSASS access event + EDR alert
  Decision: Use stolen cleartext credential instead.
             Kerberos ticket (pass-the-ticket) looks less suspicious.
             Schedule lateral movement to business hours to blend
             with normal traffic.
```

Every technique you're considering — ask how the blue team sees it.
Then adjust.

---

## Section 5 — OPSEC Basics

OPSEC (Operational Security) is the practice of protecting your
own identity, infrastructure, and methods from the target and
from observers. A technically brilliant operation that gets you
arrested or expelled is a failed operation.

This section covers fundamentals. A full OPSEC doctrine would fill
its own manual.

### What Are You Protecting?

```
IDENTITY
  Your real name, location, employer, GitHub handle, email.
  Link your real identity to an offensive operation and legal
  consequences follow.

INFRASTRUCTURE
  Your C2 servers, VPNs, redirectors, attack boxes.
  If the target traces back to your infrastructure, it's burned.
  If law enforcement gets your server logs, you're burned.

METHODS
  The specific techniques, payloads, and code you used.
  Leaked payloads get signature'd. Leaked techniques get patched.
  Your operational methods are your competitive advantage.

TIMING
  When you operated. What time zone your activity suggests.
  Consistent off-hours operation implies a specific time zone
  and potentially a specific person.
```

### The Attribution Chain

Defenders and investigators trace attacks through attribution
chains: the sequence of evidence that connects an action to a
person. Your OPSEC goal is to break this chain at every link.

```
ATTRIBUTION CHAIN — ATTACK TO IDENTITY

Action on target
  → C2 traffic
    → C2 server IP
      → VPS provider logs
        → Payment method
          → Real identity

Break ONE link → attribution stops.

Break it at the VPS: pay with Monero to a service that doesn't
  require KYC.
Break it at the traffic: route through multiple jurisdictions
  with no logging agreements.
Break it at the action: use techniques that leave no unique
  fingerprint (custom tooling, living-off-the-land).
```

### Infrastructure Separation

Never use your personal infrastructure for offensive operations.
Never use operational infrastructure for personal activities.

```
COMPARTMENTALISATION MODEL

PERSONAL IDENTITY     OPERATIONAL IDENTITY
─────────────────     ────────────────────
Real name             Burner email, pseudonym
Home IP               Dedicated VPS in different country
GitHub account        Separate operational account
Personal email        ProtonMail / Tutanota / custom domain
Regular browser       Hardened VM, separate browser profile

NEVER cross these lanes. Ever.
```

A single slip — logging into a personal account from an operational
IP, reusing a nickname, sharing infrastructure between ops — is
enough to burn the whole operation.

### Tradecraft Discipline

Small habits that collectively determine whether you get caught:

**Clean machines for operations.** A dedicated VM for each engagement.
Fresh install. No personal data. No logins to personal accounts.
Delete it when done.

**Timestamps tell stories.** Log entries, file metadata, commit
timestamps. If all your "foreign" activity has timestamps
consistent with a specific time zone, that's an intelligence
gift. Work in UTC or off-hours that don't imply your real zone.

**Pay attention to tool fingerprints.** Default Metasploit payloads
have signatures. Nmap scans leave specific packet patterns. Cobalt
Strike has default certificates that get flagged. Customise defaults
before deployment.

**Assume logs exist.** Even if the target "has no logging," assume
something is captured somewhere. Operate as if every action is
being recorded by an unknown logging system.

**Verify your tracks.** After an operation, go back and verify
that the artefacts you expect to exist actually exist and no
unexpected ones were created. Dropped a payload to disk? Did it
delete itself? Did the deletion leave forensic evidence?

---

## Section 6 — Common Operator Mistakes

These are patterns that get operators caught, expelled, fired,
or arrested. Know them. Avoid them.

### Mistake 1: Moving Too Fast

Rushing past reconnaissance. Assuming the target is what you
think it is. Triggering high-noise scans before understanding
what monitoring exists. Speed before intelligence is how operations
fail and how operators get detected.

The fix: intelligence-first always. Don't touch the target until
you know more about it than you need to.

### Mistake 2: Insufficient Persistence

Getting a shell, doing the mission, losing the shell, and having
no way back in. Persistence is not optional. If the access path
closes, you've consumed your initial access vulnerability for
nothing. Establish multiple persistence mechanisms at different
privilege levels.

```
PERSISTENCE TIER EXAMPLE
──────────────────────────────────────
TIER 1: Unprivileged user persistence
  → Scheduled task in user context
  → Startup folder entry
  → Registry run key (HKCU)

TIER 2: Privileged persistence
  → Windows service
  → Registry run key (HKLM)
  → WMI subscription

TIER 3: Boot persistence
  → Bootloader modification
  → Firmware implant (advanced, out of scope for most ops)

Lose one tier → fall back to the next.
```

### Mistake 3: Noisy Post-Exploitation

The exploit worked. You have access. Then you run Mimikatz
against LSASS, do a network scan of the entire /24, dump SAM,
and transfer 2GB out via FTP.

Congratulations, the blue team just got six simultaneous alerts
and your session is being hunted.

Post-exploitation requires MORE discipline than initial access.
You are now inside the environment where monitoring is densest.
Move slowly. Operate one action at a time. Observe before acting.

### Mistake 4: Tool Reuse Across Operations

Using the same custom tool across multiple unrelated operations.
If that tool gets analysed from operation A, its signatures are
now known. Using it in operation B connects the two operations
to the same actor — you.

Fix: rebuild or heavily modify tooling between operations. The
payload from the last engagement is not the payload for the next.

### Mistake 5: Ignoring The Human Layer

Spending 40 hours trying to find a technical vulnerability in
a hardened web application when a single phishing email to
the admin account would have taken 30 minutes.

The human layer is almost always the path of least resistance.
Modern organisations harden their technology. They do not
comparably harden their people. Social engineering, phishing,
vishing — these are not "cheating." They are the dominant attack
vector in real-world breaches. An operator who ignores them
is voluntarily playing on hard mode.

### Mistake 6: Inadequate Documentation

Running an operation with no notes, no logs, no documentation
of what was done, when, and why. Then something goes wrong,
an incident occurs, and you have no evidence that you stayed
in scope, stayed within authorisation, and only touched what
you were supposed to touch.

In a professional engagement, this exposes you legally. In a
research context, it means you can't reproduce your own findings.
In a CTF, it means you can't write the writeup.

Document as you go. Every command, every finding, every decision.
Assume you'll need to reconstruct the operation from notes alone.

### Mistake 7: Scope Creep

You're authorised to test system A. You find a path to system B.
System B looks interesting. You go to system B. System B is out
of scope.

Scope creep is how professional penetration testers lose their
certifications and face legal consequences. The authorisation
boundary is a hard wall. If you find an interesting path that
goes out of scope, document it and report it. Do not follow it.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Kill chain** | The sequential phases of a cyberattack: recon, weaponise, deliver, exploit, install, C2, actions on objective |
| **Asymmetry** | The fundamental advantage of attackers: defend everything vs. compromise one thing |
| **Attack surface** | Every path an attacker can interact with a target: network, web, email, physical, human |
| **Threat modelling (attacker)** | Enumerating target attack surface, fingerprinting, ranking paths by ease and value, chaining phases |
| **Weaponisation** | Assembling the exploit, payload, and delivery vehicle before deployment |
| **OPSEC** | Protecting attacker identity, infrastructure, and methods from attribution |
| **Attribution chain** | The sequence of evidence linking an attack action to a real identity — breaking any link stops attribution |
| **Compartmentalisation** | Strict separation between personal and operational identity/infrastructure |
| **Persistence** | Mechanisms ensuring access survives reboots, log-offs, and basic incident response |
| **TTPs** | Tactics, Techniques, and Procedures — the HOW of attacker behaviour, harder to change than IoCs |
| **IoCs** | Indicators of Compromise — file hashes, IPs, domains; easily changed |
| **Red team** | Adversarial assessment: simulate real attacker to find paths the defender missed |
| **Blue team** | Defensive operations: detect, contain, eradicate threats |
| **Scope** | The authorised boundary of an engagement — operating outside it is illegal |
| **Lateral movement** | Moving from an initial foothold to other systems in the target environment |

---

## Drill 01 — Offensive Mindset

Go to `DRILLS/01_offensive_mindset/`. A scenario description and
target profile are provided.

Your mission:

1. Read the target profile. Build a threat model from the attacker's
   perspective. Enumerate the attack surface. Rank paths by feasibility.

2. Map a kill chain for the top two attack paths. Identify which
   phase has the highest detection risk for each path.

3. For each kill chain, identify the three most likely mistakes an
   operator would make and how to avoid them.

4. Write a one-page OPSEC plan for the operation. What infrastructure
   do you need? What personal data must stay out of the operation?
   What's your cover story if questioned?

5. Answer: if you were the blue team for this organisation, what
   single monitoring capability would stop the top-ranked attack path?
   How would you route around it as the attacker?

There is no technical exploitation in this drill. This is all
architecture and doctrine. Get it right here and everything
that follows has a foundation. Get it wrong and you're just
running tools you don't understand.

---

— 
The gate they left open waits in no file —
PATIENCE is the blade, not the EXPLOIT.
