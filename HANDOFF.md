# 22DIV — AI HANDOFF DOCUMENT

> This document gives any AI model full operational context to continue work on this project without prior conversation history. Read this before doing anything else.

---

## OPERATOR

**Name:** George Wu  
**Callsign:** VADER  
**DOB:** 17/07/1996 (29, Sydney AU)  
**GitHub:** [rainfantry](https://github.com/rainfantry)  
**Email:** gwu0738@gmail.com  
**Company:** OCCUPATION FORCE CALLSIGN GSW PTY. LTD. t/a **22ND SURVEY DIVISION**  
**ABN:** 50 692 429 397 | **ACN:** 692 429 397 (Pty Ltd, NSW, registered 1 Nov 2025)  
**LinkedIn:** https://www.linkedin.com/company/22div/

**Status:** CSEC independent security researcher. Off stimulants since Feb 2026. Medical TRT. Gray Rock at home. Zero support network — talks to Oracle (AI) and RADON (work partner Raed/Ghaleb). Goal chain: security research → legitimate income → financial independence → exit.

---

## COMMUNICATION PROTOCOL

- **Execution mode** (caps/short/profane/direct): shut up and execute. No planning loops.
- **Planning mode** (lowercase/questions): discuss first.
- Never ask "are you sure?" Match energy. Swear back.
- Voice output: `python "C:/Users/gwu07/machine-spirit/talkytalk/talkytalk.py" "MSG"` (ElevenLabs BILLING BLOCKED as of 2026-06-26 — falls back to local TTS)
- **BLACKOPS:** No `Co-Authored-By: Claude`, no AI markers ANYWHERE. All output is George's work.

---

## PRIMARY WEBSITE

**Live:** https://rainfantry.github.io/22nd-survey-division/  
**Repo:** https://github.com/rainfantry/22nd-survey-division  
**Local:** `C:/Users/gwu07/Desktop/repos/22nd-survey-division/`

### Landing page features (as of 2026-06-26):
- PIN gate `668340` — localStorage key `22div_gate_auth = '1'`
- Gate fires on ALL course access points (landing page CTAs + direct URL to reader.html)
- Pricing section: $497 AUD, email enrol, Stripe placeholder
- Proof cards: real program screenshots (no AI chat screenshots)
- Interactive demo section: terminal replay, MCQ, fill-in-blank (no PIN required)
- 13 proof cards from private repos (showcase screenshots)

### Payment (placeholder — not live):
- See `PAYMENT_INTEGRATION.md` in repo root
- Options: Stripe AU (recommended), Square AU, Pin Payments, Zip
- Success URL pattern: `?access=stripe_success` → sets localStorage auth

---

## FIELD MANUAL (COURSE)

**Live:** https://rainfantry.github.io/books/reader.html  
**Repo:** https://github.com/rainfantry/rainfantry.github.io  
**Local:** `C:/Users/gwu07/Desktop/repos/rainfantry.github.io/`

### Reader features:
- PIN gate enforced at reader.html level (not just landing page clicks)
- Unauthorized access → redirects to `22nd-survey-division/?unlock=1&ret=ENCODED_URL`
- After unlock → returns to original chapter URL
- Per-chapter sidecar JSON files:
  - `books/sitrep.json` — MISSION BRIEFING (ENEMY/SITREP/WHY YOU/DOCTRINE) for all 22 chapters
  - `books/primers.json` — LANGUAGE PRIMER (collapsible term/meaning table) for 14 chapters
  - `books/exercises/*.json` — interactive exercises (terminal/MCQ/fill-in) for 5+ chapters

### Chapter structure (per chapter):
1. `MISSION BRIEFING` (from sitrep.json — enemy, situation, why soldiers, doctrine)
2. `LANGUAGE PRIMER` (from primers.json — collapsible, language terms used in this chapter)
3. Chapter markdown content
4. `INTERACTIVE EXERCISES` (from exercises/SLUG.json — terminal replay, MCQ, fill-in-blank)

### Main track chapters (22 modules):
| # | Slug | Topic |
|---|------|-------|
| 01 | 01_OFFENSIVE_MINDSET | Doctrine, 0x1security methodology |
| 02 | 02_RECON_FOOTPRINTING | OSINT, DNS, passive recon |
| 03 | 03_VULNERABILITY_RESEARCH | Fuzzing, bug finding, CVE research |
| 04 | 04_MITIGATIONS | ASLR, DEP, CFG, Secure Boot |
| 05 | 05_EXPLOIT_DEVELOPMENT | Stack overflow, heap, primitives |
| 06 | 06_WINDOWS_INTERNALS | Kernel/user, tokens, handles |
| 07 | 07_EXPLOIT_PRIMITIVES | Read/write primitives |
| 08 | 08_PRIVILEGE_ESCALATION | CWE-732, CWE-427, winrecon |
| 09 | 09_MALWARE_DEVELOPMENT | Dropper/loader/stager, dynAPI |
| 10 | 10_CODE_INJECTION | DLL inject, process hollow |
| 11 | 11_ROOTKITS | HWBP AMSI/ETW bypass, VULN-195458 |
| 12 | 12_ANTIVIRUS_EVASION | 5-gate model, IRON-DOME |
| 13 | 13_MEMORY_FORENSICS | Volatility, forensic wipe |
| 14 | 14_REVERSE_ENGINEERING | Ghidra, x64dbg |
| 15 | 15_POST_EXPLOITATION | Creds, lateral movement, persist |
| 16 | 16_COMMAND_AND_CONTROL | CHEYANNE C2, beacons |
| 17 | 17_NETWORK_WARFARE | Pivoting, segmentation |
| 18 | 18_CRYPTOGRAPHY_EVASION | XOR, RC4, AES |
| 19 | 19_LIVING_OFF_THE_LAND | IEX, certutil, regsvr32 |
| 20 | 20_ACTIVE_DIRECTORY | Kerberoasting, DCSync |
| 21 | 21_MOBILE_SECURITY | STARKILLER Android RAT |
| 22 | 22_OSINT_SOCIAL_ENGINEERING | OSINT, social eng |

---

## SECURITY RESEARCH (PRIVATE REPOS)

All repos at https://github.com/rainfantry — private unless stated.

| Repo | Status | Description |
|------|--------|-------------|
| **vader-rootkit** | Active | HWBP AMSI/ETW bypass. Commit 119f93e. 26 binaries CLEAN. |
| **cheyanne** | Active | C2 framework. Full kill chain. PENTEST_LOG.md at root. |
| **starkiller** | Active | Android RAT Phase 1 COMPLETE. GPS exfil confirmed. Commit 67aa4fd. |
| **eclipse** | Active | Polymorphic PE builder. Per-run mutation. |
| **iron-sun** | Active | TCP reverse shell. 7-layer evasion. |
| **flagship** | Active | GUI kill chain. Automated QA harness. 26+ binaries, VERDICT PASS. |
| **ghost-encoder** | Active | Steganography / covert channel. |
| **winrecon** | Active | 20-section recon tool. CWE-732/427 detection. |
| **GeoDefend** | Planned | Capstone defensive automation platform. |
| **radon-fid-tools** | Active | Survey tools (private). DXF sanitizer, AutoLISP F&R. |
| **csec-research-authorization** | Public | Research authorization framework. |

### MSRC Research:
- **VULN-195458:** HWBP Tamper Protection bypass via hardware debug registers. CVSS 7.1 High. Submitted June 2026. REJECTED — "outside security boundary." Embargo void. Published. Technique used in vader-rootkit and IRON-DOME.

---

## LOCAL ENVIRONMENT

```
OS:       Windows 11 Home 10.0.26200
Shell:    Git Bash (preferred) / PowerShell
Editor:   VS Code
Python:   System PATH
Node:     nvm/system
Git:      Configured, gh CLI authenticated
Parrot:   Secondary laptop (security/exploration)
RunPod:   RTX 5090, Claude Code v2.1.41
```

### Key paths:
```
Repos:          C:/Users/gwu07/Desktop/repos/
Machine Spirit: C:/Users/gwu07/machine-spirit/
SERVITOR:       C:/Users/gwu07/mrrobot/
Hermes agent:   C:/Users/gwu07/AppData/Local/hermes/
22DIV agent:    C:/Users/gwu07/22DIV/
RADON tools:    C:/Users/gwu07/Documents/radon/
TalkyTalk:      C:/Users/gwu07/machine-spirit/talkytalk/talkytalk.py
```

### Remote servers:
```
PRODUCTION:  ssh -p 2683 divcom22@S06ee.syd5.hostingplatform.net.au  (paramiko, pw auth)
             Files in public_html/. Read before write. NEVER DELETE.
RunPod:      Key auth. PTY required — use runpod_ssh.py helper.
             python C:/Users/gwu07/machine-spirit/runpod/runpod_ssh.py "cmd"
```

---

## DOCTRINE

### 0x1security (Unit 8200 methodology):
- Search for KNOWLEDGE. Not bugs.
- Crash → Leak → Execute.
- Assume compromise.
- 80% recon, 20% action.
- Soldiers before hackers. Teach the defence architecture first — the bypass is a side effect.

### BLACKOPS:
- No `Co-Authored-By: Claude` anywhere. Ever.
- No AI markers in commits, code comments, READMEs, or anywhere else.
- All output is George's work.

### Teaching doctrine (course):
1. MISSION BRIEFING — what is the enemy, why does this matter
2. LANGUAGE PRIMER — what syntax you'll encounter (collapsible)
3. Chapter content — technique, code with inline comments, install steps, expected output
4. Defender's takeaway — how to detect/prevent this
5. Interactive exercises — terminal replay, MCQ, fill-in-blank

---

## CURRENT PRIORITIES (as of 2026-06-26)

1. **Course quality loop** — workflow running: audit all 22 chapters as paying student, rewrite weak lessons
2. **Payment integration** — Stripe AU when ready. See `PAYMENT_INTEGRATION.md` in 22nd-survey-division repo.
3. **GeoDefend** — capstone defensive automation project (not yet started, planned as course outcome)
4. **RADON** — survey work with Raed, 4 days/week (income base)

---

## PORTFOLIO / SHOWCASE

- **Portfolio site:** https://rainfantry.github.io/22nd-survey-division/
- **Field manual:** https://rainfantry.github.io/books/reader.html
- **IRON-DOME release:** https://rainfantry.github.io/irondome.html
- **Showcase screenshots:** https://github.com/rainfantry/rainfantry.github.io/tree/main/showcase

---

## RULES FOR THIS AI

1. Direct. No corporate fluff. Military protocol. Match energy — if George is in caps and profane, you execute. If lowercase, discuss.
2. Production server (22div.com.au): read first, back up, never delete.
3. RunPod: sandbox — move fast, break things.
4. No attribution. Ever.
5. TAFE coursework took priority until ~May 2026. Now CSEC research is primary.
6. Don't plan when George says execute. Don't execute when George says plan.
7. If you see "VADER" in caps context — full execution mode. No hedging.
8. Never ask "are you sure?" George knows what he wants.
