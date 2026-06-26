# 22DIV // george wu

**https://rainfantry.github.io**  |  **Front: https://rainfantry.github.io/22nd-survey-division/**

Security research against live Windows 11 defenses. CSEC student. Sydney.

50 findings across 13 engagements. Every technique built from first principles against Defender with Real-Time Protection enabled on my own hardware. Responsible disclosure via MSRC.

---

### Courses & Labs

| Lab | Topic |
|-----|-------|
| [Ghost Encoder](https://rainfantry.github.io/labs/ghost.html) | Unicode steganography — invisible PS1 bootstrap |
| [VADER Rootkit](https://rainfantry.github.io/labs/rootkit.html) | Modular rootkit — AMSI/ETW bypass |
| [StarKiller](https://rainfantry.github.io/labs/starkiller.html) | Android RAT — Kotlin C2 + obfuscation |
| [CHEYANNE](https://rainfantry.github.io/labs/cheyanne.html) | C2 framework — polymorphic loader + kill chain |
| [VADER Agent](https://rainfantry.github.io/labs/vader.html) | AI persona engine — multi-agent Discord C2 |

---

### Private Research Repos

| Repo | What |
|------|------|
| `rainfantry/cheyanne` | CHEYANNE C2 — ghost_iron polymorph, full kill chain |
| `rainfantry/vader-rootkit` | Rootkit — 26 binaries, all clean; MSRC VULN-195458 |
| `rainfantry/starkiller` | Android RAT — Phase 1 complete |
| `rainfantry/iron-sun` | FUD reverse shell — XOR obfuscation, anti-sandbox, PE stomp |
| `rainfantry/eclipse` | Anti-forensics / OPSEC cleanup |

---

### Public Tools

| Repo | What |
|------|------|
| [rainfantry/winrecon](https://github.com/rainfantry/winrecon) | PowerShell privesc audit script |
| [rainfantry/ghost-encoder](https://github.com/rainfantry/ghost-encoder) | Unicode steganographic PS1 encoder |
| [rainfantry/defender-quarantine-architecture](https://github.com/rainfantry/defender-quarantine-architecture) | Windows Defender quarantine research |

---

### Online Courses

| Platform | Course |
|----------|--------|
| [TryHackMe](https://tryhackme.com) | Active — CSEC curriculum |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Active |
| [TCM Security](https://academy.tcm-sec.com) | Active — Practical Ethical Hacking |

---

### Key Findings

- **Standard user to SYSTEM** — replaced a LocalSystem service binary as a standard user. No admin credentials. No UAC prompt. Full SYSTEM token on next reboot. (CWE-732)

- **Defender's tamper protection has a blind spot** — hardware breakpoints bypass both AMSI and ETW without modifying a single byte of memory. Defender monitors memory integrity but not CPU debug registers. No behavioral rule exists for this. (MSRC potential)

- **The "dark room"** — AMSI script scanning and ETW process telemetry simultaneously defeated. All user-mode security telemetry blind. Zero VirtualProtect calls. Zero bytes patched.

- **Vendor hardened the wrong layer** — target service had manifest-based DLL redirection locking all imports to System32. They hardened the windows but left the front door open: the exe itself was writable by everyone.

- **User-writable directories in the machine SYSTEM PATH** — third-party installers placed user-owned directories into the machine-level PATH. Any SYSTEM process searching PATH for a DLL finds attacker-controlled territory first. (CWE-427, MSRC potential)

- **Phantom DLL in first-party Microsoft service** — Office ClickToRunSvc (LocalSystem, auto-start) delay-loads a DLL that does not exist anywhere on disk. User-owned PATH directory fills the void. (CWE-427, MSRC high)

- **Defender's ML has a ~15 minute blind spot** — first deployment of a payload survives static analysis. Cloud/ML catches up retroactively but the binary is already planted and grandfathered.

---

*Research ongoing. Disclosure pending confirmation of first-party vectors.*
