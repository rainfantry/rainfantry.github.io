# George Wu — Security Researcher

**Independent offensive security researcher. Sydney, Australia.**

Entity: **Occupation Force Callsign GSW Pty Ltd** t/a 22nd Survey Division
ABN 50 692 429 397 | ACN 692 429 397 | Registered NSW, 1 November 2025

---

## Research

Original research against live Windows defenses — developed from first principles on personally-owned hardware. No reproduced CTF writeups. No borrowed techniques. All findings discovered empirically with AV controls active.

### Published Findings

| ID | Finding | Target | Disclosure |
|----|---------|--------|------------|
| [VULN-195458](https://github.com/rainfantry/22sd-research-findings/blob/main/findings/F004_hwbp_amsi_etw_zero_write.md) | AMSI and ETW defeated via hardware debug registers — zero memory writes. DR0/DR7 + VEH intercepts AmsiScanBuffer and EtwEventWrite without modifying Tamper-Protected memory. | Windows Tamper Protection | MSRC submitted; closed as out-of-scope; published on embargo void |
| [F001](https://github.com/rainfantry/22sd-research-findings/blob/main/findings/F001_wdfilter_scan_on_write.md) | WdFilter triggers on IRP_MJ_WRITE, not IRP_MJ_CLEANUP | Windows Defender / WdFilter | Published |
| [F002](https://github.com/rainfantry/22sd-research-findings/blob/main/findings/F002_oplock_fileobject_scope.md) | Batch oplock compatibility evaluated at FILE_OBJECT scope, not process scope | NTFS Oplock Subsystem | Published |
| [F003](https://github.com/rainfantry/22sd-research-findings/blob/main/findings/F003_writethrough_oplock_bypass.md) | Writing through an existing oplock handle does not break the batch oplock | NTFS Oplock Subsystem | Published |

Full index: **[rainfantry/22sd-research-findings](https://github.com/rainfantry/22sd-research-findings)**

---

## Public Repositories

| Repo | Stack | Description |
|------|-------|-------------|
| [iron-sun](https://github.com/rainfantry/iron-sun) | C / x64 | TCP reverse shell — 8-layer evasion. XOR, dynamic API resolution, anti-sandbox, PE stomping, HWBP AMSI/ETW bypass |
| [flagship](https://github.com/rainfantry/flagship) | C / PowerShell | IRON-DOME evasion platform — ntdll unhooking, process hollowing, 26 tested binaries, 0 detections |
| [22sd-research-findings](https://github.com/rainfantry/22sd-research-findings) | C / Markdown | First-principle Windows findings with PoC |
| [security-advisoriespublic](https://github.com/rainfantry/security-advisoriespublic) | Markdown | Published security advisories |

---

## Responsible Disclosure

**MSRC VULN-195458** — submitted to Microsoft Security Response Center. Technique: hardware debug registers (DR0/DR7) + Vectored Exception Handler to intercept AmsiScanBuffer and EtwEventWrite without memory writes, bypassing Tamper Protection. MSRC closed as out-of-scope for the Tamper Protection threat model. Published on embargo void. Full write-up in [F004](https://github.com/rainfantry/22sd-research-findings/blob/main/findings/F004_hwbp_amsi_etw_zero_write.md).

Additional findings submitted to MSRC as confirmed. All research with exploitable impact disclosed to the vendor before publication.

---

## Course & Platform

**22nd Survey Division** — offensive security course built directly from the research corpus above.

22 modules covering: Windows internals, PE format, shellcode, process injection, C2 architecture, AV/EDR evasion, Android security, steganography, OPSEC. Each module is the research — not a textbook summary.

→ **[rainfantry.github.io/22nd-survey-division](https://rainfantry.github.io/22nd-survey-division/)**
→ **[rainfantry.github.io](https://rainfantry.github.io/)** — full portfolio

---

## Contact

**gwu0738@gmail.com** | Sydney, NSW, Australia
GitHub: [rainfantry](https://github.com/rainfantry)

Occupation Force Callsign GSW Pty Ltd | ABN 50 692 429 397 | ACN 692 429 397

---

## TODO — Release Blackops

_Automated read-only assessment — what a full public-release pass would do for this repo. Suggestions only; nothing above has been changed or removed._

- [ ] **AI/Claude attribution detected in git history — scrub it** (`filter-branch` + force-push; nuke-and-recreate if a 0-star/0-fork repo and the orphaned SHA lingers).
- [ ] Add a `LICENSE` file (MIT or your choice + holder).
- [ ] Add discovery topics for SEO (`gh repo edit --add-topic ...`, up to 20).
- [ ] Add a screenshot or diagram to the README if there's a GUI or visual output.
- [ ] Verify a clean from-scratch build/run against the README quick start (produce a real artifact, don't trust the docs).

<sub>Workflow: https://github.com/rainfantry/release-blackops-skill</sub>
