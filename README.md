# 22DIV // george wu

**https://rainfantry.github.io**

Security research against live Windows 11 defenses. CSEC student. Sydney.

50 findings across 13 engagements. Every technique built from first principles against Defender with Real-Time Protection enabled on my own hardware. Responsible disclosure via MSRC.

---

### Key Findings

- **Standard user to SYSTEM** — replaced a LocalSystem service binary as a standard user. No admin credentials. No UAC prompt. Full SYSTEM token on next reboot. (CWE-732)

- **Defender's tamper protection has a blind spot** — hardware breakpoints bypass both AMSI and ETW without modifying a single byte of memory. Defender monitors memory integrity but not CPU debug registers. No behavioral rule exists for this. (MSRC potential)

- **The "dark room"** — AMSI script scanning and ETW process telemetry simultaneously defeated. All user-mode security telemetry blind. Zero VirtualProtect calls. Zero bytes patched.

- **Vendor hardened the wrong layer** — target service had manifest-based DLL redirection locking all imports to System32. They hardened the windows but left the front door open: the exe itself was writable by everyone.

- **User-writable directories in the machine SYSTEM PATH** — third-party installers placed user-owned directories into the machine-level PATH. Any SYSTEM process searching PATH for a DLL finds attacker-controlled territory first. (CWE-427, MSRC potential)

- **Phantom DLL in first-party Microsoft service** — Office ClickToRunSvc (LocalSystem, auto-start) delay-loads a DLL that doesn't exist anywhere on disk. User-owned PATH directory fills the void. (CWE-427, MSRC high)

- **Defender's ML has a ~15 minute blind spot** — first deployment of a payload survives static analysis. Cloud/ML catches up retroactively but the binary is already planted and grandfathered.

---

*Research ongoing. Disclosure pending confirmation of first-party vectors.*
