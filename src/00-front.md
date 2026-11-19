# CRTO I — Red Team Operator Playbook

**Exam-day command reference, attack paths, and OPSEC for the Zero Point Security Certified Red Team Operator (Red Team Ops I) practical exam.**

> **Scope:** Windows / Active Directory red team operations with Cobalt Strike as the primary C2.
> **Built from:** the public 28-module Red Team Ops curriculum, public tool documentation (Cobalt Strike, Mimikatz, Rubeus, PowerView, BloodHound/SharpHound, Certify/Certipy, SharpDPAPI, Impacket), MITRE ATT&CK, and public candidate reports.
>
> **This is a study aid, not a substitute for hands-on practice.** The exam grades execution and OPSEC, not recall. Every command here should be practised in the lab until it is routine.
>
> **For authorized lab and exam use only.**

## Verify before exam day

- **The exam format has changed more than once.** Public 2025–2026 reports describe a **pausable practical lab**: roughly **24–48 hours of active lab time inside a 7-day window**, **100 points with 85 to pass**, and roughly **half the points for the operational objective and half for OPSEC/detection**. Zero Point does not publish the exact rubric. Confirm the current format, Rules of Engagement, and **restricted-host list** in your Candidate Handbook / portal before you start.
- **Cobalt Strike and kit syntax drifts between versions.** Anything marked ⚠ must be tested in the lab.
- **You do not need to be perfect.** Public pass reports range from the high 80s to the high 90s. Losing a few OPSEC points is survivable; leaking a beacon on a restricted host or tripping whitelisting repeatedly is not.

## Legend

| Tag | Meaning |
|---|---|
| ✅ | Verified against public tool documentation or CRTO write-ups |
| ⚠ | Version, build, or kit dependent — test it in the lab |
| 🔊 | Noisy / high detection risk |
| 🟢 | Lower-noise alternative where one exists |
| **OPSEC** | What the action leaves behind and how to reduce it |

## How to use this under exam pressure

1. **Part II is the playbook.** Start at the phase you are in. Every technique follows the same shape: *when to use → exact commands → OPSEC → troubleshooting.*
2. **Part III is the lookup.** When you know the tool but not the flag, jump straight to the appendix.
3. **Before every action, run the three OPSEC questions** (Part I): *What process runs? What does it touch? What does it write or send?*
4. **Keep a running action log** — timestamp, host, technique, artifact created. It makes cleanup and the OPSEC half of the exam far easier.
5. **When stuck, change one variable at a time.** Most "beacon won't run" failures are payload/architecture/listener mismatch, AV/AMSI, or egress — not a broken tool.

## The exam attack path at a glance

If you remember nothing else, remember the shape of the exam:

```text
1. Foothold            → quiet recon: know the host, the user, the monitoring
2. Find the path       → BloodHound DCOnly + targeted PowerView
                         (Kerberoast, AS-REP, ACL, delegation, ADCS, LAPS, MSSQL)
3. Credentials         → tokens / tickets / DPAPI first; LSASS last
4. Local privilege     → only if the path requires it
5. Lateral movement    → WinRM or an SMB beacon; PsExec only as a fallback
6. Domain escalation   → ACL → DCSync → golden/diamond, or ADCS/delegation
7. Objective host      → quietest reliable path, minimum actions, maximum cleanup
8. Cleanup + submit    → Appendix G checklist
```

**The five OPSEC decisions that decide pass/fail:**

1. **C2 customised before the first beacon** — profile, port, pipe, `spawnto`.
2. **No default indicators** — no default `rundll32.exe` parent, no default URIs/pipe/port.
3. **No LSASS access on restricted hosts** — use tokens, tickets, DPAPI, SYSVOL.
4. **No debris** — remove services, tasks, files, firewall rules, ACL changes.
5. **No security-control changes and no detections on restricted hosts.**

## Contents

- **Part I — Doctrine**
  - 1. Exam mechanics and scoring
  - 2. The OPSEC model
  - 3. Telemetry: what your actions trigger
  - 4. Exam-day workflow and time-boxing
- **Part II — Playbook**
  - 5. C2 setup and payloads (Cobalt Strike)
  - 6. Foothold and reconnaissance
  - 7. Credential access
  - 8. Local privilege escalation
  - 9. Lateral movement
  - 10. Pivoting and tunnelling
  - 11. Active Directory reconnaissance
  - 12. Kerberos and domain escalation
  - 13. Active Directory Certificate Services (ADCS)
  - 14. Persistence
  - 15. Defense evasion and OPSEC deep dive
  - 16. Data hunting, exfiltration, and cleanup
- **Part III — Appendices**
  - A. Beacon command reference
  - B. Tool reference (Mimikatz, Rubeus, PowerView, SharpDPAPI, Seatbelt, SharpUp, SQL)
  - C. One-liners
  - D. Ports, services, and protocols
  - E. Kerberos attack decision tree
  - F. Event ID and detection table
  - G. OPSEC checklist (use this before submitting)
  - H. Tool paths and file transfer
  - I. Troubleshooting
- **Sources and further reading**

---

## A note on sources

The public CRTO curriculum is 28 modules: Getting Started, Command & Control, External Reconnaissance, Initial Compromise, Host Reconnaissance, Host Persistence, Host Privilege Escalation, Host Persistence (Reprised), Credential Theft, Password Cracking, Domain Reconnaissance, User Impersonation, Lateral Movement, Data Protection API, Kerberos, Pivoting, ADCS, Group Policy, MS SQL Servers, Microsoft Configuration Manager, Domain Dominance, Forest & Domain Trusts, LAPS, Microsoft Defender Antivirus, Application Whitelisting, Data Hunting & Exfiltration, Extending Cobalt Strike, and Exam Preparation.

This playbook condenses the operator-facing parts of that scope. It does **not** reproduce Zero Point Security's paid course text, labs, or slides. Commands are standard public tool syntax; OPSEC guidance combines public documentation with themes reported by candidates who have taken the exam.

