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

