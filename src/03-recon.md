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

