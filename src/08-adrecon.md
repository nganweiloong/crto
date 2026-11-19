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

### 11.5 The high-value findings

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

### 11.6 OPSEC for AD reconnaissance

- **LDAP is cheap; SMB sweeps are not.** Prefer `DCOnly` collection and targeted LDAP filters.
- **Avoid `Session` collection** unless you need it. It touches every computer.
- **Do not run SharpHound `All` from a DC or restricted host.**
- **LDAP logging:** if "Directory Service Access" auditing is on, searches can be logged (1644). Volume and unusual filters matter.
- **`setspn -T` and `dsquery` are normal admin activity**; a burst of `Find-LocalAdminAccess` from a user workstation is not.
- **Tier your queries:** run the loud ones from Tier 2, then move only the results.

### 11.7 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| BloodHound import fails | Corrupt/partial zip | Re-collect; check file size |
| SharpHound returns no sessions | No admin / SMB blocked | Use `DCOnly`; collect from a host with access |
| `Get-Domain` returns nothing | Not domain-joined, or DNS wrong | `nltest /dsgetdc`; set DNS to DC |
| PowerView blocked by AMSI | Script contains signatures | Use SharpView / `execute-assembly` equivalents |
| ACL query slow | Large domain | Filter by object; use BloodHound |
| BloodHound shows no path | Stale data | Re-collect after changes |

