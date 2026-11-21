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

