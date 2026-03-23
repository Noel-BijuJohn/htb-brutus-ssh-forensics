# Indicators of Compromise — HTB Brutus

**Source:** auth.log + wtmp forensic analysis
**Incident:** SSH Brute Force & Persistence — Confluence Server

---

## Network IOCs

| Type | Value | Context |
|---|---|---|
| **IP Address** | `65.2.161.68` | Attacker source IP — SSH brute force + manual sessions |
| **Target Port** | `22 (SSH)` | Service attacked on Confluence server |

---

## Host IOCs

| Type | Value | Context |
|---|---|---|
| **Compromised Account** | `root` | Credential obtained via SSH brute force |
| **Backdoor Account** | `cyberjunkie` | Created by attacker for persistent access |
| **Backdoor Group** | `sudo` | cyberjunkie added for full privilege escalation |
| **Automated Session** | `Session 34` | Opened and closed same second — brute force confirmation |
| **Manual Session** | `Session 37` | Interactive root session 06:32:45–06:37:24 UTC |

---

## File / URL IOCs

| Type | Value | Context |
|---|---|---|
| **Script Name** | `linper.sh` | Linux Persistence Toolkit (montysecurity) |
| **Script URL** | `https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` | Remote download source |
| **Download Command** | `sudo /usr/bin/curl <url>` | Executed by cyberjunkie after root session ended |

---

## Timeline IOCs

| Timestamp (UTC) | Event |
|---|---|
| Prior to `06:31` | Brute force activity begins |
| `06:31:33` | Root credentials confirmed — Session 34 auto-closes |
| `06:32:44` | Manual root auth — `Accepted password` in auth.log |
| `06:32:45` | Session 37 established (wtmp) |
| `06:37:24` | Session 37 closed |
| Post `06:37` | cyberjunkie login + linper.sh download |

---

## Blocking Recommendations

```bash
# Block attacker IP at firewall
iptables -A INPUT -s 65.2.161.68 -j DROP

# Disable root SSH login
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd

# Remove backdoor account
userdel -r cyberjunkie

# Audit sudo group membership
grep sudo /etc/group
```
