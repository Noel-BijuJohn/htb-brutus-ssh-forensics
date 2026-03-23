# MITRE ATT&CK Mapping — HTB Brutus

**Investigation:** SSH Brute Force & Post-Compromise Activity
**System:** Confluence Server (Linux)

---

## Full Technique Mapping

| Tactic | Technique | Sub-Technique | ID | Evidence |
|---|---|---|---|---|
| **Reconnaissance** | Active Scanning | — | T1595 | 165+ failed SSH attempts from single IP indicating systematic scanning |
| **Initial Access** | Brute Force | Password Guessing | T1110.001 | Automated SSH credential stuffing from 65.2.161.68 against root account |
| **Execution** | Command and Scripting Interpreter | Unix Shell | T1059.004 | Post-compromise commands executed via interactive SSH shell (Session 37) |
| **Persistence** | Create Account | Local Account | T1136.001 | `useradd cyberjunkie` — backdoor local account created for persistent access |
| **Privilege Escalation** | Abuse Elevation Control Mechanism | Sudo and Sudo Caching | T1548.003 | `usermod -aG sudo cyberjunkie` — backdoor account granted full sudo privileges |
| **Defense Evasion** | Use Alternate Authentication Material | — | T1550 | Pivoting from root session to cyberjunkie account avoids continued root exposure |
| **Command & Control / Exfil** | Ingress Tool Transfer | — | T1105 | `sudo curl` used to download linper.sh from external GitHub URL |

---

## Technique Detail

### T1110.001 — Brute Force: Password Guessing
**What happened:** Attacker ran an automated credential tool against the SSH service on port 22. 165+ failed attempts from `65.2.161.68` recorded before root credentials were found.

**Detection opportunity:**
- Alert on ≥10 failed SSH auth attempts from a single IP within 60 seconds
- Monitor for `sshd: Failed password` volume spikes in auth.log / SIEM
- Deploy Fail2Ban or equivalent to auto-block offending IPs

---

### T1136.001 — Create Account: Local Account
**What happened:** After gaining root access, attacker created `cyberjunkie` — a new local user account — to maintain persistent access independent of the root credentials.

**Detection opportunity:**
- Alert on `useradd` / `adduser` events on servers (especially production systems)
- Monitor for new accounts added to `sudo` or `wheel` groups
- Baseline expected user accounts and alert on deviations

---

### T1548.003 — Abuse Elevation Control: Sudo
**What happened:** `cyberjunkie` was immediately added to the sudo group via `usermod -aG sudo`. This grants the account full root-equivalent privileges via `sudo`.

**Detection opportunity:**
- Monitor `usermod` events that modify group membership
- Alert specifically on additions to `sudo`, `wheel`, `admin` groups
- Audit `/etc/sudoers` and `/etc/group` for unexpected changes

---

### T1105 — Ingress Tool Transfer
**What happened:** Using the `cyberjunkie` account, the attacker executed `sudo /usr/bin/curl` to download `linper.sh` — a Linux persistence toolkit — from a raw GitHub URL.

**Detection opportunity:**
- Alert on curl/wget executed with sudo privileges
- Monitor outbound connections from servers to `raw.githubusercontent.com`
- Implement egress filtering to block unexpected outbound HTTP/HTTPS from internal servers

---

## Detection Rule Ideas (Elastic / Splunk)

```
# Brute force detection — auth.log
event.outcome: "failure" AND event.category: "authentication" 
  | threshold: ≥10 from same source.ip within 60s

# Account creation on server
event.action: "useradd" OR event.action: "adduser"
  | alert: new account created on production host

# Sudo group modification
event.action: "usermod" AND process.args: "*sudo*"
  | alert: account added to privileged group

# curl/wget with sudo
event.category: "process" AND process.name: ("curl" OR "wget") 
  AND process.args: "*githubusercontent*"
  | alert: suspicious outbound download via curl
```
