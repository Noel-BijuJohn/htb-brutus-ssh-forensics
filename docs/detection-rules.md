# Detection Rules — SSH Brute Force & Post-Compromise Activity

Rules derived from the attack patterns observed in the HTB Brutus investigation.
Each rule targets a specific attacker behaviour identified in the `auth.log` and `wtmp` artifacts.

---

## 1 — SSH Brute Force: High Volume Failures from Single IP

**Behaviour:** Attacker sent 165+ failed SSH login attempts from `65.2.161.68` in a short window.

### Elastic (KQL + Threshold Rule)
```
event.dataset: "system.auth" AND
event.outcome: "failure" AND
event.category: "authentication" AND
process.name: "sshd"
```
> Rule type: **Threshold** — group by `source.ip`, threshold ≥ 10 within 60 seconds
> Severity: Medium → escalate to High if threshold exceeds 50

### Splunk SPL
```spl
index=linux_logs sourcetype=syslog "Failed password" "sshd"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 10
| sort -count
```

### Sigma Rule
```yaml
title: SSH Brute Force - High Volume Failed Logins
id: a1b2c3d4-0001-4000-8000-brutus-rule-01
status: stable
description: Detects high volume of failed SSH authentication attempts from a single source IP, consistent with automated brute force tooling such as Hydra or Medusa.
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: Noel Biju John
date: 2026-03-01
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: auth
detection:
  selection:
    process.name: sshd
    event.outcome: failure
  condition: selection | count() by source.ip > 10
falsepositives:
  - Misconfigured automation or monitoring tools
  - Legitimate penetration testing activity
level: medium
```

---

## 2 — SSH Brute Force Success: Accepted Password After Failures

**Behaviour:** After 165 failures, attacker successfully authenticated as root — `Accepted password for root` in auth.log.

### Elastic (EQL Sequence Rule)
```eql
sequence by source.ip with maxspan=5m
  [authentication where event.outcome == "failure" and process.name == "sshd"]
  [authentication where event.outcome == "failure" and process.name == "sshd"]
  [authentication where event.outcome == "failure" and process.name == "sshd"]
  [authentication where event.outcome == "success" and process.name == "sshd"]
```
> Rule type: **EQL Sequence** — detects failures followed by success from same IP within 5 minutes
> Severity: **High**

### Splunk SPL
```spl
index=linux_logs sourcetype=syslog "sshd"
| rex field=_raw "(?P<status>Failed password|Accepted password) for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval success=if(status="Accepted password", 1, 0)
| stats sum(success) as successes, count as total by src_ip, user
| where successes > 0 AND total > 5
```

### Sigma Rule
```yaml
title: SSH Brute Force Followed by Successful Login
id: a1b2c3d4-0002-4000-8000-brutus-rule-02
status: stable
description: Detects a successful SSH login following multiple failed attempts from the same source IP — indicating a successful brute force attack.
author: Noel Biju John
date: 2026-03-01
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: auth
detection:
  failures:
    process.name: sshd
    event.outcome: failure
  success:
    process.name: sshd
    event.outcome: success
  condition: failures | count() by source.ip > 5 and success
falsepositives:
  - Legitimate users with expired passwords
level: high
```

---

## 3 — Privileged Account SSH Login (Root Login via SSH)

**Behaviour:** Root account logged in directly via SSH — a configuration that should be disabled on any hardened system.

### Elastic (KQL)
```
event.dataset: "system.auth" AND
event.outcome: "success" AND
process.name: "sshd" AND
user.name: "root"
```
> Rule type: **Query** — any match should alert
> Severity: **High** — root SSH login should never occur on a hardened system

### Splunk SPL
```spl
index=linux_logs sourcetype=syslog "Accepted password for root"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, src_ip, host
```

---

## 4 — New Local User Account Created

**Behaviour:** Attacker created `cyberjunkie` backdoor account using `useradd` during Session 37.

### Elastic (KQL)
```
event.dataset: "system.auth" AND
event.action: "added-user-account" AND
process.name: ("useradd" OR "adduser")
```

### Splunk SPL
```spl
index=linux_logs sourcetype=syslog ("useradd" OR "adduser" OR "new user")
| rex field=_raw "new user: name=(?P<new_user>\S+)"
| table _time, host, new_user
```

### Sigma Rule
```yaml
title: New Local User Account Created on Linux
id: a1b2c3d4-0003-4000-8000-brutus-rule-03
status: stable
description: Detects creation of a new local user account on a Linux system. On servers, new account creation is unusual and may indicate attacker persistence activity.
author: Noel Biju John
date: 2026-03-01
tags:
  - attack.persistence
  - attack.t1136.001
logsource:
  product: linux
  service: auth
detection:
  selection:
    process.name:
      - useradd
      - adduser
  condition: selection
falsepositives:
  - Legitimate user provisioning via configuration management (Ansible, Puppet)
  - Onboarding automation
level: medium
```

---

## 5 — Account Added to Privileged Group (sudo / wheel)

**Behaviour:** Attacker immediately ran `usermod -aG sudo cyberjunkie` — granting the backdoor account full administrative privileges.

### Elastic (KQL)
```
event.dataset: "system.auth" AND
process.name: "usermod" AND
process.args: (*sudo* OR *wheel* OR *admin*)
```

### Splunk SPL
```spl
index=linux_logs sourcetype=syslog "usermod"
| rex field=_raw "to group '(?P<group>\S+)'"
| where group IN ("sudo", "wheel", "admin", "root")
| table _time, host, group
```

### Sigma Rule
```yaml
title: User Added to Privileged Group on Linux
id: a1b2c3d4-0004-4000-8000-brutus-rule-04
status: stable
description: Detects a user being added to a privileged group (sudo, wheel, admin) on Linux. Commonly used by attackers to maintain elevated access via a backdoor account.
author: Noel Biju John
date: 2026-03-01
tags:
  - attack.privilege_escalation
  - attack.t1548.003
logsource:
  product: linux
  service: auth
detection:
  selection:
    process.name: usermod
    process.args|contains:
      - sudo
      - wheel
      - admin
  condition: selection
falsepositives:
  - Legitimate privilege assignment by system administrators
level: high
```

---

## 6 — Suspicious Download via sudo curl / wget

**Behaviour:** Attacker used `sudo /usr/bin/curl` to download `linper.sh` — a Linux persistence toolkit — from a raw GitHub URL.

### Elastic (KQL)
```
event.dataset: "system.auth" AND
event.action: "sudo" AND
process.args: (*curl* OR *wget*) AND
process.args: (*githubusercontent* OR *pastebin* OR *raw.*)
```

### Splunk SPL
```spl
index=linux_logs sourcetype=syslog "sudo" ("curl" OR "wget")
| rex field=_raw "COMMAND=(?P<cmd>.+)"
| where match(cmd, "githubusercontent|pastebin|transfer\.sh|raw\.")
| table _time, host, user, cmd
```

### Sigma Rule
```yaml
title: Suspicious Download via sudo curl or wget
id: a1b2c3d4-0005-4000-8000-brutus-rule-05
status: stable
description: Detects use of curl or wget with sudo to download content from external URLs. Commonly used by attackers to pull persistence scripts or payloads from GitHub or paste sites.
author: Noel Biju John
date: 2026-03-01
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  product: linux
  service: auth
detection:
  selection:
    event.action: sudo
    process.name:
      - curl
      - wget
    process.args|contains:
      - githubusercontent
      - pastebin
      - raw.
  condition: selection
falsepositives:
  - Legitimate admin scripts that download configuration from trusted repos
level: high
```

---

## Correlation Rule — Full Attack Chain

Combine all the above to detect the complete brute force → persistence sequence:

```
Step 1: ≥10 SSH failures from same source.ip within 60s         → T1110.001
Step 2: SSH success from same source.ip after failures           → T1110.001
Step 3: root login via SSH                                       → alert immediately
Step 4: useradd or adduser executed within 10m of SSH login      → T1136.001
Step 5: usermod with sudo/wheel/admin group                      → T1548.003
Step 6: sudo curl/wget to external URL within 30m of login       → T1105
```

If steps 1 → 6 all occur from the same host within a 30-minute window — **treat as confirmed compromise**.

---

## Rule Import Notes

- **Elastic rules** (`.ndjson` format): import via Kibana → Security → Rules → Import
- **Sigma rules**: convert to target format using [sigmac](https://github.com/SigmaHQ/sigma) or [pySigma](https://github.com/SigmaHQ/pySigma)
- **Splunk**: paste SPL into a new saved search or scheduled alert
