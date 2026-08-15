# SSH Log analyser

A Python-based Linux security log analyser that collects SSH authentication events from `systemd-journald`, parses them into structured events, and detects suspicious authentication activity such as SSH brute-force attempts and successful logins following repeated failures.

The project was built as a practical cybersecurity learning project focused on **Linux logging, authentication telemetry, detection engineering, event correlation, and security automation**.

---

## Features

- Collects SSH authentication logs from `systemd-journald`
- Parses successful and failed SSH authentication events
- Extracts:
  - Timestamps
  - Usernames
  - Source IP addresses
  - Source ports
  - Authentication methods
- Groups authentication activity by source IP
- Detects SSH brute-force patterns using configurable thresholds
- Correlates repeated failed logins with subsequent successful logins
- Assigns severity levels to detected activity
- Supports configurable analysis periods and detection windows
- Exports security alerts to JSON and CSV
- Includes automated unit tests for parsing and detection logic
- Uses only Python's standard library

---

## Detection Rules

### 1. SSH Brute Force

Detects repeated failed SSH authentication attempts from the same source IP within a configurable time window.

**Default configuration:**

```text
Threshold: 3 failed attempts
Window:    60 seconds
Severity:  HIGH
Rule ID:   SSH_BRUTE_FORCE
```

Example:

```text
FAILED → FAILED → FAILED
          ↓
    3 attempts / 60 seconds
          ↓
       HIGH ALERT
```

---

### 2. Brute Force Followed by Successful Login

Detects a successful SSH authentication following repeated failed attempts from the same source IP within the configured detection window.

**Default configuration:**

```text
Threshold: 3 failed attempts
Window:    60 seconds
Severity:  CRITICAL
Rule ID:   SSH_BRUTE_FORCE_SUCCESS
```

Example:

```text
FAILED → FAILED → FAILED → SUCCESS
                    ↓
          Correlated activity
                    ↓
             CRITICAL ALERT
```

This rule is designed to identify situations where repeated authentication failures are followed by a successful login.

---

## Architecture

```text
                 systemd-journald
                        │
                        ▼
                 Log Collection
                        │
                        ▼
                  Event Parsing
                        │
                        ▼
                Structured Events
                        │
                        ▼
                Detection Engine
                 ┌──────┴──────┐
                 │             │
                 ▼             ▼
          Brute-Force      Correlation
           Detection        Detection
                 │             │
                 └──────┬──────┘
                        ▼
                  Alert Objects
                        │
              ┌─────────┼─────────┐
              │         │         │
              ▼         ▼         ▼
           Terminal    JSON       CSV
```

---

## Event Processing

Raw journal entries are converted into structured Python dictionaries.

For example:

```python
{
    "timestamp": "...",
    "event_type": "failed_login",
    "username": "kali",
    "source_ip": "192.168.1.50",
    "source_port": 50000,
    "auth_method": "password"
}
```

This normalization allows the detection engine to operate on structured security events instead of raw log strings.

---

## Alert Structure

Detected activity is represented using standardized alert objects.

Example:

```json
{
    "severity": "HIGH",
    "rule": "SSH_BRUTE_FORCE",
    "source_ip": "192.168.1.50",
    "description": "3 failed SSH authentication attempts within 60 seconds."
}
```

Correlation alerts can additionally contain contextual information such as the affected username.

---

## Command-Line Usage

Run the analyser with the default configuration:

```bash
python3 analyser.py
```

Display available options:

```bash
python3 analyser.py --help
```

Example help output:

```text
usage: analyser.py [-h] [--days DAYS] [--threshold THRESHOLD] [--window WINDOW]
                   [--format {json,csv,both}]
```

### Configure the Analysis Period

Analyze logs from the last 7 days:

```bash
python3 analyser.py --days 7
```

### Change the Brute-Force Threshold

Require 5 failed attempts before triggering the brute-force rule:

```bash
python3 analyser.py --threshold 5
```

### Change the Detection Window

Use a 120-second detection window:

```bash
python3 analyser.py --threshold 3 --window 120
```

### Select an Output Format

JSON:

```bash
python3 analyser.py --format json
```

CSV:

```bash
python3 analyser.py --format csv
```

Both:

```bash
python3 analyser.py --format both
```

---

## Example Output

```text
SSH Log analyser
================

Total log lines retrieved: 49

Authentication Summary
----------------------
Successful logins: 2
Failed logins:     6

Security Alerts
---------------

[HIGH] SSH_BRUTE_FORCE
Source: ::1
Description: 3 failed SSH authentication attempts within 60 seconds.

[CRITICAL] SSH_BRUTE_FORCE_SUCCESS
Source: ::1
Description: Successful SSH login after 3 failed authentication attempts.
Username: kali
```

---

## Testing

The project includes automated tests using Python's built-in `unittest` framework.

Run the complete test suite:

```bash
python3 -m unittest tests.test
```

Current test coverage includes:

- Failed authentication parsing
- Successful authentication parsing
- Irrelevant log handling
- Brute-force detection
- Insufficient-failure handling
- Source-IP separation
- Failed → successful authentication correlation
- Successful authentication without preceding failures
- Temporal boundaries for correlation detection

Current result:

```text
.........
----------------------------------------------------------------------
Ran 9 tests

OK
```

---

## Project Structure

```text
ssh-analyser/
│
├── analyser.py
├── README.md
├── .gitignore
│
├── tests/
│   ├── __init__.py
│   └── test.py
│
└── Screenshots/
```

`alerts.json` and `alerts.csv` are generated at runtime and excluded from version control.

---

## Requirements

- Linux system using `systemd-journald`
- Python 3
- SSH service/logs available through `journalctl`
- `sudo` access for reading the SSH journal

No external Python packages are required.

The project uses Python's standard library, including:

- `argparse`
- `csv`
- `datetime`
- `json`
- `re`
- `subprocess`
- `unittest`

---

## Security Concepts Demonstrated

This project focuses on several practical security engineering concepts:

- Linux system logging
- SSH authentication telemetry
- Log parsing
- Regular expressions
- Event normalization
- Source-IP analysis
- Time-window detection
- Brute-force detection
- Event correlation
- Severity classification
- False-positive testing
- Security alert generation
- Machine-readable security data
- Python automation
- Unit testing

---

## Limitations

This project is intentionally scoped as a local SSH log analyser.

Current limitations include:

- Primarily focused on SSH authentication events
- Uses `systemd-journald` as its log source
- Detection rules are currently static rather than externally configurable
- No persistent alert database
- No web dashboard
- No real-time monitoring daemon
- No distributed log collection

These limitations provide potential directions for future versions.

---

## Future Development

Potential future improvements include:

- Additional SSH detection rules
- Real-time log monitoring
- Persistent alert storage
- More sophisticated event correlation
- Configuration files for detection rules
- Alert deduplication
- Integration with a SIEM/SOC environment
- Web-based visualization
- Integration with the Home SOC project

---

## Development Progress

Screenshots documenting the development and testing process are available in the [`Screenshots/`](Screenshots/) directory.

---

## Project Status

**Version: 1.0**

The current version implements the core log collection, event parsing, detection, correlation, alerting, export, CLI configuration, and automated testing functionality.