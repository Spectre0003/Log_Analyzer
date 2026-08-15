# SSH Log Analyser

A Python-based security log analysis tool for detecting suspicious SSH authentication activity on Linux systems.

## Features

- Parses SSH authentication logs from systemd journal
- Detects failed SSH authentication attempts
- Detects successful SSH logins
- Groups authentication events by source IP
- Detects brute-force authentication patterns
- Detects successful logins following repeated failures
- Uses configurable detection thresholds and time windows
- Assigns severity levels to security alerts
- Exports alerts to JSON and CSV
- Includes automated unit tests

## Detection Rules

### SSH Brute Force

Detects repeated failed authentication attempts from the same source IP within a configurable time window.

Default:

- Threshold: 3 failures
- Window: 60 seconds
- Severity: HIGH

### Brute Force Followed by Successful Login

Detects a successful SSH login following repeated failed authentication attempts from the same source IP.

Default:

- Threshold: 3 failures
- Window: 60 seconds
- Severity: CRITICAL

## Usage

### Run with default settings:

python3 analyser.py

### Show help:

python3 analyser.py --help

### Customize detection:

python3 analyser.py --days 7 --threshold 5 --window 120

### Choose output format:

python3 analyser.py --format json
python3 analyser.py --format csv
python3 analyser.py --format both

### Run the automated tests:

python3 tests/test.py
