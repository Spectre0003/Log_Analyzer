from datetime import datetime
import re
import subprocess
import argparse
import json
import csv
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs for suspicious activity."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days of SSH logs to analyze."
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of failed attempts required to trigger detection."
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Time window in seconds for brute-force detection."
    )
    parser.add_argument(
	    "--format",
	    choices=["json", "csv", "both"],
	    default="both",
	    help="Output format for alerts."
    )
    return parser.parse_args()
def collect_logs(lookback):
    result = subprocess.run(
        [
            "sudo",
            "journalctl",
            "-u",
            "ssh",
            "--since",
            lookback,
            "--no-pager"
        ],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print("Error: Failed to retrieve SSH logs.")
        return []
    return result.stdout.splitlines()
def parse_events(logs):
    events = []
    for line in logs:
        failed_match = re.search(
            r"Failed password for (\S+) from (\S+) port (\d+)",
            line
        )
        if failed_match:
            timestamp_text = " ".join(line.split()[:3])

            timestamp = datetime.strptime(
                f"{datetime.now().year} {timestamp_text}",
                "%Y %b %d %H:%M:%S"
            )
            event = {
                "timestamp": timestamp,
                "event_type": "failed_login",
                "username": failed_match.group(1),
                "source_ip": failed_match.group(2),
                "source_port": int(failed_match.group(3)),
                "auth_method": "password"
            }
            events.append(event)
            continue
        accepted_match = re.search(
            r"Accepted (password|publickey) for (\S+) from (\S+) port (\d+)",
            line
        )
        if accepted_match:
            timestamp_text = " ".join(line.split()[:3])

            timestamp = datetime.strptime(
                f"{datetime.now().year} {timestamp_text}",
                "%Y %b %d %H:%M:%S"
            )
            event = {
                "timestamp": timestamp,
                "event_type": "successful_login",
                "username": accepted_match.group(2),
                "source_ip": accepted_match.group(3),
                "source_port": int(accepted_match.group(4)),
                "auth_method": accepted_match.group(1)
            }
            events.append(event)
    return events
def detect_bruteforce(events, threshold=3, window_seconds=60):
    events_by_ip = {}
    for event in events:
        ip = event["source_ip"]
        if ip not in events_by_ip:
            events_by_ip[ip] = []
        events_by_ip[ip].append(event)
    alerts = []
    for ip, ip_events in events_by_ip.items():
        for i in range(len(ip_events)):
            window_start = ip_events[i]["timestamp"]
            count = 0
            for event in ip_events[i:]:
                difference = (
                    event["timestamp"] - window_start
                ).total_seconds()
                if difference <= window_seconds:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "severity": "HIGH",
                    "rule": "SSH_BRUTE_FORCE",
                    "source_ip": ip,
                    "description": (
                        f"{count} failed SSH authentication attempts "
                        f"within {window_seconds} seconds."
                    )
                })
                break
    return alerts
def detect_success_after_failures(
    events,
    threshold=3,
    window_seconds=60
):
    alerts = []
    events_by_ip = {}
    for event in events:
        ip = event["source_ip"]
        if ip not in events_by_ip:
            events_by_ip[ip] = []
        events_by_ip[ip].append(event)
    for ip, ip_events in events_by_ip.items():
        for i, event in enumerate(ip_events):
            if event["event_type"] != "successful_login":
                continue
            success_time = event["timestamp"]
            failure_count = 0
            for previous_event in reversed(ip_events[:i]):
                difference = (
                    success_time - previous_event["timestamp"]
                ).total_seconds()
                if difference <= window_seconds:
                    if previous_event["event_type"] == "failed_login":
                        failure_count += 1
                else:
                    break
            if failure_count >= threshold:
                alerts.append({
		    "severity": "CRITICAL",
		    "rule": "SSH_BRUTE_FORCE_SUCCESS",
		    "source_ip": ip,
		    "description": (
			f"Successful SSH login after {failure_count} "
			f"failed authentication attempts."
		    ),
		    "username": event["username"]
		})
    return alerts
def export_json(alerts, filename):
    with open(filename, "w") as file:
        json.dump(alerts, file, indent=4)
def export_csv(alerts, filename):
    if not alerts:
        with open(filename, "w", newline="") as file:
            file.write("")
        return
    fieldnames = sorted({
        key
        for alert in alerts
        for key in alert.keys()
    })
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(alerts)
def main():
    args = parse_arguments()
    logs = collect_logs(f"{args.days} days ago")
    print("SSH Log Analyzer")
    print("================")
    print(f"Total log lines retrieved: {len(logs)}")
    events = parse_events(logs)
    successful_count = sum(
        1 for event in events
        if event["event_type"] == "successful_login"
    )
    failed_count = sum(
        1 for event in events
        if event["event_type"] == "failed_login"
    )
    print()
    print("Authentication Summary")
    print("----------------------")
    print(f"Successful logins: {successful_count}")
    print(f"Failed logins:     {failed_count}")
    alerts = detect_bruteforce(
	events,
	threshold=args.threshold,
	window_seconds=args.window
    )
    correlation_alerts = detect_success_after_failures(
	    events,
	    threshold=args.threshold,
	    window_seconds=args.window
    )
    all_alerts = alerts + correlation_alerts
    print()
    print("Security Alerts")
    print("---------------")
    if not all_alerts:
        print("No security alerts detected.")
    for alert in all_alerts:
        print(f"[{alert['severity']}] {alert['rule']}")
        print(f"Source: {alert['source_ip']}")
        print(f"Description: {alert['description']}")
        if "username" in alert:
            print(f"Username: {alert['username']}")
        print()
    if args.format in ["json", "both"]:
        export_json(all_alerts, "alerts.json")
    if args.format in ["csv", "both"]:
        export_csv(all_alerts, "alerts.csv")
if __name__ == "__main__":
    main()
