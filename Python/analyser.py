from datetime import datetime
import re
import subprocess
import argparse
import json
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
    return parser.parse_args()
args=parse_arguments()
LOOKBACK=f"{args.days} days ago"
FAILURE_THRESHOLD=args.threshold
WINDOW_SECONDS=args.window
def collect_logs():
	result = subprocess.run(
		["sudo","journalctl","-u","ssh","--since",LOOKBACK,"--no-pager"],
		capture_output=True,
		text=True
	)
	if result.returncode!=0:
		print("Error:Failed to retrieve logs.")
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
def detect_bruteforce(events):
	events_by_ip={}
	for event in events:
		ip=event["source_ip"]
		if ip not in events_by_ip:
			events_by_ip[ip]=[]
		events_by_ip[ip].append(event)
	alerts=[]
	for ip, ip_events in events_by_ip.items():
		for i in range(len(ip_events)):
			window_start=ip_events[i]["timestamp"]
			count=0
			for event in ip_events[i:]:
				difference=(event["timestamp"]-window_start).total_seconds()
				if difference<=WINDOW_SECONDS:
					count+=1
				else:
					break
			if count>=FAILURE_THRESHOLD:
				alerts.append({
				    "severity": "HIGH",
				    "rule": "SSH_BRUTE_FORCE",
				    "source_ip": ip,
				    "description": (
					f"{count} failed SSH authentication attempts "
					f"within {WINDOW_SECONDS} seconds."
				    )
				})
				break
	return alerts
def detect_success_after_failures(events):
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
                if difference <= WINDOW_SECONDS:
                    if previous_event["event_type"] == "failed_login":
                        failure_count += 1
                else:
                    break
            if failure_count >= FAILURE_THRESHOLD:
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
logs = collect_logs()
print("SSH Log Analyzer")
print("================")
print(f"Total log lines retrieved: {len(logs)}")
print()
events = parse_events(logs)
successful_count = sum(
    1 for event in events
    if event["event_type"] == "successful_login"
)
failed_count = sum(
    1 for event in events
    if event["event_type"] == "failed_login"
)
print("Authentication Summary")
print("----------------------")
print(f"Successful logins: {successful_count}")
print(f"Failed logins:     {failed_count}")
print()
alerts = detect_bruteforce(events)
correlation_alerts=detect_success_after_failures(events)
print()
all_alerts = alerts + correlation_alerts
export_json(all_alerts, "alerts.json")
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
