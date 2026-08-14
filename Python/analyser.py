from datetime import datetime
import re
import subprocess
LOOKBACK="7 days ago"
FAILURE_THRESHOLD=3
WINDOW_SECONDS=60
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
				alerts.append({"source_ip":ip,"attempts":count,"window_seconds":WINDOW_SECONDS})
				break
	return alerts
	
logs = collect_logs()

print("SSH Log Analyzer")
print("================")
print(f"Total log lines retrieved: {len(logs)}")
events = parse_events(logs)
alerts = detect_bruteforce(events)
for alert in alerts:
    print(
        f"ALERT: Possible SSH brute-force activity "
        f"from {alert['source_ip']}!"
    )
    print(
        f"{alert['attempts']} failed attempts "
        f"within {alert['window_seconds']} seconds."
    )
