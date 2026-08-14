from datetime import datetime
import re
import subprocess
print("SSH Log Analyzer")
print("=================")
result = subprocess.run(
    ["sudo", "journalctl", "-u", "ssh", "--since", "7 days ago", "--no-pager"],
    capture_output=True,
    text=True
)
logs = result.stdout.splitlines()
print(f"Total log lines retrieved: {len(logs)}")
events = []
for line in logs:
    match = re.search(
        r"Failed password for (\S+) from (\S+) port (\d+)",
        line
    )

    if match:
        timestamp_text = " ".join(line.split()[:3])
        timestamp = datetime.strptime(
            f"{datetime.now().year} {timestamp_text}",
            "%Y %b %d %H:%M:%S"
        )

        event = {
            "timestamp": timestamp,
            "event_type": "failed_login",
            "username": match.group(1),
            "source_ip": match.group(2),
            "source_port": match.group(3)
        }

        events.append(event)
events_by_ip = {}
for event in events:
    ip = event["source_ip"]

    if ip not in events_by_ip:
        events_by_ip[ip] = []

    events_by_ip[ip].append(event)
threshold = 3
window_seconds = 60
for ip, ip_events in events_by_ip.items():
    for i in range(len(ip_events)):
        window_start = ip_events[i]["timestamp"]
        count = 0
        for event in ip_events[i:]:
            difference = (event["timestamp"] - window_start).total_seconds()
            if difference <= window_seconds:
                count += 1
            else:
                break
        if count >= threshold:
            print(f"Alert: Possible SSH brute-force activity from {ip}!")
            print(
                f"{len(events)} failed attempts occurred within "
                f"{int(difference)} seconds."
            )
            break