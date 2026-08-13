import subprocess
print("SSH Log Analyzer")
print("=================")
result = subprocess.run(
    ["sudo", "journalctl", "-u", "ssh", "--since", "24 hours ago", "--no-pager"],
    capture_output=True,
    text=True
)
logs = result.stdout.splitlines()
successful = []
for line in logs:
    if "Accepted" in line:
        successful.append(line)
print(f"Successful Logins: {len(successful)}")
for line in successful:
    print(line)