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
failed=[]
for line in logs:
    if "Accepted" in line:
        successful.append(line)
for line in logs:
    if "Failed" in line:
        failed.append(line)
print(f"Successful Logins: {len(successful)}")
for line in successful:
    print(line)
print(f"Failed Logins: {len(failed)}")
for line in failed:
    print(line)