import subprocess
print("SSH Log Analyzer")
print("=================")
result=subprocess.run(
    ["sudo","journalctl","-u","ssh","--since","24 hours ago","--no-pager"],
    capture_output=True, text=True
)
print(result.stdout)