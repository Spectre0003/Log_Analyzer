print("SSH Log Analyzer")
print("=================")
successful = 1
failed = 3
failed_logins=[
    "Failed login from ::1",
    "Failed login from 192.168.1.20",
    "Failed login from 162.170.2.20"
]
print("SSH Security Summary")
print("--------------------")
print(f"Successful Logins: {successful}")
print(f"Failed Logins: {failed}")
if failed > 0:
    print("Warning: Failed Logins Detected!")
else:
    print("No Failed Logins Detected.")

for login in failed_logins:
    print(login)