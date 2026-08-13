print("SSH Log Analyzer")
print("================")
successful=1
failed=3
print("SSH Security Summary")
print("--------------------")
print(f"Successful Logins: {successful}")
print(f"Failed Logins: {failed}")
if failed > 0:
    print("Warning: Failed Logins Detected!")
else:
    print("No Failed Logins Detected.")