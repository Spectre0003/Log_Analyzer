#!/bin/bash
#Initial script running directly to check logins on ssh
get_ssh_logs() {
    sudo journalctl -u ssh --since "24 hours ago" --no-pager
}
successful=$(get_ssh_logs | grep "Accepted" | wc -l)
failed=$(get_ssh_logs | grep "Failed" | wc -l)
echo "SSH Security Summary"
echo "--------------------"
echo "Successful Logins: $successful"
echo "Failed Logins:     $failed"
if [ "$failed" -gt 0 ]; then
    echo "Warning: Failed Logins Detected!"
else
    echo "No Failed Logins Detected."
fi
echo ""
echo "Recent Failed Logins:"
echo "---------------------"
get_ssh_logs | grep "Failed"