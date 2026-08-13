#!/bin/bash
#Initial script running directly to check logins on ssh
successful= $(sudo journalctl -u ssh --since "24 hours ago" | grep "Accepted" | wc -l)
failed= $(sudo journalctl -u ssh --since "24 hours ago" | grep "Failed" | wc -l)
echo "Successful logins: $successful"
echo "Failed logins: $failed"
if [ "$failed" -gt 0 ]; then
    echo "Warning: Failed Logins Detected!"
fi
echo ""
echo "Recent Failed Logins:"
echo "---------------------"
sudo journalctl -u ssh --since "24 hours ago" --no-pager | grep "Failed"