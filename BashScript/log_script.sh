#!/bin/bash
#Initial script running directly to check logins on ssh
successful= $(sudo journalctl -u ssh --since "24 hours ago" | grep "Accepted password" | wc -l)
failed= $(sudo journalctl -u ssh --since "24 hours ago" | grep "Failed password" | wc -l)
echo "Successful logins: $successful"
echo "Failed logins: $failed"