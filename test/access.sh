#!/bin/bash

# check_access.sh
echo "Checking network access..."
echo "1. Network interfaces:"
ip link show

echo -e "\n2. Process listing access:"
ps aux | head -n 5

echo -e "\n3. Netstat access:"
netstat -tuln

echo -e "\n4. ARP table:"
arp -n

echo -e "\n5. Network namespaces:"
ls -l /var/run/netns

echo -e "\n6. Process namespace:"
ls -l /proc/1/ns/

echo -e "\n7. System information:"
uname -a