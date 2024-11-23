#!/bin/bash
set -e

# Initialize iptables
sudo iptables -F
sudo ip6tables -F

# Create required iptables chains if they don't exist
sudo iptables -N FIREWALL_CUSTOM 2>/dev/null || true
sudo iptables -A OUTPUT -j FIREWALL_CUSTOM

sudo ip6tables -N FIREWALL_CUSTOM 2>/dev/null || true
sudo ip6tables -A OUTPUT -j FIREWALL_CUSTOM


echo "Ensuring proper permissions..."
chmod -R 777 /app/logs

echo "Starting network monitor..."
exec python /app/network_control.py