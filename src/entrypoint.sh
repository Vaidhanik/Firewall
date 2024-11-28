#!/bin/bash
set -e

# Initialize iptables
sudo iptables -F
sudo ip6tables -F

# Create required iptables chains if they don't exist
sudo iptables -N FIREWALL_CUSTOM 2>/dev/null || true
sudo iptables -A OUTPUT -j FIREWALL_CUSTOM || true

sudo ip6tables -N FIREWALL_CUSTOM 2>/dev/null || true
sudo ip6tables -A OUTPUT -j FIREWALL_CUSTOM || true

# Ensure proper permissions
mkdir -p /app/logs
chmod -R 777 /app/logs

# Initialize the database directory if using SQLite
mkdir -p /app/data
chmod -R 777 /app/data

# Start the Flask application
exec python /app/server.py