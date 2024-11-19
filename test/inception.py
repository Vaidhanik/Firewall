import os
import re
import csv
import time
import json
import fcntl
import socket
import struct
import datetime
import netifaces
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Set
from collections import defaultdict

class NetworkMonitor:
    def __init__(self):
        # ... (previous __init__ code remains the same) ...
        
        # Add blocked IPs set
        self.blocked_ips: Set[str] = set()
        # Initialize firewall rules
        self._initialize_firewall()
    
    def _initialize_firewall(self):
        """Initialize firewall by flushing existing rules and setting up base rules"""
        try:
            # Ensure we have root privileges
            if os.geteuid() != 0:
                print("Warning: Root privileges required for firewall management")
                return

            # Flush existing rules
            subprocess.run(["iptables", "-F"], check=True)
            
            # Set default policies
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
            
            print("Firewall initialized successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error initializing firewall: {e}")
        except Exception as e:
            print(f"Unexpected error in firewall initialization: {e}")

    def block_ip(self, ip: str) -> bool:
        """
        Block outgoing traffic to a specific IP address
        
        Args:
            ip (str): IP address to block
            
        Returns:
            bool: True if blocking was successful, False otherwise
        """
        try:
            if not self._validate_ip(ip):
                print(f"Invalid IP address format: {ip}")
                return False

            if os.geteuid() != 0:
                print("Root privileges required for blocking IPs")
                return False

            # Add rules to block outgoing traffic to the IP
            subprocess.run([
                "iptables", "-A", "OUTPUT", 
                "-d", ip, 
                "-j", "DROP"
            ], check=True)

            # Add rules to block incoming traffic from the IP
            subprocess.run([
                "iptables", "-A", "INPUT", 
                "-s", ip, 
                "-j", "DROP"
            ], check=True)

            self.blocked_ips.add(ip)
            print(f"Successfully blocked IP: {ip}")
            
            # Log the blocking action
            self._log_blocking_action(ip, "BLOCK")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error while blocking IP {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock previously blocked IP address
        
        Args:
            ip (str): IP address to unblock
            
        Returns:
            bool: True if unblocking was successful, False otherwise
        """
        try:
            if not self._validate_ip(ip):
                print(f"Invalid IP address format: {ip}")
                return False

            if os.geteuid() != 0:
                print("Root privileges required for unblocking IPs")
                return False

            # Remove blocking rules
            subprocess.run([
                "iptables", "-D", "OUTPUT", 
                "-d", ip, 
                "-j", "DROP"
            ], check=True)

            subprocess.run([
                "iptables", "-D", "INPUT", 
                "-s", ip, 
                "-j", "DROP"
            ], check=True)

            self.blocked_ips.remove(ip)
            print(f"Successfully unblocked IP: {ip}")
            
            # Log the unblocking action
            self._log_blocking_action(ip, "UNBLOCK")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP {ip}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error while unblocking IP {ip}: {e}")
            return False

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _log_blocking_action(self, ip: str, action: str):
        """Log IP blocking/unblocking actions"""
        timestamp = datetime.datetime.now().isoformat()
        log_file = self.logs_dir / 'ip_blocking.csv'
        
        # Create log file with headers if it doesn't exist
        if not log_file.exists():
            with open(log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'ip', 'action'])
        
        # Log the action
        with open(log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, ip, action])

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)

    # ... (rest of the original code remains the same) ...

    def monitor(self):
        """Main monitoring loop with blocking check"""
        print("\nNetwork Monitor Started")
        print(f"Logs directory: {self.logs_dir}")
        print("\nMonitoring network connections (Press Ctrl+C to stop)...")
        print("-" * 80)
        
        try:
            while True:
                connections = self.get_connections()
                for conn in connections:
                    if conn['state'] == 'ESTABLISHED' or conn['protocol'] == 'udp':
                        # Check if the remote IP is blocked
                        if conn['remote_addr'] in self.blocked_ips:
                            print(f"Blocked connection attempt to {conn['remote_addr']} by {conn['program']}")
                        self.log_connection(conn)
                self.update_stats(connections)
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nStopping Monitor...")
            self._cleanup()
            # ... (rest of the original cleanup code) ...

    def _cleanup(self):
        """Cleanup firewall rules on exit"""
        try:
            if os.geteuid() == 0:
                # Remove all blocking rules
                subprocess.run(["iptables", "-F"], check=True)
                print("Firewall rules cleaned up successfully")
        except Exception as e:
            print(f"Error cleaning up firewall rules: {e}")

if __name__ == "__main__":
    monitor = NetworkMonitor()
    # Example of blocking an IP
    # monitor.block_ip("1.2.3.4")
    monitor.monitor()
