import os
import re
import csv
import time
import json
import fcntl
import socket
import struct
import platform
import datetime
import netifaces
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Set
from collections import defaultdict

class FirewallManager:
    """Abstract base class for firewall management"""
    def initialize(self):
        raise NotImplementedError

    def block_ip(self, ip: str) -> bool:
        raise NotImplementedError

    def unblock_ip(self, ip: str) -> bool:
        raise NotImplementedError

    def cleanup(self):
        raise NotImplementedError

class WindowsFirewall(FirewallManager):
    def initialize(self):
        try:
            # Check if we have admin privileges
            if not self._is_admin():
                print("Warning: Administrator privileges required for firewall management")
                return False

            # Create a new firewall rule group
            subprocess.run([
                "netsh", "advfirewall", "set", "allprofiles", "state", "on"
            ], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error initializing Windows Firewall: {e}")
            return False

    def block_ip(self, ip: str) -> bool:
        try:
            rule_name = f"BlockIP_{ip.replace('.', '_')}"
            
            # Block outbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + rule_name + "_out",
                "dir=out",
                "action=block",
                "remoteip=" + ip
            ], check=True)

            # Block inbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + rule_name + "_in",
                "dir=in",
                "action=block",
                "remoteip=" + ip
            ], check=True)

            return True
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP in Windows Firewall: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        try:
            rule_name = f"BlockIP_{ip.replace('.', '_')}"
            
            # Remove outbound rule
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + rule_name + "_out"
            ], check=True)

            # Remove inbound rule
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + rule_name + "_in"
            ], check=True)

            return True
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP in Windows Firewall: {e}")
            return False

    def cleanup(self):
        try:
            # Clean up all rules created by this program
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=BlockIP_*"
            ], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error cleaning up Windows Firewall rules: {e}")

    def _is_admin(self):
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

class LinuxFirewall(FirewallManager):
    def initialize(self):
        try:
            if os.geteuid() != 0:
                print("Warning: Root privileges required for firewall management")
                return False

            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error initializing iptables: {e}")
            return False

    def block_ip(self, ip: str) -> bool:
        try:
            # Block outbound
            subprocess.run([
                "iptables", "-A", "OUTPUT", 
                "-d", ip, 
                "-j", "DROP"
            ], check=True)

            # Block inbound
            subprocess.run([
                "iptables", "-A", "INPUT", 
                "-s", ip, 
                "-j", "DROP"
            ], check=True)

            return True
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP in iptables: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        try:
            # Remove outbound block
            subprocess.run([
                "iptables", "-D", "OUTPUT", 
                "-d", ip, 
                "-j", "DROP"
            ], check=True)

            # Remove inbound block
            subprocess.run([
                "iptables", "-D", "INPUT", 
                "-s", ip, 
                "-j", "DROP"
            ], check=True)

            return True
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP in iptables: {e}")
            return False

    def cleanup(self):
        try:
            subprocess.run(["iptables", "-F"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error cleaning up iptables rules: {e}")

class NetworkMonitor:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.logs_dir = self.script_dir / 'logs'
        self.logs_dir.mkdir(exist_ok=True)
        
        self.active_apps = set()
        self.start_time = datetime.datetime.now()
        self.blocked_ips: Set[str] = set()

        # Initialize OS-specific firewall
        self.os_type = platform.system().lower()
        if self.os_type == "windows":
            self.firewall = WindowsFirewall()
        else:  # Linux
            self.firewall = LinuxFirewall()
        
        # Initialize firewall
        self.firewall.initialize()
        
        # Rest of your initialization code...
        [Previous initialization code remains the same]

    def block_ip(self, ip: str) -> bool:
        """
        Block outgoing traffic to a specific IP address (cross-platform)
        
        Args:
            ip (str): IP address to block
            
        Returns:
            bool: True if blocking was successful, False otherwise
        """
        try:
            if not self._validate_ip(ip):
                print(f"Invalid IP address format: {ip}")
                return False

            if self.firewall.block_ip(ip):
                self.blocked_ips.add(ip)
                print(f"Successfully blocked IP: {ip}")
                self._log_blocking_action(ip, "BLOCK")
                return True
            return False

        except Exception as e:
            print(f"Unexpected error while blocking IP {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock previously blocked IP address (cross-platform)
        
        Args:
            ip (str): IP address to unblock
            
        Returns:
            bool: True if unblocking was successful, False otherwise
        """
        try:
            if not self._validate_ip(ip):
                print(f"Invalid IP address format: {ip}")
                return False

            if self.firewall.unblock_ip(ip):
                self.blocked_ips.remove(ip)
                print(f"Successfully unblocked IP: {ip}")
                self._log_blocking_action(ip, "UNBLOCK")
                return True
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
                writer.writerow(['timestamp', 'ip', 'action', 'platform'])
        
        # Log the action
        with open(log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, ip, action, self.os_type])

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)

    def _cleanup(self):
        """Cleanup firewall rules on exit"""
        try:
            self.firewall.cleanup()
            print("Firewall rules cleaned up successfully")
        except Exception as e:
            print(f"Error cleaning up firewall rules: {e}")

    # ... (rest of the original NetworkMonitor class remains the same) ...

if __name__ == "__main__":
    monitor = NetworkMonitor()
    
    # Example usage:
    # monitor.block_ip("1.2.3.4")
    monitor.monitor()
