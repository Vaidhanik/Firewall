import os
import platform
from monitorv2 import NetworkMonitor
from inception import FirewallManager
from system import get_installed_apps
from typing import Dict, List, Set
import time

class NetworkController:
    def __init__(self):
        # Initialize components
        self.monitor = NetworkMonitor()
        self.firewall = FirewallManager()
        self.installed_apps = self.load_installed_apps()
        self.blocked_rules: Dict[str, Set[str]] = {}  # app -> set of blocked IPs

    def load_installed_apps(self) -> List[str]:
        """Load installed applications list"""
        try:
            return get_installed_apps()
        except OSError as e:
            print(f"Error loading applications: {e}")
            return []

    def block_app_network(self, app_name: str, ip: str) -> bool:
        """Block application from accessing specific IP/network"""
        if app_name not in self.installed_apps:
            print(f"Warning: Application '{app_name}' not found in installed apps")
            
        if app_name not in self.blocked_rules:
            self.blocked_rules[app_name] = set()
            
        if self.firewall.block_ip(app_name, ip):
            self.blocked_rules[app_name].add(ip)
            print(f"✓ Blocked {app_name} from accessing {ip}")
            return True
        return False

    def unblock_app_network(self, app_name: str, ip: str) -> bool:
        """Unblock application access to specific IP/network"""
        if app_name in self.blocked_rules and ip in self.blocked_rules[app_name]:
            if self.firewall.unblock_ip(app_name, ip):
                self.blocked_rules[app_name].remove(ip)
                print(f"✓ Unblocked {app_name} for {ip}")
                return True
        return False

    def monitor_with_control(self):
        """Monitor network with active blocking rules"""
        print("\nStarting Network Control System...")
        print(f"Monitoring {len(self.installed_apps)} applications")
        print("Press Ctrl+C to stop monitoring")
        
        try:
            while True:
                connections = self.monitor.get_connections()
                for conn in connections:
                    app_name = conn['program']
                    remote_ip = conn['remote_addr']
                    
                    # Check if connection should be blocked
                    if (app_name in self.blocked_rules and 
                        remote_ip in self.blocked_rules[app_name]):
                        print(f"⚠ Blocked connection: {app_name} → {remote_ip}")
                        continue
                    
                    # Log allowed connection
                    self.monitor.log_connection(conn)
                
                self.monitor.update_stats(connections)
                time.sleep(1)

        except KeyboardInterrupt:
            print("\nStopping Network Control System...")
            self._cleanup()

    def _cleanup(self):
        """Cleanup resources and save final logs"""
        # Remove firewall rules
        for app, ips in self.blocked_rules.items():
            for ip in ips:
                self.firewall.unblock_ip(app, ip)
        
        # Let monitor save its logs
        self.monitor._cleanup()

def display_menu():
    print("\n=== Network Control Menu ===")
    print("1. List installed applications")
    print("2. Block application's network access")
    print("3. Unblock application's network access")
    print("4. View current blocks")
    print("5. Start monitoring")
    print("6. Exit")
    return input("Select an option (1-6): ")

def main():
    controller = NetworkController()
    
    while True:
        choice = display_menu()
        
        if choice == "1":
            print("\nInstalled Applications:")
            for i, app in enumerate(controller.installed_apps, 1):
                print(f"{i}. {app}")
        
        elif choice == "2":
            print("\nEnter application name (or part of name to search):")
            search = input("> ").lower()
            
            # Find matching apps
            matches = [app for app in controller.installed_apps 
                      if search in app.lower()]
            
            if not matches:
                print("No matching applications found")
                continue
                
            # Display matches
            print("\nMatching applications:")
            for i, app in enumerate(matches, 1):
                print(f"{i}. {app}")
            
            # Get app selection
            app_idx = int(input("\nSelect application number: ")) - 1
            if 0 <= app_idx < len(matches):
                selected_app = matches[app_idx]
                
                # Get IP/domain to block
                print("\nEnter IP address or domain to block:")
                target = input("> ")
                
                if controller.block_app_network(selected_app, target):
                    print(f"\nSuccessfully blocked {selected_app} from accessing {target}")
                else:
                    print("\nFailed to create blocking rule")
                    
        elif choice == "3":
            if not controller.blocked_rules:
                print("\nNo active blocks found")
                continue
                
            print("\nCurrent blocks:")
            blocks = []
            for app, ips in controller.blocked_rules.items():
                for ip in ips:
                    blocks.append((app, ip))
                    print(f"{len(blocks)}. {app} ⟶ {ip}")
            
            idx = int(input("\nSelect block number to remove: ")) - 1
            if 0 <= idx < len(blocks):
                app, ip = blocks[idx]
                if controller.unblock_app_network(app, ip):
                    print(f"\nSuccessfully unblocked {app} for {ip}")
                else:
                    print("\nFailed to remove block")
                    
        elif choice == "4":
            if not controller.blocked_rules:
                print("\nNo active blocks")
            else:
                print("\nCurrent blocking rules:")
                for app, ips in controller.blocked_rules.items():
                    for ip in ips:
                        print(f"• {app} ⟶ {ip}")
                        
        elif choice == "5":
            controller.monitor_with_control()
            
        elif choice == "6":
            print("\nCleaning up and exiting...")
            controller._cleanup()
            break
            
        else:
            print("\nInvalid option")

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()