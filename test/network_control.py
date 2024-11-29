import os
import time
import json
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from pathlib import Path
from monitor import NetworkMonitor
from interceptor import NetworkInterceptor
from system import get_installed_apps

class NetworkController:
    def __init__(self):
        """Initialize the network control system"""
        # Initialize components
        self.monitor = NetworkMonitor()
        self.interceptor = NetworkInterceptor()
        self.installed_apps = self.load_installed_apps()
        
        # Setup logging directory
        self.logs_dir = Path('test/logs')
        self.logs_dir.mkdir(exist_ok=True)
        
        # Cache for faster rule lookup
        self.rule_cache = {}
        self.last_cache_update = 0
        self.CACHE_TIMEOUT = 5  # Refresh cache every 5 seconds
        
        # Track active applications and their states
        self.active_apps: Set[str] = set()
        self.app_states: Dict[str, Dict] = {}
        
        # Statistics tracking
        self.stats = {
            'total_connections': 0,
            'blocked_attempts': 0,
            'active_rules': 0
        }
        
        print(f"\nInitialized Network Controller")
        print(f"Found {len(self.installed_apps)} installed applications")
        print(f"Logs directory: {self.logs_dir}")

    def load_installed_apps(self) -> List[str]:
        """Load list of installed applications"""
        try:
            apps = get_installed_apps()
            return sorted(apps)
        except OSError as e:
            print(f"Error loading applications: {e}")
            return []

    def search_installed_apps(self, search_term: str) -> List[str]:
        """Search for installed applications matching the search term"""
        search_term = search_term.lower()
        return [app for app in self.installed_apps if search_term in app.lower()]

    def _update_rule_cache(self) -> None:
        """Update the cached rules if cache timeout exceeded"""
        current_time = time.time()
        if current_time - self.last_cache_update > self.CACHE_TIMEOUT:
            rules = self.interceptor.get_active_rules()
            self.rule_cache = {}
            
            for rule in rules:
                rule_id, app_name, target, target_type, resolved_ips = rule
                if app_name not in self.rule_cache:
                    self.rule_cache[app_name] = []
                self.rule_cache[app_name].append({
                    'id': rule_id,
                    'target': target,
                    'type': target_type,
                    'ips': set(resolved_ips.split(','))
                })
            
            self.last_cache_update = current_time
            self.stats['active_rules'] = len(rules)

    def check_connection_allowed(self, conn: Dict) -> Tuple[bool, Optional[Dict]]:
        """
        Check if a connection is allowed based on rules
        Returns (allowed, rule_details if blocked else None)
        """
        self._update_rule_cache()
        
        app_name = conn['program']
        remote_ip = conn['remote_addr']
        
        # Quick return if no rules for this app
        if app_name not in self.rule_cache:
            return True, None
            
        # Check against cached rules
        for rule in self.rule_cache[app_name]:
            if remote_ip in rule['ips']:
                # For domain rules, check if IPs have changed
                if rule['type'] == 'domain':
                    current_ips = set(self.interceptor.resolve_domain(rule['target']))
                    if current_ips != rule['ips']:
                        rule['ips'] = current_ips
                        self.interceptor.update_resolved_ips(rule['id'], current_ips)
                
                if remote_ip in rule['ips']:
                    return False, {
                        'rule_id': rule['id'],
                        'target': rule['target'],
                        'type': rule['type']
                    }
        
        return True, None

    def block_app_network(self, app_name: str, target: str) -> bool:
        """Block application from accessing specific target"""
        # Validate app existence
        if app_name not in self.installed_apps:
            print(f"Warning: Application '{app_name}' not found in installed apps")
            matching_apps = self.search_installed_apps(app_name)
            if matching_apps:
                print("\nDid you mean one of these?")
                for i, app in enumerate(matching_apps[:5], 1):
                    print(f"{i}. {app}")
            return False
        
        # Validate target
        if not self.interceptor._is_ip(target):
            print(f"Resolving domain {target}...")
            ips = self.interceptor.resolve_domain(target)
            if not ips:
                print(f"Error: Could not resolve {target}")
                return False
            print(f"Resolved to: {', '.join(ips)}")
        
        # Add rule and create firewall rules
        if self.interceptor.add_blocking_rule(app_name, target):
            # Force cache update
            self.last_cache_update = 0
            print(f"✓ Blocked {app_name} from accessing {target}")
            
            # Update statistics
            self._update_rule_cache()
            return True
            
        return False

    def unblock_app_network(self, rule_id: int) -> bool:
        """Enhanced unblock method"""
        try:
            # Get rule details before removing
            blocks = self.get_active_blocks()
            rule = next((b for b in blocks if b['id'] == rule_id), None)

            if not rule:
                print(f"Rule {rule_id} not found or already removed")
                return False

            # Remove from interceptor
            result = self._unblock_app_network(rule_id)

            if result:
                # Remove from proxy
                self.proxy.remove_blocking_rule(rule_id)

                # Force cache update
                self.last_cache_update = 0
                self._update_rule_cache()

            return result

        except Exception as e:
            print(f"Error removing rule: {e}")
            return False

    def get_active_blocks(self) -> List[Dict]:
        """Get list of active blocking rules"""
        self._update_rule_cache()
        
        blocks = []
        for app_name, rules in self.rule_cache.items():
            for rule in rules:
                blocks.append({
                    'id': rule['id'],
                    'app': app_name,
                    'target': rule['target'],
                    'type': rule['type'],
                    'ips': list(rule['ips'])
                })
        
        return blocks

    def update_app_state(self, connections: List[Dict]) -> None:
        """Update state of active applications"""
        current_apps = set()
        
        for conn in connections:
            app_name = conn['program']
            current_apps.add(app_name)
            
            if app_name not in self.app_states:
                self.app_states[app_name] = {
                    'first_seen': datetime.now().isoformat(),
                    'connections': 0,
                    'blocked_attempts': 0,
                    'unique_destinations': set()
                }
            
            self.app_states[app_name]['connections'] += 1
            self.app_states[app_name]['unique_destinations'].add(conn['remote_addr'])

        # Check for new and stopped applications
        new_apps = current_apps - self.active_apps
        stopped_apps = self.active_apps - current_apps
        
        for app in new_apps:
            print(f"\n[+] New application detected: {app}")
            # Log relevant details about new application
            if app in self.rule_cache:
                print(f"    └─ Has {len(self.rule_cache[app])} active blocking rules")
        
        for app in stopped_apps:
            print(f"\n[-] Application stopped: {app}")
            # Log final statistics for stopped application
            if app in self.app_states:
                stats = self.app_states[app]
                print(f"    └─ Total connections: {stats['connections']}")
                print(f"    └─ Blocked attempts: {stats['blocked_attempts']}")
                print(f"    └─ Unique destinations: {len(stats['unique_destinations'])}")
        
        self.active_apps = current_apps

    def monitor_with_control(self):
        """Main monitoring loop with integrated blocking"""
        print("\nStarting Network Control System...")
        print(f"Monitoring {len(self.installed_apps)} applications")
        print("Press Ctrl+C to stop monitoring")
        
        try:
            while True:
                connections = self.monitor.get_connections()
                self.update_app_state(connections)
                
                for conn in connections:
                    self.stats['total_connections'] += 1
                    # Get process info for better logging
                    process_info = self.interceptor.get_process_info(conn['pid'])
                    
                    allowed, rule = self.check_connection_allowed(conn)
                    
                    if not allowed:
                        self.stats['blocked_attempts'] += 1
                        
                        if conn['program'] in self.app_states:
                            self.app_states[conn['program']]['blocked_attempts'] += 1
                        
                        # Enhanced logging with process info
                        details = (f"Process: {process_info['command']} "
                                 f"User: {process_info['user']} "
                                 f"Rule: {rule['type']} targeting {rule['target']}")
                        
                        self.interceptor.log_blocked_attempt(
                            rule['rule_id'],
                            conn['program'],
                            conn['local_addr'],
                            conn['remote_addr'],
                            details
                        )
                        
                        # Log to console if not in detached mode
                        print(f"\n⚠ Blocked: {conn['program']} -> {conn['remote_addr']}")
                        print(f"  └─ {details}")
                        
                        # Ensure firewall rule is active
                        self.interceptor.enforce_firewall_rule(
                            conn['program'],
                            conn['remote_addr']
                        )
                    else:
                        # Log allowed connection with process info
                        self.monitor.log_connection(conn)
                        if process_info['user']:  # Only log if we have process info
                            print(f"\n✓ Allowed: {conn['program']} ({process_info['user']}) -> {conn['remote_addr']}")
                
                self.monitor.update_stats(connections)
                time.sleep(1)
    
        except KeyboardInterrupt:
            print("\nStopping Network Control System...")
            self._cleanup()

    def get_statistics(self) -> Dict:
        """Get current monitoring statistics"""
        return {
            'total_connections': self.stats['total_connections'],
            'blocked_attempts': self.stats['blocked_attempts'],
            'active_rules': self.stats['active_rules'],
            'active_apps': len(self.active_apps),
            'monitored_apps': len(self.app_states)
        }

    def _cleanup(self):
        """Enhanced cleanup with better error handling"""
        try:
            # First try to cleanup monitor
            if hasattr(self.monitor, '_cleanup'):
                self.monitor._cleanup()
                
            # Save controller state
            final_state = {
                'timestamp': datetime.now().isoformat(),
                'statistics': self.get_statistics(),
                'active_rules': self.get_active_blocks(),
                'app_states': {
                    app: {
                        **state,
                        'unique_destinations': list(state['unique_destinations'])
                    }
                    for app, state in self.app_states.items()
                }
            }
            
            state_file = self.logs_dir / 'controller_state.json'
            with open(state_file, 'w') as f:
                json.dump(final_state, f, indent=2)
                
            print(f"\nController state saved to: {state_file}")
            
            # Cleanup interceptor rules if needed
            if hasattr(self, 'interceptor'):
                # @dev >>>>>> DONT REMOVE THIS SEC.
                # active_blocks = self.get_active_blocks()
                # if active_blocks:
                #     print("\nCleaning up firewall rules...")
                #     for block in active_blocks:
                #         try:
                #             self.unblock_app_network(block['id'])
                #         except:
                #             print(f"Failed to remove rule for {block['app']} -> {block['target']}")
                self.interceptor.force_cleanup_rules()
                            
        except Exception as e:
            print(f"\nWarning: Cleanup encountered errors: {e}")
            print("Some resources may need manual cleanup")

    def display_statistics(self):
        """Display current system statistics"""
        stats = self.get_statistics()
        print("\n=== System Statistics ===")
        print(f"Total Connections: {stats['total_connections']}")
        print(f"Blocked Attempts: {stats['blocked_attempts']}")
        print(f"Active Rules: {stats['active_rules']}")
        print(f"Active Applications: {stats['active_apps']}")
        print(f"Total Monitored Apps: {stats['monitored_apps']}")

        if self.app_states:
            print("\nPer-Application Statistics:")
            for app, state in self.app_states.items():
                print(f"\n{app}:")
                print(f"  └─ Connections: {state['connections']}")
                print(f"  └─ Blocked Attempts: {state['blocked_attempts']}")
                print(f"  └─ Unique Destinations: {len(state['unique_destinations'])}")

def display_menu():
    """Display the main menu"""
    print("\n=== Network Control System ===")
    print("1. List installed applications")
    print("2. Block application's network access")
    print("3. View/Remove blocking rules")
    print("4. View current statistics")
    print("5. Start monitoring")
    print("6. Search applications")
    print("7. View logs")
    print("8. Exit")
    return input("\nSelect an option (1-8): ").strip()
def handle_block_app(controller):
    """Handle application blocking menu"""
    print("\nEnter application name (or part of name to search):")
    search = input("> ").lower()
    
    # Find matching apps
    matches = controller.search_installed_apps(search)
    
    if not matches:
        print("\nNo matching applications found")
        return
            
    # Display matches
    print("\nMatching applications:")
    for i, app in enumerate(matches, 1):
        print(f"{i}. {app}")
    
    try:
        app_idx = int(input("\nSelect application number (0 to cancel): ")) - 1
        if app_idx == -1:
            return
        if 0 <= app_idx < len(matches):
            selected_app = matches[app_idx]
            
            print("\nEnter target to block (IP or domain):")
            target = input("> ").strip()
            
            if controller.block_app_network(selected_app, target):
                print(f"\nSuccessfully blocked {selected_app} from accessing {target}")
            else:
                print("\nFailed to create blocking rule")
        else:
            print("\nInvalid selection")
    except ValueError:
        print("\nInvalid input")

def handle_view_rules(controller):
    """Handle viewing and removing blocking rules"""
    blocks = controller.get_active_blocks()
    
    if not blocks:
        print("\nNo active blocking rules")
        return
    
    print("\nCurrent blocking rules:")
    for i, block in enumerate(blocks, 1):
        print(f"{i}. {block['app']} ⟶ {block['target']}")
        print(f"   └─ Type: {block['type']}")
        print(f"   └─ IPs: {', '.join(block['ips'])}")
    
    try:
        action = input("\nEnter rule number to remove (0 to cancel): ").strip()
        if action == '0':
            return
            
        rule_idx = int(action) - 1
        if 0 <= rule_idx < len(blocks):
            block = blocks[rule_idx]
            if controller.unblock_app_network(block['id']):
                print(f"\nSuccessfully removed blocking rule")
            else:
                print("\nFailed to remove blocking rule")
        else:
            print("\nInvalid rule number")
    except ValueError:
        print("\nInvalid input")

def handle_view_logs(controller):
    """Handle viewing system logs"""
    print("\n=== Available Logs ===")
    log_files = list(controller.logs_dir.glob('*.log'))
    if not log_files:
        print("No log files found")
        return
        
    for i, log_file in enumerate(log_files, 1):
        print(f"{i}. {log_file.name}")
    
    try:
        choice = int(input("\nSelect log file to view (0 to cancel): "))
        if choice == 0:
            return
            
        if 1 <= choice <= len(log_files):
            log_file = log_files[choice - 1]
            print(f"\n=== Contents of {log_file.name} ===")
            with open(log_file, 'r') as f:
                # Show last 20 lines by default
                lines = f.readlines()
                for line in lines[-20:]:
                    print(line.strip())
                    
            input("\nPress Enter to continue...")
        else:
            print("\nInvalid selection")
    except ValueError:
        print("\nInvalid input")

def main():
    """Main application loop"""
    controller = NetworkController()
    print("\nNetwork Control System Initialized")
    print(f"Found {len(controller.installed_apps)} installed applications")
    
    while True:
        choice = display_menu()
        
        if choice == "1":
            print("\nInstalled Applications:")
            for i, app in enumerate(controller.installed_apps, 1):
                print(f"{i}. {app}")
        
        elif choice == "2":
            handle_block_app(controller)
            
        elif choice == "3":
            handle_view_rules(controller)
            
        elif choice == "4":
            controller.display_statistics()
            
        elif choice == "5":
            print("\nStarting network monitoring...")
            print("Press Ctrl+C to stop")
            controller.monitor_with_control()
            
        elif choice == "6":
            print("\nEnter search term:")
            search = input("> ").strip()
            matches = controller.search_installed_apps(search)
            
            if matches:
                print("\nMatching applications:")
                for app in matches:
                    print(f"- {app}")
            else:
                print("\nNo matching applications found")
                
        elif choice == "7":
            handle_view_logs(controller)
            
        elif choice == "8":
            print("\nCleaning up and exiting...")
            controller._cleanup()
            break
            
        else:
            print("\nInvalid option selected")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting Network Control System...")
    except Exception as e:
        print(f"\nError: {e}")
        print("Exiting due to error...")