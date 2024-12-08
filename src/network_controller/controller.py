import sys
import json
import time
import multiprocessing
from pathlib import Path
from datetime import datetime

from monitor import MonitorFactory
from interceptor import NetworkInterceptor
from network_controller.proxy import ProxyInterceptor
from network_controller.system import get_installed_apps
from network_controller.internal import InternalController

from typing import Dict, List, Optional, Tuple

class NetworkController:
    def __init__(self):
        """Initialize the network control system"""
        # Initialize components
        self.proxy = ProxyInterceptor()
        self.internal = InternalController()
        self.interceptor = NetworkInterceptor()
        self.monitor = MonitorFactory().create_monitor()
    
        # Setup logging
        self.interceptor.setup_logging()
        self.logger = self.interceptor.logger

        self.installed_apps = self.load_installed_apps()
        
        # Setup logging directory
        self.logs_dir = Path('logs')
        self.logs_dir.mkdir(exist_ok=True)
        
        self._init_monitor()
        
        print(f"\nInitialized Network Controller")
        print(f"Found {len(self.installed_apps)} installed applications")
        print(f"Logs directory: {self.logs_dir}")

    def _init_monitor(self):
        """Initialize controller state"""
        # Monitor process state
        self.monitor_process = None
        self.monitor_running = multiprocessing.Value('b', False)
        self.monitor_stats = multiprocessing.Manager().dict()
        self.monitor_stats.update({
            'total_connections': 0,
            'blocked_attempts': 0,
            'active_rules': 0,
            'active_apps': 0,
            'start_time': None,
            'is_running': False
        })

    def _run_monitor_process(self, running_flag, stats_dict):
        """Running monitoring in separate process"""
        try:
            # Set process start method for windows
            if sys.platform == 'win32':
                multiprocessing.freeze_support()

            log_file = self.logs_dir / 'monitor.log'
            self.logs_dir.mkdir(exist_ok=True)

            print(f"Monitor process starting, logging to: {log_file}")

            with open(log_file, 'a') as f:
                f.write(f"\n=== Monitor started at {datetime.now().isoformat()} ===\n")
                f.flush()

                while running_flag.value:  # Check the flag at the start of each loop
                    try:
                        if not running_flag.value:  # Double check before heavy operations
                            break

                        connections = self.monitor.get_connections()
                        self.update_app_state(connections, quiet=True)

                        for conn in connections:
                            stats_dict['total_connections'] += 1
                            allowed, rule = self.check_connection_allowed(conn)

                            if not allowed:
                                stats_dict['blocked_attempts'] += 1
                                f.write(
                                    f"{datetime.now().isoformat()} - Blocked: {conn['program']} -> "
                                    f"{conn['remote_addr']}:{conn['remote_port']}\n"
                                )
                                f.flush()

                                self.interceptor.enforce_firewall_rule(
                                    conn['program'],
                                    conn['remote_addr']
                                )
                            else:
                                self.monitor.log_connection(conn)

                        stats_dict['active_apps'] = len(self.internal.active_apps)
                        stats_dict['active_rules'] = len(self.get_active_blocks())
                        time.sleep(1)  # Add sleep to reduce CPU usage and allow interrupts

                    except Exception as e:
                        f.write(f"\nError in monitor loop: {e}\n")
                        f.flush()
                        time.sleep(1)

        except Exception as e:
            with open(self.logs_dir / 'monitor_error.log', 'a') as f:
                f.write(f"\nFatal error in monitor process: {e}\n")
        finally:
            # Cleanup when process stops
            if hasattr(self.monitor, '_cleanup'):
                self.monitor._cleanup()
            print("Monitor process cleanup completed")

    def start_proxy(self) -> bool:
        """Start the proxy server"""
        try:
            if self.internal.proxy_running:
                print("\nProxy is already running!")
                return False
            
            # Start the proxy
            self.proxy.start()
            self.internal.proxy_running = True
            
            # Give it a moment to start
            time.sleep(2)
            
            # Configure system proxy
            self.internal._configure_system_proxy()
            print("\n✓ Proxy server started")
            return True
            
        except Exception as e:
            print(f"\nError starting proxy: {e}")
            self.internal.proxy_running = False
            return False
    
    def stop_proxy(self) -> bool:
        """Stop the proxy server"""
        self.internal.stop_proxy()

    def stop_monitor(self):
        """Safely stop the monitor process"""
        if self.monitor_process and self.monitor_process.is_alive():
            print("Stopping monitor process...")
            try:
                # Signal the process to stop
                self.monitor_running.value = False

                # Give it time to cleanup gracefully
                for _ in range(10):  # Wait up to 2 seconds
                    if not self.monitor_process.is_alive():
                        break
                    time.sleep(0.2)

                # If still alive after grace period
                if self.monitor_process.is_alive():
                    print("Monitor process didn't stop gracefully, terminating...")
                    self.monitor_process.terminate()
                    self.monitor_process.join(2)  # Wait up to 2 seconds for termination

                    # If still alive after terminate
                    if self.monitor_process.is_alive():
                        print("Forcing monitor process to stop...")
                        self.monitor_process.kill()  # Force kill as last resort
                        self.monitor_process.join(1)

            except Exception as e:
                print(f"Error stopping monitor process: {e}")
            finally:
                self.monitor_stats['is_running'] = False
                print("Monitor process stopped")
                return True
        return False
    
    def start_detached_monitor(self) -> bool:
        """Start monitoring in a separate process"""
        if self.monitor_process and self.monitor_process.is_alive():
            print("\nMonitoring is already running!")
            return False

        try:
            # Create a pipe for communication
            self.monitor_running.value = True
            self.monitor_stats['start_time'] = datetime.now().isoformat()
            self.monitor_stats['is_running'] = True  # Set the running flag

            # Create and start monitor process
            self.monitor_process = multiprocessing.Process(
                target=self._run_monitor_process,
                args=(self.monitor_running, self.monitor_stats)
            )
            self.monitor_process.daemon = False  # Change to non-daemon process
            self.monitor_process.start()

            # Wait a moment to ensure process starts
            time.sleep(1)

            if not self.monitor_process.is_alive():
                raise Exception("Monitor process failed to start")

            print(f"\n✓ Monitoring started in background (PID: {self.monitor_process.pid})")
            return True

        except Exception as e:
            print(f"\nError starting monitor: {e}")
            self.monitor_stats['is_running'] = False
            self.monitor_running.value = False
            return False

    def get_monitor_status(self) -> Dict:
        """Get status of monitoring process"""
        if self.monitor_process and self.monitor_process.is_alive():
            uptime = 0
            if self.monitor_stats.get('start_time'):
                start_time = datetime.fromisoformat(self.monitor_stats['start_time'])
                uptime = (datetime.now() - start_time).total_seconds()

            return {
                'running': True,
                'pid': self.monitor_process.pid,
                'uptime_seconds': uptime,
                'total_connections': self.monitor_stats['total_connections'],
                'blocked_attempts': self.monitor_stats['blocked_attempts'],
                'active_apps': self.monitor_stats['active_apps'],
                'active_rules': self.monitor_stats['active_rules']
            }
        return {
            'running': False,
            'total_connections': self.monitor_stats['total_connections'],
            'blocked_attempts': self.monitor_stats['blocked_attempts']
        }

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

    def check_connection_allowed(self, conn: Dict) -> Tuple[bool, Optional[Dict]]:
        """Check if a connection is allowed based on rules"""
        self.internal._update_rule_cache()
        
        app_name = conn['program']
        remote_ip = conn['remote_addr']
        
        # Quick return if no rules for this app
        if app_name not in self.internal.rule_cache:
            return True, None
            
        # Check against cached rules
        for rule in self.internal.rule_cache[app_name]:
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
            self.internal.last_cache_update = 0
            print(f"✓ Blocked {app_name} from accessing {target}")
            
            # Also add rule to proxy
            if self.internal.proxy_running:
                self.proxy.add_blocking_rule(app_name, target)
            
            # Update statistics
            print("controller::_update_rule_cache")
            self.internal._update_rule_cache()
            return True
            
        return False
    
    def unblock_app_network(self, rule_id: int) -> bool:
        """Remove blocking rule for application"""
        # Get rule details before removing
        blocks = self.get_active_blocks()
        rule = next((b for b in blocks if b['id'] == rule_id), None)
        
        if self.interceptor.remove_blocking_rule(rule_id):
            # Force cache update
            self.internal.last_cache_update = 0
            print(f"✓ Removed blocking rule {rule_id}")
            
            # Also remove from proxy if running
            if self.internal.proxy_running and rule:
                self.proxy.remove_blocking_rule(rule_id)
            
            # Update statistics
            self.internal._update_rule_cache()
            return True
            
        return False

    def update_app_state(self, connections: List[Dict], quiet: bool = False) -> None:
        """Update state of active applications"""
        current_apps = set()

        for conn in connections:
            app_name = conn['program']
            current_apps.add(app_name)

            if app_name not in self.internal.app_states:
                self.internal.app_states[app_name] = {
                    'first_seen': datetime.now().isoformat(),
                    'connections': 0,
                    'blocked_attempts': 0,
                    'unique_destinations': set()
                }

            self.internal.app_states[app_name]['connections'] += 1
            self.internal.app_states[app_name]['unique_destinations'].add(conn['remote_addr'])

        # Check for new and stopped applications
        new_apps = current_apps - self.internal.active_apps
        stopped_apps = self.internal.active_apps - current_apps

        # Only print if not in quiet mode
        if not quiet:
            for app in new_apps:
                print(f"\n[+] New application detected: {app}")
                if app in self.internal.rule_cache:
                    print(f"    └─ Has {len(self.internal.rule_cache[app])} active blocking rules")

            for app in stopped_apps:
                print(f"\n[-] Application stopped: {app}")
                if app in self.internal.app_states:
                    stats = self.internal.app_states[app]
                    print(f"    └─ Total connections: {stats['connections']}")
                    print(f"    └─ Blocked attempts: {stats['blocked_attempts']}")
                    print(f"    └─ Unique destinations: {len(stats['unique_destinations'])}")

        self.internal.active_apps = current_apps

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
                    self.internal.stats['total_connections'] += 1
                    # Get process info for better logging
                    process_info = self.interceptor.get_process_info(conn['pid'])
                    
                    allowed, rule = self.check_connection_allowed(conn)
                    
                    if not allowed:
                        self.internal.stats['blocked_attempts'] += 1
                        
                        if conn['program'] in self.internal.app_states:
                            self.internal.app_states[conn['program']]['blocked_attempts'] += 1
                        
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
            self.internal._cleanup()

    def display_statistics(self):
        """Display current system statistics"""
        stats = self.internal.get_statistics()
        print("\n=== System Statistics ===")
        print(f"Total Connections: {stats['total_connections']}")
        print(f"Blocked Attempts: {stats['blocked_attempts']}")
        print(f"Active Rules: {stats['active_rules']}")
        print(f"Active Applications: {stats['active_apps']}")
        print(f"Total Monitored Apps: {stats['monitored_apps']}")

        if self.internal.app_states:
            print("\nPer-Application Statistics:")
            for app, state in self.internal.app_states.items():
                print(f"\n{app}:")
                print(f"  └─ Connections: {state['connections']}")
                print(f"  └─ Blocked Attempts: {state['blocked_attempts']}")
                print(f"  └─ Unique Destinations: {len(state['unique_destinations'])}")

    def get_active_blocks(self) -> List[Dict]:
        """Enhanced cleanup with better error handling"""
        return self.internal.get_active_blocks()
    
    def cleanup(self):
        """Enhanced cleanup with better error handling"""
        try:
            # First stop the monitor process
            self.stop_monitor()

            # Stop proxy
            if self.internal.proxy_running:
                self.internal.stop_proxy()
                
            # Save controller state
            final_state = {
                'timestamp': datetime.now().isoformat(),
                'statistics': self.internal.get_statistics(),
                'active_rules': self.get_active_blocks(),
                'app_states': {
                    app: {
                        **state,
                        'unique_destinations': list(state['unique_destinations'])
                    }
                    for app, state in self.internal.app_states.items()
                }
            }
            
            state_file = self.logs_dir / 'controller_state.json'
            with open(state_file, 'w') as f:
                json.dump(final_state, f, indent=2)
                
            print(f"\nController state saved to: {state_file}")
            
            # Cleanup interceptor rules if needed
            if hasattr(self, 'interceptor'):
                active_blocks = self.get_active_blocks()
                if active_blocks:
                    print("\nCleaning up firewall rules...")
                    for block in active_blocks:
                        try:
                            self.unblock_app_network(block['id'])
                        except:
                            print(f"Failed to remove rule for {block['app']} -> {block['target']}")
                            
        except Exception as e:
            print(f"\nWarning: Cleanup encountered errors: {e}")
            print("Some resources may need manual cleanup")

    ##############
    ## AI STUFF ##
    ##############
    
    def get_ai_decisions(self, limit: int = 100) -> list:
        """Get recent AI decisions with error handling"""
        try:
            print("Debug: Fetching decisions from MongoDB...")
            decisions = list(self.interceptor.ai_service.get_recent_decisions(limit))
            print(f"Debug: Found {len(decisions)} decisions")
            return decisions
        except Exception as e:
            print(f"Error fetching AI decisions: {e}")
            return []
        
    def implement_ai_recommendation(self, recommendation_id: int) -> bool:
        """Implement AI recommendation as blocking rule"""
        try:
            # Get recommendation
            recommendation = self.interceptor.db.get_ai_recommendation(recommendation_id)
            if not recommendation:
                print(f"AI recommendation {recommendation_id} not found")
                return False

            # Use existing block_app_network which handles all the firewall rules
            if self.block_app_network(recommendation["app_name"], recommendation["dest_ip"]):
                # Update AI recommendation to mark as implemented
                self.interceptor.db.ai_decisions_collection.update_one(
                    {"id": recommendation_id},
                    {
                        "$set": {
                            "active": True,  # Keep consistent with storage format
                            "updated_at": datetime.now().isoformat(),
                            "implemented": True,  # New status field
                            "implementation_time": datetime.now().isoformat(),  # Track when implemented
                            "implementation_status": "success"  # Track implementation status
                        }
                    }
                )
                print(f"✓ Successfully implemented recommendation for {recommendation['app_name']} → {recommendation['dest_ip']}")
                return True

            print(f"✗ Failed to implement blocking rule for recommendation {recommendation_id}")
            return False

        except Exception as e:
            print(f"Error implementing AI recommendation: {e}")
            return False