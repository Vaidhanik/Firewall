import os
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from monitor import MonitorFactory
from interceptor import NetworkInterceptor
from network_controller.proxy import ProxyInterceptor

class InternalController:
    def __init__(self):
        """Initialize Internal Controller"""
        self.proxy = ProxyInterceptor()
        self.interceptor = NetworkInterceptor()
        self.monitor = MonitorFactory().create_monitor()

        self.CACHE_TIMEOUT = 5  # Refresh cache every 5 seconds
        self.last_cache_update = 0
        self.proxy_running = False
        
        self.logs_dir = Path('logs')
        self.logs_dir.mkdir(exist_ok=True)

        self._init_state()
        
        print(f"\nInitialized Internal Network Controller")
        print(f"Logs directory: {self.logs_dir}")

    def _init_state(self):
        """Initialize controller state"""
        # Cache for faster rule lookup
        self.rule_cache = {}
        self.active_apps = set()
        self.app_states = {}
        
        # Statistics tracking
        self.stats = {
            'total_connections': 0,
            'blocked_attempts': 0,
            'active_rules': 0
        }
        
    def _configure_system_proxy(self):
        """Configure system to use our proxy"""
        proxy_host = "127.0.0.1"
        proxy_port = "8080"
        
        # Set environment variables
        os.environ['HTTP_PROXY'] = f"http://{proxy_host}:{proxy_port}"
        os.environ['HTTPS_PROXY'] = f"http://{proxy_host}:{proxy_port}"
        
        # Try to set system proxy settings
        try:
            if os.name == 'posix':  # Linux/Unix
                # Try GNOME settings
                subprocess.run([
                    'gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'manual'
                ])
                subprocess.run([
                    'gsettings', 'set', 'org.gnome.system.proxy.http', 'host', 
                    proxy_host
                ])
                subprocess.run([
                    'gsettings', 'set', 'org.gnome.system.proxy.http', 'port', 
                    proxy_port
                ])
        except Exception as e:
            print(f"Warning: Could not set system proxy: {e}")
    
    def _remove_system_proxy(self):
        """Remove system proxy settings"""
        try:
            if os.name == 'posix':
                subprocess.run([
                    'gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none'
                ])
            
            # Clear environment variables
            os.environ.pop('HTTP_PROXY', None)
            os.environ.pop('HTTPS_PROXY', None)
        except Exception as e:
            print(f"Warning: Could not remove system proxy: {e}")
    
    
    def _run_monitor_process(self, running_flag, stats_dict):
        """Running monitoring in separate process"""
        try:
            # Redirect output to log file
            log_file = self.logs_dir / 'monitor.log'
            with open(log_file, 'a') as f:
                f.write(f"\n=== Monitor started at {datetime.now().isoformat()} ===\n")
    
                while running_flag.value:
                    connections = self.monitor.get_connections()
                    self.update_app_state(connections, quiet=True)
    
                    for conn in connections:
                        stats_dict['total_connections'] += 1
                        allowed, rule = self.check_connection_allowed(conn)
    
                        if not allowed:
                            stats_dict['blocked_attempts'] += 1
                            
                            if conn['program'] in self.app_states:
                                self.app_states[conn['program']]['blocked_attempts'] += 1
                            
                            # Log blocked attempt quietly
                            f.write(
                                f"{datetime.now().isoformat()} - Blocked: {conn['program']} -> "
                                f"{conn['remote_addr']}:{conn['remote_port']}\n"
                            )
                            f.flush()
    
                            self.interceptor.log_blocked_attempt(
                                rule['rule_id'],
                                conn['program'],
                                conn['local_addr'],
                                conn['remote_addr'],
                                f"Blocked by {rule['type']} rule targeting {rule['target']}"
                            )
                            self.interceptor.enforce_firewall_rule(
                                conn['program'],
                                conn['remote_addr']
                            )
    
                        else:
                            self.monitor.log_connection(conn)
                    stats_dict['active_apps'] = len(self.active_apps)
                    stats_dict['active_rules'] = len(self.get_active_blocks())
                    time.sleep(1)
    
        except Exception as e:
            with open(self.logs_dir / 'monitor_error.log', 'a') as f:
                f.write(f"\nError in monitor: {e}\n")
    
        finally:
            if hasattr(self.monitor, '_cleanup'):
                self.monitor._cleanup()
    
    def _update_rule_cache(self) -> None:
        """Update the cached rules if cache timeout exceeded"""
        try:
            current_time = time.time()
            if current_time - self.last_cache_update > self.CACHE_TIMEOUT:
                rules = self.interceptor.get_active_rules()

                # Clear existing cache
                self.rule_cache = {}
                
                if not rules:  # If no rules exist
                    self.last_cache_update = current_time
                    self.stats['active_rules'] = 0
                    return
                
                for rule in rules:
                    rule_id, app_name, target, target_type, resolved_ips = rule
                    if app_name not in self.rule_cache:
                        self.rule_cache[app_name] = []
                    
                    # Handle empty resolved_ips
                    if not resolved_ips:
                        if target_type == 'domain':
                            resolved_ips = ','.join(self.interceptor.resolve_domain(target))
                        else:
                            resolved_ips = target
    
                    self.rule_cache[app_name].append({
                        'id': rule_id,
                        'target': target,
                        'type': target_type,
                        'ips': set(ip.strip() for ip in resolved_ips.split(',') if ip.strip())
                    })
                
                self.last_cache_update = current_time
                self.stats['active_rules'] = len(rules)
        except Exception as e:
            print(f"Error updating rule cache: {e}")
            self.rule_cache = {}  # Reset cache on error
            self.stats['active_rules'] = 0
    
    def get_statistics(self) -> Dict:
        """Get current monitoring statistics"""
        return {
            'total_connections': self.stats['total_connections'],
            'blocked_attempts': self.stats['blocked_attempts'],
            'active_rules': self.stats['active_rules'],
            'active_apps': len(self.active_apps),
            'monitored_apps': len(self.app_states)
        }
    
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
    
    def stop_proxy(self) -> bool:
        """Stop the proxy server"""
        try:
            if not self.proxy_running:
                print("\nProxy is not running")
                return False
            
            # Remove proxy settings first
            self._remove_system_proxy()
            
            # Stop the proxy
            self.proxy.stop()
            self.proxy_running = False
            
            print("\n✓ Proxy server stopped")
            return True
            
        except Exception as e:
            print(f"\nError stopping proxy: {e}")
            return False
        
    def get_global_blocks(self) -> List[Dict]:
        """Get list of active global blocks"""
        try:
            blocks = self.interceptor.get_global_blocks()
            
            # Also update our internal cache
            self._update_rule_cache()
            
            # Add any additional stats if needed
            for block in blocks:
                if 'active_since' not in block:
                    block['active_since'] = block.get('created_at', 'unknown')
                
                # Get stats for this block if available
                stats = self.stats.get(f"global_block_{block['id']}", {})
                if stats:
                    block.update(stats)
            
            return blocks
            
        except Exception as e:
            self.logger.error(f"Error getting global blocks: {e}")
            return []