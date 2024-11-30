import os
import subprocess
import win32api
import win32con
import win32security
import win32com.client
from pathlib import Path
from typing import Optional, List, Dict
from .base import BaseInterceptor

class WindowsInterceptor(BaseInterceptor):
    def __init__(self):
        super().__init__()
        # Initialize WMI client for process management
        self.wmi = win32com.client.GetObject("winmgmts:")
        
    def _create_rule_name(self, app_name: str, target_ip: str) -> str:
        """Create standardized rule name"""
        process_name = os.path.basename(app_name)
        return f"APP_{process_name.upper()}_BLOCK_{target_ip}"
        
    def _get_app_rules(self, app_name: str) -> List[str]:
        """Get all firewall rules for an application"""
        try:
            process_name = os.path.basename(app_name)
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                f'name=APP_{process_name.upper()}_BLOCK*'
            ]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            rules = []
            current_rule = None
            for line in output.split('\n'):
                if line.startswith('Rule Name:'):
                    if current_rule: # Doubt....<<<<
                        rules.append(current_rule)
                    current_rule = line.split(':', 1)[1].strip()
            
            if current_rule:
                rules.append(current_rule)
                
            return rules
            
        except subprocess.CalledProcessError:
            return []
            
    def _get_process_sid(self) -> str:
        """Get current user's SID"""
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            sid = win32security.GetTokenInformation(
                token,
                win32security.TokenUser
            )[0]
            return win32security.ConvertSidToStringSid(sid)
        except Exception as e:
            self.logger.error(f"Failed to get process SID: {e}")
            return None
        
    def _create_windows_rules(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create Windows Firewall rules for both TCP and UDP"""
        try:
            # Get full path of application
            try:
                app_path = win32api.GetLongPathName(app_path)
                process_name = os.path.basename(app_path)
            except Exception:
                self.logger.error(f"Could not find path for {app_path}")
                return False
                
            # Get user SID for rule targeting
            user_sid = self._get_process_sid()
            if not user_sid:
                return False
                
            rule_base_name = self._create_rule_name(process_name, target_ip)
            
            if action == 'add':
                # Create rules for TCP, UDP
                protocols = ['TCP', 'UDP']
                for protocol in protocols:
                    rule_name = f"{rule_base_name}_{protocol}"
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}',
                        'dir=out',
                        'action=block',
                        'enable=yes',
                        f'program={app_path}',
                        f'protocol={protocol}',
                        f'remoteip={target_ip}',
                        f'security={user_sid}'  # Target specific user
                    ]
                    
                    subprocess.run(cmd, check=True)
                    self.logger.info(f"Added {protocol} rule: {rule_name}")
                    
                return True
                
            else:  # Remove rules
                # Get existing rules
                rules = self._get_app_rules(process_name)
                matching_rules = [r for r in rules if target_ip in r]
                
                for rule_name in matching_rules:
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name={rule_name}'
                    ]
                    subprocess.run(cmd, check=True)
                    self.logger.info(f"Removed rule: {rule_name}")
                    
                return True
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to {'add' if action == 'add' else 'remove'} firewall rules: {e}")
            return False
        
    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule"""
        # Check if target is IP or domain
        target_type = 'ip' if self._is_ip(target) else 'domain'
        resolved_addresses = {'ipv4': [], 'ipv6': []}
        
        if target_type == 'domain':
            self.logger.info(f"Resolving domain {target}...")
            resolved_addresses = self.resolve_domain(target)
            if not resolved_addresses['ipv4'] and not resolved_addresses['ipv6']:
                self.logger.error(f"Could not resolve {target}")
                return False
                
            self.logger.info("Resolved addresses:")
            if resolved_addresses['ipv4']:
                self.logger.info(f"IPv4: {', '.join(resolved_addresses['ipv4'])}")
            if resolved_addresses['ipv6']:
                self.logger.info(f"IPv6: {', '.join(resolved_addresses['ipv6'])}")
        else:
            # Single IP address
            if ':' in target:
                resolved_addresses['ipv6'] = [target]
            else:
                resolved_addresses['ipv4'] = [target]
                
        try:
            # Add to database first
            all_ips = resolved_addresses['ipv4'] + resolved_addresses['ipv6']
            rule_id = self.db.add_rule(app_name, target, target_type, all_ips)
            if not rule_id:
                return False
                
            # Add rules for each IP
            success = True
            added_rules = []
            
            for ip in all_ips:
                if self._create_windows_rules(app_name, ip, 'add'):
                    added_rules.append(ip)
                else:
                    success = False
                    break
                    
            if not success:
                # Rollback added rules
                for ip in added_rules:
                    try:
                        self._create_windows_rules(app_name, ip, 'remove')
                    except:
                        pass
                return False
                
            self.logger.info(f"Successfully added blocking rules for {app_name} -> {target}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding blocking rule: {e}")
            return False    

    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule"""
        try:
            # Get rule details
            rules = self.db.get_active_rules()
            rule = next((r for r in rules if r[0] == rule_id), None)
            if not rule:
                return False
                
            app_name, target, target_type, resolved_ips = rule[1:]
            
            success = True
            if resolved_ips:
                for ip in resolved_ips.split(','):
                    if not self._create_windows_rules(app_name, ip.strip(), 'remove'):
                        success = False
                        
            # Also try target if it's an IP
            if target_type == 'ip':
                if not self._create_windows_rules(app_name, target, 'remove'):
                    success = False
                    
            # Deactivate in database if any rules were removed
            if success:
                self.db.deactivate_rule(rule_id)
                self.logger.info(f"Successfully removed blocking rule for {app_name} -> {target}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error removing blocking rule: {e}")
            return False
            
    def force_cleanup_rules(self):
        """Force cleanup of all firewall rules"""
        try:
            # Get all rules with our prefix
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                'name=APP_*', 'verbose'
            ]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            # Parse rules and delete them
            current_rule = None
            for line in output.split('\n'):
                if line.startswith('Rule Name:'):
                    rule_name = line.split(':', 1)[1].strip()
                    if rule_name.startswith('APP_'):
                        try:
                            subprocess.run([
                                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                                f'name={rule_name}'
                            ], check=True)
                            self.logger.info(f"Removed rule: {rule_name}")
                        except subprocess.CalledProcessError:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Error in force cleanup: {e}")
            
    def get_process_info(self, pid: str) -> dict:
        """Get process information using WMI"""
        try:
            query = f"SELECT * FROM Win32_Process WHERE ProcessId = {pid}"
            process = self.wmi.ExecQuery(query)[0]
            
            return {
                'user': process.GetOwner()[2],  # Returns domain, user
                'command': process.Name
            }
        except Exception:
            return {'user': None, 'command': None}