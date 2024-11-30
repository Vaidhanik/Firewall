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