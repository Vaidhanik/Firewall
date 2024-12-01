import os
import ctypes
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
        
    def _get_app_path(self, app_name: str) -> str:
        """
        Get full path for any application using multiple resolution methods
        """
        try:
            # Normalize the app name
            app_name_lower = app_name.lower()

            # Method 1: Check if it's already a full path
            if os.path.exists(app_name):
                return os.path.abspath(app_name)

            # Method 2: Special handling for Chrome-based browsers
            if any(browser in app_name_lower for browser in ['chrome', 'brave']):
                program_dirs = [
                    os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
                    os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'),
                    os.environ.get('LOCALAPPDATA')
                ]

                # Known possible paths for Chrome and Brave
                chrome_paths = {
                    'chrome': [
                        'Google\\Chrome\\Application\\chrome.exe',
                        'Google\\Chrome Beta\\Application\\chrome.exe',
                        'Google\\Chrome Dev\\Application\\chrome.exe',
                        'Google\\Chrome Canary\\Application\\chrome.exe'
                    ]
                }

                # Determine which paths to check
                check_paths = []
                if 'chrome' in app_name_lower:
                    check_paths = chrome_paths['chrome']
                elif 'brave' in app_name_lower:
                    check_paths = chrome_paths['brave']

                # Check each possible location
                for program_dir in program_dirs:
                    if program_dir:
                        for relative_path in check_paths:
                            full_path = os.path.join(program_dir, relative_path)
                            if os.path.exists(full_path):
                                return full_path

                # Try registry for Chrome-based browsers
                try:
                    import winreg
                    # Registry paths to check
                    registry_paths = []
                    if 'chrome' in app_name_lower:
                        registry_paths = [
                            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"),
                            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")
                        ]
                    elif 'brave' in app_name_lower:
                        registry_paths = [
                            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe"),
                            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe")
                        ]

                    for hkey, sub_key in registry_paths:
                        try:
                            with winreg.OpenKey(hkey, sub_key) as key:
                                path = winreg.QueryValue(key, None)
                                if os.path.exists(path):
                                    return path
                        except:
                            continue
                except:
                    pass

            # Method 3: Try 'where' command (checks PATH)
            try:
                path = subprocess.check_output(['where', app_name], 
                                             universal_newlines=True).strip().split('\n')[0]
                if os.path.exists(path):
                    return path
            except:
                pass

            # Method 4: Search Program Files recursively as last resort
            program_dirs = [
                os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
                os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'),
                os.environ.get('LOCALAPPDATA'),
                os.environ.get('APPDATA')
            ]

            base_name = f"{os.path.splitext(os.path.basename(app_name))[0]}.exe"
            for program_dir in program_dirs:
                if program_dir:
                    for root, dirs, files in os.walk(program_dir):
                        if base_name.lower() in (f.lower() for f in files):
                            return os.path.join(root, base_name)

            self.logger.error(f"Could not find path for {app_name}")
            return None

        except Exception as e:
            self.logger.error(f"Error resolving app path: {e}")
            return None
        
    def _create_windows_rules(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create Windows Firewall rules for both TCP and UDP"""
        try:
            # Get full path of application
            resolved_path = self._get_app_path(app_path)
            if not resolved_path:
                self.logger.error(f"Could not find path for {app_path}")
                return False

            process_name = os.path.basename(resolved_path)

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

                    # Create powershell command to add rule (handles permissions better)
                    ps_cmd = [
                        'powershell', '-Command',
                        f'New-NetFirewallRule',
                        f'-DisplayName "{rule_name}"',
                        f'-Name "{rule_name}"',
                        '-Direction Outbound',
                        '-Action Block',
                        '-Enabled True',
                        f'-Program "{resolved_path}"',
                        f'-Protocol {protocol}',
                        f'-RemoteAddress {target_ip}',
                        '-Profile Private,Public,Domain'
                    ]

                    self.logger.info(f"Executing command: {' '.join(ps_cmd)}")

                    # Run with elevated privileges if possible
                    try:
                        if os.name == 'nt':  # On Windows
                            import ctypes
                            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                                self.logger.warning("Not running with admin privileges. Rules may not be created.")

                        process = subprocess.run(
                            ps_cmd,
                            capture_output=True,
                            text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )

                        if process.returncode != 0:
                            error_msg = process.stderr or "No error message available"
                            self.logger.error(f"Command failed with output: {error_msg}")
                            # Try alternative method with netsh if powershell fails
                            netsh_cmd = [
                                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                f'name="{rule_name}"',
                                'dir=out',
                                'action=block',
                                'enable=yes',
                                f'program="{resolved_path}"',
                                f'protocol={protocol}',
                                f'remoteip={target_ip}',
                                'profile=private,public,domain'
                            ]

                            self.logger.info("Trying alternative method with netsh...")
                            process = subprocess.run(
                                netsh_cmd,
                                capture_output=True,
                                text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW
                            )

                            if process.returncode != 0:
                                self.logger.error(f"Both methods failed. Last error: {process.stderr}")
                                return False

                        self.logger.info(f"Added {protocol} rule: {rule_name}")

                    except Exception as e:
                        self.logger.error(f"Error executing command: {e}")
                        return False

                return True

            else:  # Remove rules
                try:
                    # Use PowerShell for removal
                    ps_cmd = [
                        'powershell', '-Command',
                        f'Get-NetFirewallRule -DisplayName "APP_{process_name}_BLOCK*" | Remove-NetFirewallRule'
                    ]

                    subprocess.run(ps_cmd, check=False, capture_output=True, text=True)

                    # Also try netsh removal as backup
                    rules = self._get_app_rules(process_name)
                    matching_rules = [r for r in rules if target_ip in r]

                    for rule_name in matching_rules:
                        cmd = [
                            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            f'name="{rule_name}"'
                        ]
                        subprocess.run(cmd, check=False, capture_output=True, text=True)

                    self.logger.info(f"Removed rules for {process_name}")
                    return True

                except Exception as e:
                    self.logger.error(f"Error removing rules: {e}")
                    return False

        except Exception as e:
            self.logger.error(f"Error in create_windows_rules: {e}")
            return False

    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
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