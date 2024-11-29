import subprocess
from .base import BaseInterceptor

class WindowsInterceptor(BaseInterceptor):
    def create_rule(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create Windows Firewall rule"""
        try:
            rule_name = f"Block {app_path} to {target_ip}"
            
            if action == 'add':
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=' + rule_name,
                    'dir=out',
                    'action=block',
                    'enable=yes',
                    'program=' + app_path,
                    'remoteip=' + target_ip
                ]
            else:
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    'name=' + rule_name
                ]
            
            subprocess.run(cmd, check=True)
            self.logger.info(f"{'Added' if action == 'add' else 'Removed'} Windows Firewall rule for {app_path} -> {target_ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to {'add' if action == 'add' else 'remove'} Windows Firewall rule: {e}")
            return False
            
    def remove_rule(self, app_path: str, target_ip: str) -> bool:
        """Remove Windows Firewall rule"""
        return self.create_rule(app_path, target_ip, action='remove')
        
    def cleanup_rules(self) -> bool:
        """Clean up all Windows Firewall rules"""
        try:
            # Remove all rules created by our app
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=all',
                'dir=out'
            ]
            subprocess.run(cmd, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to cleanup Windows Firewall rules: {e}")
            return False