import subprocess
from .base import BaseInterceptor

class MacOSInterceptor(BaseInterceptor):
    def __init__(self):
        super().__init__()
        self.anchor_base = "/etc/pf.anchors"
        
    def create_rule(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create PF firewall rule"""
        try:
            # Create unique anchor name
            anchor_name = f"block.{app_path.replace('/', '_')}.{target_ip}"
            
            if action == 'add':
                # Create rule file
                rule = f"block drop out proto {{tcp,udp}} from any to {target_ip}"
                rule_file = f"{self.anchor_base}/{anchor_name}"
                
                # Write rule to file
                with open(rule_file, 'w') as f:
                    f.write(rule)
                
                # Add anchor and enable PF
                subprocess.run(['sudo', 'pfctl', '-a', anchor_name, '-f', rule_file], check=True)
                subprocess.run(['sudo', 'pfctl', '-e'], check=True)
                
                self.logger.info(f"Added PF rule for {app_path} -> {target_ip}")
                return True
                
            else:
                # Remove anchor
                subprocess.run(['sudo', 'pfctl', '-a', anchor_name, '-F', 'all'], check=True)
                self.logger.info(f"Removed PF rule for {app_path} -> {target_ip}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to {'add' if action == 'add' else 'remove'} PF rule: {e}")
            return False
            
    def remove_rule(self, app_path: str, target_ip: str) -> bool:
        """Remove PF firewall rule"""
        return self.create_rule(app_path, target_ip, action='remove')
        
    def cleanup_rules(self) -> bool:
        """Clean up all PF rules"""
        try:
            # Remove all block anchors
            subprocess.run(['sudo', 'pfctl', '-F', 'all'], check=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to cleanup PF rules: {e}")
            return False