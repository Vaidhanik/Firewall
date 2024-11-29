import platform
from typing import List, Tuple
from .linux import LinuxInterceptor
from .macos import MacOSInterceptor
from .database import DatabaseHandler
from .windows import WindowsInterceptor

class NetworkInterceptor:
    """Main network interceptor class that handles platform-specific implementations"""
    
    def __init__(self, db_path: str = "interceptor.db"):
        # Initialize platform-specific interceptor
        os_type = platform.system().lower()
        if os_type == 'linux':
            self.interceptor = LinuxInterceptor()
        elif os_type == 'darwin':
            self.interceptor = MacOSInterceptor()
        elif os_type == 'windows':
            self.interceptor = WindowsInterceptor()
        else:
            raise NotImplementedError(f"Unsupported operating system: {os_type}")
            
        # Initialize database handler
        self.db = DatabaseHandler(db_path)
        
        # Setup logging
        self.interceptor.setup_logging()
        self.logger = self.interceptor.logger
        
    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule"""
        # Check if target is IP or domain
        target_type = 'ip' if self.interceptor._is_ip(target) else 'domain'
        resolved_addresses = {'ipv4': [], 'ipv6': []}
        
        if target_type == 'domain':
            self.logger.info(f"Resolving domain {target}...")
            resolved_addresses = self.interceptor.resolve_domain(target)
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
                
            # Track successful rules for rollback
            successful_rules = []
            failed = False
            
            # Add IPv4 rules
            for ip in resolved_addresses['ipv4']:
                if self.interceptor.create_rule(app_name, ip, 'add'):
                    successful_rules.append(('ipv4', ip))
                else:
                    failed = True
                    break
                    
            # Add IPv6 rules if IPv4 was successful
            if not failed:
                for ip in resolved_addresses['ipv6']:
                    if self.interceptor.create_rule(app_name, ip, 'add'):
                        successful_rules.append(('ipv6', ip))
                    else:
                        failed = True
                        break
                        
            if failed:
                # Rollback successful rules
                for ip_version, ip in successful_rules:
                    try:
                        self.interceptor.create_rule(app_name, ip, 'remove')
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
            # Remove firewall rules
            if resolved_ips:
                for ip in resolved_ips.split(','):
                    if not self.interceptor.remove_rule(app_name, ip.strip()):
                        success = False
                        
            # Also try target if it's an IP
            if target_type == 'ip':
                if not self.interceptor.remove_rule(app_name, target):
                    success = False
                    
            # Deactivate in database if successful
            if success:
                self.db.deactivate_rule(rule_id)
                self.logger.info(f"Successfully removed blocking rule for {app_name} -> {target}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error removing blocking rule: {e}")
            return False
            
    def get_active_rules(self) -> List[Tuple]:
        """Get all active blocking rules"""
        return self.db.get_active_rules()
        
    def cleanup_rules(self) -> bool:
        """Clean up all rules"""
        return self.interceptor.cleanup_rules()
        
    def log_blocked_attempt(self, rule_id: int, app_name: str, 
                          source_ip: str, target: str, details: str):
        """Log blocked connection attempt"""
        self.db.log_blocked_attempt(rule_id, app_name, source_ip, target, details)
        self.logger.warning(
            f"Blocked connection attempt: {app_name} "
            f"({source_ip}) -> {target}\nDetails: {details}"
        )