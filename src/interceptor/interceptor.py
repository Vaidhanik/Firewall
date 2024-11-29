import platform
from typing import List, Tuple
from .linux import LinuxInterceptor
from .macos import MacOSInterceptor
from .database import DatabaseHandler
from .windows import WindowsInterceptor

class NetworkInterceptor():
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
    
    def setup_logging(self):
        """Setup logging for interceptor"""
        return self.interceptor.setup_logging()
    
    def resolve_domain(self, domain: str) -> dict:
        """Resolve domain to both IPv4 and IPv6 addresses"""
        return self.interceptor.resolve_domain(domain)

    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule"""
        return self.interceptor.add_blocking_rule(app_name, target)

    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule"""
        print("remove_blocking_rule")
        return self.interceptor.remove_blocking_rule(rule_id)

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

    def _is_ip(self, addr: str) -> bool:
        """Check if string is IP address"""
        return self.interceptor._is_ip(addr)