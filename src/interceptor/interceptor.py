import platform
from typing import Dict, List, Tuple
from .linux import LinuxInterceptor
from .macos import MacOSInterceptor
from .database import DatabaseHandler
from .windows import WindowsInterceptor
from ai import AIDecisionService, ConnectionData # Issue with import + No `ConnectionClass`

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
        # self.db = DatabaseHandler(db_path)
        self.db = DatabaseHandler()

        # AI - model
        # self.ai_service = AIDecisionService(self.db.ai_client)
        try:
            print("Debug: Initializing AI service...")
            self.ai_service = AIDecisionService(self.db.rules_db)
            print("Debug: AI service initialized successfully")
        except Exception as e:
            print(f"Error initializing AI service: {e}")
            raise
        
        # Setup logging
        self.interceptor.setup_logging()
        self.logger = self.interceptor.logger
    
    def setup_logging(self):
        """Setup logging for interceptor"""
        return self.interceptor.setup_logging()
    
    def resolve_domain(self, domain: str) -> dict:
        """Resolve domain to both IPv4 and IPv6 addresses"""
        return self.interceptor.resolve_domain(domain)
    
    def update_resolved_ips(self, rule_id: int, ips: List[str]) -> bool:
        """Resolve domain to both IPv4 and IPv6 addresses"""
        return self.interceptor.db.update_resolved_ips(rule_id, ips)
    
    def get_process_info(self, pid: str) -> dict:
        """Resolve domain to both IPv4 and IPv6 addresses"""
        return self.interceptor.get_process_info(pid)

    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule"""
        return self.interceptor.add_blocking_rule(app_name, target)

    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule"""
        return self.interceptor.remove_blocking_rule(rule_id)

    def get_active_rules(self) -> List[Tuple]:
        """Get all active blocking rules"""
        return self.db.get_active_rules()
        
    def force_cleanup_rules(self):
        """Force cleanup of all firewall rules"""
        return self.interceptor.force_cleanup_rules()
        
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

    def add_global_blocking_rule(self, target: str) -> bool:
        """Add global blocking rule"""
        return self.interceptor.add_global_blocking_rule(target)

    def remove_global_blocking_rule(self, rule_id: int) -> bool:
        """Remove global blocking rule"""
        return self.interceptor.remove_global_blocking_rule(rule_id)

    def get_global_blocks(self) -> List[Dict]:
        """Get list of active global blocking rules"""
        return self.db.get_active_global_rules()

    def check_connection_allowed(self, conn_data: Dict) -> Tuple[bool, Dict]:
        """
        Check if connection should be allowed based on network patterns
        Returns (allowed, details)
        """
        try:
            # Analyze connection pattern first
            analysis = self.db.analyze_connection_pattern(conn_data)

            # Get AI decision
            allowed, reason = self.db.check_ai_allowed(conn_data)

            details = {
                "type": "ai_decision",
                "reason": reason,
                "analysis": analysis,
                "program": conn_data['program'],
                "connection": f"{conn_data['local_addr']}:{conn_data['local_port']}->{conn_data['remote_addr']}:{conn_data['remote_port']}"
            }

            return allowed, details

        except Exception as e:
            self.logger.error(f"Error checking connection: {e}")
            return True, {"type": "error", "reason": f"Error: {str(e)}"}
        
    def enforce_ai_decision(self, conn_data: Dict, decision: Dict):
        """Enforce AI decision by adding firewall rules if needed"""
        if not decision.get('allowed', True):
            # Add firewall rule to block this connection pattern
            app_name = conn_data['program']
            target_ip = conn_data['remote_addr']

            self.interceptor.create_rule(app_name, target_ip, 'add')

            # Log enforcement
            self.logger.info(
                f"AI Decision enforced: Blocked {app_name} from accessing {target_ip}\n"
                f"Reason: {decision.get('reason', 'Unknown')}"
            )

    def get_ai_decisions(self, limit: int = 100) -> list:
        """Get recent AI decisions"""
        return self.db.get_recent_ai_decisions(limit)