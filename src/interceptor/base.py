import socket
import logging
from pathlib import Path
from abc import ABC, abstractmethod
from .database import DatabaseHandler

class BaseInterceptor(ABC):
    """Base class for all platform-specific interceptors"""
    
    def __init__(self):
        self.logger = logging.getLogger('interceptor')
        self.db = DatabaseHandler()
        
    def setup_logging(self):
        """Setup logging for interceptor"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger('interceptor')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        fh = logging.FileHandler(log_dir / 'interceptor.log')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
    
    def resolve_domain(self, domain: str) -> dict:
        """Resolve domain to both IPv4 and IPv6 addresses"""
        addresses = {'ipv4': [], 'ipv6': []}
        try:
            # Get all address info
            addrinfo = socket.getaddrinfo(domain, None)
            for addr in addrinfo:
                ip = addr[4][0]
                if ':' in ip:  # IPv6
                    addresses['ipv6'].append(ip)
                else:  # IPv4
                    addresses['ipv4'].append(ip)

            # Remove duplicates
            addresses['ipv4'] = list(set(addresses['ipv4']))
            addresses['ipv6'] = list(set(addresses['ipv6']))
            return addresses
        except socket.gaierror:
            self.logger.error(f"Failed to resolve domain: {domain}")
            return addresses

    def _is_ip(self, addr: str) -> bool:
        """Check if string is IP address"""
        try:
            socket.inet_pton(socket.AF_INET, addr)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, addr)
                return True
            except socket.error:
                return False
    
    @abstractmethod
    def create_rule(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create firewall rule - must be implemented by platform-specific classes"""
        pass
        
    @abstractmethod
    def remove_rule(self, app_path: str, target_ip: str) -> bool:
        """Remove firewall rule - must be implemented by platform-specific classes"""
        pass
        
    @abstractmethod
    def cleanup_rules(self) -> bool:
        """Cleanup all rules - must be implemented by platform-specific classes"""
        pass