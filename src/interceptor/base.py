import ipaddress
import socket
import logging
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Dict, List, Set

import dns
from .database import DatabaseHandler

class EnhancedDNSResolver:
    def __init__(self):
        # Initialize with common public DNS servers
        self.dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '9.9.9.9',      # Quad9
            '208.67.222.222'  # OpenDNS
        ]
        
    def resolve_domain(self, domain: str) -> Dict[str, List[str]]:
        """
        Enhanced domain resolution that handles CDNs and multiple DNS servers
        Returns {'ipv4': [...], 'ipv6': [...]}
        """
        resolved_ips: Dict[str, Set[str]] = {'ipv4': set(), 'ipv6': set()}
        
        # Function to safely add IPs to our sets
        def add_ip(ip: str):
            try:
                addr = ipaddress.ip_address(ip)
                if isinstance(addr, ipaddress.IPv4Address):
                    resolved_ips['ipv4'].add(ip)
                else:
                    resolved_ips['ipv6'].add(ip)
            except ValueError:
                pass

        # 1. Standard DNS Resolution
        for dns_server in self.dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            
            # Try both A and AAAA records
            for record_type in ['A', 'AAAA']:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for rdata in answers:
                        add_ip(str(rdata))
                except Exception:
                    continue

        # 2. Resolve common CDN domains
        cdn_domains = [
            f'cdn.{domain}',
            f'static.{domain}',
            f'media.{domain}',
            f'assets.{domain}',
            f'content.{domain}'
        ]
        
        for cdn_domain in cdn_domains:
            try:
                addrs = socket.getaddrinfo(cdn_domain, None)
                for addr in addrs:
                    add_ip(addr[4][0])
            except socket.gaierror:
                continue

        # 3. Handle specific cases for major services
        if any(service in domain for service in ['facebook', 'instagram', 'whatsapp', 'chat.openai.com', 'openai', 'chatgpt']):
            try:
                # Get edge IPs for Facebook's infrastructure
                edge_domains = [
                    f'edge-{domain}',
                    f'star-mini.{domain}',
                    f'connect.{domain}',
                    f'graph.{domain}'
                ]
                
                for edge_domain in edge_domains:
                    try:
                        addrs = socket.getaddrinfo(edge_domain, None)
                        for addr in addrs:
                            add_ip(addr[4][0])
                    except socket.gaierror:
                        continue
                        
            except Exception:
                pass

        # 4. Handle subdomains
        common_subdomains = ['www', 'm', 'api', 'mobile']
        for subdomain in common_subdomains:
            try:
                full_domain = f'{subdomain}.{domain}'
                addrs = socket.getaddrinfo(full_domain, None)
                for addr in addrs:
                    add_ip(addr[4][0])
            except socket.gaierror:
                continue

        # Convert sets back to lists
        return {
            'ipv4': list(resolved_ips['ipv4']),
            'ipv6': list(resolved_ips['ipv6'])
        }

    def resolve_with_asn(self, domain: str) -> Dict[str, List[str]]:
        """
        Additional method to resolve IPs using ASN information
        This can help catch entire IP ranges used by major services
        """
        try:
            # First get standard IPs
            resolved = self.resolve_domain(domain)
            
            # Then try to get ASN info for one of the IPs
            if resolved['ipv4']:
                sample_ip = resolved['ipv4'][0]
                # Use ipwhois or similar service to get ASN info
                # This would require additional setup/API keys
                # Add implementation here if needed
                
            return resolved
        except Exception:
            return {'ipv4': [], 'ipv6': []}

class BaseInterceptor(ABC):
    """Base class for all platform-specific interceptors"""
    
    def __init__(self):
        self.logger = logging.getLogger('interceptor')
        self.db = DatabaseHandler()
        self.dns_resolver = EnhancedDNSResolver()

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
    
    # def resolve_domain(self, domain: str) -> dict:
    #     """Resolve domain to both IPv4 and IPv6 addresses"""
    #     addresses = {'ipv4': [], 'ipv6': []}
    #     try:
    #         # Get all address info
    #         addrinfo = socket.getaddrinfo(domain, None)
    #         for addr in addrinfo:
    #             ip = addr[4][0]
    #             if ':' in ip:  # IPv6
    #                 addresses['ipv6'].append(ip)
    #             else:  # IPv4
    #                 addresses['ipv4'].append(ip)

    #         # Remove duplicates
    #         addresses['ipv4'] = list(set(addresses['ipv4']))
    #         addresses['ipv6'] = list(set(addresses['ipv6']))
    #         return addresses
    #     except socket.gaierror:
    #         self.logger.error(f"Failed to resolve domain: {domain}")
    #         return addresses

    def resolve_domain(self, domain: str) -> dict:
        """Resolve domain to both IPv4 and IPv6 addresses using enhanced resolver"""
        try:
            resolved = self.dns_resolver.resolve_domain(domain)
            if not resolved['ipv4'] and not resolved['ipv6']:
                resolved = self.dns_resolver.resolve_with_asn(domain)
                
            # Remove duplicates
            resolved['ipv4'] = list(set(resolved['ipv4']))
            resolved['ipv6'] = list(set(resolved['ipv6']))
            return resolved
            
        except Exception as e:
            self.logger.error(f"Failed to resolve domain {domain}: {e}")
            return {'ipv4': [], 'ipv6': []}

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
    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Create firewall rule - must be implemented by platform-specific classes"""
        pass
        
    @abstractmethod
    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove firewall rule - must be implemented by platform-specific classes"""
        pass
        
    @abstractmethod
    def force_cleanup_rules(self):
        """Cleanup all rules - must be implemented by platform-specific classes"""
        pass
    
    @abstractmethod
    def get_process_info(self, pid: str) -> dict:
        """Cleanup all rules - must be implemented by platform-specific classes"""
        pass