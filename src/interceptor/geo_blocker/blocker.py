import subprocess
import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger('interceptor')

class LinuxGeoBlocker:
    def __init__(self):
        self.ipset_name_template = "country_{}"
        
    def _create_country_ipset(self, country_code: str) -> bool:
        """Create an ipset for a country"""
        try:
            ipset_name = self.ipset_name_template.format(country_code.lower())
            
            # Create the ipset if it doesn't exist
            subprocess.run([
                'sudo', 'ipset', 'create', ipset_name, 'hash:net',
                'family', 'inet', 'hashsize', '4096'
            ], check=False)  # Use check=False as it might already exist
            
            return True
        except Exception as e:
            logger.error(f"Error creating ipset for {country_code}: {e}")
            return False
            
    def add_country_block(self, app_name: str, country_code: str) -> bool:
        """Add iptables rules to block traffic to a country for an app"""
        try:
            ipset_name = self.ipset_name_template.format(country_code.lower())
            chain_name = f"APP_{app_name.upper()}"
            
            # Create ipset for country if needed
            if not self._create_country_ipset(country_code):
                return False
                
            # Add iptables rules using ipset
            rules = [
                ['sudo', 'iptables', '-A', chain_name,
                 '-m', 'set', '--match-set', ipset_name, 'dst',
                 '-j', 'DROP'],
                ['sudo', 'ip6tables', '-A', chain_name,
                 '-m', 'set', '--match-set', ipset_name, 'dst',
                 '-j', 'DROP']
            ]
            
            for rule in rules:
                subprocess.run(rule, check=True)
                
            return True
            
        except Exception as e:
            logger.error(f"Error adding country block for {app_name}/{country_code}: {e}")
            return False
            
    def remove_country_block(self, app_name: str, country_code: str) -> bool:
        """Remove country block for an app"""
        try:
            ipset_name = self.ipset_name_template.format(country_code.lower())
            chain_name = f"APP_{app_name.upper()}"
            
            # Remove iptables rules
            rules = [
                ['sudo', 'iptables', '-D', chain_name,
                 '-m', 'set', '--match-set', ipset_name, 'dst',
                 '-j', 'DROP'],
                ['sudo', 'ip6tables', '-D', chain_name,
                 '-m', 'set', '--match-set', ipset_name, 'dst',
                 '-j', 'DROP']
            ]
            
            for rule in rules:
                subprocess.run(rule, check=False)  # Use check=False as rule might not exist
                
            return True
            
        except Exception as e:
            logger.error(f"Error removing country block for {app_name}/{country_code}: {e}")
            return False
            
    def update_country_ipset(self, country_code: str, ip_ranges: List[str]) -> bool:
        """Update IP ranges in country ipset"""
        try:
            ipset_name = self.ipset_name_template.format(country_code.lower())
            
            # Flush existing entries
            subprocess.run(['sudo', 'ipset', 'flush', ipset_name], check=True)
            
            # Add new IP ranges
            for ip_range in ip_ranges:
                subprocess.run([
                    'sudo', 'ipset', 'add', ipset_name, ip_range
                ], check=True)
                
            return True
            
        except Exception as e:
            logger.error(f"Error updating ipset for {country_code}: {e}")
            return False

    def cleanup_country_ipsets(self):
        """Clean up all country ipsets"""
        try:
            # List all ipsets
            output = subprocess.check_output(['sudo', 'ipset', 'list']).decode()
            
            # Find and remove country ipsets
            for line in output.split('\n'):
                if line.startswith('Name: country_'):
                    ipset_name = line.split()[1]
                    subprocess.run(['sudo', 'ipset', 'destroy', ipset_name], check=False)
                    
        except Exception as e:
            logger.error(f"Error cleaning up country ipsets: {e}")