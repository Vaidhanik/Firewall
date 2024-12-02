import subprocess
import logging
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger('interceptor')

class LinuxGeoBlocker:
    def __init__(self):
        self.ipset_name_template = "country_{}"
        self.logger = logging.getLogger('interceptor')
        
    def check_dependencies(self) -> bool:
        """Check if required dependencies are installed"""
        try:
            subprocess.run(['which', 'ipset'], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            self.logger.error("ipset command not found. Please install ipset package.")
            print("\nMissing required package: ipset")
            print("Please install it using:")
            print("  sudo apt-get install ipset    # For Debian/Ubuntu")
            print("  sudo yum install ipset        # For RHEL/CentOS")
            return False
            
    def _create_country_ipset(self, country_code: str) -> Tuple[bool, bool]:
        """Create ipsets for a country for both IPv4 and IPv6"""
        try:
            if not self.check_dependencies():
                return False, False
                
            ipv4_success = False
            ipv6_success = False
            
            # Create IPv4 ipset
            ipset_name_v4 = f"{self.ipset_name_template.format(country_code.lower())}_v4"
            try:
                subprocess.run([
                    'sudo', 'ipset', 'create', ipset_name_v4, 'hash:net',
                    'family', 'inet', 'hashsize', '4096'
                ], check=False, capture_output=True)
                
                # Add example IPv4 ranges
                example_ips_v4 = ['1.2.3.0/24', '5.6.7.0/24']
                for ip in example_ips_v4:
                    subprocess.run([
                        'sudo', 'ipset', 'add', ipset_name_v4, ip
                    ], check=False, capture_output=True)
                ipv4_success = True
            except Exception as e:
                self.logger.error(f"Error creating IPv4 ipset: {e}")
                
            # Create IPv6 ipset
            ipset_name_v6 = f"{self.ipset_name_template.format(country_code.lower())}_v6"
            try:
                subprocess.run([
                    'sudo', 'ipset', 'create', ipset_name_v6, 'hash:net',
                    'family', 'inet6', 'hashsize', '4096'
                ], check=False, capture_output=True)
                
                # Add example IPv6 ranges
                example_ips_v6 = ['2001:db8::/32', '2001:db9::/32']
                for ip in example_ips_v6:
                    subprocess.run([
                        'sudo', 'ipset', 'add', ipset_name_v6, ip
                    ], check=False, capture_output=True)
                ipv6_success = True
            except Exception as e:
                self.logger.error(f"Error creating IPv6 ipset: {e}")
                
            return ipv4_success, ipv6_success
            
        except Exception as e:
            self.logger.error(f"Error creating ipsets for {country_code}: {e}")
            return False, False
            
    def add_country_block(self, app_name: str, country_code: str) -> bool:
        """Add iptables rules to block traffic to a country for an app"""
        try:
            if not self.check_dependencies():
                return False
                
            chain_name = f"APP_{app_name.upper()}"
            ipv4_success, ipv6_success = self._create_country_ipset(country_code)
            
            if not ipv4_success and not ipv6_success:
                return False
                
            success = True
            
            # Handle IPv4 rules
            if ipv4_success:
                ipset_name_v4 = f"{self.ipset_name_template.format(country_code.lower())}_v4"
                try:
                    # Check if chain exists
                    check = subprocess.run(
                        ['sudo', 'iptables', '-L', chain_name],
                        capture_output=True,
                        check=False
                    )
                    
                    if check.returncode != 0:
                        subprocess.run(['sudo', 'iptables', '-N', chain_name], check=True)
                        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-j', chain_name], check=True)
                    
                    # Add IPv4 rule
                    subprocess.run([
                        'sudo', 'iptables', '-A', chain_name,
                        '-m', 'set', '--match-set', ipset_name_v4, 'dst',
                        '-j', 'DROP'
                    ], check=True, capture_output=True)
                except Exception as e:
                    self.logger.error(f"Error adding IPv4 rule: {e}")
                    success = False
            
            # Handle IPv6 rules
            if ipv6_success:
                ipset_name_v6 = f"{self.ipset_name_template.format(country_code.lower())}_v6"
                try:
                    # Check if chain exists
                    check = subprocess.run(
                        ['sudo', 'ip6tables', '-L', chain_name],
                        capture_output=True,
                        check=False
                    )
                    
                    if check.returncode != 0:
                        subprocess.run(['sudo', 'ip6tables', '-N', chain_name], check=True)
                        subprocess.run(['sudo', 'ip6tables', '-A', 'OUTPUT', '-j', chain_name], check=True)
                    
                    # Add IPv6 rule
                    subprocess.run([
                        'sudo', 'ip6tables', '-A', chain_name,
                        '-m', 'set', '--match-set', ipset_name_v6, 'dst',
                        '-j', 'DROP'
                    ], check=True, capture_output=True)
                except Exception as e:
                    self.logger.error(f"Error adding IPv6 rule: {e}")
                    success = False
            
            if success:
                self.logger.info(f"Successfully added country block for {app_name} -> {country_code}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error adding country block for {app_name}/{country_code}: {e}")
            return False
        
    def remove_country_block(self, app_name: str, country_code: str) -> bool:
        """Remove country block for an application"""
        try:
            chain_name = f"APP_{app_name.upper()}"
            ipset_name_v4 = f"{self.ipset_name_template.format(country_code.lower())}_v4"
            ipset_name_v6 = f"{self.ipset_name_template.format(country_code.lower())}_v6"

            # Remove IPv4 rules
            try:
                subprocess.run([
                    'sudo', 'iptables', '-D', chain_name,
                    '-m', 'set', '--match-set', ipset_name_v4, 'dst',
                    '-j', 'DROP'
                ], check=False, capture_output=True)

                # Destroy IPv4 ipset
                subprocess.run([
                    'sudo', 'ipset', 'destroy', ipset_name_v4
                ], check=False, capture_output=True)
            except Exception as e:
                self.logger.warning(f"Error removing IPv4 rules: {e}")

            # Remove IPv6 rules
            try:
                subprocess.run([
                    'sudo', 'ip6tables', '-D', chain_name,
                    '-m', 'set', '--match-set', ipset_name_v6, 'dst',
                    '-j', 'DROP'
                ], check=False, capture_output=True)

                # Destroy IPv6 ipset
                subprocess.run([
                    'sudo', 'ipset', 'destroy', ipset_name_v6
                ], check=False, capture_output=True)
            except Exception as e:
                self.logger.warning(f"Error removing IPv6 rules: {e}")

            self.logger.info(f"Successfully removed country block for {app_name} -> {country_code}")
            return True

        except Exception as e:
            self.logger.error(f"Error removing country block: {e}")
            return False
        
    def cleanup_country_ipsets(self):
        """Clean up all country-related ipsets"""
        try:
            # List all ipsets
            output = subprocess.check_output(['sudo', 'ipset', 'list', '-n'], 
                                          universal_newlines=True)
            
            # Find and remove country ipsets (both v4 and v6)
            for ipset_name in output.split('\n'):
                if ipset_name.startswith('country_'):
                    try:
                        subprocess.run(['sudo', 'ipset', 'destroy', ipset_name.strip()], 
                                    check=False,
                                    capture_output=True)
                        self.logger.info(f"Removed ipset: {ipset_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to remove ipset {ipset_name}: {e}")
                        
            return True
        except Exception as e:
            self.logger.error(f"Error cleaning up ipsets: {e}")
            return False