import os
import subprocess
import logging

import requests
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger('interceptor')

class LinuxGeoBlocker:
    def __init__(self):
        self.ipset_name_template = "country_{}"
        self.logger = logging.getLogger('interceptor')
        self.geoip_db_path = Path(os.path.abspath('GeoLite2-Country.mmdb'))
        print(f"DB Path: {self.geoip_db_path}")
        print(f"File exists: {self.geoip_db_path.exists()}")
        self.update_geoip_database()
        
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
  
    def update_geoip_database(self):
        """Download/update MaxMind GeoIP database"""
        if not self.geoip_db_path.exists():
            try:
                license_key = "YOUR_LICENSE_KEY"
                url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
                response = requests.get(url)

                # Save tar.gz file
                temp_file = Path("GeoLite2-Country.tar.gz")
                with open(temp_file, 'wb') as f:
                    f.write(response.content)

                # Extract database file
                import tarfile
                with tarfile.open(temp_file) as tar:
                    db_file = [f for f in tar.getnames() if f.endswith('GeoLite2-Country.mmdb')][0]
                    tar.extract(db_file)
                    Path(db_file).rename(self.geoip_db_path)

                # Cleanup
                temp_file.unlink()

            except Exception as e:
                self.logger.error(f"Failed to download GeoIP database: {e}")

    def _get_country_ip_ranges(self, country_code: str) -> Tuple[List[str], List[str]]:
        """Get IP ranges from RIPE database"""
        try:
            url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={country_code.upper()}"
            response = requests.get(url).json()

            ipv4 = response['data']['resources'].get('ipv4', [])
            ipv6 = response['data']['resources'].get('ipv6', [])

            return ipv4, ipv6
        except Exception as e:
            self.logger.error(f"Error getting ranges: {e}")
            return [], []
        
    def _get_country_domains(self, country_code: str) -> List[str]:
        """Get domains for country using public TLD database"""
        try:
            # Get ccTLD (country code top-level domain)
            ccTLD = f".{country_code.lower()}"
            
            # Get domains from public DNS zone files or TLD database
            url = f"https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
            response = requests.get(url)
            tlds = [line.strip().lower() for line in response.text.splitlines() 
                    if line.strip().lower().endswith(country_code.lower())]
            
            return tlds + [ccTLD]
        except Exception as e:
            self.logger.error(f"Error getting country domains: {e}")
            return [ccTLD]  # Fallback to just ccTLD
        
    def _create_country_ipset(self, country_code: str) -> Tuple[bool, bool]:
        """Create ipsets for a country using real IP ranges"""
        if not self.check_dependencies():
            return False, False
            
        ipv4_ranges, ipv6_ranges = self._get_country_ip_ranges(country_code)
        ipv4_success = self._create_ipset_with_ranges(country_code, 'inet', ipv4_ranges)
        ipv6_success = self._create_ipset_with_ranges(country_code, 'inet6', ipv6_ranges)
        
        return ipv4_success, ipv6_success
        
    def _create_ipset_with_ranges(self, country_code: str, family: str, ranges: List[str]) -> bool:
        """Create ipset and populate with IP ranges"""
        version = 'v4' if family == 'inet' else 'v6'
        ipset_name = f"{self.ipset_name_template.format(country_code.lower())}_{version}"
        
        try:
            # Create ipset
            subprocess.run([
                'sudo', 'ipset', 'create', ipset_name, 'hash:net',
                'family', family, 'hashsize', '4096'
            ], check=True)
            
            # Add IP ranges in batches
            for ip_range in ranges:
                subprocess.run([
                    'sudo', 'ipset', 'add', ipset_name, ip_range
                ], check=False)
                
            return True
        except Exception as e:
            self.logger.error(f"Error creating {family} ipset: {e}")
            return False
            
    def _add_dns_blocks(self, domains: List[str]):
        """Block domains via /etc/hosts"""
        try:
            with open('/etc/hosts', 'a') as f:
                for domain in domains:
                    f.write(f'0.0.0.0 {domain}\n')
                    f.write(f':: {domain}\n')
        except Exception as e:
            self.logger.error(f"Error adding DNS blocks: {e}")
            
    def add_country_block(self, app_name: str, country_code: str) -> bool:
        """Add comprehensive country blocking for an app"""
        try:
            chain_name = f"APP_{app_name.upper()}"
            ipv4_success, ipv6_success = self._create_country_ipset(country_code)
            
            if not ipv4_success and not ipv6_success:
                return False
                
            # Add DNS blocks
            domains = self._get_country_domains(country_code)
            self._add_dns_blocks(domains)
            
            # Add iptables rules with process matching
            if ipv4_success:
                self._add_iptables_rules('iptables', chain_name, app_name, country_code)
                
            if ipv6_success:
                self._add_iptables_rules('ip6tables', chain_name, app_name, country_code)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding country block: {e}")
            return False
            
    def _add_iptables_rules(self, cmd: str, chain: str, app: str, country: str):
        version = 'v4' if cmd == 'iptables' else 'v6'
        ipset_name = f"{self.ipset_name_template.format(country.lower())}_{version}"

        try:
            # Get user running Firefox
            user = subprocess.check_output(['whoami']).decode().strip()

            # Create chain if not exists
            check = subprocess.run(['sudo', cmd, '-L', chain], capture_output=True, check=False)
            if check.returncode != 0:
                subprocess.run(['sudo', cmd, '-N', chain], check=True)
                subprocess.run(['sudo', cmd, '-A', 'OUTPUT', '-j', chain], check=True)

            # Add rule with user matching
            subprocess.run([
                'sudo', cmd, '-A', chain,
                '-m', 'owner', '--uid-owner', user,
                '-m', 'set', '--match-set', ipset_name, 'dst',
                '-j', 'DROP'
            ], check=True)

        except Exception as e:
            self.logger.error(f"Error adding {cmd} rules: {e}")
            
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