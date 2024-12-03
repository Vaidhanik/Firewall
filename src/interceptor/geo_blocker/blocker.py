import os
import subprocess
import logging
import tempfile
# import pandas as pd
import geoip2.database
import requests
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger('interceptor')

class LinuxGeoBlocker:
    def __init__(self):
        self.ipset_name_template = "country_{}"
        self.logger = logging.getLogger('interceptor')
        self.geoip_db_path = Path(os.path.abspath('GeoLite2-Country.mmdb'))
        
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

    def _get_country_cidrs(self, country_code: str) -> Tuple[List[str], List[str]]:
        """Get IPv4 and IPv6 CIDR ranges for country using CSV files"""
        try:
            import csv

            # Get geoname_id for country
            geoname_id = None
            with open('GeoLite2-Country-CSV_20241129/GeoLite2-Country-Locations-en.csv') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['country_iso_code'] == country_code:
                        geoname_id = int(row['geoname_id'])
                        break

            if not geoname_id:
                return [], []

            ipv4_ranges = []
            with open('GeoLite2-Country-CSV_20241129/GeoLite2-Country-Blocks-IPv4.csv') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['geoname_id'] and int(float(row['geoname_id'])) == geoname_id:
                        ipv4_ranges.append(row['network'])

            ipv6_ranges = []
            with open('GeoLite2-Country-CSV_20241129/GeoLite2-Country-Blocks-IPv6.csv') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['geoname_id'] and int(float(row['geoname_id'])) == geoname_id:
                        ipv6_ranges.append(row['network'])

            return ipv4_ranges, ipv6_ranges

        except Exception as e:
            self.logger.error(f"Error getting country CIDRs: {e}")
            return [], []
        
    def _setup_ipset(self, name: str, family: str) -> bool:
        try:
            subprocess.run(['sudo', 'ipset', 'create', name, 'hash:net',
                          'family', family, 'hashsize', '4096', '-exist'], check=True)
            return True
        except Exception as e:
            self.logger.error(f"Error creating ipset {name}: {e}")
            return False
        
    def _populate_ipset(self, name: str, cidrs: List[str]) -> bool:
        try:
            # Remove duplicates while preserving order
            unique_cidrs = list(dict.fromkeys(cidrs))
            
            with tempfile.NamedTemporaryFile(mode='w') as f:
                # Flush existing entries
                f.write(f"flush {name}\n")
                
                # Add unique entries
                for cidr in unique_cidrs:
                    f.write(f"add {name} {cidr}\n")
                f.flush()
                
                subprocess.run(['sudo', 'ipset', 'restore', '-f', f.name], check=True)
            return True
            
        except Exception as e:
            self.logger.error(f"Error populating ipset {name}: {e}")
            return False

    def _add_iptables_rules(self, cmd: str, app_name: str, ipset_name: str, country: str) -> bool:
        try:
            chain_name = f"APP_{app_name.upper()}"
            user = subprocess.check_output(['whoami']).decode().strip()

            subprocess.run(['sudo', cmd, '-N', chain_name], check=False)
            check = subprocess.run(['sudo', cmd, '-C', 'OUTPUT', '-j', chain_name],
                                 capture_output=True, check=False)
            if check.returncode != 0:
                subprocess.run(['sudo', cmd, '-I', 'OUTPUT', '1', '-j', chain_name], check=True)    

            rule_cmd = [
                'sudo', cmd, '-A', chain_name,
                '-m', 'owner', '--uid-owner', user,
                '-m', 'set', '--match-set', ipset_name, 'dst',
                '-j', 'DROP'
            ]
            subprocess.run(rule_cmd, check=True)
            return True

        except Exception as e:
            self.logger.error(f"Error adding {cmd} rules: {e}")
            return False    

    def add_country_block(self, app_name: str, country_code: str) -> bool:
        try:
            country_code = country_code.upper()
            app_name = app_name.lower()

            ipv4_ranges, ipv6_ranges = self._get_country_cidrs(country_code)
            if not ipv4_ranges and not ipv6_ranges:
                self.logger.error(f"No IP ranges found for {country_code}")
                return False

            ipset_v4 = f"{self.ipset_name_template.format(country_code.lower())}_v4"
            ipset_v6 = f"{self.ipset_name_template.format(country_code.lower())}_v6"

            success_v4 = success_v6 = True

            if ipv4_ranges:
                if self._setup_ipset(ipset_v4, 'inet'):
                    success_v4 = self._populate_ipset(ipset_v4, ipv4_ranges)
                    if success_v4:
                        success_v4 = self._add_iptables_rules('iptables', app_name, ipset_v4, country_code)

            if ipv6_ranges:
                if self._setup_ipset(ipset_v6, 'inet6'):
                    success_v6 = self._populate_ipset(ipset_v6, ipv6_ranges)
                    if success_v6:
                        success_v6 = self._add_iptables_rules('ip6tables', app_name, ipset_v6, country_code)

            return success_v4 or success_v6

        except Exception as e:
            self.logger.error(f"Error in add_country_block: {e}")
            return False    
        
    def remove_country_block(self, app_name: str, country_code: str) -> bool:
        try:
            country_code = country_code.upper()
            app_name = app_name.lower()
            
            chain_name = f"APP_{app_name.upper()}"
            ipset_v4 = f"{self.ipset_name_template.format(country_code.lower())}_v4"
            ipset_v6 = f"{self.ipset_name_template.format(country_code.lower())}_v6"
            
            success = True
            
            try:
                subprocess.run(['sudo', 'iptables', '-D', chain_name,
                              '-m', 'set', '--match-set', ipset_v4, 'dst',
                              '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'ipset', 'destroy', ipset_v4], check=False)
            except Exception as e:
                self.logger.warning(f"Error removing IPv4 rules: {e}")
                success = False
                
            try:
                subprocess.run(['sudo', 'ip6tables', '-D', chain_name,
                              '-m', 'set', '--match-set', ipset_v6, 'dst',
                              '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'ipset', 'destroy', ipset_v6], check=False)
            except Exception as e:
                self.logger.warning(f"Error removing IPv6 rules: {e}")
                success = False
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error in remove_country_block: {e}")
            return False
        
    def cleanup_country_ipsets(self):
        try:
            output = subprocess.check_output(['sudo', 'ipset', 'list', '-n'],
                                          universal_newlines=True)
            for ipset_name in output.split('\n'):
                if ipset_name.startswith('country_'):
                    subprocess.run(['sudo', 'ipset', 'destroy', ipset_name.strip()],
                                 check=False, capture_output=True)
            return True
        except Exception as e:
            self.logger.error(f"Error cleaning up ipsets: {e}")
            return False