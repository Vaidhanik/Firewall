import os
import logging
import ipaddress
import geoip2.database
from pathlib import Path
from typing import List, Dict, Optional
from geoip2.errors import AddressNotFoundError

logger = logging.getLogger('interceptor')

class GeoBlockManager:
    def __init__(self):
        self.db_dir = Path('geoip_db')
        self.db_dir.mkdir(exist_ok=True)
        self.db_path = self.db_dir / 'GeoLite2-Country.mmdb'
        self._download_db_if_needed()
        
    def _download_db_if_needed(self):
        """Download GeoLite2 database if not present"""
        if not self.db_path.exists():
            import requests
            # Use a mirror or your MaxMind license key in production
            url = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
            response = requests.get(url)
            with open(self.db_path, 'wb') as f:
                f.write(response.content)
            logger.info(f"Downloaded GeoIP database to {self.db_path}")

    def get_country_for_ip(self, ip: str) -> Optional[str]:
        """Get country code for an IP address"""
        try:
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.country(ip)
                return response.country.iso_code
        except (AddressNotFoundError, ValueError):
            return None
        except Exception as e:
            logger.error(f"Error getting country for IP {ip}: {e}")
            return None

    def get_country_ip_ranges(self, country_code: str) -> Dict[str, List[str]]:
        """Get all IP ranges for a country"""
        ip_ranges = {'ipv4': [], 'ipv6': []}
        # This would ideally use a proper IP range database
        # For now, return example ranges
        return ip_ranges