import socket
import subprocess
import csv
import datetime
import time
from pathlib import Path
import json
from collections import defaultdict
import os
import re
from typing import Optional, Dict

class NetworkMonitor:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.logs_dir = self.script_dir / 'logs'
        self.logs_dir.mkdir(exist_ok=True)
        
        self.active_apps = set()
        self.start_time = datetime.datetime.now()
        
        # Enhanced service ports mapping
        self.service_ports = {
            # Email related ports
            25: 'SMTP', 
            465: 'SMTPS',
            587: 'SMTP/Submission',
            110: 'POP3',
            995: 'POP3S',
            143: 'IMAP',
            993: 'IMAPS',
            # Web related
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            # File Transfer
            20: 'FTP-Data',
            21: 'FTP-Control',
            22: 'SSH/SFTP',
            69: 'TFTP',
            # Database
            1433: 'MSSQL',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            # Other common services
            53: 'DNS',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            389: 'LDAP',
            636: 'LDAPS',
            1080: 'SOCKS',
            3389: 'RDP',
            5222: 'XMPP',
            5269: 'XMPP-Server',
            6379: 'Redis'
        }

        # Email service domains
        self.email_domains = {
            'gmail.com', 'smtp.gmail.com', 'imap.gmail.com', 'pop.gmail.com',
            'outlook.com', 'smtp.office365.com', 'outlook.office365.com',
            'yahoo.com', 'smtp.mail.yahoo.com',
            'smtp.live.com', 'hotmail.com',
            'protonmail.com', 'mail.protonmail.com'
        }
        
        self.initialize_logs()

    def initialize_logs(self):
        """Initialize log files with enhanced headers"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Connection logs
        self.conn_file = self.logs_dir / f"connections_{timestamp}.csv"
        self.conn_headers = [
            'timestamp', 'app_name', 'pid', 'protocol',
            'local_addr', 'local_port', 'local_mac', 'remote_addr', 'remote_port', 'remote_mac',
            'domain', 'service', 'direction', 'state', 'service_type'
        ]
        
        # Application stats logs
        self.stats_file = self.logs_dir / f"app_stats_{timestamp}.csv"
        self.stats_headers = [
            'timestamp', 'app_name', 'total_connections',
            'unique_destinations', 'services_accessed', 'email_connections'
        ]

        # Email traffic logs
        self.email_file = self.logs_dir / f"email_traffic_{timestamp}.csv"
        self.email_headers = [
            'timestamp', 'app_name', 'service_type', 'remote_domain',
            'protocol', 'direction'
        ]

        # Initialize all CSV files
        for file_path, headers in [
            (self.conn_file, self.conn_headers),
            (self.stats_file, self.stats_headers),
            (self.email_file, self.email_headers)
        ]:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def get_connections(self):
        """Get both TCP and UDP connections"""
        connections = []
        try:
            # Get TCP connections
            tcp_cmd = ["netstat", "-tnp"]
            if os.geteuid() != 0:
                tcp_cmd.insert(0, "sudo")
            tcp_output = subprocess.check_output(tcp_cmd, universal_newlines=True)
            
            # Get UDP connections
            udp_cmd = ["netstat", "-unp"]
            if os.geteuid() != 0:
                udp_cmd.insert(0, "sudo")
            udp_output = subprocess.check_output(udp_cmd, universal_newlines=True)
            
            # Process both outputs
            for output in [tcp_output, udp_output]:
                for line in output.split('\n')[2:]:
                    if not line:
                        continue
                    try:
                        parts = line.split()
                        if len(parts) < 7:
                            continue

                        proto = parts[0]
                        local = parts[3]
                        remote = parts[4]
                        state = parts[5] if proto == 'tcp' else 'stateless'
                        program_info = parts[6]

                        local_addr, local_port = local.rsplit(':', 1)
                        remote_addr, remote_port = remote.rsplit(':', 1)
                        
                        program_parts = program_info.split('/')
                        program = program_parts[1]
                        pid = program_parts[0] if len(program_parts) > 1 else 'Unknown'

                        connections.append({
                            'protocol': proto,
                            'local_addr': local_addr,
                            'local_port': int(local_port),
                            'remote_addr': remote_addr,
                            'remote_port': int(remote_port),
                            'state': state,
                            'program': program,
                            'pid': pid
                        })

                    except (ValueError, IndexError):
                        continue

        except subprocess.CalledProcessError as e:
            print(f"Error running netstat: {e}")
        
        return connections

    def is_email_related(self, domain, port):
        """Check if connection is email related"""
        if port in [25, 465, 587, 110, 995, 143, 993]:
            return True
        return any(email_domain in domain.lower() for email_domain in self.email_domains)

    def get_service_type(self, domain, port):
        """Determine service type with enhanced email detection"""
        if self.is_email_related(domain, port):
            if port in [25, 465, 587]:
                return 'EMAIL-SMTP'
            elif port in [110, 995]:
                return 'EMAIL-POP3'
            elif port in [143, 993]:
                return 'EMAIL-IMAP'
            return 'EMAIL-OTHER'
        
        base_service = self.service_ports.get(port, '')
        if 'HTTP' in base_service:
            return 'WEB'
        elif 'FTP' in base_service:
            return 'FILE-TRANSFER'
        elif port in [1433, 3306, 5432, 27017]:
            return 'DATABASE'
        return 'OTHER'
    
    '''
    Remote MAC addresses will only be available for devices on the local network
    Non-local addresses will show 'N/A' for MAC
    Both arp and ip neighbor commands require root privileges
    '''
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP using arp command"""
        if ip in ['0.0.0.0', '::', '*', '127.0.0.1', '::1']:
            return None

        try:
            # Run arp command
            arp_cmd = ["arp", "-n", ip]
            if os.geteuid() != 0:
                arp_cmd.insert(0, "sudo")

            output = subprocess.check_output(arp_cmd, universal_newlines=True)

            # Extract MAC address using regex
            mac_match = re.search(r"(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})", output)
            if mac_match:
                return mac_match.group(1).upper()

            # Try using ip neighbor command as fallback
            ip_cmd = ["ip", "neighbor", "show", ip]
            if os.geteuid() != 0:
                ip_cmd.insert(0, "sudo")

            output = subprocess.check_output(ip_cmd, universal_newlines=True)
            mac_match = re.search(r"(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})", output)
            return mac_match.group(1).upper() if mac_match else None

        except (subprocess.CalledProcessError, IndexError):
            return None

    def resolve_domain(self, ip):
        """Resolve IP to domain with timeout"""
        if ip in ['0.0.0.0', '::', '*', '127.0.0.1', '::1']:
            return ip
        try:
            socket.setdefaulttimeout(1)
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip

    def log_connection(self, conn):
        """Log connection with enhanced service detection"""
        timestamp = datetime.datetime.now().isoformat()
        domain = self.resolve_domain(conn['remote_addr'])
        service = self.service_ports.get(conn['remote_port'], f"PORT-{conn['remote_port']}")
        service_type = self.get_service_type(domain, conn['remote_port'])
        
        direction = 'OUTBOUND' if conn['remote_port'] in self.service_ports else 'INBOUND'

        local_mac = self.get_mac_address(conn['local_addr'])
        remote_mac = self.get_mac_address(conn['remote_addr'])
        
        # Log to main connection file
        conn_row = {
            'timestamp': timestamp,
            'app_name': conn['program'],
            'pid': conn['pid'],
            'protocol': conn['protocol'],
            'local_addr': conn['local_addr'],
            'local_port': conn['local_port'],
            'local_mac': local_mac or 'N/A',
            'remote_addr': conn['remote_addr'],
            'remote_port': conn['remote_port'],
            'remote_mac': remote_mac or 'N/A',
            'domain': domain,
            'service': service,
            'direction': direction,
            'state': conn['state'],
            'service_type': service_type
        }

        with open(self.conn_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.conn_headers)
            writer.writerow(conn_row)

        # Log email-specific connections
        if service_type.startswith('EMAIL'):
            email_row = {
                'timestamp': timestamp,
                'app_name': conn['program'],
                'service_type': service_type,
                'remote_domain': domain,
                'protocol': conn['protocol'],
                'direction': direction
            }
            
            with open(self.email_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.email_headers)
                writer.writerow(email_row)

    def update_stats(self, connections):
        """Update statistics with email tracking"""
        timestamp = datetime.datetime.now().isoformat()
        app_stats = defaultdict(lambda: {
            'connections': set(),
            'destinations': set(),
            'services': set(),
            'email_connections': 0
        })

        current_apps = set()
        for conn in connections:
            if conn['state'] == 'ESTABLISHED' or conn['protocol'] == 'udp':
                app = conn['program']
                current_apps.add(app)
                domain = self.resolve_domain(conn['remote_addr'])
                service_type = self.get_service_type(domain, conn['remote_port'])
                
                app_stats[app]['connections'].add(f"{conn['remote_addr']}:{conn['remote_port']}")
                app_stats[app]['destinations'].add(domain)
                app_stats[app]['services'].add(service_type)
                
                if service_type.startswith('EMAIL'):
                    app_stats[app]['email_connections'] += 1

        # Check for new and stopped applications
        new_apps = current_apps - self.active_apps
        stopped_apps = self.active_apps - current_apps

        # for app in new_apps:
        #     print(f"\n[+] New application detected: {app}")
        #     if any(conn['program'] == app and self.get_service_type(self.resolve_domain(conn['remote_addr']), 
        #            conn['remote_port']).startswith('EMAIL') for conn in connections):
        #         print(f"    └─ Email-related activity detected")
        #     if conn['program'] not in self.active_apps:
        #         mac_info = f"\n    └─ Local MAC: {conn["local_mac"] or 'N/A'}"
        #         if conn["remote_mac"]:
        #             mac_info += f"\n    └─ Remote MAC: {conn["remote_mac"]}"
        #         print(mac_info)

        for app in new_apps:
            print(f"\n[+] New application detected: {app}")
            # Find the connection details for this app
            for conn in connections:
                if conn['program'] == app:
                    # Check for email activity
                    domain = self.resolve_domain(conn['remote_addr'])
                    if self.get_service_type(domain, conn['remote_port']).startswith('EMAIL'):
                        print(f"    └─ Email-related activity detected")
                    
                    # Get and display MAC addresses
                    local_mac = self.get_mac_address(conn['local_addr'])
                    remote_mac = self.get_mac_address(conn['remote_addr'])
                    
                    print(f"    └─ Local MAC: {local_mac or 'N/A'}")
                    if remote_mac:
                        print(f"    └─ Remote MAC: {remote_mac}")
                    break  # Show MAC info only once per new app

        for app in stopped_apps:
            print(f"\n[-] Application stopped: {app}")

        self.active_apps = current_apps

        # Log statistics
        with open(self.stats_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.stats_headers)
            
            for app, stats in app_stats.items():
                row = {
                    'timestamp': timestamp,
                    'app_name': app,
                    'total_connections': len(stats['connections']),
                    'unique_destinations': len(stats['destinations']),
                    'services_accessed': ','.join(stats['services']),
                    'email_connections': stats['email_connections']
                }
                writer.writerow(row)

    def monitor(self):
        """Main monitoring loop"""
        print("\nNetwork Monitor Started")
        print(f"Logs directory: {self.logs_dir}")
        print("\nMonitoring network connections (Press Ctrl+C to stop)...")
        print("-" * 80)
        
        try:
            while True:
                connections = self.get_connections()
                for conn in connections:
                    if conn['state'] == 'ESTABLISHED' or conn['protocol'] == 'udp':
                        self.log_connection(conn)
                self.update_stats(connections)
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nStopping Monitor...")
            
            summary = {
                'monitoring_period': {
                    'start': self.start_time.isoformat(),
                    'end': datetime.datetime.now().isoformat()
                },
                'total_applications': len(self.active_apps),
                'applications_monitored': list(self.active_apps),
                'log_files': {
                    'connections': str(self.conn_file.name),
                    'statistics': str(self.stats_file.name),
                    'email_traffic': str(self.email_file.name)
                }
            }
            
            summary_file = self.logs_dir / 'summary.json'
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=4)
            
            print("\nMonitoring Summary:")
            print(f"Total Applications Monitored: {len(self.active_apps)}")
            print(f"\nLog Files:")
            print(f"- Connections: {self.conn_file.name}")
            print(f"- Statistics: {self.stats_file.name}")
            print(f"- Email Traffic: {self.email_file.name}")
            print(f"- Summary: {summary_file.name}")

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.monitor()