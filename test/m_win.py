import os
import re
import csv
import time
import json
import socket
import logging
import datetime
import subprocess
from pathlib import Path
from typing import Optional, Dict
from collections import defaultdict

class WindowsNetworkMonitor:
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

        self.interface_macs = self.get_all_interface_macs()
        print("\nDetected Network Interfaces:")
        for interface, mac in self.interface_macs.items():
            print(f"    {interface}: {mac}")

        self.initialize_logs()

    def initialize_logs(self):
        """Initialize log files with enhanced headers"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Connection logs
        self.conn_file = self.logs_dir / f"connections_{timestamp}.csv"
        self.conn_headers = [
            'timestamp', 'app_name', 'pid', 'protocol',
            'local_addr', 'local_port', 'remote_addr', 'remote_port',
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
        """Get both TCP and UDP connections using netstat for Windows"""
        connections = []
        try:
            # Get TCP and UDP connections using netstat
            cmd = ["netstat", "-ano"]
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            for line in output.split('\n')[4:]:  # Skip header lines
                if not line.strip():
                    continue
                try:
                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    proto = parts[0].lower()
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3] if len(parts) > 3 and proto == 'tcp' else 'stateless'
                    pid = parts[-1]

                    local_addr, local_port = local.rsplit(':', 1)
                    remote_addr, remote_port = remote.rsplit(':', 1)

                    # Get process name from PID
                    try:
                        tasklist_cmd = f'tasklist /FI "PID eq {pid}" /FO CSV /NH'
                        process_output = subprocess.check_output(tasklist_cmd, universal_newlines=True)
                        program = process_output.split(',')[0].strip('"')
                    except:
                        program = 'Unknown'

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

    def get_all_interface_macs(self) -> Dict[str, str]:
        """Get MAC addresses of all network interfaces using Windows commands"""
        interfaces = {}
        try:
            output = subprocess.check_output("ipconfig /all", universal_newlines=True)
            current_interface = None
            current_mac = None
            
            for line in output.split('\n'):
                if ': ' in line:
                    if 'adapter' in line.lower():
                        current_interface = line.split(':')[0].strip()
                        current_mac = None
                    elif 'physical address' in line.lower():
                        current_mac = line.split(':')[1].strip()
                        if current_interface and current_mac:
                            interfaces[current_interface] = current_mac
                            
        except subprocess.CalledProcessError:
            print("Error getting network interfaces")
        
        return interfaces

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

        # Log to main connection file
        conn_row = {
            'timestamp': timestamp,
            'app_name': conn['program'],
            'pid': conn['pid'],
            'protocol': conn['protocol'],
            'local_addr': conn['local_addr'],
            'local_port': conn['local_port'],
            'remote_addr': conn['remote_addr'],
            'remote_port': conn['remote_port'],
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
        
        for app in new_apps:
            print(f"\n[+] New application detected: {app}")

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
            self._cleanup()

    def _cleanup(self):
        """Cleanup monitoring resources and save final state"""
        try:
            # Calculate monitoring duration
            end_time = datetime.datetime.now()
            duration = end_time - self.start_time

            # Create final summary
            summary = {
                'monitoring_session': {
                    'start_time': self.start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'duration_seconds': duration.total_seconds()
                },
                'connection_stats': {
                    'total_connections_logged': 0,
                    'unique_applications': len(self.active_apps),
                    'applications': list(self.active_apps)
                },
                'log_files': {
                    'connections': str(self.conn_file),
                    'statistics': str(self.stats_file),
                    'email_traffic': str(self.email_file)
                }
            }

            # Count total connections from the connection log
            try:
                with open(self.conn_file, 'r') as f:
                    # Subtract 1 for header row
                    summary['connection_stats']['total_connections_logged'] = sum(1 for _ in f) - 1
            except:
                pass

            # Save summary to JSON
            summary_file = self.logs_dir / f'monitor_summary_{end_time.strftime("%Y%m%d_%H%M%S")}.json'
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)

            print("\nNetwork Monitor Summary:")
            print(f"Session Duration: {duration}")
            print(f"Total Applications Monitored: {len(self.active_apps)}")
            print("\nLog Files:")
            print(f"- Connections: {self.conn_file.name}")
            print(f"- Statistics: {self.stats_file.name}")
            print(f"- Email Traffic: {self.email_file.name}")
            print(f"- Summary: {summary_file.name}")

            # Close any open file handles
            for handler in logging.getLogger().handlers[:]:
                handler.close()
                logging.getLogger().removeHandler(handler)

        except Exception as e:
            print(f"Error during cleanup: {e}")

def main():
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

    # Create and start the monitor
    try:
        monitor = WindowsNetworkMonitor()
        monitor.monitor()
    except Exception as e:
        logging.error(f"Error in network monitor: {e}")
        raise

if __name__ == "__main__":
    main()