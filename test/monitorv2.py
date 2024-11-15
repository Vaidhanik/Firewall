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

class NetworkMonitor:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.logs_dir = self.script_dir / 'logs'
        self.logs_dir.mkdir(exist_ok=True)
        
        # Track active applications
        self.active_apps = set()
        self.start_time = datetime.datetime.now()
        
        # Service ports mapping
        self.service_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP/SSL',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5672: 'AMQP', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
            27017: 'MongoDB', 50000: 'DB2'
        }
        
        self.initialize_logs()

    def initialize_logs(self):
        """Initialize log files with enhanced headers"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Connection logs
        self.conn_file = self.logs_dir / f"connections_{timestamp}.csv"
        self.conn_headers = [
            'timestamp', 'app_name', 'pid', 'protocol',
            'local_addr', 'local_port', 'remote_addr', 'remote_port',
            'domain', 'service', 'direction', 'state'
        ]
        
        # Application stats logs
        self.stats_file = self.logs_dir / f"app_stats_{timestamp}.csv"
        self.stats_headers = [
            'timestamp', 'app_name', 'total_connections',
            'unique_destinations', 'services_accessed'
        ]

        # Initialize CSV files
        for file_path, headers in [
            (self.conn_file, self.conn_headers),
            (self.stats_file, self.stats_headers)
        ]:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def get_service(self, port):
        """Identify service from port number"""
        return self.service_ports.get(port, f'PORT-{port}')

    def get_connections(self):
        """Get current network connections"""
        try:
            cmd = ["netstat", "-tnp"]
            if os.geteuid() != 0:
                cmd.insert(0, "sudo")
            
            output = subprocess.check_output(cmd, universal_newlines=True)
            connections = []
            
            for line in output.split('\n')[2:]:  # Skip headers
                if not line:
                    continue
                try:
                    # Parse connection details
                    parts = line.split()
                    if len(parts) < 7:
                        continue

                    proto = parts[0]
                    local = parts[3]
                    remote = parts[4]
                    state = parts[5]
                    program_info = parts[6]

                    # Parse addresses
                    local_addr, local_port = local.rsplit(':', 1)
                    remote_addr, remote_port = remote.rsplit(':', 1)
                    
                    # Get program name and PID
                    program_parts = program_info.split('/')
                    program = program_parts[0]
                    pid = program_parts[1] if len(program_parts) > 1 else 'Unknown'

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

            return connections
        except subprocess.CalledProcessError as e:
            print(f"Error running netstat: {e}")
            return []

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
        """Log connection details to CSV"""
        timestamp = datetime.datetime.now().isoformat()
        domain = self.resolve_domain(conn['remote_addr'])
        service = self.get_service(conn['remote_port'])
        
        # Determine direction
        direction = 'OUTBOUND' if conn['remote_port'] in self.service_ports else 'INBOUND'
        
        row = {
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
            'state': conn['state']
        }

        with open(self.conn_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.conn_headers)
            writer.writerow(row)

    def update_stats(self, connections):
        """Update application statistics"""
        timestamp = datetime.datetime.now().isoformat()
        app_stats = defaultdict(lambda: {
            'connections': set(),
            'destinations': set(),
            'services': set()
        })

        current_apps = set()
        for conn in connections:
            if conn['state'] == 'ESTABLISHED':
                app = conn['pid']
                current_apps.add(app)
                dest = f"{conn['remote_addr']}:{conn['remote_port']}"
                service = self.get_service(conn['remote_port'])
                
                app_stats[app]['connections'].add(dest)
                app_stats[app]['destinations'].add(conn['remote_addr'])
                app_stats[app]['services'].add(service)

        # Check for new and stopped applications
        new_apps = current_apps - self.active_apps
        stopped_apps = self.active_apps - current_apps

        # Print new and stopped applications
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
                    'services_accessed': ','.join(stats['services'])
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
                    if conn['state'] == 'ESTABLISHED':
                        self.log_connection(conn)
                self.update_stats(connections)
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\nStopping Monitor...")
            
            # Save summary
            summary = {
                'monitoring_period': {
                    'start': self.start_time.isoformat(),
                    'end': datetime.datetime.now().isoformat()
                },
                'total_applications': len(self.active_apps),
                'applications_monitored': list(self.active_apps),
                'log_files': {
                    'connections': str(self.conn_file.name),
                    'statistics': str(self.stats_file.name)
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
            print(f"- Summary: {summary_file.name}")

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.monitor()