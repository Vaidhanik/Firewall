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

class EnhancedNetworkMonitor:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.logs_dir = self.script_dir / 'logs'
        self.logs_dir.mkdir(exist_ok=True)
        
        self.connections = defaultdict(lambda: {
            'bytes_sent': 0,
            'connections': set(),
            'domains': set()
        })
        
        # Common ports and their services
        self.service_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP/Submission',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            27017: 'MongoDB'
        }
        
        # Track active applications
        self.active_apps = set()
        
        # Initialize log files
        self.initialize_files()
    
    def initialize_files(self):
        """Initialize log files with enhanced headers"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d')
        
        # Main connection log
        self.conn_log_file = self.logs_dir / f"connection_log_{timestamp}.csv"
        self.conn_headers = [
            'timestamp', 
            'program', 
            'pid',
            'protocol',
            'local_address', 
            'local_port',
            'foreign_address', 
            'foreign_port',
            'domain_name',
            'service',
            'direction',
            'state',
            'bytes_transferred'
        ]
        
        # Application statistics log
        self.stats_log_file = self.logs_dir / f"app_statistics_{timestamp}.csv"
        self.stats_headers = [
            'timestamp',
            'program',
            'total_connections',
            'active_connections',
            'unique_destinations',
            'bytes_sent',
            'bytes_received',
            'most_accessed_service'
        ]
        
        # Security events log
        self.security_log_file = self.logs_dir / f"security_events_{timestamp}.csv"
        self.security_headers = [
            'timestamp',
            'program',
            'event_type',
            'description',
            'severity'
        ]
        
        # Initialize all CSV files
        for file, headers in [
            (self.conn_log_file, self.conn_headers),
            (self.stats_log_file, self.stats_headers),
            (self.security_log_file, self.security_headers)
        ]:
            if not file.exists():
                with open(file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)

    def get_service_name(self, port):
        """Get service name from port number"""
        return self.service_ports.get(port, f"PORT-{port}")

    def get_connection_direction(self, local_port, foreign_port):
        """Determine if connection is incoming or outgoing"""
        if local_port > foreign_port and foreign_port in self.service_ports:
            return "INCOMING"
        return "OUTGOING"

    def parse_netstat_line(self, line):
        """Parse a single line of netstat output"""
        try:
            parts = line.split()
            if len(parts) < 7:
                return None
                
            proto = parts[0]
            local_full = parts[3]
            foreign_full = parts[4]
            state = parts[5]
            program_info = parts[6] if len(parts) > 6 else "unknown"
            
            # Parse program info
            pid_match = re.search(r'/(\d+)', program_info)
            pid = pid_match.group(1) if pid_match else "0"
            program = program_info.split('/')[0]
            
            # Parse addresses
            local_addr, local_port = local_full.rsplit(':', 1)
            foreign_addr, foreign_port = foreign_full.rsplit(':', 1)
            
            try:
                local_port = int(local_port)
                foreign_port = int(foreign_port)
            except ValueError:
                return None
                
            return {
                'protocol': proto,
                'program': program,
                'pid': pid,
                'local_address': local_addr,
                'local_port': local_port,
                'foreign_address': foreign_addr,
                'foreign_port': foreign_port,
                'state': state,
                'service': self.get_service_name(foreign_port),
                'direction': self.get_connection_direction(local_port, foreign_port)
            }
        except Exception as e:
            print(f"Error parsing netstat line: {e}")
            return None

    def get_connections_linux(self):
        """Get detailed network connections on Linux"""
        try:
            cmd = ["netstat", "-tunwp"]
            if os.geteuid() != 0:
                cmd.insert(0, "sudo")
            
            output = subprocess.check_output(cmd, universal_newlines=True)
            connections = []
            
            for line in output.split('\n')[2:]:
                if not line:
                    continue
                    
                conn_info = self.parse_netstat_line(line)
                if conn_info:
                    connections.append(conn_info)
            
            return connections
        except subprocess.CalledProcessError as e:
            print(f"Error running netstat: {e}")
            return []

    def resolve_domain(self, ip):
        """Resolve IP to domain name with timeout"""
        try:
            if ip in ['0.0.0.0', '::', '*', '127.0.0.1', '::1']:
                return ip
            socket.setdefaulttimeout(1)  # 1 second timeout
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def log_connection(self, connection):
        """Log connection with enhanced details"""
        timestamp = datetime.datetime.now().isoformat()
        
        # Resolve domain
        domain = self.resolve_domain(connection['foreign_address'])
        
        # Estimate bytes transferred (this is a simple estimation)
        bytes_transferred = 0  # In a real scenario, you'd want to track actual bytes
        
        row = {
            'timestamp': timestamp,
            'program': connection['program'],
            'pid': connection['pid'],
            'protocol': connection['protocol'],
            'local_address': connection['local_address'],
            'local_port': connection['local_port'],
            'foreign_address': connection['foreign_address'],
            'foreign_port': connection['foreign_port'],
            'domain_name': domain,
            'service': connection['service'],
            'direction': connection['direction'],
            'state': connection['state'],
            'bytes_transferred': bytes_transferred
        }
        
        with open(self.conn_log_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.conn_headers)
            writer.writerow(row)
        
        return row

    def log_security_event(self, program, event_type, description, severity):
        """Log security-related events"""
        timestamp = datetime.datetime.now().isoformat()
        
        row = {
            'timestamp': timestamp,
            'program': program,
            'event_type': event_type,
            'description': description,
            'severity': severity
        }
        
        with open(self.security_log_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.security_headers)
            writer.writerow(row)

    def update_app_statistics(self, connections):
        """Update and log application statistics"""
        timestamp = datetime.datetime.now().isoformat()
        app_stats = defaultdict(lambda: {
            'total_connections': 0,
            'active_connections': 0,
            'unique_destinations': set(),
            'bytes_sent': 0,
            'bytes_received': 0,
            'services': defaultdict(int)
        })
        
        # Collect statistics
        for conn in connections:
            program = conn['program']
            app_stats[program]['total_connections'] += 1
            if conn['state'] == 'ESTABLISHED':
                app_stats[program]['active_connections'] += 1
            app_stats[program]['unique_destinations'].add(conn['foreign_address'])
            app_stats[program]['services'][conn['service']] += 1
        
        # Log statistics for each application
        with open(self.stats_log_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.stats_headers)
            
            for program, stats in app_stats.items():
                most_accessed_service = max(stats['services'].items(), 
                                         key=lambda x: x[1])[0] if stats['services'] else 'None'
                
                row = {
                    'timestamp': timestamp,
                    'program': program,
                    'total_connections': stats['total_connections'],
                    'active_connections': stats['active_connections'],
                    'unique_destinations': len(stats['unique_destinations']),
                    'bytes_sent': stats.get('bytes_sent', 0),
                    'bytes_received': stats.get('bytes_received', 0),
                    'most_accessed_service': most_accessed_service
                }
                writer.writerow(row)

    def monitor_connections(self):
        """Main monitoring loop with enhanced logging"""
        print(f"Starting Enhanced Network Monitor...")
        print(f"Logs directory: {self.logs_dir}")
        print("Press Ctrl+C to stop monitoring...")
        
        try:
            while True:
                connections = self.get_connections_linux()
                current_apps = set()
                
                for conn in connections:
                    if conn['state'] == 'ESTABLISHED':
                        program = conn['program']
                        current_apps.add(program)
                        
                        # Log new applications
                        if program not in self.active_apps:
                            self.active_apps.add(program)
                            print(f"\n[+] New application detected: {program}")
                            self.log_security_event(program, 'NEW_APPLICATION', 
                                                 f"New application started network activity", 'INFO')
                        
                        self.log_connection(conn)
                
                # Check for closed applications
                closed_apps = self.active_apps - current_apps
                for app in closed_apps:
                    print(f"\n[-] Application stopped: {app}")
                    self.log_security_event(app, 'APPLICATION_STOPPED', 
                                         f"Application stopped network activity", 'INFO')
                self.active_apps = current_apps
                
                # Update statistics
                self.update_app_statistics(connections)
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping monitor...")
            
            # Save final summary
            summary_file = self.logs_dir / 'network_summary.json'
            with open(summary_file, 'w') as f:
                summary = {
                    'monitoring_period': {
                        'start': datetime.datetime.now().isoformat(),
                        'end': datetime.datetime.now().isoformat()
                    },
                    'total_applications': len(self.active_apps),
                    'applications': list(self.active_apps),
                    'log_files': {
                        'connections': str(self.conn_log_file),
                        'statistics': str(self.stats_log_file),
                        'security': str(self.security_log_file)
                    }
                }
                json.dump(summary, f, indent=4)
            
            print("\nMonitoring Summary:")
            print(f"Total Applications Monitored: {len(self.active_apps)}")
            print(f"Log files saved in: {self.logs_dir}")
            print("Available logs:")
            print(f"- Connection logs: {self.conn_log_file.name}")
            print(f"- Application statistics: {self.stats_log_file.name}")
            print(f"- Security events: {self.security_log_file.name}")
            print(f"- Summary: {summary_file.name}")

if __name__ == "__main__":
    monitor = EnhancedNetworkMonitor()
    monitor.monitor_connections()