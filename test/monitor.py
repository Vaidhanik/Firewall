import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP
import psutil
import time
import socket
import datetime
import csv
import os
import threading
import json
from collections import defaultdict
from pathlib import Path

class NetworkMonitor:
    def __init__(self):
        # Get the directory where the script is located
        self.script_dir = Path(__file__).parent.absolute()
        
        # Create 'logs' directory inside script directory if it doesn't exist
        self.logs_dir = self.script_dir / 'logs'
        self.logs_dir.mkdir(exist_ok=True)
        
        # Initialize data structures
        self.traffic_data = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'connections': set(),
            'domains': set(),
            'last_seen': None
        })
        self.process_cache = {}
        self.lock = threading.Lock()
        
        # Initialize CSV files
        self.initialize_csv_files()
        
    def initialize_csv_files(self):
        """Initialize CSV files with headers"""
        # Traffic log CSV
        self.traffic_log_file = self.logs_dir / f"traffic_log_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        self.traffic_headers = [
            'timestamp', 'app', 'protocol', 'src_ip', 'src_port', 
            'dst_ip', 'dst_port', 'size', 'domain'
        ]
        
        # Application stats CSV
        self.stats_file = self.logs_dir / "application_stats.csv"
        self.stats_headers = [
            'timestamp', 'app', 'bytes_sent', 'unique_connections', 
            'domains_accessed', 'last_seen'
        ]
        
        # Initialize files if they don't exist
        for file, headers in [
            (self.traffic_log_file, self.traffic_headers),
            (self.stats_file, self.stats_headers)
        ]:
            if not file.exists():
                with open(file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)

    def get_process_by_port(self, port):
        """Get process information using port number"""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port:
                    if conn.pid in self.process_cache:
                        return self.process_cache[conn.pid]
                    
                    process = psutil.Process(conn.pid)
                    process_info = {
                        'name': process.name(),
                        'exe': process.exe(),
                        'cmdline': process.cmdline(),
                        'pid': process.pid
                    }
                    self.process_cache[conn.pid] = process_info
                    return process_info
        except:
            return None
        return None

    def resolve_domain(self, ip):
        """Resolve IP to domain name"""
        try:
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except:
            return ip

    def log_to_csv(self, file_path, data_dict, headers):
        """Generic CSV logging function"""
        try:
            with open(file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writerow(data_dict)
        except Exception as e:
            print(f"Error writing to CSV: {e}")

    def packet_callback(self, packet):
        """Process each captured packet"""
        if IP in packet:
            timestamp = datetime.datetime.now()
            
            # Extract IP layer info
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            # Get transport layer info
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = 'TCP'
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'UDP'
            else:
                return
            
            # Try to get process info
            process_info = self.get_process_by_port(src_port) or self.get_process_by_port(dst_port)
            
            if process_info:
                app_name = process_info['name']
                
                with self.lock:
                    # Update traffic stats
                    self.traffic_data[app_name]['bytes_sent'] += length
                    self.traffic_data[app_name]['last_seen'] = timestamp
                    self.traffic_data[app_name]['connections'].add(f"{dst_ip}:{dst_port}")
                    self.traffic_data[app_name]['domains'].add(self.resolve_domain(dst_ip))
                
                # Prepare and log traffic data
                traffic_entry = {
                    'timestamp': timestamp.isoformat(),
                    'app': app_name,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'size': length,
                    'domain': self.resolve_domain(dst_ip)
                }
                
                self.log_to_csv(self.traffic_log_file, traffic_entry, self.traffic_headers)
                self.print_connection(traffic_entry)

    def print_connection(self, entry):
        """Print connection information to console"""
        print(f"\n{'-'*80}")
        print(f"Time: {entry['timestamp']}")
        print(f"Application: {entry['app']}")
        print(f"Connection: {entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}")
        print(f"Protocol: {entry['protocol']}")
        print(f"Domain: {entry['domain']}")
        print(f"Size: {entry['size']} bytes")

    def save_statistics(self):
        """Save current statistics to CSV"""
        timestamp = datetime.datetime.now().isoformat()
        
        with self.lock:
            for app, data in self.traffic_data.items():
                stats_entry = {
                    'timestamp': timestamp,
                    'app': app,
                    'bytes_sent': data['bytes_sent'],
                    'unique_connections': len(data['connections']),
                    'domains_accessed': len(data['domains']),
                    'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
                }
                self.log_to_csv(self.stats_file, stats_entry, self.stats_headers)

    def print_statistics(self):
        """Print periodic statistics and save to CSV"""
        while True:
            time.sleep(60)  # Update every minute
            self.save_statistics()
            
            with self.lock:
                print("\n=== Traffic Statistics ===")
                for app, data in self.traffic_data.items():
                    print(f"\nApplication: {app}")
                    print(f"Total Bytes Sent: {data['bytes_sent']:,}")
                    print(f"Unique Connections: {len(data['connections'])}")
                    print(f"Domains Accessed: {len(data['domains'])}")
                    print(f"Last Activity: {data['last_seen']}")
                    print("-" * 40)

    def start_monitoring(self):
        """Start network monitoring"""
        print(f"Starting Network Monitor...")
        print(f"Logs will be saved in: {self.logs_dir}")
        print("Monitoring network traffic (Press Ctrl+C to stop)...")
        
        # Start statistics thread
        stats_thread = threading.Thread(target=self.print_statistics)
        stats_thread.daemon = True
        stats_thread.start()
        
        try:
            # Start packet capture
            scapy.sniff(prn=self.packet_callback, store=False)
        except KeyboardInterrupt:
            print("\nStopping Network Monitor...")
            # Save final statistics
            self.save_statistics()
            
            # Save summary to JSON
            summary_file = self.logs_dir / 'summary.json'
            with open(summary_file, 'w', encoding='utf-8') as f:
                stats = {
                    app: {
                        'bytes_sent': data['bytes_sent'],
                        'unique_connections': len(data['connections']),
                        'domains': list(data['domains']),
                        'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
                    }
                    for app, data in self.traffic_data.items()
                }
                json.dump(stats, f, indent=4)
            print(f"Final statistics saved in {self.logs_dir}")

if __name__ == "__main__":
    # Note: This script requires root/administrator privileges
    monitor = NetworkMonitor()
    monitor.start_monitoring()