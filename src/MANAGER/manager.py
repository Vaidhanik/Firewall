import subprocess
import re
import requests
from tabulate import tabulate

def get_network_info():
    """Get all IP and MAC addresses in the network"""
    network_info = {}
    
    # Get ARP table
    arp_result = subprocess.run(["arp", "-n"], stdout=subprocess.PIPE, text=True)
    
    # Get IP addresses using ip neighbor (for Linux)
    ip_neigh_result = subprocess.run(["ip", "neigh"], stdout=subprocess.PIPE, text=True)
    
    # Combine outputs
    combined_output = arp_result.stdout + "\n" + ip_neigh_result.stdout
    
    # Parse with more flexible regex
    ip_pattern = r"([\d\.]+)"
    mac_pattern = r"(?:[0-9a-fA-F]:?){12}"
    
    for line in combined_output.split('\n'):
        ip_match = re.search(ip_pattern, line)
        mac_match = re.search(mac_pattern, line)
        
        if ip_match:
            ip = ip_match.group(1)
            mac = mac_match.group(0) if mac_match else "Unknown"
            network_info[ip] = {
                'mac': mac,
                'status': 'REACHABLE' if 'REACHABLE' in line else 'STALE'
            }
    
    return network_info

def print_network_info(network_info):
    """Print network information in table format"""
    headers = ["IP Address", "MAC Address", "Status"]
    table_data = [
        [ip, info['mac'], info['status']]
        for ip, info in network_info.items()
    ]
    
    print("\n=== Network Devices ===")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print(f"\nTotal devices: {len(network_info)}")

if __name__ == "__main__":
    print("Scanning network...")
    network_info = get_network_info()
    print_network_info(network_info)
    
    # Return IP-MAC mapping
    ip_mac_mapping = {ip: info['mac'] for ip, info in network_info.items()}
    print("\nIP-MAC Mapping:")
    for ip, mac in ip_mac_mapping.items():
        print(f"{ip} -> {mac}")