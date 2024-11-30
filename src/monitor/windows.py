import subprocess
import socket
import re
from typing import Dict, List, Optional
from src.monitor.base import NetworkMonitorBase

class WindowsNetworkMonitor(NetworkMonitorBase):
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

    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP using Windows ARP table"""
        if ip in ['0.0.0.0', '::', '*', '127.0.0.1', '::1']:
            return None

        try:
            # First try to ping the IP to ensure it's in the ARP table
            if ip.startswith(('192.168.', '10.', '172.')):
                try:
                    subprocess.run(["ping", "-n", "1", "-w", "1000", ip], 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL)
                except:
                    pass

            # Use arp -a to get MAC address
            try:
                output = subprocess.check_output(["arp", "-a", ip], universal_newlines=True)
                # Windows ARP output format: "Internet Address      Physical Address      Type"
                lines = output.split('\n')
                for line in lines:
                    if ip in line:
                        # Extract MAC address using regex
                        mac_match = re.search(r"([0-9A-F]{2}[-][0-9A-F]{2}[-][0-9A-F]{2}[-][0-9A-F]{2}[-][0-9A-F]{2}[-][0-9A-F]{2})", line.upper())
                        if mac_match:
                            # Convert Windows format (XX-XX-XX-XX-XX-XX) to standard format (XX:XX:XX:XX:XX:XX)
                            return mac_match.group(1).replace('-', ':')
            except:
                pass

            # Alternative method using getmac command
            try:
                output = subprocess.check_output(f"getmac /NH /V /FO CSV", universal_newlines=True)
                for line in output.split('\n'):
                    if line and ip in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            mac = parts[1].strip('" ')
                            return mac.replace('-', ':')
            except:
                pass

        except Exception as e:
            print(f"Debug - MAC detection error for {ip}: {str(e)}")
        
        return None

    def get_interface_by_ip(self, ip: str) -> Optional[str]:
        """Get network interface name for an IP address in Windows"""
        try:
            # Use ipconfig to find the interface
            output = subprocess.check_output("ipconfig /all", universal_newlines=True)
            current_interface = None
            
            for line in output.split('\n'):
                line = line.strip()
                
                if line.endswith(':') and 'adapter' in line.lower():
                    current_interface = line[:-1].strip()
                elif 'IPv4 Address' in line and ip in line:
                    return current_interface
                # Also check for IPv6 addresses
                elif 'IPv6 Address' in line and ip in line:
                    return current_interface

            # Alternative method using route print
            output = subprocess.check_output("route print", universal_newlines=True)
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        interface_number = parts[3]
                        # Get interface name from number
                        output = subprocess.check_output(f"netsh interface show interface", universal_newlines=True)
                        for iface_line in output.split('\n'):
                            if interface_number in iface_line:
                                return iface_line.split()[-1]
        except:
            pass
        
        return None

    def get_connections(self) -> List[Dict]:
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