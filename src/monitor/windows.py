import re
import subprocess
from typing import Dict, List, Optional
from monitor.base import NetworkMonitorBase

class WindowsNetworkMonitor(NetworkMonitorBase):
    def get_all_interface_macs(self) -> Dict[str, str]:
        """Get MAC addresses of all network interfaces using Windows commands"""
        interfaces = {}
        try:
            # Using getmac command for more reliable MAC retrieval
            output = subprocess.check_output("getmac /v /fo csv /nh", universal_newlines=True)
            for line in output.split('\n'):
                if line.strip():
                    try:
                        # Parse CSV output from getmac
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            interface_name = parts[0].strip('"')
                            mac = parts[1].strip('"').replace('-', ':').upper()
                            if mac != 'N/A':
                                interfaces[interface_name] = mac
                                # print(f"Found interface: {interface_name} -> MAC: {mac}")  # Debug print
                    except Exception as e:
                        print(f"Error parsing interface line: {e}")
                        
        except subprocess.CalledProcessError as e:
            print(f"Error getting network interfaces: {e}")
        
        return interfaces

    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP using Windows commands, supporting both IPv4 and IPv6"""
        if ip in ['0.0.0.0', '::', '*', '127.0.0.1', '::1']:
            return None

        # Check if it's an IPv6 address
        if ':' in ip and '.' not in ip:  # IPv6 check
            try:
                # For IPv6, first try to ping to update neighbor cache
                subprocess.run(
                    ['ping', '-6', '-n', '1', '-w', '1000', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                # Use netsh command for IPv6
                output = subprocess.check_output(
                    ['netsh', 'interface', 'ipv6', 'show', 'neighbors'],
                    universal_newlines=True
                )
                # print(f"IPv6 neighbors output for {ip}:")  # Debug print
                # print(output)  # Debug print
                
                for line in output.split('\n'):
                    if ip in line:
                        # Look for MAC address format
                        mac_match = re.search(r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})", line)
                        if mac_match:
                            mac = mac_match.group(1).replace('-', ':').upper()
                            # print(f"Found IPv6 MAC: {mac}")  # Debug print
                            return mac
            except Exception as e:
                print(f"IPv6 MAC detection error for {ip}: {str(e)}")

        else:  # IPv4
            try:
                # Ensure IP is in ARP cache
                subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

                # Try using arp -a
                output = subprocess.check_output(['arp', '-a'], universal_newlines=True)
                # print(f"ARP table output for {ip}:")  # Debug print
                # print(output)  # Debug print
                
                for line in output.split('\n'):
                    if ip in line:
                        # Look for MAC address in format XX-XX-XX-XX-XX-XX
                        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", line)
                        if mac_match:
                            mac = mac_match.group(1).replace('-', ':').upper()
                            # print(f"Found IPv4 MAC: {mac}")  # Debug print
                            return mac

                # Try using getmac as fallback
                output = subprocess.check_output(f'getmac /v /NH /FO CSV', universal_newlines=True)
                for line in output.split('\n'):
                    if ip in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            mac = parts[1].strip('" ').replace('-', ':').upper()
                            if mac != 'N/A':
                                # print(f"Found MAC via getmac: {mac}")  # Debug print
                                return mac

            except Exception as e:
                print(f"IPv4 MAC detection error for {ip}: {str(e)}")

        return None

    def get_interface_by_ip(self, ip: str) -> Optional[str]:
        """Get network interface name for an IP address in Windows"""
        try:
            # Use ipconfig with more detailed parsing
            output = subprocess.check_output(['ipconfig', '/all'], universal_newlines=True)
            current_interface = None
            
            for line in output.split('\n'):
                line = line.strip()
                
                if 'adapter' in line.lower() and ':' in line:
                    current_interface = line.split(':')[0].strip()
                elif any(addr_type in line for addr_type in ['IPv4 Address', 'IPv6 Address', 'IP Address']):
                    # Extract IP from the line
                    ip_match = re.search(r":\s*([0-9a-fA-F:\.]+)", line)
                    if ip_match and ip_match.group(1).strip('() ') == ip:
                        # print(f"Found interface for IP {ip}: {current_interface}")  # Debug print
                        return current_interface
            
        except Exception as e:
            print(f"Error finding interface for IP {ip}: {e}")
        
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