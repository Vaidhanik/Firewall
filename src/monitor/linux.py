import os
import re
import fcntl
import struct
import socket
import netifaces
import subprocess
from typing import Dict, List, Optional
from monitor.base import NetworkMonitorBase

class LinuxNetworkMonitor(NetworkMonitorBase):
    def get_connections(self) -> List[Dict]:
        """Get both TCP and UDP connections"""
        connections = []
        try:
            # Get TCP connections
            tcp_cmd = ["netstat", "-tnp"]
            if os.geteuid() != 0:
                tcp_cmd.insert(0, "sudo")
            tcp_output = subprocess.check_output(tcp_cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
            
            # Get UDP connections
            udp_cmd = ["netstat", "-unp"]
            if os.geteuid() != 0:
                udp_cmd.insert(0, "sudo")
            udp_output = subprocess.check_output(udp_cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
            
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
                        program = program_parts[1] if len(program_parts) > 1 else 'Unknown'
                        pid = program_parts[0]

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
    
    def get_interface_mac(self, interface: str) -> Optional[str]:
        """Get MAC address of a network interface"""
        try:
            # Try using netifaces first
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in addrs:
                return addrs[netifaces.AF_LINK][0]['addr'].upper()

            # Fallback to socket method
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', interface[:15].encode()))
            return ':'.join(['%02x' % b for b in info[18:24]]).upper()
        except:
            return None

    def get_all_interface_macs(self) -> Dict[str, str]:
        """Get MAC addresses of all network interfaces"""
        interfaces = {}
        for interface in netifaces.interfaces():
            if interface != 'lo':  # Skip loopback
                mac = self.get_interface_mac(interface)
                if mac:
                    interfaces[interface] = mac
        return interfaces
    
    def get_interface_by_ip(self, ip: str) -> Optional[str]:
        """Get network interface name for an IP address"""
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr['addr'] == ip:
                            return interface
        except:
            return None
        return None

    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP"""
        if ip in ['0.0.0.0', '::', '*', '127.0.0.1', '::1']:
            return None

        try:
            # Try multiple methods for remote MAC
            # Method 1: arp command
            try:
                cmd = ["arp", "-n", ip]
                if os.geteuid() != 0:
                    cmd.insert(0, "sudo")
                output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
                mac_match = re.search(r"(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})", output)
                if mac_match:
                    return mac_match.group(1).upper()
            except:
                pass

            # Method 2: ip neighbor
            try:
                cmd = ["ip", "neighbor", "show", ip]
                if os.geteuid() != 0:
                    cmd.insert(0, "sudo")
                output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
                mac_match = re.search(r"(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})", output)
                if mac_match:
                    return mac_match.group(1).upper()
            except:
                pass

            # Method 3: For local network, try ping first to ensure ARP entry
            if ip.startswith(('192.168.', '10.', '172.')):
                try:
                    subprocess.run(["ping", "-c", "1", "-W", "1", ip], 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL)
                    # Try ARP again after ping
                    output = subprocess.check_output(["arp", "-n", ip], universal_newlines=True)
                    mac_match = re.search(r"(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})", output)
                    if mac_match:
                        return mac_match.group(1).upper()
                except:
                    pass

        except Exception as e:
            print(f"Debug - MAC detection error for {ip}: {str(e)}")
            return None

        return None