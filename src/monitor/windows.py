import subprocess
from typing import Dict, List
from base import NetworkMonitorBase

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