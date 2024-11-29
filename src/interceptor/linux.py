import os
import subprocess
from pathlib import Path
from typing import Optional
from .base import BaseInterceptor

class LinuxInterceptor(BaseInterceptor):
    def __init__(self):
        super().__init__()
        self.cgroup_base = Path("/sys/fs/cgroup/net_cls")
        
    def _setup_cgroup_for_app(self, app_name: str) -> Optional[int]:
        """Setup cgroup for application and return classid"""
        try:
            # Ensure net_cls cgroup exists
            if not self.cgroup_base.exists():
                subprocess.run(['sudo', 'modprobe', 'cls_cgroup'], check=True)
                subprocess.run(['sudo', 'mkdir', '-p', str(self.cgroup_base)], check=True)
                subprocess.run([
                    'sudo', 'mount', '-t', 'cgroup', '-o', 'net_cls',
                    'net_cls', str(self.cgroup_base)
                ], check=False)  # Don't error if already mounted
            
            # Create app-specific cgroup
            app_cgroup = self.cgroup_base / app_name
            if not app_cgroup.exists():
                subprocess.run(['sudo', 'mkdir', '-p', str(app_cgroup)], check=True)
            
            # Generate unique classid (1:1000-1:65535)
            classid = abs(hash(app_name)) % 64535 + 1000
            
            # Set the classid
            subprocess.run([
                'sudo', 'sh', '-c',
                f'echo {classid} > {str(app_cgroup)}/net_cls.classid'
            ], check=True)
            
            return classid
            
        except Exception as e:
            self.logger.error(f"Failed to setup cgroup: {e}")
            return None
            
    def _track_app_processes(self, app_name: str, classid: int) -> bool:
        """Find and move application processes to cgroup"""
        try:
            # Find all processes matching app name
            ps_output = subprocess.check_output([
                'pgrep', '-f', app_name
            ], universal_newlines=True)
            
            pids = ps_output.strip().split()
            
            if not pids:
                self.logger.warning(f"No processes found for {app_name}")
                return False
            
            # Move each process to cgroup
            app_cgroup = self.cgroup_base / app_name
            for pid in pids:
                try:
                    subprocess.run([
                        'sudo', 'sh', '-c',
                        f'echo {pid.strip()} > {str(app_cgroup)}/cgroup.procs'
                    ], check=True)
                    self.logger.info(f"Moved process {pid} to cgroup")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to move process {pid}: {e}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to track processes: {e}")
            return False

    def create_rule(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create iptables rules for application"""
        try:
            # Get user ID (not root)
            user_id = int(os.environ.get('SUDO_UID', os.getuid()))

            # Get process info
            try:
                app_path = subprocess.check_output(['which', app_path]).decode().strip()
                process_name = os.path.basename(app_path)
            except subprocess.CalledProcessError:
                self.logger.error(f"Could not find path for {app_path}")
                return False
                
            # Setup cgroup
            classid = self._setup_cgroup_for_app(process_name)
            if not classid:
                self.logger.error("Failed to setup cgroup")
                return False
                
            self._track_app_processes(process_name, classid)

            # Determine IP version and command
            ip_version = 'ipv6' if ':' in target_ip else 'ipv4'
            iptables_cmd = 'ip6tables' if ip_version == 'ipv6' else 'iptables'
            chain_name = f"APP_{process_name.upper()}"
            comment = f"block_{process_name}_{target_ip}"
            
            if action == 'add':
                return self._add_rules(iptables_cmd, chain_name, process_name, target_ip, user_id, classid, comment)
            else:
                return self._remove_rules(iptables_cmd, chain_name, target_ip)
                
        except Exception as e:
            self.logger.error(f"Error managing {iptables_cmd} rules: {e}")
            return False
            
    def _add_rules(self, iptables_cmd: str, chain_name: str, process_name: str, 
                   target_ip: str, user_id: int, classid: int, comment: str) -> bool:
        """Add iptables rules"""
        try:
            # Create chain if doesn't exist
            subprocess.run(['sudo', iptables_cmd, '-N', chain_name], check=False)
            
            # Check and add jump rule
            check_jump = subprocess.run(
                ['sudo', iptables_cmd, '-C', 'OUTPUT', '-j', chain_name],
                capture_output=True
            )
            
            if check_jump.returncode != 0:
                subprocess.run([
                    'sudo', iptables_cmd, '-I', 'OUTPUT', '1',
                    '-m', 'owner', '--uid-owner', str(user_id),
                    '-m', 'cgroup', '--cgroup', str(classid),
                    '-j', chain_name
                ], check=True)

            # Add blocking rules
            rules_to_add = [
                # TCP
                [
                    'sudo', iptables_cmd, '-A', chain_name,
                    '-p', 'tcp',
                    '-d', target_ip,
                    '-m', 'state', '--state', 'NEW,ESTABLISHED',
                    '-m', 'comment', '--comment', comment,
                    '-j', 'DROP'
                ],
                # UDP
                [
                    'sudo', iptables_cmd, '-A', chain_name,
                    '-p', 'udp',
                    '-d', target_ip,
                    '-m', 'comment', '--comment', comment,
                    '-j', 'DROP'
                ],
                # ICMP
                [
                    'sudo', iptables_cmd, '-A', chain_name,
                    '-p', ('icmpv6' if iptables_cmd == 'ip6tables' else 'icmp'),
                    '-d', target_ip,
                    '-m', 'comment', '--comment', comment,
                    '-j', 'DROP'
                ]
            ]
            
            for rule in rules_to_add:
                subprocess.run(rule, check=True)
                
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to add rules: {e}")
            return False
            
    def _remove_rules(self, iptables_cmd: str, chain_name: str, target_ip: str) -> bool:
        """Remove iptables rules"""
        try:
            # Check if chain exists
            chain_check = subprocess.run(
                ['sudo', iptables_cmd, '-L', chain_name, '-n'],
                capture_output=True
            )
            
            if chain_check.returncode != 0:
                return True  # Chain doesn't exist, nothing to remove

            # Get rules
            output = subprocess.check_output([
                'sudo', iptables_cmd, '-L', chain_name, '--line-numbers', '-n'
            ], stderr=subprocess.PIPE).decode()

            # Find matching rules
            rule_numbers = []
            for line in output.split('\n'):
                if target_ip in line:
                    try:
                        rule_num = line.split()[0]
                        rule_numbers.append(int(rule_num))
                    except (IndexError, ValueError):
                        continue

            # Remove rules in reverse order
            for rule_num in sorted(rule_numbers, reverse=True):
                try:
                    subprocess.run([
                        'sudo', iptables_cmd, '-D', chain_name, str(rule_num)
                    ], check=True)
                except subprocess.CalledProcessError:
                    self.logger.error(f"Failed to remove rule {rule_num}")

            # Check if chain is empty
            remaining_output = subprocess.check_output([
                'sudo', iptables_cmd, '-L', chain_name, '-n'
            ], stderr=subprocess.PIPE).decode()
            
            remaining_rules = [line for line in remaining_output.split('\n')[2:] if line.strip()]
            
            if not remaining_rules:
                # Remove jump rule and chain
                subprocess.run([
                    'sudo', iptables_cmd, '-D', 'OUTPUT', '-j', chain_name
                ], check=False)
                subprocess.run(['sudo', iptables_cmd, '-X', chain_name], check=False)
                
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error removing rules: {e}")
            return False

    def cleanup_rules(self) -> bool:
        """Clean up all iptables rules"""
        try:
            for cmd in ['iptables', 'ip6tables']:
                try:
                    # Get all APP_ chains
                    output = subprocess.check_output([
                        'sudo', cmd, '-L', '-n'
                    ], stderr=subprocess.PIPE).decode()

                    for line in output.split('\n'):
                        if line.startswith('Chain APP_'):
                            chain = line.split()[1]
                            try:
                                # Flush and remove chain
                                subprocess.run(['sudo', cmd, '-F', chain], check=True)
                                subprocess.run(['sudo', cmd, '-D', 'OUTPUT', '-j', chain], check=False)
                                subprocess.run(['sudo', cmd, '-X', chain], check=True)
                            except subprocess.CalledProcessError:
                                continue

                except subprocess.CalledProcessError:
                    continue

            return True
            
        except Exception as e:
            self.logger.error(f"Error in cleanup: {e}")
            return False
        

    def remove_rule(self, app_path: str, target_ip: str) -> bool:
        """Remove firewall rules for application"""
        # This is just a wrapper that calls create_rule with action='remove'
        return self.create_rule(app_path, target_ip, action='remove')