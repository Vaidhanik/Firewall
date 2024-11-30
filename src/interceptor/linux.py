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

    def _create_linux_rules(self, app_path: str, target_ip: str, ip_version: str, action: str = 'add') -> bool:
        """Create iptables/ip6tables rule for Linux systems"""
        try:
            # Get the actual user ID (not root)
            user_id = int(os.environ.get('SUDO_UID', os.getuid()))

            # Get full path of the application
            try:
                app_path = subprocess.check_output(['which', app_path]).decode().strip()
                process_name = os.path.basename(app_path)
            except subprocess.CalledProcessError:
                self.logger.error(f"Could not find path for {app_path}")
                return False
            
            classid = self._setup_cgroup_for_app(process_name)
            if not classid:
                self.logger.error("Failed to setup cgroup")
                return False
            
            if not self._track_app_processes(process_name, classid):
                self.logger.warning("No processes tracked, rules may not work until app restarts")

            # Use appropriate command based on IP version
            iptables_cmd = 'ip6tables' if ip_version == 'ipv6' else 'iptables'
            # icmp_protocol = 'icmpv6' if ip_version == 'ipv6' else 'icmp'

            # Create a unique comment for this rule
            comment = f"block_{process_name}_{target_ip}"
            chain_name = f"APP_{process_name.upper()}"
            
            if action == 'add':
                try:
                    # Create chain if it doesn't exist
                    subprocess.run(['sudo', iptables_cmd, '-N', chain_name], check=False)

                    # Check if jump rule exists
                    check_jump = subprocess.run(
                        ['sudo', iptables_cmd, '-C', 'OUTPUT', '-j', chain_name],
                        capture_output=True
                    )

                    # Add jump rule if it doesn't exist
                    if check_jump.returncode != 0:
                        subprocess.run([
                            'sudo', iptables_cmd, '-I', 'OUTPUT', '1',
                            '-m', 'owner', '--uid-owner', str(user_id),
                            '-m', 'cgroup', '--cgroup', str(classid),  # Add cgroup match
                            '-j', chain_name
                        ], check=True)

                    rules_to_add = []
                    if ip_version == 'ipv6':
                        rules_to_add = [
                            # Block TCP for IPv6
                            [
                                'sudo', 'ip6tables',
                                '-A', chain_name,
                                '-p', 'tcp',
                                '-d', target_ip,
                                '-m', 'owner', '--uid-owner', str(user_id),
                                '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED',
                                '-m', 'comment', '--comment', comment,
                                '-j', 'DROP'
                            ],
                            # Block UDP for IPv6
                            [
                                'sudo', 'ip6tables',
                                '-A', chain_name,
                                '-p', 'udp',
                                '-d', target_ip,
                                '-m', 'owner', '--uid-owner', str(user_id),
                                '-m', 'comment', '--comment', comment,
                                '-j', 'DROP'
                            ],
                            # Block ICMPv6
                            [
                                'sudo', 'ip6tables',
                                '-A', chain_name,
                                '-p', 'icmpv6',
                                '-d', target_ip,
                                '-m', 'owner', '--uid-owner', str(user_id),
                                '-m', 'comment', '--comment', comment,
                                '-j', 'DROP'
                            ]
                        ]
                    else:
                        rules_to_add = [
                            # Block TCP for IPv4
                            [
                                'sudo', 'iptables',
                                '-A', chain_name,
                                '-p', 'tcp',
                                '-d', target_ip,
                                '-m', 'owner', '--uid-owner', str(user_id),
                                '-m', 'state', '--state', 'NEW,ESTABLISHED',
                                '-m', 'comment', '--comment', comment,
                                '-j', 'DROP'
                            ],
                            # Block UDP for IPv4
                            [
                                'sudo', 'iptables',
                                '-A', chain_name,
                                '-p', 'udp',
                                '-d', target_ip,
                                '-m', 'owner', '--uid-owner', str(user_id),
                                '-m', 'comment', '--comment', comment,
                                '-j', 'DROP'
                            ],
                            # Block ICMP for IPv4
                            [
                                'sudo', 'iptables',
                                '-A', chain_name,
                                '-p', 'icmp',
                                '-d', target_ip,
                                '-m', 'owner', '--uid-owner', str(user_id),
                                '-m', 'comment', '--comment', comment,
                                '-j', 'DROP'
                            ]
                        ]

                    for rule_cmd in rules_to_add:
                        subprocess.run(rule_cmd, check=True)

                    # Log the current state of the chain
                    self.logger.info(f"Rules in {chain_name}:")
                    rules = subprocess.check_output(
                        ['sudo', iptables_cmd, '-L', chain_name, '-n', '-v']
                    ).decode()
                    self.logger.info(rules)

                except subprocess.CalledProcessError:
                    subprocess.run([
                        'sudo', iptables_cmd, '-A', 'OUTPUT', '-j', chain_name
                    ], check=True)

            else:  # Remove rules
                try:
                    output = subprocess.check_output([
                        'sudo', iptables_cmd, '-L', chain_name, '--line-numbers', '-n'
                    ]).decode()

                    rule_numbers = []
                    for line in output.split('\n'):
                        if comment in line:
                            try:
                                rule_num = line.split()[0]
                                rule_numbers.append(int(rule_num))
                            except (IndexError, ValueError):
                                continue
                            
                    for rule_num in sorted(rule_numbers, reverse=True):
                        subprocess.run([
                            'sudo', iptables_cmd, '-D', chain_name, str(rule_num)
                        ], check=True)

                    # If no rules left in chain, remove chain
                    remaining_rules = subprocess.check_output([
                        'sudo', iptables_cmd, '-L', chain_name, '-n'
                    ]).decode()

                    # if 'Chain APP_' in remaining_rules and 'target' in remaining_rules:
                    if 'Chain APP_' in remaining_rules and not any(line.strip() for line in remaining_rules.split('\n')[2:]):
                        # Remove jump rule and chain
                        subprocess.run([
                            'sudo', iptables_cmd, '-D', 'OUTPUT', '-j', chain_name
                        ], check=False)
                        subprocess.run([
                            'sudo', iptables_cmd, '-X', chain_name
                        ], check=False)
        
                except subprocess.CalledProcessError:
                    self.logger.error(f"Failed to remove rules: {e}")
                    return False

            return True
        
        except Exception as e:
            self.logger.error(f"Error managing {iptables_cmd} rules: {e}")
            return False
        
    def _remove_firewall_rules(self, app_name: str, target_ip: str) -> bool:
       """Remove all firewall rules for this app and target"""
       try:
           process_name = os.path.basename(app_name)
           chain_name = f"APP_{process_name.upper()}"

           for cmd in ['iptables', 'ip6tables']:
               try:
                   # First check if chain exists
                   chain_check = subprocess.run(
                       ['sudo', cmd, '-L', chain_name, '-n'],
                       capture_output=True
                   )

                   if chain_check.returncode != 0:
                       continue

                   # Get chain rules
                   output = subprocess.check_output([
                       'sudo', cmd, '-L', chain_name, '--line-numbers', '-n'
                   ], stderr=subprocess.PIPE).decode()

                   # Remove rules matching our target IP
                   rule_numbers = []
                   for line in output.split('\n'):
                       if target_ip in line:
                           try:
                               rule_num = line.split()[0]
                               rule_numbers.append(int(rule_num))
                           except (IndexError, ValueError):
                               continue

                   # Remove matching rules in reverse order
                   for rule_num in sorted(rule_numbers, reverse=True):
                       try:
                           subprocess.run([
                               'sudo', cmd, '-D', chain_name, str(rule_num)
                           ], check=True)
                           self.logger.info(f"Removed rule {rule_num} from {chain_name}")
                       except subprocess.CalledProcessError:
                           self.logger.error(f"Failed to remove rule {rule_num}")

                   # Check if chain is completely empty
                   remaining_output = subprocess.check_output([
                       'sudo', cmd, '-L', chain_name, '-n'
                   ], stderr=subprocess.PIPE).decode()

                   # Count actual rules (skip header lines)
                   remaining_rules = [line for line in remaining_output.split('\n')[2:] if line.strip()]

                   # Log the state
                   if remaining_rules:
                       self.logger.info(f"Chain {chain_name} still has {len(remaining_rules)} rules, keeping chain")
                       # Keep the chain since it has other rules
                       continue

                   # At this point, chain is empty, get all references to the chain
                   refs_output = subprocess.check_output([
                       'sudo', cmd, '-L', 'OUTPUT', '-n'
                   ], stderr=subprocess.PIPE).decode()

                   chain_referenced = False
                   for line in refs_output.split('\n'):
                       if chain_name in line:
                           chain_referenced = True
                           break

                   if not chain_referenced:
                       self.logger.info(f"Chain {chain_name} is unused, removing completely")
                       # No references and no rules, safe to remove
                       try:
                           subprocess.run([
                               'sudo', cmd, '-F', chain_name  # Flush first
                           ], check=True)
                           subprocess.run([
                               'sudo', cmd, '-X', chain_name  # Then delete
                           ], check=True)
                           self._cleanup_app_cgroup(process_name)
                           self.logger.info(f"Successfully removed chain {chain_name}")
                       except subprocess.CalledProcessError as e:
                           self.logger.warning(f"Could not remove chain {chain_name}: {e}")
                   else:
                       self.logger.info(f"Chain {chain_name} is still referenced, keeping chain")

               except subprocess.CalledProcessError as e:
                   self.logger.error(f"Error processing {cmd} rules: {e}")
                   continue

           return True

       except Exception as e:
           self.logger.error(f"Error removing firewall rules: {e}")
           return False
     
    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule"""
        # Check if target is IP or domain
        target_type = 'ip' if self._is_ip(target) else 'domain'
        resolved_addresses = {'ipv4': [], 'ipv6': []}
        
        if target_type == 'domain':
            self.logger.info(f"Resolving domain {target}...")
            resolved_addresses = self.resolve_domain(target)
            if not resolved_addresses['ipv4'] and not resolved_addresses['ipv6']:
                self.logger.error(f"Could not resolve {target}")
                return False
                
            self.logger.info("Resolved addresses:")
            if resolved_addresses['ipv4']:
                self.logger.info(f"IPv4: {', '.join(resolved_addresses['ipv4'])}")
            if resolved_addresses['ipv6']:
                self.logger.info(f"IPv6: {', '.join(resolved_addresses['ipv6'])}")
        else:
            # Single IP address
            if ':' in target:
                resolved_addresses['ipv6'] = [target]
            else:
                resolved_addresses['ipv4'] = [target]
        
        try:
            # Add to database first
            all_ips = resolved_addresses['ipv4'] + resolved_addresses['ipv6']
            rule_id = self.db.add_rule(app_name, target, target_type, all_ips)
            if not rule_id:
                return False
                
            # Track successful rules for rollback
            successful_rules = []
            failed = False
            
            # Add IPv4 rules
            for ip in resolved_addresses['ipv4']:
                if self.create_rule(app_name, ip, 'add'):
                    successful_rules.append(('ipv4', ip))
                else:
                    failed = True
                    break
                    
            # Add IPv6 rules if IPv4 was successful
            if not failed:
                for ip in resolved_addresses['ipv6']:
                    if self.create_rule(app_name, ip, 'add'):
                        successful_rules.append(('ipv6', ip))
                    else:
                        failed = True
                        break
                        
            if failed:
                # Rollback successful rules
                for ip_version, ip in successful_rules:
                    try:
                        self.create_rule(app_name, ip, 'remove')
                    except:
                        pass
                return False
                
            self.logger.info(f"Successfully added blocking rules for {app_name} -> {target}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding blocking rule: {e}")
            return False
      
    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule"""
        try:
            # Get rule details
            rules = self.db.get_active_rules()
            rule = next((r for r in rules if r[0] == rule_id), None)
            if not rule:
                return False
                
            app_name, target, target_type, resolved_ips = rule[1:]
            
            success = True
            # Remove firewall rules
            if resolved_ips:
                for ip in resolved_ips.split(','):
                    if not self._remove_firewall_rules(app_name, ip.strip()):
                        success = False
                        
            # Also try target if it's an IP
            if target_type == 'ip':
                if not self._remove_firewall_rules(app_name, target):
                    success = False
                    
            # Deactivate in database if successful
            if success:
                self.db.deactivate_rule(rule_id)
                self.logger.info(f"Successfully removed blocking rule for {app_name} -> {target}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error removing blocking rule: {e}")
            return False
    
    def force_cleanup_rules(self):
        """Force cleanup of all firewall rules"""
        try:
            # Get all rules to find app chains
            app_chains = set()
            for cmd in ['iptables', 'ip6tables']:
                try:
                    output = subprocess.check_output(
                        ['sudo', cmd, '-L', '-n'],
                        stderr=subprocess.PIPE
                    ).decode()

                    # Find all APP_ chains
                    for line in output.split('\n'):
                        if line.startswith('Chain APP_'):
                            chain = line.split()[1]
                            app_chains.add(chain)

                    # Clean up chains
                    for chain in app_chains:
                        try:
                            # Flush chain
                            subprocess.run(['sudo', cmd, '-F', chain], check=True)
                            # Remove jump rule
                            subprocess.run(['sudo', cmd, '-D', 'OUTPUT', '-j', chain], check=False)
                            # Delete chain
                            subprocess.run(['sudo', cmd, '-X', chain], check=True)
                        except subprocess.CalledProcessError:
                            continue

                except subprocess.CalledProcessError:
                    continue

        except Exception as e:
            self.logger.error(f"Error in force cleanup: {e}")

    def get_process_info(self, pid: str) -> dict:
        """Get process information including executable path and user"""
        try:
            process = subprocess.check_output(['ps', '-p', pid, '-o', 'user,comm'], 
                                           universal_newlines=True).split('\n')[1]
            user, comm = process.strip().split()
            return {'user': user, 'command': comm}
        except:
            return {'user': None, 'command': None}
        
    def create_rule(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        if ':' in target_ip:  # IPv6
            return self._create_linux_rules(app_path, target_ip, 'ipv6', action)
        else:  # IPv4
            return self._create_linux_rules(app_path, target_ip, 'ipv4', action)