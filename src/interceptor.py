import os
import socket
import sqlite3
import logging
import platform
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, List

class NetworkInterceptor:
    def __init__(self, db_path: str = "interceptor.db"):
        self.db_path = db_path
        self.os_type = platform.system().lower()
        self.setup_database()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging for interceptor"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger('interceptor')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        fh = logging.FileHandler(log_dir / 'interceptor.log')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def setup_database(self):
        """Initialize SQLite database for storing rules"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocking_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    resolved_ips TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    app_name TEXT NOT NULL,
                    source_ip TEXT,
                    target TEXT,
                    details TEXT,
                    FOREIGN KEY (rule_id) REFERENCES blocking_rules(id)
                )
            ''')
            conn.commit()
        
    def _create_linux_rules(self, app_path: str, target_ip: str, ip_version: str, action: str = 'add') -> bool:
        """Create iptables/ip6tables rule for Linux systems"""
        try:
            # Get the actual user ID (not root)
            user_id = int(os.environ.get('SUDO_UID', os.getuid()))
            
            # Use appropriate command based on IP version
            iptables_cmd = 'ip6tables' if ip_version == 'ipv6' else 'iptables'
            icmp_protocol = 'icmpv6' if ip_version == 'ipv6' else 'icmp'
            
            # Create a unique comment for this rule
            comment = f"block_{app_path.replace('/', '_')}_{target_ip}"
            
            if action == 'add':
                # First remove any existing rules for this target
                try:
                    subprocess.run(
                        ['sudo', iptables_cmd, '-L', 'OUTPUT', '-n'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True
                    )
                except subprocess.CalledProcessError:
                    self.logger.error(f"{iptables_cmd} not available")
                    return False
                
                # Define rules based on IP version
                if ip_version == 'ipv6':
                    rules_to_add = [
                        # Block TCP for IPv6
                        [
                            'sudo', 'ip6tables',
                            '-A', 'OUTPUT',
                            '-p', 'tcp',
                            '-d', target_ip,
                            '-m', 'owner', '--uid-owner', str(user_id),
                            '-m', 'comment', '--comment', comment,
                            '-j', 'DROP'
                        ],
                        # Block UDP for IPv6
                        [
                            'sudo', 'ip6tables',
                            '-A', 'OUTPUT',
                            '-p', 'udp',
                            '-d', target_ip,
                            '-m', 'owner', '--uid-owner', str(user_id),
                            '-m', 'comment', '--comment', comment,
                            '-j', 'DROP'
                        ],
                        # Block ICMPv6
                        [
                            'sudo', 'ip6tables',
                            '-A', 'OUTPUT',
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
                            '-A', 'OUTPUT',
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
                            '-A', 'OUTPUT',
                            '-p', 'udp',
                            '-d', target_ip,
                            '-m', 'owner', '--uid-owner', str(user_id),
                            '-m', 'comment', '--comment', comment,
                            '-j', 'DROP'
                        ],
                        # Block ICMP for IPv4
                        [
                            'sudo', 'iptables',
                            '-A', 'OUTPUT',
                            '-p', 'icmp',
                            '-d', target_ip,
                            '-m', 'owner', '--uid-owner', str(user_id),
                            '-m', 'comment', '--comment', comment,
                            '-j', 'DROP'
                        ]
                    ]
                
                # Add each rule
                for rule_cmd in rules_to_add:
                    try:
                        subprocess.run(rule_cmd, check=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Failed to add {iptables_cmd} rule: {e}")
                        return False
                        
            else:  # Remove rules
                try:
                    # List current rules
                    rules = subprocess.check_output(
                        ['sudo', iptables_cmd, '-L', 'OUTPUT', '--line-numbers', '-n']
                    ).decode()
                    
                    # Find and remove rules containing our target IP and comment
                    for line in reversed(rules.split('\n')):
                        if target_ip in line and comment in line:
                            try:
                                rule_num = line.split()[0]
                                subprocess.run(
                                    ['sudo', iptables_cmd, '-D', 'OUTPUT', rule_num],
                                    check=True
                                )
                            except (IndexError, ValueError, subprocess.CalledProcessError):
                                continue
                                
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Error removing {iptables_cmd} rules: {e}")
                    return False
                    
            self.logger.info(f"{'Added' if action == 'add' else 'Removed'} {iptables_cmd} rules for {app_path} -> {target_ip}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error managing {iptables_cmd} rules: {e}")
            return False
        
    def _create_windows_rule(self, app_path: str, target_ip: str, action: str = 'add'):
        """Create Windows Firewall rule"""
        try:
            rule_name = f"Block {app_path} to {target_ip}"
            
            if action == 'add':
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=' + rule_name,
                    'dir=out',
                    'action=block',
                    'enable=yes',
                    'program=' + app_path,
                    'remoteip=' + target_ip
                ]
            else:
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    'name=' + rule_name
                ]
            
            subprocess.run(cmd, check=True)
            self.logger.info(f"{'Added' if action == 'add' else 'Removed'} Windows Firewall rule for {app_path} -> {target_ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to {'add' if action == 'add' else 'remove'} Windows Firewall rule: {e}")
            return False

    def _create_macos_rule(self, app_path: str, target_ip: str, action: str = 'add'):
        """Create PF firewall rule for macOS"""
        try:
            # Create unique anchor name for this rule
            anchor_name = f"block.{app_path.replace('/', '_')}.{target_ip}"
            
            if action == 'add':
                # Create rule file
                rule = f"block drop out proto {{tcp,udp}} from any to {target_ip}"
                rule_file = f"/etc/pf.anchors/{anchor_name}"
                
                with open(rule_file, 'w') as f:
                    f.write(rule)
                
                # Add anchor to main config
                subprocess.run(['sudo', 'pfctl', '-a', anchor_name, '-f', rule_file], check=True)
                # Enable PF if not enabled
                subprocess.run(['sudo', 'pfctl', '-e'], check=True)
                
            else:
                # Remove anchor
                subprocess.run(['sudo', 'pfctl', '-a', anchor_name, '-F', 'all'], check=True)
            
            self.logger.info(f"{'Added' if action == 'add' else 'Removed'} PF rule for {app_path} -> {target_ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to {'add' if action == 'add' else 'remove'} PF rule: {e}")
            return False
        
    def get_process_info(self, pid: str) -> dict:
        """Get process information including executable path and user"""
        try:
            process = subprocess.check_output(['ps', '-p', pid, '-o', 'user,comm'], 
                                           universal_newlines=True).split('\n')[1]
            user, comm = process.strip().split()
            return {'user': user, 'command': comm}
        except:
            return {'user': None, 'command': None}
        
    def create_firewall_rule(self, app_path: str, target_ip: str, action: str = 'add') -> bool:
        """Create appropriate firewall rule based on OS"""
        if self.os_type == 'linux':
            if ':' in target_ip:  # IPv6
                return self._create_linux_rules(app_path, target_ip, 'ipv6', action)
            else:  # IPv4
                return self._create_linux_rules(app_path, target_ip, 'ipv4', action)
            # return self._create_linux_rule(app_path, target_ip, action)
        elif self.os_type == 'windows':
            return self._create_windows_rule(app_path, target_ip, action)
        elif self.os_type == 'darwin':
            return self._create_macos_rule(app_path, target_ip, action)
        else:
            self.logger.error(f"Unsupported operating system: {self.os_type}")
            return False

    def resolve_domain(self, domain: str) -> dict:
        """Resolve domain to both IPv4 and IPv6 addresses"""
        addresses = {'ipv4': [], 'ipv6': []}
        try:
            # Get all address info
            addrinfo = socket.getaddrinfo(domain, None)
            for addr in addrinfo:
                ip = addr[4][0]
                if ':' in ip:  # IPv6
                    addresses['ipv6'].append(ip)
                else:  # IPv4
                    addresses['ipv4'].append(ip)

            # Remove duplicates
            addresses['ipv4'] = list(set(addresses['ipv4']))
            addresses['ipv6'] = list(set(addresses['ipv6']))
            return addresses
        except socket.gaierror:
            self.logger.error(f"Failed to resolve domain: {domain}")
            return addresses

    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule and create firewall rules"""
        target_type = 'ip' if self._is_ip(target) else 'domain'
        resolved_addresses = {'ipv4': [], 'ipv6': []}

        if target_type == 'domain':
            print(f"Resolving domain {target}...")
            resolved_addresses = self.resolve_domain(target)
            if not resolved_addresses['ipv4'] and not resolved_addresses['ipv6']:
                print(f"Error: Could not resolve {target}")
                return False

            print("Resolved addresses:")
            if resolved_addresses['ipv4']:
                print(f"IPv4: {', '.join(resolved_addresses['ipv4'])}")
            if resolved_addresses['ipv6']:
                print(f"IPv6: {', '.join(resolved_addresses['ipv6'])}")
        else:
            # Determine IP version and add to appropriate list
            if ':' in target:
                resolved_addresses['ipv6'] = [target]
            else:
                resolved_addresses['ipv4'] = [target]

        try:
            # Add to database first
            all_ips = resolved_addresses['ipv4'] + resolved_addresses['ipv6']
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blocking_rules 
                    (app_name, target, target_type, resolved_ips)
                    VALUES (?, ?, ?, ?)
                ''', (app_name, target, target_type, ','.join(all_ips)))

                rule_id = cursor.lastrowid

            # Track successful rules
            successful_rules = []
            failed = False

            # Add IPv4 rules
            for ip in resolved_addresses['ipv4']:
                if self.create_firewall_rule(app_name, ip, 'add'):
                    successful_rules.append(('ipv4', ip))
                else:
                    failed = True
                    break

            # Add IPv6 rules if IPv4 was successful
            if not failed:
                for ip in resolved_addresses['ipv6']:
                    if self.create_firewall_rule(app_name, ip, 'add'):
                        successful_rules.append(('ipv6', ip))
                    else:
                        failed = True
                        break

            if failed:
                # Rollback successful rules
                for ip_version, ip in successful_rules:
                    try:
                        if ip_version == 'ipv6':
                            self._create_linux_rules(app_name, ip, 'ipv6', 'remove')
                        else:
                            self._create_linux_rules(app_name, ip, 'ipv4', 'remove')
                    except:
                        pass
                return False

            self.logger.info(
                f"Successfully added blocking rules for {app_name} -> {target}"
            )
            return True

        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            return False
    
    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule and associated firewall rules"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get rule details first
                cursor.execute('''
                    SELECT app_name, target, target_type, resolved_ips 
                    FROM blocking_rules 
                    WHERE id = ? AND active = 1
                ''', (rule_id,))
                
                rule = cursor.fetchone()
                if not rule:
                    return False
                
                app_name, target, target_type, resolved_ips = rule
                
                # Remove firewall rules
                for ip in resolved_ips.split(','):
                    if not self.create_firewall_rule(app_name, ip, 'remove'):
                        self.logger.error(f"Failed to remove firewall rule for {app_name} -> {ip}")
                        return False
                
                # Update database
                cursor.execute('''
                    UPDATE blocking_rules 
                    SET active = 0 
                    WHERE id = ?
                ''', (rule_id,))
                
                self.logger.info(f"Removed blocking rule ID: {rule_id}")
                return True
                
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            return False

    def get_active_rules(self) -> List[Tuple]:
        """Get all active blocking rules"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, app_name, target, target_type, resolved_ips 
                    FROM blocking_rules 
                    WHERE active = 1
                ''')
                return cursor.fetchall()
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            return []

    def log_blocked_attempt(self, rule_id: int, app_name: str, 
                          source_ip: str, target: str, details: str):
        """Log blocked connection attempt"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blocked_attempts 
                    (rule_id, app_name, source_ip, target, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (rule_id, app_name, source_ip, target, details))
                
                self.logger.warning(
                    f"Blocked connection attempt: {app_name} "
                    f"({source_ip}) -> {target}\nDetails: {details}"
                )
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")

    def _is_ip(self, addr: str) -> bool:
        """Check if string is IP address"""
        try:
            socket.inet_pton(socket.AF_INET, addr)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, addr)
                return True
            except socket.error:
                return False