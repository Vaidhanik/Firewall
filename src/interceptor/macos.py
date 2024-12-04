import os
import socket
import logging
from pathlib import Path
from abc import ABC, abstractmethod
import subprocess
from .database import DatabaseHandler
from .base import BaseInterceptor


class MacOSInterceptor(BaseInterceptor):
    """MacOS-specific network interceptor."""
    
    def __init__(self):
        super().__init__()
        self.blocked_rules = {}  # Store blocked rules per application
        self.custom_rules_file = "/etc/pf_rules.conf"
        self.setup_logging()
        self.logger.info("MacOSInterceptor initialized.")
    
    def setup_pf_config(self):
        """Ensure custom PF configuration is included."""
        main_pf_conf = "/etc/pf.conf"
        try:
            if not os.path.exists(self.custom_rules_file):
                with open(self.custom_rules_file, 'w') as f:
                    f.write("# Custom PF rules\n")
                self.logger.info(f"Created {self.custom_rules_file}.")

            # Check if custom rules file is included in main PF config
            include_directive = 'anchor "custom_rules"\nload anchor "custom_rules" from "/etc/pf_rules.conf"'
            with open(main_pf_conf, 'r') as f:
                content = f.read()
            
            if include_directive not in content:
                with open(main_pf_conf, 'a') as f:
                    f.write(f"\n{include_directive}\n")
                self.logger.info(f"Updated {main_pf_conf} to include custom rules.")

        except Exception as e:
            self.logger.error(f"Failed to set up PF configuration: {e}")
            raise e

    def append_rule(self, rule: str):
        """Append a new rule to the custom PF rules file."""
        try:
            with open(self.custom_rules_file, 'a') as f:
                f.write(rule + '\n')
            self.logger.info(f"Appended rule to {self.custom_rules_file}: {rule}")
        except Exception as e:
            self.logger.error(f"Failed to append rule to {self.custom_rules_file}: {e}")
            raise e

    def reload_pf_rules(self):
        """Reload PF rules without flushing the main configuration."""
        try:
            subprocess.run(['sudo', 'pfctl', '-a', 'custom_rules', '-f', self.custom_rules_file], check=True)
            self.logger.info("Successfully reloaded custom PF rules.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to reload PF rules: {e}")
            raise e

    def validate_pf_config(self):
        """Validate PF configuration for syntax errors."""
        try:
            subprocess.run(['sudo', 'pfctl', '-nf', '/etc/pf.conf'], check=True)
            self.logger.info("PF configuration validated successfully.")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"PF configuration validation failed: {e}")
            return False

    def should_block_request(self, app_name: str, target: str) -> bool:
        """Placeholder for ML-based decision logic to block a request."""
        # TODO: Call ML model here; return True to block, False to allow
        self.logger.info(f"ML model evaluating: {app_name}, {target}")
        return False  # Example: always allow for demonstration

    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add a blocking rule for an application and target."""
        self.logger.info(f"Adding blocking rule for {app_name}: {target}")
        
        if not self.should_block_request(app_name, target):
            self.logger.info(f"Request allowed by ML model: {app_name} -> {target}")
            return False

        # Resolve domain to IP addresses if needed
        if not self._is_ip(target):
            resolved_ips = self.resolve_domain(target)
            targets = resolved_ips['ipv4'] + resolved_ips['ipv6']
        else:
            targets = [target]

        # Prevent duplicate rules
        if app_name not in self.blocked_rules:
            self.blocked_rules[app_name] = set()

        for ip in targets:
            if ip in self.blocked_rules[app_name]:
                self.logger.info(f"Rule for {ip} already exists for {app_name}. Skipping.")
                continue
            rule = f"block out quick proto tcp from any to {ip}"
            self.append_rule(rule)
            self.blocked_rules[app_name].add(ip)

        # Validate and reload PF configuration
        if self.validate_pf_config():
            self.reload_pf_rules()
            return True
        else:
            self.logger.error("Failed to validate or reload PF configuration.")
            return False

    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule by ID (line number in rules file)."""
        self.logger.info(f"Attempting to remove rule with ID: {rule_id}")

        try:
            if not os.path.exists(self.custom_rules_file):
                self.logger.error(f"{self.custom_rules_file} does not exist.")
                return False

            # Read current rules
            with open(self.custom_rules_file, 'r') as f:
                rules = f.readlines()
            if rule_id < 0 or rule_id >= len(rules):
                self.logger.error(f"Invalid rule ID: {rule_id}. No rule exists at this index.")
                return False

            # Remove the specified rule
            removed_rule = rules.pop(rule_id)

            # Write the updated rules back to the file
            with open(self.custom_rules_file, 'w') as f:
                f.writelines(rules)
            self.logger.info(f"Removed rule: {removed_rule.strip()}")

            # Reload PF rules
            if self.validate_pf_config():
                self.reload_pf_rules()
                return True
            else:
                self.logger.error("Failed to validate or reload PF configuration.")
                return False

        except Exception as e:
            self.logger.error(f"Error while removing rule with ID {rule_id}: {e}")
            return False


    def force_cleanup_rules(self):
        """Remove all custom rules."""
        try:
            with open(self.custom_rules_file, 'w') as f:
                f.write("# Custom PF rules\n")
            self.reload_pf_rules()
            self.blocked_rules.clear()
            self.logger.info("All custom rules cleared.")
        except Exception as e:
            self.logger.error(f"Failed to clean up rules: {e}")
            raise e

    def get_process_info(self, pid: str) -> dict:
        """Fetch process information by PID."""
        try:
            process_info = subprocess.check_output(['ps', '-p', pid, '-o', 'comm='])
            app_name = process_info.decode().strip()
            self.logger.info(f"Process info for PID {pid}: {app_name}")
            return {"pid": pid, "app_name": app_name}
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get process info for PID {pid}: {e}")
            return {"pid": pid, "app_name": None}
