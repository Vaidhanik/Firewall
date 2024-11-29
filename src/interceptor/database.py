import sqlite3
import logging
from typing import List, Tuple, Optional

class DatabaseHandler:
    def __init__(self, db_path: str = "interceptor.db"):
        self.db_path = db_path
        self.logger = logging.getLogger('interceptor')
        self.setup_database()
        
    def setup_database(self):
        """Initialize SQLite database for storing rules"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
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
            
    def add_rule(self, app_name: str, target: str, target_type: str, resolved_ips: List[str]) -> Optional[int]:
        """Add new rule to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blocking_rules 
                    (app_name, target, target_type, resolved_ips)
                    VALUES (?, ?, ?, ?)
                ''', (app_name, target, target_type, ','.join(resolved_ips)))
                return cursor.lastrowid
        except sqlite3.Error as e:
            self.logger.error(f"Database error adding rule: {e}")
            return None
            
    def get_active_rules(self) -> List[Tuple]:
        """Get all active blocking rules"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, app_name, target, target_type, IFNULL(resolved_ips, '') 
                    FROM blocking_rules 
                    WHERE active = 1
                ''')
                return cursor.fetchall()
        except sqlite3.Error as e:
            self.logger.error(f"Database error getting rules: {e}")
            return []
            
    def deactivate_rule(self, rule_id: int) -> bool:
        """Deactivate a rule"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE blocking_rules 
                    SET active = 0 
                    WHERE id = ?
                ''', (rule_id,))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Database error deactivating rule: {e}")
            return False
            
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
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Database error logging attempt: {e}")
            
    def update_resolved_ips(self, rule_id: int, ips: List[str]) -> bool:
        """Update resolved IPs for a rule"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE blocking_rules
                    SET resolved_ips = ?
                    WHERE id = ?
                ''', (','.join(ips), rule_id))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Database error updating IPs: {e}")
            return False