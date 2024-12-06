import os
import sqlite3
import hashlib
import logging
from datetime import datetime
from pymongo import MongoClient
from typing import List, Tuple, Optional

from dotenv import load_dotenv
load_dotenv()


"""
IMPRO:::

1. Better have 2 db instances for each collection
    a.) which will have active rules -> On cleanup, will be deleted
    b.) which have historical rules -> persist even after cleanup
"""

RULES_MONGO_DB_HOST = os.environ.get('RULES_MONGO_DB_HOST', 'localhost')
RULES_MONGO_DB_PORT = os.environ.get('RULES_MONGO_DB_PORT', '27018')
RULES_MONGO_DB_USERNAME = os.environ.get('RULES_MONGO_DB_USERNAME', 'mongorulesuser')
RULES_MONGO_DB_PASSWORD = os.environ.get('RULES_MONGO_DB_PASSWORD', 'rulespass')
ATTEMPTS_MONGO_DB_HOST = os.environ.get('ATTEMPTS_MONGO_DB_HOST', 'localhost')
ATTEMPTS_MONGO_DB_PORT = os.environ.get('ATTEMPTS_MONGO_DB_PORT', '27019')
ATTEMPTS_MONGO_DB_USERNAME = os.environ.get('ATTEMPTS_MONGO_DB_USERNAME', 'mongoattemptsuser')
ATTEMPTS_MONGO_DB_PASSWORD = os.environ.get('ATTEMPTS_MONGO_DB_PASSWORD', 'attemptspass')

class DatabaseHandler:
    # def __init__(self, db_path: str = "interceptor.db"):
    #     self.db_path = db_path
    #     self.logger = logging.getLogger('interceptor')
    #     self.setup_database()

    def __init__(self, max_retries=5, retry_delay=2):
        self.logger = logging.getLogger('interceptor')
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        self.rules_client = None
        self.attempts_client = None
        self.rules_db = None
        self.attempts_db = None
        
        self._connect_with_retry()
        self.setup_database()

    def _generate_id(self, data: dict) -> int:
        """Generate unique ID from data using SHA256"""
        combined = ''.join(str(v) for v in data.values())
        hash_obj = hashlib.sha256(combined.encode())
        return int(hash_obj.hexdigest(), 16) % (10 ** 10)  # 10-digit integer
    
    def _check_id_exists(self, collection, id: int) -> bool:
        """Check if ID exists in collection"""
        return collection.find_one({"id": id}) is not None
    
    def _get_unique_id(self, data: dict, collection) -> int:
        """Get unique ID, regenerate if collision occurs"""
        while True:
            new_id = self._generate_id(data)
            if not self._check_id_exists(collection, new_id):
                return new_id

    def _connect_with_retry(self):
        """Establish MongoDB connections with retry logic"""
        import time
        
        for attempt in range(self.max_retries):
            try:
                if not self.rules_client:
                    # self.rules_client = MongoClient(
                    #     'mongodb://mongorulesuser:rulespass@localhost:27018/',
                    #     serverSelectionTimeoutMS=5000
                    # )

                    self.rules_client = MongoClient(
                                            username=RULES_MONGO_DB_USERNAME, 
                                            password=RULES_MONGO_DB_PASSWORD, 
                                            host=RULES_MONGO_DB_HOST, 
                                            port=int(RULES_MONGO_DB_PORT)
                                        )
                    self.rules_db = self.rules_client.interceptor
                    self.blocking_rules_collection = self.rules_db.blocking_rules
                    # Test connection
                    self.rules_client.admin.command('ping')
                
                if not self.attempts_client:
                    self.attempts_client = MongoClient(
                                                username=ATTEMPTS_MONGO_DB_USERNAME, 
                                                password=ATTEMPTS_MONGO_DB_PASSWORD, 
                                                host=ATTEMPTS_MONGO_DB_HOST, 
                                                port=int(ATTEMPTS_MONGO_DB_PORT)
                                            )
                    self.attempts_db = self.attempts_client.interceptor
                    self.blocked_attempts_collection = self.attempts_db.blocked_attempts
                    # Test connection
                    self.attempts_client.admin.command('ping')
                
                self.logger.info("Successfully connected to MongoDB instances")
                return
            
            except Exception as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    raise Exception("Failed to connect to MongoDB after maximum retries")
        
    def setup_database(self):
        """Initialize SQLite database for storing rules"""
        # with sqlite3.connect(self.db_path) as conn:
        #     cursor = conn.cursor()
            
        #     cursor.execute('''
        #         CREATE TABLE IF NOT EXISTS blocking_rules (
        #             id INTEGER PRIMARY KEY AUTOINCREMENT,
        #             app_name TEXT NOT NULL,
        #             target TEXT NOT NULL,
        #             target_type TEXT NOT NULL,
        #             resolved_ips TEXT,
        #             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        #             active BOOLEAN DEFAULT 1
        #         )
        #     ''')
            
        #     cursor.execute('''
        #         CREATE TABLE IF NOT EXISTS blocked_attempts (
        #             id INTEGER PRIMARY KEY AUTOINCREMENT,
        #             rule_id INTEGER,
        #             timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        #             app_name TEXT NOT NULL,
        #             source_ip TEXT,
        #             target TEXT,
        #             details TEXT,
        #             FOREIGN KEY (rule_id) REFERENCES blocking_rules(id)
        #         )
        #     ''')
        #     conn.commit()
        try:
            # Setup rules collection
            self.rules_db.blocking_rules.create_index([("app_name", 1)])
            self.rules_db.blocking_rules.create_index([("target", 1)])
            
            # Setup attempts collection
            self.attempts_db.blocked_attempts.create_index([("rule_id", 1)])
            self.attempts_db.blocked_attempts.create_index([("timestamp", -1)])
        except Exception as e:
            self.logger.error(f"Database setup error: {e}")

            
    def add_rule(self, app_name: str, target: str, target_type: str, resolved_ips: List[str]) -> Optional[int]:
        """Add new rule to database"""
        # try:
        #     with sqlite3.connect(self.db_path) as conn:
        #         cursor = conn.cursor()
        #         cursor.execute('''
        #             INSERT INTO blocking_rules 
        #             (app_name, target, target_type, resolved_ips)
        #             VALUES (?, ?, ?, ?)
        #         ''', (app_name, target, target_type, ','.join(resolved_ips)))
        #         return cursor.lastrowid
        # except sqlite3.Error as e:
        #     self.logger.error(f"Database error adding rule: {e}")
        #     return None
        try:
            rule = {
                "app_name": app_name,
                "target": target,
                "target_type": target_type,
                "resolved_ips": resolved_ips,
                "created_at": datetime.utcnow(),
                "active": True
            }
            rule["id"] = self._get_unique_id(rule, self.blocking_rules_collection)
            result = self.blocking_rules_collection.insert_one(rule)
            return rule["id"]
        except Exception as e:
            self.logger.error(f"Database error adding rule: {e}")
            return None
            
    def get_active_rules(self) -> List[Tuple]:
        """Get all active blocking rules"""
        # try:
        #     with sqlite3.connect(self.db_path) as conn:
        #         cursor = conn.cursor()
        #         cursor.execute('''
        #             SELECT id, app_name, target, target_type, IFNULL(resolved_ips, '') 
        #             FROM blocking_rules 
        #             WHERE active = 1
        #         ''')
        #         return cursor.fetchall()
        # except sqlite3.Error as e:
        #     self.logger.error(f"Database error getting rules: {e}")
        #     return []

        try:
            rules = self.blocking_rules_collection.find({"active": True})
            return [(
                rule["id"],
                rule["app_name"],
                rule["target"], 
                rule["target_type"],
                ','.join(rule.get("resolved_ips", []))
            ) for rule in rules]
        except Exception as e:
            self.logger.error(f"Database error getting rules: {e}")
            return []
                
    def deactivate_rule(self, rule_id: int) -> bool:
        """Deactivate a rule"""
        # try:
        #     with sqlite3.connect(self.db_path) as conn:
        #         cursor = conn.cursor()
        #         cursor.execute('''
        #             UPDATE blocking_rules 
        #             SET active = 0 
        #             WHERE id = ?
        #         ''', (rule_id,))
        #         conn.commit()
        #         return True
        # except sqlite3.Error as e:
        #     self.logger.error(f"Database error deactivating rule: {e}")
        #     return False

        try:
            result = self.blocking_rules_collection.update_one(
                {"id": rule_id},
                {"$set": {"active": False}}
            )
            return result.modified_count > 0
        except Exception as e:
            self.logger.error(f"Database error deactivating rule: {e}")
            return False
            
    def log_blocked_attempt(self, rule_id: int, app_name: str, 
                          source_ip: str, target: str, details: str):
        """Log blocked connection attempt"""
        # try:
        #     with sqlite3.connect(self.db_path) as conn:
        #         cursor = conn.cursor()
        #         cursor.execute('''
        #             INSERT INTO blocked_attempts 
        #             (rule_id, app_name, source_ip, target, details)
        #             VALUES (?, ?, ?, ?, ?)
        #         ''', (rule_id, app_name, source_ip, target, details))
        #         conn.commit()
        # except sqlite3.Error as e:
        #     self.logger.error(f"Database error logging attempt: {e}")
        try:
            attempt = {
                "rule_id": rule_id,
                "app_name": app_name,
                "source_ip": source_ip,
                "target": target,
                "details": details,
                "timestamp": datetime.utcnow()
            }
            self.blocked_attempts_collection.insert_one(attempt)
        except Exception as e:
            self.logger.error(f"Database error logging attempt: {e}")
            
    def update_resolved_ips(self, rule_id: int, ips: List[str]) -> bool:
        """Update resolved IPs for a rule"""
        # try:
        #     with sqlite3.connect(self.db_path) as conn:
        #         cursor = conn.cursor()
        #         cursor.execute('''
        #             UPDATE blocking_rules
        #             SET resolved_ips = ?
        #             WHERE id = ?
        #         ''', (','.join(ips), rule_id))
        #         conn.commit()
        #         return True
        # except sqlite3.Error as e:
        #     self.logger.error(f"Database error updating IPs: {e}")
        #     return False

        try:
           result = self.blocking_rules_collection.update_one(
               {"id": rule_id},
               {"$set": {"resolved_ips": ips}}
           )
           return result.modified_count > 0
        except Exception as e:
           self.logger.error(f"Database error updating IPs: {e}")
           return False