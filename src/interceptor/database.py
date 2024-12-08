import os
import sqlite3
import hashlib
import logging
from datetime import datetime
from pymongo import MongoClient
from typing import Dict, List, Tuple, Optional
from monitor import NetworkMonitorBase

import random
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
AI_MONGO_DB_HOST = os.environ.get('AI_MONGO_DB_HOST', 'localhost')
AI_MONGO_DB_PORT = os.environ.get('AI_MONGO_DB_PORT', '27021')
AI_MONGO_DB_USERNAME = os.environ.get('AI_MONGO_DB_USERNAME', 'mongoaiuser')
AI_MONGO_DB_PASSWORD = os.environ.get('AI_MONGO_DB_PASSWORD', 'aipass')

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

        #############MONITOR
        self.mongo_host = os.environ.get('MONITOR_MONGO_HOST', 'localhost')
        self.mongo_port = int(os.environ.get('MONITOR_MONGO_PORT', '27020'))
        self.mongo_user = os.environ.get('MONITOR_MONGO_ROOT_USERNAME', 'mongouser')
        self.mongo_pass = os.environ.get('MONITOR_MONGO_ROOT_PASSWORD', 'mongopass')
        self.mongo_client = MongoClient(
               host=self.mongo_host,
               port=self.mongo_port,
               username=self.mongo_user,
               password=self.mongo_pass
           )
        self.db = self.mongo_client.network_monitor
        self.connections_collection = self.db.connections
        #############
        
        self._connect_with_retry()
        self.setup_database()

        # AI DB
        self.ai_decisions_collection = self.rules_db.ai_decisions
        self._setup_ai_indexes()

    def _setup_ai_indexes(self):
        """Setup indexes for AI decisions"""
        try:
            self.ai_decisions_collection.create_index([
                ("source_ip", 1),
                ("dest_ip", 1),
                ("timestamp", -1)
            ])
            self.ai_decisions_collection.create_index([("program", 1)])
        except Exception as e:
            self.logger.error(f"Error setting up AI indexes: {e}")

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

    ##############
    ## AI STUFF ##
    ##############

    # def store_ai_decision(self, connection: dict, allowed: bool) -> bool:
    #     """Store AI decision in MongoDB"""
    #     try:
    #         doc = {
    #             "source_ip": connection['local_addr'],
    #             "source_port": connection['local_port'],
    #             "dest_ip": connection['remote_addr'],
    #             "dest_port": connection['remote_port'],
    #             "protocol": connection['protocol'],
    #             "program": connection['program'],
    #             "allowed": allowed,
    #             "timestamp": datetime.now().isoformat(),
    #         }
    #         self.ai_decisions_collection.insert_one(doc)
    #         return True
    #     except Exception as e:
    #         self.logger.error(f"Error storing AI decision: {e}")
    #         return False
        
    # def get_recent_ai_decisions(self, limit: int = 100) -> list:
    #     """Get recent AI decisions"""
    #     try:
    #         return list(self.ai_decisions_collection.find(
    #             {},
    #             sort=[("timestamp", -1)],
    #             limit=limit
    #         ))
    #     except Exception as e:
    #         self.logger.error(f"Error fetching AI decisions: {e}")
    #         return []
        
    
    # def check_ai_allowed(self, connection: dict) -> Tuple[bool, str]:
    #     """Check if connection should be allowed based on historical data"""
    #     try:
    #         # Get connection history for this app/IP combination
    #         history = list(self.connections_collection.find({
    #             "app_name": connection['program'],
    #             "remote_addr": connection['remote_addr']
    #         }).sort("timestamp", -1).limit(100))

    #         print(f"\nAnalyzing connection pattern:")
    #         print(f"  └─ Found {len(history)} historical connections")

    #         # Analyze connection patterns
    #         pattern = self._analyze_connection_history(connection, history)
            
    #         # TODO: Replace with actual model
    #         # For now, using random but considering history
    #         if len(history) > 0:
    #             # Make decision based on historical data
    #             allowed = random.choice([True, False])
    #         else:
    #             # No history, allow by default
    #             allowed = True

    #         # Store decision with pattern analysis
    #         doc = {
    #             "source_ip": connection['local_addr'],
    #             "source_port": connection['local_port'],
    #             "dest_ip": connection['remote_addr'],
    #             "dest_port": connection['remote_port'],
    #             "protocol": connection['protocol'],
    #             "program": connection['program'],
    #             "allowed": allowed,
    #             "pattern_analysis": pattern,
    #             "timestamp": datetime.utcnow()
    #         }
    #         self.ai_decisions_collection.insert_one(doc)

    #         reason = (f"Based on {len(history)} historical connections. "
    #                  f"Unique destinations: {pattern['unique_destinations']}")
    #         return allowed, reason

    #     except Exception as e:
    #         self.logger.error(f"Error in AI decision: {e}")
    #         return True, "Error analyzing connection data"
        
    # def check_ai_allowed(self, connection: dict) -> Tuple[bool, str]:
    #     """Check if connection should be allowed based on historical data"""
    #     try:
    #         print(f"\nDebug: Checking connection for {connection['program']} → {connection['remote_addr']}:{connection['remote_port']}")
            
    #         # Get historical connections
    #         history = list(self.connections_collection.find({
    #             "app_name": connection['program'],
    #             "remote_addr": connection['remote_addr']
    #         }).sort("timestamp", -1).limit(100))
            
    #         print(f"Debug: Found {len(history)} historical connections")
    
    #         # Make decision
    #         # For now using random but with weighted probability based on history
    #         import random
    #         if len(history) > 0:
    #             # More history = more likely to allow
    #             probability_allow = min(0.8, len(history) / 100)
    #             allowed = random.random() < probability_allow
    #         else:
    #             # No history = 50/50 chance
    #             allowed = random.choice([True, False])
    
    #         # Store decision with details
    #         decision_doc = {
    #             "source_ip": connection['local_addr'],
    #             "source_port": connection['local_port'],
    #             "dest_ip": connection['remote_addr'],
    #             "dest_port": connection['remote_port'],
    #             "protocol": connection['protocol'],
    #             "program": connection['program'],
    #             "allowed": allowed,
    #             "history_count": len(history),
    #             "timestamp": datetime.utcnow()
    #         }
            
    #         print(f"Debug: Storing decision: {'ALLOW' if allowed else 'BLOCK'}")
    #         result = self.ai_decisions_collection.insert_one(decision_doc)
    #         print(f"Debug: Decision stored with ID: {result.inserted_id}")
    
    #         return allowed, f"Based on {len(history)} historical connections"
    
    #     except Exception as e:
    #         print(f"Debug: Error in AI decision: {e}")
    #         return True, "Error in decision making"

    # def get_recent_ai_decisions(self, limit: int = 100) -> list:
    #     """Get recent AI decisions with connection data"""
    #     try:
    #         decisions = list(self.ai_decisions_collection.find(
    #             {},
    #             sort=[("timestamp", -1)],
    #             limit=limit
    #         ))

    #         # Enrich with connection history
    #         for decision in decisions:
    #             history = list(self.connections_collection.find({
    #                 "app_name": decision['program'],
    #                 "remote_addr": decision['dest_ip']
    #             }).sort("timestamp", -1).limit(5))
                
    #             decision['recent_connections'] = len(history)
    #             decision['connection_history'] = history

    #         return decisions

    #     except Exception as e:
    #         self.logger.error(f"Error fetching decisions: {e}")
    #         return []
    # def get_recent_ai_decisions(self, limit: int = 100) -> list:
    #     """Get recent AI decisions"""
    #     try:
    #         print("\nDebug: Fetching recent AI decisions")
    #         decisions = list(self.ai_decisions_collection.find(
    #             {},
    #             sort=[("timestamp", -1)],
    #             limit=limit
    #         ))
    #         print(f"Debug: Found {len(decisions)} decisions")
    #         return decisions

    #     except Exception as e:
    #         print(f"Debug: Error fetching decisions: {e}")
    #         return []

    # def analyze_connection_pattern(self, connection: dict) -> dict:
    #     """Analyze a connection pattern for suspicious behavior"""
    #     try:
    #         # Get recent history for this source IP
    #         source_history = self.get_connection_history({
    #             "source.ip": connection['local_addr']
    #         })

    #         # Get recent history for this destination
    #         dest_history = self.get_connection_history({
    #             "destination.ip": connection['remote_addr']
    #         })

    #         return {
    #             "source_connections": len(source_history),
    #             "dest_connections": len(dest_history),
    #             "recent_blocks": sum(1 for x in source_history if not x['allowed']),
    #             "common_ports": list(set(x['destination']['port'] for x in source_history))
    #         }

    #     except Exception as e:
    #         self.logger.error(f"Error analyzing connection pattern: {e}")
    #         return {}

    # def _analyze_connection_history(self, current: dict, history: List[dict]) -> dict:
    #     """Analyze historical connections for patterns"""
    #     try:
    #         destinations = set()
    #         ports = set()
    #         service_types = set()

    #         for conn in history:
    #             destinations.add(conn['remote_addr'])
    #             ports.add(conn['remote_port'])
    #             if 'service_type' in conn:
    #                 service_types.add(conn['service_type'])

    #         return {
    #             "unique_destinations": len(destinations),
    #             "common_ports": list(ports),
    #             "service_types": list(service_types),
    #             "total_connections": len(history)
    #         }

    #     except Exception as e:
    #         self.logger.error(f"Error analyzing history: {e}")
    #         return {}
        
    def analyze_historical_connections(self, n_records: int = 1000) -> List[Dict]:
        """
        Analyze recent connections and recommend blocks
        Returns list of recommended blocks with reasons
        """
        try:
            print(f"\nAnalyzing last {n_records} connections...")

            # Get recent connections from monitor DB
            recent_connections = list(self.connections_collection.find(
                {},
                sort=[("timestamp", -1)],
                limit=n_records
            ))

            print(f"Found {len(recent_connections)} connections to analyze")

            # Group by app and destination
            app_connections = {}
            for conn in recent_connections:
                app_name = conn['app_name']
                dest = conn['remote_addr']

                if app_name not in app_connections:
                    app_connections[app_name] = {}

                if dest not in app_connections[app_name]:
                    app_connections[app_name][dest] = []

                app_connections[app_name][dest].append(conn)

            # Analyze patterns and generate recommendations
            recommendations = []

            for app_name, destinations in app_connections.items():
                for dest_ip, connections in destinations.items():
                    analysis = self._analyze_connection_group(connections)

                    # For now using simple rules, replace with AI model later
                    should_block = (
                        analysis['suspicious_ports'] or
                        analysis['high_frequency'] or
                        analysis['unusual_protocols']
                    )

                    if should_block:
                        recommendations.append({
                            "app_name": app_name,
                            "dest_ip": dest_ip,
                            "confidence": analysis['confidence'],
                            "reason": analysis['reason'],
                            "connection_count": len(connections),
                            "analysis": analysis
                        })

            # Sort by confidence
            recommendations.sort(key=lambda x: x['confidence'], reverse=True)
            return recommendations

        except Exception as e:
            self.logger.error(f"Error analyzing connections: {e}")
            return []

    # def _analyze_connection_group(self, connections: List[Dict]) -> Dict:
    #     """Analyze a group of connections for suspicious patterns"""
    #     try:
    #         # Count unique ports
    #         ports = set(conn['remote_port'] for conn in connections)

    #         # Calculate frequency
    #         timestamps = [conn['timestamp'] for conn in connections]
    #         if len(timestamps) >= 2:
    #             time_diff = max(timestamps) - min(timestamps)
    #             frequency = len(connections) / time_diff.total_seconds() if time_diff.seconds > 0 else 0
    #         else:
    #             frequency = 0

    #         # Check protocols
    #         protocols = set(conn['protocol'] for conn in connections)

    #         # Analyze patterns
    #         suspicious_ports = any(port not in [80, 443, 53] for port in ports)
    #         high_frequency = frequency > 10  # More than 10 connections per second
    #         unusual_protocols = any(proto not in ['tcp', 'udp'] for proto in protocols)

    #         # Calculate confidence score (0-1)
    #         confidence = 0.0
    #         reasons = []

    #         if suspicious_ports:
    #             confidence += 0.4
    #             reasons.append(f"Unusual ports: {', '.join(map(str, ports))}")

    #         if high_frequency:
    #             confidence += 0.3
    #             reasons.append(f"High frequency: {frequency:.2f} conn/sec")

    #         if unusual_protocols:
    #             confidence += 0.3
    #             reasons.append(f"Unusual protocols: {', '.join(protocols)}")

    #         return {
    #             "suspicious_ports": suspicious_ports,
    #             "high_frequency": high_frequency,
    #             "unusual_protocols": unusual_protocols,
    #             "confidence": min(confidence, 1.0),
    #             "reason": " | ".join(reasons) if reasons else "No specific concerns",
    #             "metrics": {
    #                 "unique_ports": len(ports),
    #                 "frequency": frequency,
    #                 "protocols": list(protocols)
    #             }
    #         }

    #     except Exception as e:
    #         self.logger.error(f"Error in connection analysis: {e}")
    #         return {
    #             "suspicious_ports": False,
    #             "high_frequency": False,
    #             "unusual_protocols": False,
    #             "confidence": 0.0,
    #             "reason": "Analysis error",
    #             "metrics": {}
    #         }

    def analyze_historical_connections(self, n_records: int = 1000) -> List[Dict]:
        """
        Analyze recent connections and recommend blocks
        Returns list of recommended blocks with reasons
        """
        try:
            print(f"\nAnalyzing last {n_records} connections...")

            # Get recent connections from monitor DB
            recent_connections = list(self.connections_collection.find(
                {},
                sort=[("timestamp", -1)],
                limit=n_records
            ))

            print(f"Found {len(recent_connections)} connections to analyze")

            # Print sample connection for debugging
            if recent_connections:
                print("\nSample connection data:")
                print(f"Timestamp type: {type(recent_connections[0]['timestamp'])}")
                print(f"Sample data: {recent_connections[0]}")

            # Group by app and destination
            app_connections = {}
            for conn in recent_connections:
                app_name = conn['app_name']
                dest = conn['remote_addr']

                if app_name not in app_connections:
                    app_connections[app_name] = {}

                if dest not in app_connections[app_name]:
                    app_connections[app_name][dest] = []

                app_connections[app_name][dest].append(conn)

            print(f"\nFound {len(app_connections)} unique applications")

            # Analyze patterns and generate recommendations
            recommendations = []

            for app_name, destinations in app_connections.items():
                print(f"\nAnalyzing {app_name}: {len(destinations)} destinations")
                for dest_ip, connections in destinations.items():
                    analysis = self._analyze_connection_group(connections)

                    # For now using simple rules, replace with AI model later
                    should_block = (
                        analysis['suspicious_ports'] or
                        analysis['high_frequency'] or
                        analysis['unusual_protocols']
                    )

                    if should_block:
                        recommendations.append({
                            "app_name": app_name,
                            "dest_ip": dest_ip,
                            "confidence": analysis['confidence'],
                            "reason": analysis['reason'],
                            "connection_count": len(connections),
                            "analysis": analysis
                        })

            # STORAGE OF RULES
            stored_recommendations = []
            for rec in recommendations:
                rec_id = self.store_ai_recommendation(rec)
                if rec_id:
                    rec['id'] = rec_id  # Add ID to recommendation
                    stored_recommendations.append(rec)
                    print(f"Stored recommendation ID: {rec_id} for {rec['app_name']} → {rec['dest_ip']}")

            # Sort by confidence
            recommendations.sort(key=lambda x: x['confidence'], reverse=True)
            print(f"\nGenerated {len(recommendations)} recommendations")
            return recommendations

        except Exception as e:
            self.logger.error(f"Error analyzing connections: {e}")
            return []

    """
    MODELS
    KE
    LIYE
    UPDATE
    BELOW
    """
    def _analyze_connection_group(self, connections: List[Dict]) -> Dict:
        """Analyze a group of connections for suspicious patterns"""
        try:
            # Count unique ports
            ports = set(conn['remote_port'] for conn in connections)

            # Calculate frequency by converting timestamps to datetime
            timestamps = []
            for conn in connections:
                # Handle string timestamp
                if isinstance(conn['timestamp'], str):
                    ts = datetime.fromisoformat(conn['timestamp'].replace('Z', '+00:00'))
                elif isinstance(conn['timestamp'], datetime):
                    ts = conn['timestamp']
                else:
                    continue
                timestamps.append(ts)

            if len(timestamps) >= 2:
                min_time = min(timestamps)
                max_time = max(timestamps)
                time_diff = (max_time - min_time).total_seconds()
                frequency = len(connections) / time_diff if time_diff > 0 else 0
            else:
                frequency = 0

            # Check protocols
            protocols = set(conn['protocol'] for conn in connections)

            # Analyze patterns
            suspicious_ports = len([p for p in ports if p not in [80, 443, 53, 22, 25]]) > 0
            high_frequency = frequency > 10  # More than 10 connections per second
            unusual_protocols = any(proto not in ['tcp', 'udp'] for proto in protocols)

            # Calculate confidence score (0-1)
            confidence = 0.0
            reasons = []

            if suspicious_ports:
                confidence += 0.4
                reasons.append(f"Unusual ports: {', '.join(map(str, ports))}")

            if high_frequency:
                confidence += 0.3
                reasons.append(f"High frequency: {frequency:.2f} conn/sec")

            if unusual_protocols:
                confidence += 0.3
                reasons.append(f"Unusual protocols: {', '.join(protocols)}")

            return {
                "suspicious_ports": suspicious_ports,
                "high_frequency": high_frequency,
                "unusual_protocols": unusual_protocols,
                "confidence": min(confidence, 1.0),
                "reason": " | ".join(reasons) if reasons else "No specific concerns",
                "metrics": {
                    "unique_ports": len(ports),
                    "frequency": frequency,
                    "protocols": list(protocols)
                }
            }

        except Exception as e:
            self.logger.error(f"Error in connection analysis: {e}")
            self.logger.error(f"Connection data: {connections[0] if connections else 'No data'}")
            return {
                "suspicious_ports": False,
                "high_frequency": False,
                "unusual_protocols": False,
                "confidence": 0.0,
                "reason": "Analysis error",
                "metrics": {}
            }
        
    def store_ai_recommendation(self, recommendation: Dict) -> Optional[int]:
        """Store AI recommendation with unique ID"""
        try:
            # First check if recommendation already exists for this app->dest pair
            existing_rec = self.ai_decisions_collection.find_one({
                "app_name": recommendation["app_name"],
                "dest_ip": recommendation["dest_ip"],
                "active": True
            })

            doc = {
                "app_name": recommendation["app_name"],
                "dest_ip": recommendation["dest_ip"],
                "confidence": recommendation["confidence"],
                "reason": recommendation["reason"],
                "connection_count": recommendation["connection_count"],
                "analysis": recommendation["analysis"],
                "updated_at": datetime.now().isoformat(),
                "active": True
            }

            if existing_rec:
                # Update existing recommendation
                doc["id"] = existing_rec["id"]  # Keep the same ID
                doc["created_at"] = existing_rec.get("created_at", datetime.utcnow())  # Keep original creation time

                self.ai_decisions_collection.update_one(
                    {"id": existing_rec["id"]},
                    {"$set": doc}
                )

                print(f"Updated existing recommendation ID {existing_rec['id']} for {doc['app_name']} → {doc['dest_ip']}")
                return existing_rec["id"]
            else:
                # Create new recommendation
                # Use app_name and dest_ip for ID generation to ensure consistency
                id_base = {"app_name": doc["app_name"], "dest_ip": doc["dest_ip"]}
                doc["id"] = self._get_unique_id(id_base, self.ai_decisions_collection)
                doc["created_at"] = datetime.utcnow()

                self.ai_decisions_collection.insert_one(doc)
                print(f"Created new recommendation ID {doc['id']} for {doc['app_name']} → {doc['dest_ip']}")
                return doc["id"]

        except Exception as e:
            self.logger.error(f"Error storing AI recommendation: {e}")
            return None

    def get_ai_recommendation(self, recommendation_id: int) -> Optional[Dict]:
        """Get AI recommendation by ID"""
        try:
            return self.ai_decisions_collection.find_one({"id": recommendation_id})
        except Exception as e:
            self.logger.error(f"Error fetching AI recommendation: {e}")
            return None 

    def get_active_ai_recommendations(self) -> List[Dict]:
        """Get all active AI recommendations"""
        try:
            return list(self.ai_decisions_collection.find(
                {"active": True},
                sort=[("confidence", -1)]
            ))
        except Exception as e:
            self.logger.error(f"Error fetching active AI recommendations: {e}")
            return []