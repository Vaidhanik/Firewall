# from dataclasses import dataclass
# from datetime import datetime
# from typing import Dict, Optional
# import random  # Temporary for mock decisions

# @dataclass
# class Connection:
#     source_ip: str
#     source_port: int
#     dest_ip: str
#     dest_port: int
#     protocol: str
#     timestamp: datetime = None

#     def __post_init__(self):
#         if not self.timestamp:
#             self.timestamp = datetime.utcnow()

#     def to_dict(self) -> Dict:
#         return {
#             "source_ip": self.source_ip,
#             "source_port": self.source_port,
#             "dest_ip": self.dest_ip,
#             "dest_port": self.dest_port,
#             "protocol": self.protocol,
#             "timestamp": self.timestamp
#         }

# class DecisionService:
#     def __init__(self, storage):
#         self.storage = storage
        
#     def should_allow_connection(self, connection: Connection) -> bool:
#         """
#         Check if connection should be allowed.
#         Returns True if allowed, False if should be blocked.
#         """
#         # TODO: Replace with actual model call
#         decision = random.choice([True, False])
        
#         # Store the decision
#         self.storage.store_decision(connection, decision)
        
#         return decision
from dataclasses import dataclass
from datetime import datetime
import random
from typing import Dict, Optional
from pymongo import MongoClient

@dataclass
class NetworkConnection:
    """Represents a network connection for AI evaluation"""
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    program: str
    pid: str
    timestamp: datetime = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict:
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "program": self.program,
            "pid": self.pid,
            "timestamp": self.timestamp
        }
    
@dataclass
class ConnectionData:
    """Data class to represent a network connection"""
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    timestamp: datetime = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict:
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp
        }

class AIDecisionService:
    """Service to make and store AI decisions"""
    def __init__(self, mongo_client):
        try:
            self.db = mongo_client.interceptor
            self.decisions_collection = self.db.ai_decisions
            self._setup_indexes()
            print("Debug: AI Decision Service initialized successfully")
        except Exception as e:
            print(f"Error initializing AI Decision Service: {e}")
            raise
    
    def _setup_indexes(self):
        """Setup MongoDB indexes with error handling"""
        try:
            print("Debug: Setting up MongoDB indexes...")
            self.decisions_collection.create_index([
                ("source_ip", 1),
                ("dest_ip", 1),
                ("timestamp", -1)
            ])
            print("Debug: Indexes created successfully")
        except Exception as e:
            print(f"Error creating indexes: {e}")
            raise

    def should_allow_connection(self, connection: ConnectionData) -> bool:
        """Make and store decision with error handling"""
        try:
            print(f"Debug: Processing connection: {connection.source_ip}:{connection.source_port} → "
                  f"{connection.dest_ip}:{connection.dest_port}")
            
            # Replace with actual model later
            decision = random.choice([True, False])
            
            # Store decision
            try:
                self._store_decision(connection, decision)
                print(f"Debug: Decision stored: {decision}")
            except Exception as e:
                print(f"Error storing decision: {e}")
            
            return decision
            
        except Exception as e:
            print(f"Error in should_allow_connection: {e}")
            return True

    def _store_decision(self, connection: ConnectionData, allowed: bool):
        """Store decision with error handling"""
        try:
            doc = {
                **connection.to_dict(),
                "allowed": allowed,
                "created_at": datetime.utcnow()
            }
            print(f"Debug: Storing decision document: {doc}")
            result = self.decisions_collection.insert_one(doc)
            print(f"Debug: Decision stored with ID: {result.inserted_id}")
        except Exception as e:
            print(f"Error storing decision in MongoDB: {e}")
            raise

    def get_recent_decisions(self, limit: int = 100) -> list:
        """Get recent decisions with error handling"""
        try:
            print(f"Debug: Fetching {limit} recent decisions...")
            decisions = list(self.decisions_collection.find(
                {},
                sort=[("timestamp", -1)],
                limit=limit
            ))
            print(f"Debug: Found {len(decisions)} decisions")
            return decisions
        except Exception as e:
            print(f"Error fetching recent decisions: {e}")
            return []