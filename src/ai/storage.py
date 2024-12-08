from datetime import datetime
from typing import Dict, List
from pymongo import MongoClient

class DecisionStorage:
    def __init__(self, mongo_client: MongoClient):
        self.db = mongo_client.interceptor
        self.decisions = self.db.ai_decisions
        self.setup_indexes()
        
    def setup_indexes(self):
        """Setup required indexes"""
        self.decisions.create_index([
            ("source_ip", 1),
            ("dest_ip", 1),
            ("timestamp", -1)
        ])
        
    def store_decision(self, connection: 'Connection', allowed: bool):
        """Store an AI decision"""
        doc = {
            **connection.to_dict(),
            "allowed": allowed,
            "created_at": datetime.now().isoformat()
        }
        self.decisions.insert_one(doc)
        
    def get_recent_decisions(self, limit: int = 100) -> List[Dict]:
        """Get recent decisions"""
        return list(self.decisions.find(
            {},
            sort=[("timestamp", -1)],
            limit=limit
        ))