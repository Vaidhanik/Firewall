from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional
import random  # Temporary for mock decisions

@dataclass
class Connection:
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

class DecisionService:
    def __init__(self, storage):
        self.storage = storage
        
    def should_allow_connection(self, connection: Connection) -> bool:
        """
        Check if connection should be allowed.
        Returns True if allowed, False if should be blocked.
        """
        # TODO: Replace with actual model call
        decision = random.choice([True, False])
        
        # Store the decision
        self.storage.store_decision(connection, decision)
        
        return decision