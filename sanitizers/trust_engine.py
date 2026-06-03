import time
from typing import List, Dict, Optional
from pydantic import BaseModel
from logging_config import get_logger

logger = get_logger(__name__)

class TrustMetadata(BaseModel):
    source_origin: str
    modality: str
    sanitizers_applied: List[str]
    timestamp: float
    trust_lineage: List[str]
    is_malicious: bool

class TrustEngine:
    def __init__(self):
        # Stateful tracking: session_id -> list of prompt injection events
        # In production, this would be a Redis store or database.
        self.history: Dict[str, int] = {}
        
        # Formula Weights
        self.alpha = 0.25  # Source reliability
        self.beta = 0.25   # Policy compliance
        self.gamma = 0.25  # Historical behavior
        self.delta = 0.25  # Retrieval confidence

    def register_injection(self, session_id: str):
        """Track a malicious event for a session to solve the Amnesia Vulnerability."""
        if session_id not in self.history:
            self.history[session_id] = 0
        self.history[session_id] += 1
        logger.warning(f"TrustEngine: Registered injection for session {session_id}. Total: {self.history[session_id]}")

    def calculate_trust(self, session_id: str, source: str, is_malicious: bool) -> float:
        """
        Calculate Trust Score: T(x) = αS(x) + βP(x) + γH(x) + δR(x)
        """
        # S(x): Source Reliability
        # For simplicity: internal/system = 1.0, user = 0.5
        S_x = 1.0 if source == "system" else 0.5
        
        # P(x): Policy compliance
        # If malicious, compliance is 0. Else 1.0.
        P_x = 0.0 if is_malicious else 1.0
        
        # H(x): Historical behavior
        # Starts at 1.0. Drops by 0.5 per injection in this session.
        injections = self.history.get(session_id, 0)
        H_x = max(0.0, 1.0 - (injections * 0.5))
        
        # R(x): Retrieval confidence (Mocked to 1.0 for non-RAG, or calculated in RAG sanitizer)
        R_x = 1.0 
        
        trust_score = (self.alpha * S_x) + (self.beta * P_x) + (self.gamma * H_x) + (self.delta * R_x)
        return round(trust_score, 2)

    def determine_tier(self, trust_score: float) -> str:
        if trust_score >= 0.8:
            return "HIGH"
        elif trust_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
            
    def process_payload(self, session_id: str, payload: str, source: str, is_malicious: bool) -> tuple[float, str]:
        """Process a payload, update state, and return the new trust score and tier."""
        if is_malicious:
            self.register_injection(session_id)
            
        score = self.calculate_trust(session_id, source, is_malicious)
        tier = self.determine_tier(score)
        
        logger.info(f"TrustEngine: session={session_id}, score={score:.2f}, tier={tier}")
        
        try:
            from dashboard_events import push_dashboard_event
            push_dashboard_event("TRUST_UPDATE", {
                "session_id": session_id,
                "score": round(score, 2),
                "tier": tier
            })
        except Exception:
            pass
            
        return score, tier

# Global instance
trust_engine = TrustEngine()
