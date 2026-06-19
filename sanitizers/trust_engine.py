import hashlib
import threading
import time
from collections import OrderedDict
from typing import List, Dict, Optional
from pydantic import BaseModel
from logging_config import get_logger
from config import settings

logger = get_logger(__name__)

class TrustMetadata(BaseModel):
    source_origin: str
    modality: str
    sanitizers_applied: List[str]
    timestamp: float
    trust_lineage: List[str]
    is_malicious: bool

class TrustEngine:
    """Session trust scoring with bounded, thread-safe state.

    State is kept in-memory behind a lock and capped with LRU eviction so a
    long-running, multi-session server cannot grow without bound. For a
    horizontally-scaled deployment this class is the seam to back with Redis;
    the public API would not change.
    """

    def __init__(self, max_sessions: Optional[int] = None):
        self._lock = threading.RLock()
        # session_id -> injection count, and session_id -> set(content_hash).
        # OrderedDict gives O(1) LRU eviction of the oldest session.
        self.history: "OrderedDict[str, int]" = OrderedDict()
        self._seen_hashes: "OrderedDict[str, set]" = OrderedDict()
        self._max_sessions = max_sessions or settings.max_tracked_sessions

        # Formula Weights
        self.alpha = 0.25  # Source reliability
        self.beta = 0.25   # Policy compliance
        self.gamma = 0.25  # Historical behavior
        self.delta = 0.25  # Retrieval confidence

    def _touch(self, session_id: str) -> None:
        """Mark a session most-recently-used and evict the oldest if over cap.

        Caller must hold the lock.
        """
        if session_id in self.history:
            self.history.move_to_end(session_id)
        if session_id in self._seen_hashes:
            self._seen_hashes.move_to_end(session_id)
        while len(self.history) > self._max_sessions:
            old, _ = self.history.popitem(last=False)
            self._seen_hashes.pop(old, None)

    def register_injection(self, session_id: str, content_hash: Optional[str] = None):
        """Track a malicious event for a session to solve the Amnesia Vulnerability.

        Deduplicates by content hash: the same message scanned by multiple hooks
        (Supervisor + agent node) only counts once.
        """
        with self._lock:
            if content_hash:
                seen = self._seen_hashes.setdefault(session_id, set())
                if content_hash in seen:
                    logger.info(f"TrustEngine: Skipping duplicate injection for session {session_id} (same content)")
                    self._touch(session_id)
                    return
                seen.add(content_hash)
            self.history[session_id] = self.history.get(session_id, 0) + 1
            self._touch(session_id)
            logger.warning(f"TrustEngine: Registered injection for session {session_id}. Total: {self.history[session_id]}")

    def calculate_trust(self, session_id: str, source: str, is_malicious: bool, retrieval_confidence: float = 1.0) -> float:
        """
        Calculate Trust Score: T(x) = αS(x) + βP(x) + γH(x) + δR(x)
        """
        # S(x): Source Reliability.
        # Only system/internal sources are fully trusted (1.0); everything
        # else — including authenticated users and other agents — starts at
        # 0.5, because user/agent channels are the injection surface.
        S_x = 1.0 if source == "system" else 0.5

        # P(x): Policy compliance — 0 if malicious, else 1.0.
        P_x = 0.0 if is_malicious else 1.0

        # H(x): Historical behavior. Starts at 1.0, drops 0.5 per injection in
        # this session. Gentle decay prevents a single false-positive from
        # cascading trust to LOW within one multi-hook request.
        with self._lock:
            injections = self.history.get(session_id, 0)
        H_x = max(0.0, 1.0 - (injections * 0.5))

        # R(x): Retrieval confidence (only meaningful for RAG sources).
        R_x = retrieval_confidence if source == "rag" else 1.0

        trust_score = (self.alpha * S_x) + (self.beta * P_x) + (self.gamma * H_x) + (self.delta * R_x)
        return round(trust_score, 2)

    def determine_tier(self, trust_score: float) -> str:
        if trust_score >= 0.8:
            return "HIGH"
        elif trust_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def process_payload(self, session_id: str, payload: str, source: str, is_malicious: bool, retrieval_confidence: float = 1.0) -> tuple[float, str]:
        """Process a payload, update state, and return the new trust score and tier."""
        if is_malicious:
            content_hash = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]
            self.register_injection(session_id, content_hash)

        score = self.calculate_trust(session_id, source, is_malicious, retrieval_confidence)
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

    def reset_session(self, session_id: str) -> None:
        """Drop all tracked state for a session (used by tests / session end)."""
        with self._lock:
            self.history.pop(session_id, None)
            self._seen_hashes.pop(session_id, None)

# Global instance
trust_engine = TrustEngine()
