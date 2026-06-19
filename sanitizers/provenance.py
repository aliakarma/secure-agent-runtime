import threading
import uuid
import time
from collections import OrderedDict, deque
from typing import List, Dict, Any, Optional, Deque
from pydantic import BaseModel, Field

from config import settings

class ProvenanceRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    timestamp: float = Field(default_factory=time.time)
    source_origin: str
    modality: str
    raw_content: str
    sanitized_content: str
    sanitizers_applied: List[str]
    trust_score: float
    trust_tier: str
    trust_lineage: List[str] = Field(default_factory=list)

class ProvenanceLedger:
    """Bounded, thread-safe lineage store.

    Records are kept per session in a fixed-size ring buffer and the number of
    tracked sessions is LRU-capped, so the ledger cannot grow without bound on
    a long-running server.
    """

    def __init__(self, max_per_session: Optional[int] = None, max_sessions: Optional[int] = None):
        self._lock = threading.RLock()
        self._max_per_session = max_per_session or settings.max_provenance_per_session
        self._max_sessions = max_sessions or settings.max_tracked_sessions
        # session_id -> ring buffer of ProvenanceRecord
        self.records: "OrderedDict[str, Deque[ProvenanceRecord]]" = OrderedDict()

    def add_record(self, record: ProvenanceRecord):
        session_id = record.session_id
        with self._lock:
            buf = self.records.get(session_id)
            if buf is None:
                buf = deque(maxlen=self._max_per_session)
                self.records[session_id] = buf
            buf.append(record)
            self.records.move_to_end(session_id)
            while len(self.records) > self._max_sessions:
                self.records.popitem(last=False)

    def get_records(self, session_id: str) -> List[ProvenanceRecord]:
        with self._lock:
            buf = self.records.get(session_id)
            return list(buf) if buf is not None else []

    def get_lineage(self, session_id: str) -> List[Dict[str, Any]]:
        session_records = self.get_records(session_id)
        lineage = []
        for r in session_records:
            lineage.append({
                "record_id": r.record_id,
                "timestamp": r.timestamp,
                "source": r.source_origin,
                "modality": r.modality,
                "trust_score": r.trust_score,
                "trust_tier": r.trust_tier,
                "sanitizers": r.sanitizers_applied,
                "parent_records": r.trust_lineage
            })
        return lineage

    def clear(self):
        self.records.clear()

class ProvenanceAgent:
    def __init__(self, ledger: ProvenanceLedger):
        self.ledger = ledger

    def tag_input(
        self,
        session_id: str,
        content: str,
        source: str,
        modality: str,
        sanitizers: List[str],
        trust_score: float,
        trust_tier: str,
        raw_content: Optional[str] = None
    ) -> str:
        """
        Record the data ingestion and generate a provenance tag.
        """
        raw = raw_content if raw_content is not None else content
        
        # Get prior record IDs in this session to build the lineage trail
        prior_records = self.ledger.get_records(session_id)
        trust_lineage = [r.record_id for r in prior_records]
        
        record = ProvenanceRecord(
            session_id=session_id,
            source_origin=source,
            modality=modality,
            raw_content=raw,
            sanitized_content=content,
            sanitizers_applied=sanitizers,
            trust_score=trust_score,
            trust_tier=trust_tier,
            trust_lineage=trust_lineage
        )
        
        self.ledger.add_record(record)
        
        # Return a structured provenance tag to append to the content
        tag = f"[PROVENANCE: ID={record.record_id} Source={source} Modality={modality} TrustScore={trust_score} TrustTier={trust_tier}]"
        return tag

# Global instances
provenance_ledger = ProvenanceLedger()
provenance_agent = ProvenanceAgent(provenance_ledger)
