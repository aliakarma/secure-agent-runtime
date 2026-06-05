import uuid
import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

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
    def __init__(self):
        # Stateful tracking: session_id -> list of ProvenanceRecord
        self.records: Dict[str, List[ProvenanceRecord]] = {}

    def add_record(self, record: ProvenanceRecord):
        session_id = record.session_id
        if session_id not in self.records:
            self.records[session_id] = []
        self.records[session_id].append(record)

    def get_records(self, session_id: str) -> List[ProvenanceRecord]:
        return self.records.get(session_id, [])

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
