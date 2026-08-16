"""
Provenance ledger and provenance agent.

Every mediated transition is recorded as a :class:`ProvenanceRecord` carrying a
record identifier, session identifier, source origin, modality, raw and
sanitized content, applied sanitizers, trust score and tier, and a lineage list
of parent record identifiers. Tracking parents makes the ledger a directed
acyclic graph of data flow rather than a flat log, so every datum has a
traceable path back to its root input.

**Bounding (paper §5.6, §8.9).** A ledger that records raw and sanitized content
for every transaction grows without bound in a long-running session, which is a
deployment defect rather than a research nicety. Two bounds apply:

  * content bodies larger than 4 KB are replaced by a SHA-256 digest plus a
    4 KB head window, and
  * each session's ledger is capped at 512 records under LRU eviction, with
    evicted records' lineage edges preserved as **digest-only stubs** so the
    DAG remains connected rather than acquiring dangling parents.

§8.9 measures what this costs and states the resulting audit window in turns,
because turns are the unit a deployment reasons in.
"""

import hashlib
import threading
import time
import uuid
from collections import OrderedDict, deque
from typing import Any, Deque, Dict, List, Optional

from pydantic import BaseModel, Field

from config import settings

# Paper §5.6: bodies beyond this become digest + head window.
MAX_BODY_BYTES = 4096
# Paper §5.6: per-session ledger cap.
MAX_RECORDS_PER_SESSION = 512


def _bound_body(text: str) -> str:
    """Replace an oversized body with a digest plus a 4 KB head window."""
    if text is None:
        return ""
    raw = str(text)
    encoded = raw.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_BODY_BYTES:
        return raw
    digest = hashlib.sha256(encoded).hexdigest()
    head = encoded[:MAX_BODY_BYTES].decode("utf-8", errors="ignore")
    return f"{head}\n[TRUNCATED {len(encoded)} bytes; sha256={digest}]"


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


class ProvenanceStub(BaseModel):
    """What remains of an evicted record: identity and lineage, no bodies.

    Keeping the stub is what stops eviction from severing the DAG — a surviving
    child still resolves its parent edge, it just can no longer read the
    parent's content.
    """
    record_id: str
    session_id: str
    timestamp: float
    source_origin: str
    modality: str
    content_digest: str
    trust_score: float
    trust_tier: str
    trust_lineage: List[str] = Field(default_factory=list)


class ProvenanceLedger:
    """Bounded, thread-safe lineage store."""

    def __init__(self, max_per_session: Optional[int] = None, max_sessions: Optional[int] = None):
        self._lock = threading.RLock()
        self._max_per_session = max_per_session or MAX_RECORDS_PER_SESSION
        self._max_sessions = max_sessions or settings.max_tracked_sessions
        # session_id -> ring buffer of ProvenanceRecord
        self.records: "OrderedDict[str, Deque[ProvenanceRecord]]" = OrderedDict()
        # session_id -> {record_id: ProvenanceStub} for evicted records
        self._stubs: "OrderedDict[str, Dict[str, ProvenanceStub]]" = OrderedDict()

    def _stub_of(self, record: ProvenanceRecord) -> ProvenanceStub:
        digest = hashlib.sha256(
            record.raw_content.encode("utf-8", errors="replace")
        ).hexdigest()
        return ProvenanceStub(
            record_id=record.record_id,
            session_id=record.session_id,
            timestamp=record.timestamp,
            source_origin=record.source_origin,
            modality=record.modality,
            content_digest=digest,
            trust_score=record.trust_score,
            trust_tier=record.trust_tier,
            trust_lineage=list(record.trust_lineage),
        )

    def add_record(self, record: ProvenanceRecord):
        record.raw_content = _bound_body(record.raw_content)
        record.sanitized_content = _bound_body(record.sanitized_content)

        session_id = record.session_id
        with self._lock:
            buf = self.records.get(session_id)
            if buf is None:
                buf = deque()
                self.records[session_id] = buf
                self._stubs[session_id] = {}

            buf.append(record)
            # Evict from the head, demoting each evicted record to a stub so
            # surviving children keep a resolvable parent edge.
            while len(buf) > self._max_per_session:
                evicted = buf.popleft()
                self._stubs[session_id][evicted.record_id] = self._stub_of(evicted)

            self.records.move_to_end(session_id)
            self._stubs.move_to_end(session_id)
            while len(self.records) > self._max_sessions:
                old, _ = self.records.popitem(last=False)
                self._stubs.pop(old, None)

    def get_records(self, session_id: str) -> List[ProvenanceRecord]:
        with self._lock:
            buf = self.records.get(session_id)
            return list(buf) if buf is not None else []

    def get_stubs(self, session_id: str) -> List[ProvenanceStub]:
        with self._lock:
            return list(self._stubs.get(session_id, {}).values())

    def get_lineage(self, session_id: str) -> List[Dict[str, Any]]:
        lineage = []
        for r in self.get_records(session_id):
            lineage.append({
                "record_id": r.record_id,
                "timestamp": r.timestamp,
                "source": r.source_origin,
                "modality": r.modality,
                "trust_score": r.trust_score,
                "trust_tier": r.trust_tier,
                "sanitizers": r.sanitizers_applied,
                "parent_records": r.trust_lineage,
            })
        return lineage

    def get_dag(self, session_id: str) -> Dict[str, Any]:
        """Return the provenance as an explicit node/edge DAG.

        Evicted records appear as ``evicted: true`` stub nodes so an edge into
        an evicted parent still resolves and the graph stays connected.
        """
        session_records = self.get_records(session_id)
        stubs = {s.record_id: s for s in self.get_stubs(session_id)}

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        known = {r.record_id for r in session_records}

        for r in session_records:
            nodes.append({
                "id": r.record_id,
                "short_id": r.record_id[:8],
                "timestamp": r.timestamp,
                "source": r.source_origin,
                "modality": r.modality,
                "trust_score": r.trust_score,
                "trust_tier": r.trust_tier,
                "sanitizers": r.sanitizers_applied,
                "evicted": False,
            })

        referenced_stubs = {
            parent
            for r in session_records
            for parent in r.trust_lineage
            if parent in stubs
        }
        for stub_id in referenced_stubs:
            s = stubs[stub_id]
            nodes.append({
                "id": s.record_id,
                "short_id": s.record_id[:8],
                "timestamp": s.timestamp,
                "source": s.source_origin,
                "modality": s.modality,
                "trust_score": s.trust_score,
                "trust_tier": s.trust_tier,
                "sanitizers": [],
                "content_digest": s.content_digest,
                "evicted": True,
            })

        resolvable = known | referenced_stubs
        for r in session_records:
            for parent in r.trust_lineage:
                if parent in resolvable:
                    edges.append({"from": parent, "to": r.record_id})

        return {"session_id": session_id, "nodes": nodes, "edges": edges}

    def stats(self, session_id: str) -> Dict[str, Any]:
        """Resident-size accounting for the ledger-growth measurement (§8.9)."""
        records = self.get_records(session_id)
        stubs = self.get_stubs(session_id)
        record_bytes = sum(
            len(r.raw_content.encode("utf-8", "replace"))
            + len(r.sanitized_content.encode("utf-8", "replace"))
            for r in records
        )
        return {
            "session_id": session_id,
            "records": len(records),
            "stubs": len(stubs),
            "record_body_bytes": record_bytes,
            "mean_record_bytes": round(record_bytes / len(records), 1) if records else 0.0,
            "cap_per_session": self._max_per_session,
            "max_body_bytes": MAX_BODY_BYTES,
        }

    def clear(self):
        with self._lock:
            self.records.clear()
            self._stubs.clear()


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
        """Record the ingestion and return a provenance tag for the payload."""
        raw = raw_content if raw_content is not None else content

        # The new record's parent is the immediately preceding record in the
        # session, making trust_lineage a set of parent edges so the ledger is
        # a DAG rather than a flat list.
        prior_records = self.ledger.get_records(session_id)
        trust_lineage = [prior_records[-1].record_id] if prior_records else []

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

        return (
            f"[PROVENANCE: ID={record.record_id} Source={source} "
            f"Modality={modality} TrustScore={trust_score} TrustTier={trust_tier}]"
        )

    def has_modality_provenance(self, session_id: str, modality: str, within_seconds: float = 120.0) -> bool:
        """True if a modality sanitizer recorded content this turn.

        This is the authentication behind provenance-gated marker handling
        (paper §5.4): an extraction marker is honored only when the ledger can
        attest that the payload actually came from a modality sanitizer in the
        current turn. A literal marker string written into a user turn, a tool
        response, or a retrieved document has no such record.
        """
        now = time.time()
        for record in reversed(self.ledger.get_records(session_id)):
            if now - record.timestamp > within_seconds:
                break
            if record.modality == modality and record.source_origin.startswith("modality:"):
                return True
        return False


# Global instances
provenance_ledger = ProvenanceLedger()
provenance_agent = ProvenanceAgent(provenance_ledger)
