import uuid
import threading
from collections import OrderedDict, deque
from typing import Dict, Any, List, Optional, Deque

from config import settings


class GraphChain:
    """GraphChain structural pre-processing module.

    Builds a structural map of each input — its modalities, their
    cross-modality relationships, and the trust path at ingestion — so the
    downstream pipeline (and the dashboard) can reason about *how* content is
    composed, not just its raw text.

    State is bounded (LRU over sessions, ring buffer per session) so a
    long-running server cannot grow without bound, matching the other stores.
    The map is also emitted as a dashboard event so the structural view is
    observable in real time.
    """

    def __init__(self, max_per_session: Optional[int] = None, max_sessions: Optional[int] = None):
        self._lock = threading.RLock()
        self._max_per_session = max_per_session or 200
        self._max_sessions = max_sessions or settings.max_tracked_sessions
        self.graphs: "OrderedDict[str, Deque[Dict[str, Any]]]" = OrderedDict()

    def build_structural_map(
        self,
        session_id: str,
        source: str,
        content: str,
        modalities: List[str],
        initial_trust: float,
    ) -> Dict[str, Any]:
        node_id = str(uuid.uuid4())
        modality_nodes = [{"modality": mod, "status": "pending_sanitization"} for mod in modalities]

        relationships: List[Dict[str, str]] = []
        # Link every pair of modalities as a contextual-fusion edge so a
        # text+image (or any multi-modal) input is represented as a fused node.
        for i in range(len(modalities)):
            for j in range(i + 1, len(modalities)):
                relationships.append({
                    "from": modalities[i],
                    "to": modalities[j],
                    "type": "contextual_fusion",
                })

        structural_map = {
            "node_id": node_id,
            "session_id": session_id,
            "source_type": source,
            "content_summary": (content[:50] + "...") if len(content) > 50 else content,
            "content_length": len(content),
            "modalities": modality_nodes,
            "trust_path": [{"step": "ingestion", "trust_score": initial_trust}],
            "relationships": relationships,
        }

        with self._lock:
            buf = self.graphs.get(session_id)
            if buf is None:
                buf = deque(maxlen=self._max_per_session)
                self.graphs[session_id] = buf
            buf.append(structural_map)
            self.graphs.move_to_end(session_id)
            while len(self.graphs) > self._max_sessions:
                self.graphs.popitem(last=False)

        # Make the structural map observable on the dashboard.
        try:
            from dashboard_events import push_dashboard_event
            push_dashboard_event("GRAPHCHAIN", {
                "session_id": session_id,
                "node_id": node_id,
                "source": source,
                "modalities": modalities,
                "relationships": relationships,
                "initial_trust": initial_trust,
            })
        except Exception:
            pass

        return structural_map

    def get_map(self, session_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            buf = self.graphs.get(session_id)
            return list(buf) if buf is not None else []


graphchain = GraphChain()
