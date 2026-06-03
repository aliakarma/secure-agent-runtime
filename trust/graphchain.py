import uuid
import json
from typing import Dict, Any, List

class GraphChain:
    """
    GraphChain Pre-Processing Module.
    Constructs a structural map of the input capturing relationships, 
    trust paths, and modality interactions before the data enters 
    the LangGraph multi-agent security pipeline.
    """
    def __init__(self):
        self.graphs = {}

    def build_structural_map(self, session_id: str, source: str, content: str, modalities: List[str], initial_trust: float) -> Dict[str, Any]:
        """
        Builds a network/graph representation of the input.
        """
        node_id = str(uuid.uuid4())
        
        # Determine modality relationships
        modality_nodes = [{"modality": mod, "status": "pending_sanitization"} for mod in modalities]
        
        structural_map = {
            "node_id": node_id,
            "session_id": session_id,
            "source_type": source,
            "content_summary": content[:50] + "..." if len(content) > 50 else content,
            "modalities": modality_nodes,
            "trust_path": [
                {"step": "ingestion", "trust_score": initial_trust}
            ],
            "relationships": []
        }
        
        # Link modalities together if there's a cross-modality (e.g. text + image)
        if len(modalities) > 1:
            structural_map["relationships"].append({
                "from": modalities[0],
                "to": modalities[1],
                "type": "contextual_fusion"
            })
            
        if session_id not in self.graphs:
            self.graphs[session_id] = []
            
        self.graphs[session_id].append(structural_map)
        
        return structural_map
        
    def get_map(self, session_id: str) -> List[Dict[str, Any]]:
        return self.graphs.get(session_id, [])

graphchain = GraphChain()
