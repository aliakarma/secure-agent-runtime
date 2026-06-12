"""
Unit tests for the GraphChain pre-processing module (trust/graphchain.py).

GraphChain is invoked at Hook 1 (sanitizers/hooks.py) to build a structural map
of each input before it enters the multi-agent pipeline. The thesis proposal
lists it as a deliverable; these tests document and pin its behaviour.
"""

from trust.graphchain import GraphChain


def test_build_structural_map_basic_fields():
    gc = GraphChain()
    m = gc.build_structural_map(
        session_id="s1", source="user", content="Book a flight to Paris",
        modalities=["text"], initial_trust=0.5,
    )
    assert m["session_id"] == "s1"
    assert m["source_type"] == "user"
    assert m["node_id"]  # uuid assigned
    assert m["modalities"] == [{"modality": "text", "status": "pending_sanitization"}]
    assert m["trust_path"][0] == {"step": "ingestion", "trust_score": 0.5}
    assert m["relationships"] == []


def test_content_summary_truncated():
    gc = GraphChain()
    long_content = "x" * 120
    m = gc.build_structural_map("s1", "user", long_content, ["text"], 1.0)
    assert m["content_summary"].endswith("...")
    assert len(m["content_summary"]) == 53  # 50 chars + "..."


def test_cross_modality_relationship():
    gc = GraphChain()
    m = gc.build_structural_map("s1", "user", "see image", ["text", "image"], 1.0)
    assert m["relationships"] == [
        {"from": "text", "to": "image", "type": "contextual_fusion"}
    ]


def test_per_session_accumulation_and_isolation():
    gc = GraphChain()
    gc.build_structural_map("s1", "user", "a", ["text"], 1.0)
    gc.build_structural_map("s1", "user", "b", ["text"], 1.0)
    gc.build_structural_map("s2", "user", "c", ["text"], 1.0)
    assert len(gc.get_map("s1")) == 2
    assert len(gc.get_map("s2")) == 1
    assert gc.get_map("unknown") == []
