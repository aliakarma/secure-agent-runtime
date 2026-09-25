"""
Trust engine, session store, and step-up tests for the revised specification
(paper §3.3, §3.3.1, §3.5, Algorithm 1).

Every number asserted here is one the manuscript states: the §3.3 arithmetic, the
turn-scoped versus session-wide behaviour on a benign retrieval, deduplication,
convergence of the shared store, and failing closed when the store is down.
"""

import importlib
import os

import pytest


def _engine(monkeypatch, store=None, **env):
    for k, v in {"TRUST_AGGREGATION": "turn", "DISABLE_HASH_DEDUP": "0", **env}.items():
        monkeypatch.setenv(k, v)
    import config
    config.get_settings.cache_clear() if hasattr(config.get_settings, "cache_clear") else None
    config.settings = config.get_settings()
    import sanitizers.trust_engine as te
    te.settings = config.settings
    return te.TrustEngine(store)


# ── §3.3 arithmetic ──────────────────────────────────────────────────

def test_paper_arithmetic(monkeypatch):
    e = _engine(monkeypatch)
    s = "sess"
    e.begin_turn(s)
    assert e.process_payload(s, "book a hotel", "user", False) == (0.875, "HIGH")
    # First registration on a poisoned tool response: scored against H = 0.3.
    score, tier = e.process_payload(s, "poisoned tool text", "tool_search_flights", True)
    assert score == 0.40 and tier == "MEDIUM"
    assert e.calculate_trust(s, "user", False) == 0.70
    # Second registration: H = 0.09.
    assert e.process_payload(s, "second payload", "tool_x", True)[0] == 0.3475
    assert e.calculate_trust(s, "user", True) == 0.3975
    assert e.session_tier(s) == "LOW"


def test_retrieved_fragment_score(monkeypatch):
    e = _engine(monkeypatch)
    for r in (0.0, 0.5, 0.79, 0.8, 1.0):
        assert e.calculate_trust("s", "rag", False, retrieval_confidence=r) == round(0.6 + 0.25 * r, 4)


def test_flagged_user_turn_first_registration(monkeypatch):
    e = _engine(monkeypatch)
    e.begin_turn("s")
    assert e.process_payload("s", "override my booking preferences", "user", True) == (0.45, "MEDIUM")


# ── Aggregation rules ────────────────────────────────────────────────

def _benign_retrieval_then_write(e):
    s = "sess"
    e.begin_turn(s)
    e.process_payload(s, "old fragment", "rag", False, retrieval_confidence=0.5)  # 0.725 MEDIUM
    turn1 = e.session_tier(s)
    e.begin_turn(s)
    e.process_payload(s, "please book it", "user", False)
    return turn1, e.session_tier(s)


def test_turn_scoped_rule_recovers_after_benign_retrieval(monkeypatch):
    e = _engine(monkeypatch, TRUST_AGGREGATION="turn")
    assert _benign_retrieval_then_write(e) == ("MEDIUM", "HIGH")


def test_session_wide_rule_keeps_benign_retrieval_demotion(monkeypatch):
    e = _engine(monkeypatch, TRUST_AGGREGATION="session")
    assert _benign_retrieval_then_write(e) == ("MEDIUM", "MEDIUM")


@pytest.mark.parametrize("rule", ["turn", "session"])
def test_registration_is_absorbing_under_both_rules(monkeypatch, rule):
    e = _engine(monkeypatch, TRUST_AGGREGATION=rule)
    s = "sess"
    e.begin_turn(s)
    e.process_payload(s, "payload", "tool_x", True)
    for _ in range(3):
        e.begin_turn(s)
        e.process_payload(s, "clean follow-up", "user", False)
        assert e.session_tier(s) == "MEDIUM"


# ── Deduplication ────────────────────────────────────────────────────

def test_dedup_decays_once(monkeypatch):
    e = _engine(monkeypatch)
    e.process_payload("s", "same text", "user", True)
    e.process_payload("s", "--- USER INPUT START ---\nsame text\n--- USER INPUT END ---", "user", True)
    assert e.history("s") == pytest.approx(0.3)


def test_dedup_ablation_decays_twice(monkeypatch):
    e = _engine(monkeypatch, DISABLE_HASH_DEDUP="1")
    e.process_payload("s", "same text", "user", True)
    e.process_payload("s", "same text", "user", True)
    assert e.history("s") == pytest.approx(0.09)


# ── Stores and workers ───────────────────────────────────────────────

def _two_workers(monkeypatch, store_a, store_b):
    return _engine(monkeypatch, store=store_a), _engine(monkeypatch, store=store_b)


def test_in_process_workers_do_not_share_state(monkeypatch):
    from sanitizers.session_store import InProcessStore
    w0, w1 = _two_workers(monkeypatch, InProcessStore(), InProcessStore())
    w0.begin_turn("s")
    w0.process_payload("s", "payload", "tool_x", True)
    w1.begin_turn("s")
    assert w1.session_tier("s") == "HIGH" and w1.history("s") == 1.0


def test_sqlite_shared_store_converges(monkeypatch, tmp_path):
    from sanitizers.session_store import SQLiteStore
    path = str(tmp_path / "state.db")
    w0, w1 = _two_workers(monkeypatch, SQLiteStore(path), SQLiteStore(path))
    w0.begin_turn("s")
    w0.process_payload("s", "payload", "tool_x", True)
    w1.begin_turn("s")
    assert w1.session_tier("s") == "MEDIUM" and w1.history("s") == pytest.approx(0.3)
    # Order of learning does not matter (grow-only sets): a duplicate from the
    # other worker does not decay again.
    w1.process_payload("s", "payload", "tool_x", True)
    assert w0.history("s") == pytest.approx(0.3)


def test_redis_shared_store_converges(monkeypatch):
    fakeredis = pytest.importorskip("fakeredis")
    from sanitizers.session_store import RedisStore
    server = fakeredis.FakeServer()
    w0, w1 = _two_workers(monkeypatch,
                          RedisStore(client=fakeredis.FakeRedis(server=server)),
                          RedisStore(client=fakeredis.FakeRedis(server=server)))
    w0.begin_turn("s")
    w0.process_payload("s", "payload", "tool_x", True)
    w1.begin_turn("s")
    assert w1.session_tier("s") == "MEDIUM"


def test_store_failure_fails_closed(monkeypatch):
    from sanitizers.session_store import InProcessStore, StoreUnavailable

    class Down(InProcessStore):
        def read(self, session_id):
            raise StoreUnavailable("down")

        def add_registration(self, session_id, reg_id):
            raise StoreUnavailable("down")

    e = _engine(monkeypatch, store=Down())
    e.begin_turn("s")
    e.process_payload("s", "clean", "user", False)
    assert e.session_tier("s") == "MEDIUM"


def test_router_worker_selection(monkeypatch):
    _engine(monkeypatch)
    import sanitizers.trust_engine as te
    te.configure_workers(2)
    try:
        te.set_worker(0)
        te.trust_engine.begin_turn("s")
        te.trust_engine.process_payload("s", "payload", "tool_x", True)
        te.set_worker(1)
        te.trust_engine.begin_turn("s")
        assert te.trust_engine.session_tier("s") == "HIGH"
        te.set_worker(0)
        assert te.trust_engine.session_tier("s") == "MEDIUM"
    finally:
        te.configure_workers(1)
        te.set_worker(0)


# ── Step-up ──────────────────────────────────────────────────────────

def test_step_up_counts_and_decisions():
    from sanitizers import step_up
    step_up.reset()
    step_up.set_handler(lambda s, t, a: t == "reserve_hotel" and a.get("location") == "Lisbon")
    assert step_up.request_confirmation("s", "reserve_hotel", {"location": "Lisbon"})
    assert not step_up.request_confirmation("s", "reserve_hotel", {"location": "Elsewhere"})
    assert step_up.counts("s") == {"requests": 2, "approvals": 1}
    assert step_up.is_state_changing("reserve_hotel") and not step_up.is_state_changing("search_flights")
    step_up.set_handler(lambda s, t, a: False)
