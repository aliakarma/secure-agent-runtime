"""
Dynamic trust scoring and three-tier policy enforcement (paper §3.3, Algorithm 1).

    T(x, σ) = α·S(x) + β·P(x) + γ·H(σ) + δ·R(x)

  * **S(x) — source reliability.** Fixed per origin: system prompt 1.0, user turn
    0.5, retrieved memory fragment 0.4, tool/API response 0.3.
  * **P(x) — policy compliance.** 1 when no detector flags x, 0 otherwise.
  * **H(σ) — session history.** ``H = ρ^|D|`` where D is the session's set of
    registration identifiers (content digest under deduplication, a fresh event
    identifier otherwise); ρ = 0.3. It never increases within a session.
  * **R(x) — retrieval confidence.** max(0, cos(fragment, query)) for retrieved
    content, 1 otherwise.

The score is rounded to four decimals and mapped to HIGH (T ≥ 0.8), MEDIUM
(0.4 ≤ T < 0.8), or LOW (T < 0.4).

**Aggregation (§3.3.1).** ``TRUST_AGGREGATION`` selects the rule:

  * ``turn`` (default, Equation scoped): only transitions that register an
    injection lower the persistent tier ``Tier_P``; every transition lowers the
    turn tier ``Tier_t``, which is reset to ``Tier_P`` at the start of each turn.
    Phase 7 gates writes on ``Tier_t``.
  * ``session`` (Equation aggregation): every transition lowers ``Tier_P`` and
    Phase 7 gates on ``Tier_P``.

The two rules coincide within a turn.

**State.** ``D`` and the set of demoting tiers live in a
:class:`~sanitizers.session_store.SessionStore` (``SESSION_STORE``: ``memory``,
``sqlite:///path``, ``redis://...``). Both are grow-only sets, so a shared store
makes the state consistent across workers (§3.5). If the store is unreachable the
engine fails closed: the enforcement tier is at most MEDIUM.

**Workers.** ``trust_engine`` is a router over one engine per worker, selected by
:func:`set_worker`. With one worker (the default) it behaves as a single engine.
The multi-turn experiment configures two workers either with separate in-process
stores (round-robin without affinity) or with one shared store.
"""

from __future__ import annotations

import contextvars
import hashlib
import re
import threading
import uuid
from typing import Dict, Optional, Tuple

from config import settings
from logging_config import get_logger
from sanitizers.session_store import (TIER_NAME, TIER_ORDER, InProcessStore,
                                      SessionStore, StoreUnavailable, build_store)

logger = get_logger(__name__)

__all__ = ["TIER_ORDER", "TIER_NAME", "TrustEngine", "trust_engine", "set_worker",
           "configure_workers"]


def _min_tier(a: str, b: str) -> str:
    return a if TIER_ORDER[a] <= TIER_ORDER[b] else b


class TrustEngine:
    """Trust scoring and enforcement for one worker."""

    def __init__(self, store: Optional[SessionStore] = None):
        self._lock = threading.RLock()
        self.store = store if store is not None else build_store(
            settings.session_store, settings.max_tracked_sessions)
        # Turn-local state: session -> {"turn": int, "tier_t": str}. Not shared:
        # a turn executes on one worker.
        self._turns: Dict[str, Dict] = {}
        self._governing: Dict[str, float] = {}
        self.rebuild()

    def rebuild(self) -> None:
        """Re-read weights, thresholds, and the aggregation rule from settings."""
        raw = [settings.trust_alpha, settings.trust_beta, settings.trust_gamma, settings.trust_delta]
        total = sum(raw) or 1.0
        self.alpha, self.beta, self.gamma, self.delta = (w / total for w in raw)
        self.high_threshold = settings.trust_high_threshold
        self.medium_threshold = settings.trust_medium_threshold
        self.rho = settings.trust_decay_rho
        self.aggregation = settings.trust_aggregation
        self.source_scores = {
            "system": settings.trust_source_system,
            "user": settings.trust_source_user,
            "tool": settings.trust_source_tool,
            "memory": settings.trust_source_memory,
        }

    # ── Source classification ────────────────────────────────────────

    def source_score(self, source: str) -> float:
        """S(x). Unknown origins are user-tier, never more trusted than a user turn."""
        s = (source or "").strip().lower()
        if s == "system":
            return self.source_scores["system"]
        if s.startswith("tool") or s.startswith("api"):
            return self.source_scores["tool"]
        if s in ("rag", "memory", "retrieval") or s.startswith("memory"):
            return self.source_scores["memory"]
        return self.source_scores["user"]

    def describe(self) -> dict:
        return {
            "formula": "T(x,σ) = αS(x) + βP(x) + γH(σ) + δR(x)",
            "weights": {"alpha_source": round(self.alpha, 4), "beta_policy": round(self.beta, 4),
                        "gamma_history": round(self.gamma, 4), "delta_retrieval": round(self.delta, 4)},
            "tiers": {"HIGH": f">= {self.high_threshold}", "MEDIUM": f">= {self.medium_threshold}",
                      "LOW": f"< {self.medium_threshold}"},
            "aggregation": self.aggregation,
            "decay": f"H = ρ^|D|, ρ = {self.rho}",
            "store": type(self.store).__name__,
        }

    # ── Persistent state (store) ─────────────────────────────────────

    def _read(self, session_id: str) -> Tuple[int, str, bool]:
        """(|D|, Tier_P, store_ok). Fails closed on store errors."""
        try:
            n, tier_p = self.store.read(session_id)
            return n, tier_p, True
        except StoreUnavailable as exc:
            logger.error(f"TrustEngine: session store unavailable ({exc}); failing closed")
            return 1, "MEDIUM", False

    def history(self, session_id: str) -> float:
        n, _, _ = self._read(session_id)
        return self.rho ** n

    def persistent_tier(self, session_id: str) -> str:
        return self._read(session_id)[1]

    @staticmethod
    def _clean_text(payload: str) -> str:
        """Algorithm 1 CleanText: drop instrumentation so two hooks digest alike."""
        text = str(payload)
        text = re.sub(r"--- USER INPUT (?:START|END) ---", "", text)
        text = re.sub(r"\[PROVENANCE:[^\]]*\]", "", text)
        text = text.replace("[SANITIZED]", "")
        return re.sub(r"\s+", " ", text).strip()

    def digest(self, payload: str) -> str:
        return hashlib.sha256(self._clean_text(payload).encode("utf-8", errors="replace")).hexdigest()[:16]

    def register_injection(self, session_id: str, content_hash: Optional[str] = None) -> bool:
        """Add a registration to D. Deduplicated by digest unless ablated.

        Returns True if D grew (H decayed).
        """
        if content_hash and not settings.disable_hash_dedup:
            reg_id = content_hash
        else:
            reg_id = f"event:{uuid.uuid4().hex}"
        try:
            grew = self.store.add_registration(session_id, reg_id)
        except StoreUnavailable as exc:
            logger.error(f"TrustEngine: could not record registration ({exc}); failing closed")
            return False
        if grew:
            logger.warning(f"TrustEngine: registered injection for session {session_id}; "
                           f"H={self.history(session_id):.4f}")
        else:
            logger.info(f"TrustEngine: duplicate registration suppressed for session {session_id}")
        return grew

    # ── Turns ────────────────────────────────────────────────────────

    def begin_turn(self, session_id: str) -> None:
        """Algorithm 1 'Turn start': Tier_t <- Tier_P."""
        tier_p = self.persistent_tier(session_id)
        with self._lock:
            state = self._turns.setdefault(session_id, {"turn": -1, "tier_t": "HIGH"})
            state["turn"] += 1
            state["tier_t"] = tier_p

    def _turn_state(self, session_id: str) -> Dict:
        with self._lock:
            if session_id not in self._turns:
                self._turns[session_id] = {"turn": 0, "tier_t": self.persistent_tier(session_id)}
            return self._turns[session_id]

    # ── Scoring ──────────────────────────────────────────────────────

    def calculate_trust(self, session_id: str, source: str, is_malicious: bool,
                        retrieval_confidence: float = 1.0) -> float:
        S = self.source_score(source)
        P = 0.0 if is_malicious else 1.0
        H = self.history(session_id)
        R = max(0.0, float(retrieval_confidence)) if S == self.source_scores["memory"] else 1.0
        return round(self.alpha * S + self.beta * P + self.gamma * H + self.delta * R, 4)

    def determine_tier(self, trust_score: float) -> str:
        if trust_score >= self.high_threshold:
            return "HIGH"
        if trust_score >= self.medium_threshold:
            return "MEDIUM"
        return "LOW"

    def process_payload(self, session_id: str, payload: str, source: str, is_malicious: bool,
                        retrieval_confidence: float = 1.0) -> Tuple[float, str]:
        """Mediate one transition (Algorithm 1). Returns (T, enforcement tier)."""
        if is_malicious:
            self.register_injection(session_id, self.digest(payload))

        score = self.calculate_trust(session_id, source, is_malicious, retrieval_confidence)
        tau = self.determine_tier(score)

        persist = is_malicious or self.aggregation == "session"
        if persist and tau != "HIGH":
            try:
                self.store.add_demotion(session_id, tau)
            except StoreUnavailable as exc:
                logger.error(f"TrustEngine: could not record demotion ({exc}); failing closed")

        state = self._turn_state(session_id)
        with self._lock:
            state["tier_t"] = _min_tier(state["tier_t"], tau)
            if TIER_ORDER[tau] < TIER_ORDER["HIGH"]:
                prev = self._governing.get(session_id, 1.0)
                self._governing[session_id] = min(prev, score)
        tier = self.session_tier(session_id)

        logger.info(f"TrustEngine: session={session_id} T={score:.4f} τ={tau} "
                    f"enforcement={tier} rule={self.aggregation}")
        try:
            from dashboard_events import push_dashboard_event
            push_dashboard_event("TRUST_UPDATE", {"session_id": session_id, "score": round(score, 3),
                                                  "transition_tier": tau, "tier": tier})
        except Exception:
            pass
        return score, tier

    def session_tier(self, session_id: str) -> str:
        """The tier Phase 7 consults: Tier_t (turn rule) or Tier_P (session rule)."""
        _, tier_p, ok = self._read(session_id)
        if self.aggregation == "session":
            tier = tier_p
        else:
            tier = _min_tier(self._turn_state(session_id)["tier_t"], tier_p)
        return tier if ok else _min_tier(tier, "MEDIUM")

    def snapshot(self, session_id: str) -> dict:
        n, tier_p, ok = self._read(session_id)
        return {
            "session_id": session_id,
            "history": round(self.rho ** n, 4),
            "registrations": n,
            "persistent_tier": tier_p,
            "tier": self.session_tier(session_id),
            "governing_score": round(self._governing.get(session_id, 1.0), 4),
            "store_ok": ok,
            "aggregation": self.aggregation,
        }

    def reset_session(self, session_id: str) -> None:
        try:
            self.store.reset_session(session_id)
        except StoreUnavailable:
            pass
        with self._lock:
            self._turns.pop(session_id, None)
            self._governing.pop(session_id, None)

    def reset_all(self) -> None:
        try:
            self.store.reset_all()
        except StoreUnavailable:
            pass
        with self._lock:
            self._turns.clear()
            self._governing.clear()


# ═══════════════════════════════════════════════════════════════════
# Worker routing
# ═══════════════════════════════════════════════════════════════════

_current_worker = contextvars.ContextVar("trust_worker", default=0)


class _EngineRouter:
    """Delegates to the engine of the active worker (one worker by default)."""

    def __init__(self):
        self._engines = [TrustEngine()]

    def configure(self, n_workers: int = 1, shared_store: Optional[SessionStore] = None) -> None:
        """One engine per worker; each gets its own in-process store unless shared."""
        engines = []
        for _ in range(max(1, n_workers)):
            store = shared_store if shared_store is not None else InProcessStore(settings.max_tracked_sessions)
            engines.append(TrustEngine(store))
        self._engines = engines
        _current_worker.set(0)

    def active(self) -> TrustEngine:
        return self._engines[_current_worker.get() % len(self._engines)]

    @property
    def workers(self) -> int:
        return len(self._engines)

    def rebuild(self) -> None:
        """Re-read settings in every engine; rebuild stores if the spec changed."""
        if len(self._engines) == 1:
            self._engines = [TrustEngine()]
        else:
            for e in self._engines:
                e.rebuild()

    def reset_all(self) -> None:
        for e in self._engines:
            e.reset_all()

    def __getattr__(self, name):
        return getattr(self.active(), name)


trust_engine = _EngineRouter()


def set_worker(index: int) -> None:
    """Select the worker whose engine serves the current turn."""
    _current_worker.set(int(index))


def configure_workers(n_workers: int = 1, shared_store: Optional[SessionStore] = None) -> None:
    trust_engine.configure(n_workers, shared_store)
