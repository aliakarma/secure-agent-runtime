"""
Dynamic trust scoring and three-tier policy enforcement.

Implements the trust model of the paper (§5.5, §5.5.1, Algorithm 1):

    T(x, σ) = α·S(x) + β·P(x) + γ·H(σ) + δ·R(x)

with

  * **S(x) — source reliability.** A fixed tier per origin: internal system
    prompt 1.0, user turn 0.5, tool/API response 0.3, retrieved memory
    fragment 0.4. The tool and memory tiers are what make a poisoned tool
    response score materially lower than the user turn that requested it.
  * **P(x) — policy compliance.** 1.0 when no detector fires, 0.0 when the
    classifier or heuristic flags the payload.
  * **H(σ) — session history.** Initialises to 1.0 and decays *multiplicatively*
    as H ← ρH (ρ = 0.3) on each **registered** injection. Monotone
    non-increasing within a session, with no intra-session recovery.
  * **R(x) — retrieval confidence.** max(0, cos(fragment, active query)) for
    retrieved content, 1.0 for content that was not retrieved. The clip maps
    anti-correlated fragments to the bottom of the range rather than outside it.

The enforcement tier is stated over *sessions*, not transitions
(Equation 2): the session tier after k mediated transitions is the **minimum**
tier observed so far, under LOW < MEDIUM < HIGH. Because H is monotone
non-increasing and nothing else recovers, a session never returns to a higher
tier once demoted — which is what lets the write gate (Policy 1) consult the
session tier rather than the score of the write request itself.

Content-hash deduplication prevents a false trust cascade: the same message is
scanned at Hook 5 during supervisor routing and again at Hook 1 at the agent
node, and without deduplication a single classifier false positive would decay
H twice and push a benign session past MEDIUM.
"""

import hashlib
import re
import threading
import time
from collections import OrderedDict
from typing import List, Dict, Optional, Tuple
from pydantic import BaseModel
from logging_config import get_logger
from config import settings

logger = get_logger(__name__)

# Tier ordering for the Equation-2 minimum. Higher int == more capability.
TIER_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
TIER_NAME = {v: k for k, v in TIER_ORDER.items()}


class TrustMetadata(BaseModel):
    source_origin: str
    modality: str
    sanitizers_applied: List[str]
    timestamp: float
    trust_lineage: List[str]
    is_malicious: bool


class SessionState(BaseModel):
    """Per-session trust state (the σ of T(x, σ))."""
    history: float = 1.0            # H(σ)
    registrations: int = 0          # count of registered (deduplicated) injections
    tier: str = "HIGH"              # running minimum of Equation 2
    min_score: float = 1.0          # score at the governing transition


class TrustEngine:
    """Session trust scoring with bounded, thread-safe state.

    State is kept in-memory behind a lock and capped with LRU eviction so a
    long-running, multi-session server cannot grow without bound. For a
    horizontally-scaled deployment this class is the seam to back with Redis;
    the public API would not change. Paper §8.17 measures what happens when
    that seam is left unbacked behind a round-robin load balancer.
    """

    def __init__(self, max_sessions: Optional[int] = None):
        self._lock = threading.RLock()
        self._sessions: "OrderedDict[str, SessionState]" = OrderedDict()
        self._seen_hashes: "OrderedDict[str, set]" = OrderedDict()
        self._max_sessions = max_sessions or settings.max_tracked_sessions

        # Formula weights, normalised to sum to 1.0 so the score stays in
        # [0, 1] regardless of the raw values an operator supplies.
        raw = [settings.trust_alpha, settings.trust_beta, settings.trust_gamma, settings.trust_delta]
        total = sum(raw) or 1.0
        self.alpha = raw[0] / total  # Source reliability   S(x)
        self.beta = raw[1] / total   # Policy compliance    P(x)
        self.gamma = raw[2] / total  # Historical behaviour H(σ)
        self.delta = raw[3] / total  # Retrieval confidence R(x)

        self.high_threshold = settings.trust_high_threshold
        self.medium_threshold = settings.trust_medium_threshold
        self.rho = settings.trust_decay_rho

        self.source_scores = {
            "system": settings.trust_source_system,
            "user": settings.trust_source_user,
            "tool": settings.trust_source_tool,
            "memory": settings.trust_source_memory,
        }

    # ── Source classification ────────────────────────────────────────

    def source_score(self, source: str) -> float:
        """S(x): map an origin label onto its reliability tier.

        Accepts the origin vocabulary used across the hooks: ``system``,
        ``user``/``user_or_agent``/``agent``, ``tool_<name>``, ``rag``/``memory``.
        Unknown origins are treated as user-tier rather than system-tier, so an
        unrecognised label can never be *more* trusted than a user turn.
        """
        s = (source or "").strip().lower()
        if s == "system":
            return self.source_scores["system"]
        if s.startswith("tool") or s.startswith("api"):
            return self.source_scores["tool"]
        if s in ("rag", "memory", "retrieval") or s.startswith("memory"):
            return self.source_scores["memory"]
        return self.source_scores["user"]

    def describe(self) -> dict:
        """Expose the trust model for the dashboard / reproducibility."""
        return {
            "formula": "T(x,σ) = αS(x) + βP(x) + γH(σ) + δR(x)",
            "weights": {
                "alpha_source": round(self.alpha, 4),
                "beta_policy": round(self.beta, 4),
                "gamma_history": round(self.gamma, 4),
                "delta_retrieval": round(self.delta, 4),
            },
            "tiers": {
                "HIGH": f">= {self.high_threshold}",
                "MEDIUM": f">= {self.medium_threshold}",
                "LOW": f"< {self.medium_threshold}",
            },
            "aggregation": "Tier(σ_k) = min_{i<=k} τ(x_i, σ_i)  [monotone non-increasing]",
            "decay": f"H <- ρH on each registered injection, ρ = {self.rho}",
            "components": {
                "S(x)": f"source reliability (system={self.source_scores['system']}, "
                        f"user={self.source_scores['user']}, tool={self.source_scores['tool']}, "
                        f"memory={self.source_scores['memory']})",
                "P(x)": "policy compliance (malicious=0, else 1)",
                "H(σ)": "session history (init 1.0, multiplicative decay, no recovery)",
                "R(x)": "retrieval confidence max(0, cos(fragment, query)); 1.0 if not retrieved",
            },
        }

    # ── Session bookkeeping ──────────────────────────────────────────

    def _state(self, session_id: str) -> SessionState:
        """Fetch-or-create session state. Caller must hold the lock."""
        st = self._sessions.get(session_id)
        if st is None:
            st = SessionState()
            self._sessions[session_id] = st
        self._sessions.move_to_end(session_id)
        if session_id in self._seen_hashes:
            self._seen_hashes.move_to_end(session_id)
        while len(self._sessions) > self._max_sessions:
            old, _ = self._sessions.popitem(last=False)
            self._seen_hashes.pop(old, None)
        return st

    @staticmethod
    def _clean_text(payload: str) -> str:
        """Normalise a payload before digesting it (Algorithm 1, CleanText).

        Both hooks that scan a user message must produce the same digest, so
        the instrumentation markers one hook adds and the other does not are
        stripped before hashing.
        """
        text = str(payload)
        text = re.sub(r"--- USER INPUT (?:START|END) ---", "", text)
        text = re.sub(r"\[PROVENANCE:[^\]]*\]", "", text)
        return re.sub(r"\s+", " ", text).strip()

    def register_injection(self, session_id: str, content_hash: Optional[str] = None) -> bool:
        """Register a malicious event and decay H(σ) multiplicatively.

        Deduplicates by content digest: the same message scanned by multiple
        hooks decays trust exactly once. Returns True if a decay was applied.
        """
        with self._lock:
            st = self._state(session_id)
            if content_hash and not settings.disable_hash_dedup:
                seen = self._seen_hashes.setdefault(session_id, set())
                if content_hash in seen:
                    logger.info(
                        "TrustEngine: duplicate injection suppressed for session "
                        f"{session_id} (digest already registered this session)"
                    )
                    return False
                seen.add(content_hash)
            elif content_hash:
                # Dedup ablated (paper Table 10, "- content-hash deduplication"):
                # record the digest for auditing but do not suppress the decay.
                self._seen_hashes.setdefault(session_id, set()).add(content_hash)

            st.history = max(0.0, st.history * self.rho)
            st.registrations += 1
            logger.warning(
                f"TrustEngine: registered injection for session {session_id}; "
                f"H={st.history:.4f} after {st.registrations} registration(s)"
            )
            return True

    def history(self, session_id: str) -> float:
        """Current H(σ) for a session."""
        with self._lock:
            return self._state(session_id).history

    def session_tier(self, session_id: str) -> str:
        """The Equation-2 session enforcement tier."""
        with self._lock:
            return self._state(session_id).tier

    # ── Scoring ──────────────────────────────────────────────────────

    def calculate_trust(
        self,
        session_id: str,
        source: str,
        is_malicious: bool,
        retrieval_confidence: float = 1.0,
    ) -> float:
        """T(x, σ) for a single transition."""
        S_x = self.source_score(source)
        P_x = 0.0 if is_malicious else 1.0
        with self._lock:
            H_x = self._state(session_id).history
        # R(x) applies to retrieved content only; clipped below at zero so an
        # anti-correlated fragment maps to the minimum of the range.
        if self.source_score(source) == self.source_scores["memory"]:
            R_x = max(0.0, float(retrieval_confidence))
        else:
            R_x = 1.0

        trust_score = (self.alpha * S_x) + (self.beta * P_x) + (self.gamma * H_x) + (self.delta * R_x)
        return round(trust_score, 4)

    def determine_tier(self, trust_score: float) -> str:
        if trust_score >= self.high_threshold:
            return "HIGH"
        elif trust_score >= self.medium_threshold:
            return "MEDIUM"
        return "LOW"

    def process_payload(
        self,
        session_id: str,
        payload: str,
        source: str,
        is_malicious: bool,
        retrieval_confidence: float = 1.0,
    ) -> Tuple[float, str]:
        """Mediate one transition: decay, score, assign tier, aggregate.

        Returns ``(transition_score, session_tier)``. The **session** tier is
        returned rather than the transition tier because that is what the
        Phase 7 dispatch check consults (Policy 1).
        """
        if is_malicious:
            digest = hashlib.sha256(
                self._clean_text(payload).encode("utf-8", errors="replace")
            ).hexdigest()[:16]
            self.register_injection(session_id, digest)

        score = self.calculate_trust(session_id, source, is_malicious, retrieval_confidence)
        tau = self.determine_tier(score)

        # Equation 2: the session tier is the running minimum.
        with self._lock:
            st = self._state(session_id)
            if TIER_ORDER[tau] < TIER_ORDER[st.tier]:
                st.tier = tau
                st.min_score = score
                logger.info(f"TrustEngine: session {session_id} demoted to {tau} (T={score:.3f})")
            session_tier = st.tier
            governing = st.min_score

        logger.info(
            f"TrustEngine: session={session_id} T={score:.3f} τ={tau} "
            f"session_tier={session_tier} (governing T={governing:.3f})"
        )

        try:
            from dashboard_events import push_dashboard_event
            push_dashboard_event("TRUST_UPDATE", {
                "session_id": session_id,
                "score": round(score, 3),
                "transition_tier": tau,
                "tier": session_tier,
            })
        except Exception:
            pass

        return score, session_tier

    def snapshot(self, session_id: str) -> dict:
        """Full session trust state, for the tier-distribution census."""
        with self._lock:
            st = self._state(session_id)
            return {
                "session_id": session_id,
                "history": round(st.history, 4),
                "registrations": st.registrations,
                "tier": st.tier,
                "governing_score": round(st.min_score, 4),
            }

    def reset_session(self, session_id: str) -> None:
        """Drop all tracked state for a session (used by tests / session end)."""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._seen_hashes.pop(session_id, None)

    def reset_all(self) -> None:
        """Drop every session's state (used between experiment conditions)."""
        with self._lock:
            self._sessions.clear()
            self._seen_hashes.clear()


# Global instance
trust_engine = TrustEngine()
