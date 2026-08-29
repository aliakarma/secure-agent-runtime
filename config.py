"""
Central runtime configuration for the Secure Agent Runtime.

All deployment-sensitive behaviour (authentication, CORS, file handling,
security strictness) is driven from environment variables through a single
``settings`` object so the codebase has one source of truth and safe,
production-aware defaults.

Design principles
-----------------
* **Secure by default in production.** Setting ``APP_ENV=production`` flips
  every permissive development convenience (sidecar injection, arbitrary
  ``file_path`` reads) to off and makes an API token mandatory.
* **Frictionless in development / CI.** With the default ``APP_ENV`` the
  offline test-suite and the local dashboard keep working without a token.
* **Fail-closed security.** ``STRICT_SECURITY`` forces the classifier and
  multimodal extractors to fail closed instead of silently degrading to
  keyword heuristics.
"""

from __future__ import annotations

import os
from functools import lru_cache


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _csv(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


class Settings:
    """Immutable view over the process environment."""

    def __init__(self) -> None:
        self.app_env: str = os.getenv("APP_ENV", "development").strip().lower()
        self.is_production: bool = self.app_env == "production"

        # ── Authentication ────────────────────────────────────────────
        # When set, every mutating / data endpoint requires the token.
        # In production an unset token is a hard configuration error
        # (enforced at startup in main.py).
        self.api_token: str = os.getenv("API_TOKEN", "").strip()

        # ── CORS ──────────────────────────────────────────────────────
        # Default to same-origin only. Operators opt into cross-origin
        # access explicitly via ALLOWED_ORIGINS.
        self.allowed_origins: list[str] = _csv("ALLOWED_ORIGINS")

        # ── File handling ─────────────────────────────────────────────
        # User uploads are written to a dedicated sandbox, never mixed
        # with the research corpus in datasets/.
        self.upload_dir: str = os.getenv("UPLOAD_DIR", "uploads")
        self.max_upload_bytes: int = _int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024)
        self.allowed_upload_suffixes: set[str] = {
            ".png", ".jpg", ".jpeg", ".gif", ".webp",
            ".wav", ".mp3", ".m4a",
            ".mp4", ".mov",
            ".pdf",
        }

        # Permissive dev conveniences — OFF in production.
        # ALLOW_SIDECAR: honour caller-supplied "already extracted" text.
        # ALLOW_FILE_PATH: accept a server-side path instead of an upload.
        self.allow_sidecar: bool = _flag("ALLOW_SIDECAR", not self.is_production)
        self.allow_file_path: bool = _flag("ALLOW_FILE_PATH", not self.is_production)

        # ── Telemetry ─────────────────────────────────────────────────
        self.max_events: int = _int("MAX_EVENTS", 2000)
        self.max_provenance_per_session: int = _int("MAX_PROVENANCE_PER_SESSION", 500)
        self.max_tracked_sessions: int = _int("MAX_TRACKED_SESSIONS", 1000)

        # ── Security strictness ───────────────────────────────────────
        self.strict_security: bool = _flag("STRICT_SECURITY", False)

        # ── Detection backend ─────────────────────────────────────────
        # Which prompt-injection detector the TextSanitizer uses:
        #   distilbert  — local fine-tuned DistilBERT (default, ships in repo)
        #   promptguard2 — Meta Llama Prompt Guard 2 (HF: meta-llama/Llama-Prompt-Guard-2-86M)
        #   deberta-pi  — ProtectAI deberta-v3-base-prompt-injection-v2
        #   ensemble    — max-pool over the available detectors above
        # Falls back gracefully to distilbert/keyword if the requested model
        # is not downloaded (unless STRICT_SECURITY=1).
        # Default detector is DeBERTa-PI: empirically it has far better precision
        # on benign imperatives (e.g. "Read this image and proceed", which the
        # fine-tuned DistilBERT mislabels as INJECTION at 0.97 → benign uploads
        # blocked). DeBERTa-PI misses bare emission directives ("output 'X'"),
        # but the pre-LLM emission-directive layer + input normalisation cover
        # that by defence-in-depth. The model below is the locally-cached v1.
        # PAPER SPEC (§5.4, Table 3): DistilBERT is the selected detector —
        # chosen over DeBERTa-v3 on the CPU latency profile (1.66 s vs 5.82 s
        # batch over the 240-prompt validation split) at a cost of 2.3 points
        # of validation accuracy. Set DETECTOR_BACKEND=deberta-pi to restore
        # the higher-precision backend; note the live-dashboard finding that
        # DistilBERT flags benign imperatives ("Read this image and proceed")
        # at 0.97, which is why deberta-pi was previously the default here.
        self.detector_backend: str = os.getenv("DETECTOR_BACKEND", "distilbert").strip().lower()
        self.promptguard_model: str = os.getenv(
            "PROMPTGUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M"
        ).strip()
        self.deberta_pi_model: str = os.getenv(
            "DEBERTA_PI_MODEL", "protectai/deberta-v3-base-prompt-injection"
        ).strip()
        # Paper §5.4: "a fixed decision threshold of 0.5 on the injection-class
        # probability". This value now drives the sanitizer directly — it was
        # previously shadowed by a hardcoded 0.85 in sanitizers/multimodal.py.
        self.detector_threshold: float = float(os.getenv("DETECTOR_THRESHOLD", "0.5"))

        # ── Trust Engine weights (T = αS + βP + γH + δR) ───────────────
        # Config-driven so the weighting can be tuned / ablated empirically
        # instead of being hard-coded. Normalised to sum to 1.0 at use sites.
        # Paper §5.5: equal weighting is the default; §8.14 sweeps five settings.
        self.trust_alpha: float = float(os.getenv("TRUST_ALPHA", "0.25"))  # source reliability
        self.trust_beta: float = float(os.getenv("TRUST_BETA", "0.25"))    # policy compliance
        self.trust_gamma: float = float(os.getenv("TRUST_GAMMA", "0.25"))  # historical behaviour
        self.trust_delta: float = float(os.getenv("TRUST_DELTA", "0.25"))  # retrieval confidence
        self.trust_high_threshold: float = float(os.getenv("TRUST_HIGH_THRESHOLD", "0.8"))
        self.trust_medium_threshold: float = float(os.getenv("TRUST_MEDIUM_THRESHOLD", "0.4"))

        # ── Trust Engine source-reliability tiers S(x) (paper §5.5) ─────
        # "An internal system prompt scores 1.0, a user turn 0.5, a tool or
        # API response 0.3, and a retrieved memory fragment 0.4."
        self.trust_source_system: float = float(os.getenv("TRUST_SOURCE_SYSTEM", "1.0"))
        self.trust_source_user: float = float(os.getenv("TRUST_SOURCE_USER", "0.5"))
        self.trust_source_tool: float = float(os.getenv("TRUST_SOURCE_TOOL", "0.3"))
        self.trust_source_memory: float = float(os.getenv("TRUST_SOURCE_MEMORY", "0.4"))

        # H(σ) multiplicative decay factor ρ (paper §5.5, Algorithm 1).
        # H ← ρH on each *registered* injection; monotone non-increasing with
        # no intra-session recovery.
        self.trust_decay_rho: float = float(os.getenv("TRUST_DECAY_RHO", "0.3"))

        # ── Ablation switches (paper §8.3 leave-one-out, Table 10) ──────
        # Each disables exactly one mechanism from the otherwise-complete
        # pipeline. Default off = mechanism enabled.
        self.disable_structural_unrolling: bool = _flag("DISABLE_STRUCTURAL_UNROLLING", False)
        self.disable_hash_dedup: bool = _flag("DISABLE_HASH_DEDUP", False)
        self.disable_memory_adaptation: bool = _flag("DISABLE_MEMORY_ADAPTATION", False)
        # Substitutes the learned classifier for the Phase 9 keyword heuristic
        # (paper §5.8: "substituting the classifier for the heuristic at this
        # position raises attack success by five attacks").
        self.output_validator_use_classifier: bool = _flag("OUTPUT_VALIDATOR_USE_CLASSIFIER", False)

        # ── Phase 8 boundary marking (paper §8.4, Table 11) ─────────────
        # Boundary markers + canonical system prompt are a simplified form of
        # spotlighting (Hines et al. 2024) — prior work embedded in Phase 8.
        # They must toggle independently of trust-aware span masking so the
        # decontamination experiment can attribute credit.
        self.boundary_marking: bool = _flag("BOUNDARY_MARKING", True)
        # Per-span regex budget; on expiry Phase 8 FAILS CLOSED (masks).
        self.pre_llm_span_budget_ms: float = float(os.getenv("PRE_LLM_SPAN_BUDGET_MS", "50"))

        # ── Interception topology (paper §8.11 perimeter baseline) ──────
        # perimeter: detector at ingress/egress only, no internal transitions.
        # multipoint: all five hooks (default, the paper's runtime).
        self.interception_mode: str = os.getenv("INTERCEPTION_MODE", "multipoint").strip().lower()

        # ── Agent model backend (paper §7.3) ────────────────────────────
        # openai   — gpt-4o-mini-2024-07-18 via the OpenAI API
        # vllm     — meta-llama/Llama-3.1-8B-Instruct served locally, bf16
        # deterministic — the offline susceptible-model oracle (repo-only)
        self.agent_backend: str = os.getenv("AGENT_BACKEND", "openai").strip().lower()
        self.openai_agent_model: str = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini-2024-07-18").strip()
        self.vllm_model: str = os.getenv("VLLM_MODEL", "meta-llama/Llama-3.1-8B-Instruct").strip()
        self.vllm_base_url: str = os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1").strip()

        # ── Scoring instruments (paper §7.4) ────────────────────────────
        # llm_judge  — GPT-4o, the paper's PRIMARY instrument (κ=0.84)
        # rule_based — the paper's deterministic grader (κ=0.09, lower bound)
        # canary     — this repo's canary/behavioural judge (scripts/judge.py)
        self.scoring_instrument: str = os.getenv("SCORING_INSTRUMENT", "llm_judge").strip().lower()
        self.judge_model: str = os.getenv("JUDGE_MODEL", "gpt-4o-2024-08-06").strip()

        # ── Multimodal forensics ──────────────────────────────────────
        # Enable real LSB steganalysis (chi-square) on uploaded images.
        self.enable_steganalysis: bool = _flag("ENABLE_STEGANALYSIS", True)

    def require_token_enforced(self) -> bool:
        """True when a token must be presented to call protected endpoints."""
        return bool(self.api_token)


def get_settings() -> Settings:
    return Settings()


settings = get_settings()

