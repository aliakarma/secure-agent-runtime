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
        self.detector_backend: str = os.getenv("DETECTOR_BACKEND", "distilbert").strip().lower()
        self.promptguard_model: str = os.getenv(
            "PROMPTGUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M"
        ).strip()
        self.deberta_pi_model: str = os.getenv(
            "DEBERTA_PI_MODEL", "protectai/deberta-v3-base-prompt-injection-v2"
        ).strip()
        self.detector_threshold: float = float(os.getenv("DETECTOR_THRESHOLD", "0.85"))

        # ── Trust Engine weights (T = αS + βP + γH + δR) ───────────────
        # Config-driven so the weighting can be tuned / ablated empirically
        # instead of being hard-coded. Normalised to sum to 1.0 at use sites.
        self.trust_alpha: float = float(os.getenv("TRUST_ALPHA", "0.25"))  # source reliability
        self.trust_beta: float = float(os.getenv("TRUST_BETA", "0.25"))    # policy compliance
        self.trust_gamma: float = float(os.getenv("TRUST_GAMMA", "0.25"))  # historical behaviour
        self.trust_delta: float = float(os.getenv("TRUST_DELTA", "0.25"))  # retrieval confidence
        self.trust_high_threshold: float = float(os.getenv("TRUST_HIGH_THRESHOLD", "0.8"))
        self.trust_medium_threshold: float = float(os.getenv("TRUST_MEDIUM_THRESHOLD", "0.4"))

        # ── Multimodal forensics ──────────────────────────────────────
        # Enable real LSB steganalysis (chi-square) on uploaded images.
        self.enable_steganalysis: bool = _flag("ENABLE_STEGANALYSIS", True)

    def require_token_enforced(self) -> bool:
        """True when a token must be presented to call protected endpoints."""
        return bool(self.api_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
