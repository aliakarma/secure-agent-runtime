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

    def require_token_enforced(self) -> bool:
        """True when a token must be presented to call protected endpoints."""
        return bool(self.api_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
