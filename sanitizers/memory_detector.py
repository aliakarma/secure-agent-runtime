"""
Retrieval-context-aware detection at the memory boundary (Hook 4).

One of the four mechanisms the paper isolates (§1, §8.3, §8.5), and the only
leave-one-out row that clears significance at this corpus size (p = 0.008).

**The problem it solves.** A detector fine-tuned on user-side prompts sees a
retrieved memory fragment as out-of-distribution: fragments arrive without
surrounding conversational structure, carry retrieval scaffolding the detector
has never seen (``Context from previous conversations:``, list syntax,
``User:``/``Agent:`` turn markers, provenance tags), and are often sentence
fragments rather than well-formed requests. Fed to the shared detector without
adaptation, Hook 4 exhibits a 96.9% isolated false-positive rate — it flags
nearly every benign retrieval fragment. §8.5 reports the adapted figure at 21.9%.

**The adaptation is two things**, and both are ablated together by
``DISABLE_MEMORY_ADAPTATION`` so the leave-one-out row measures the mechanism
rather than one half of it:

1. *Retrieval-context normalization* — the scaffolding is stripped and each
   fragment is classified on its own, so the detector sees natural language at
   roughly the shape it was trained on rather than a concatenated block of
   metadata.
2. *A dedicated checkpoint slot* — when ``models/memory_prompt_detector/``
   exists it is used instead of the shared detector. Train it with
   ``scripts/train_memory_detector.py``, which mixes retrieval metadata and
   memory fragments into the fine-tuning corpus. When the checkpoint is absent
   the shared detector runs on the normalized text, which is the degraded but
   functional configuration.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from config import settings
from logging_config import get_logger

logger = get_logger(__name__)

MEMORY_DETECTOR_PATH = os.getenv("MEMORY_DETECTOR_PATH", "./models/memory_prompt_detector")

# Retrieval scaffolding that is structure, not content.
_SCAFFOLD_PATTERNS = [
    re.compile(r"^\s*context from previous conversations:\s*", re.IGNORECASE),
    re.compile(r"\[PROVENANCE:[^\]]*\]"),
    re.compile(r"\[SANITIZED\]"),
    re.compile(r"^\s*(?:user|agent|assistant|system)\s*:\s*", re.IGNORECASE | re.MULTILINE),
]


class MemoryBoundaryDetector:
    """Detector wrapper specialised for retrieved memory fragments."""

    _shared = None
    _shared_loaded = False

    def __init__(self):
        self._checkpoint = None
        if not settings.disable_memory_adaptation:
            self._checkpoint = self._load_checkpoint()

    @classmethod
    def _load_checkpoint(cls):
        """Load the memory-adapted checkpoint once, if it is present."""
        if cls._shared_loaded:
            return cls._shared
        cls._shared_loaded = True
        if not os.path.isdir(MEMORY_DETECTOR_PATH):
            logger.info(
                f"No memory-adapted checkpoint at {MEMORY_DETECTOR_PATH}; "
                "falling back to the shared detector over normalized fragments. "
                "Train one with scripts/train_memory_detector.py."
            )
            return None
        try:
            from sanitizers.detectors import build_detector
            detector, name, error = build_detector(
                "distilbert", local_distilbert_path=MEMORY_DETECTOR_PATH
            )
            if detector is not None:
                logger.info(f"Memory-boundary detector loaded: {name}")
            else:
                logger.warning(f"Memory-boundary detector unavailable: {error}")
            cls._shared = detector
        except Exception as exc:
            logger.warning(f"Memory-boundary detector failed to load: {exc}")
            cls._shared = None
        return cls._shared

    @staticmethod
    def normalize_fragments(chunk: str) -> List[str]:
        """Strip retrieval scaffolding and split into individual fragments.

        Returns the natural-language fragments a memory chunk carries, with the
        structural metadata removed. Each is classified separately, because a
        concatenated block of unrelated fragments is itself out-of-distribution.
        """
        if not chunk:
            return []
        text = str(chunk)
        # Python list-repr is how retrieved memory reaches the context.
        if text.strip().startswith("[") and text.strip().endswith("]"):
            try:
                import ast
                parsed = ast.literal_eval(text.strip())
                if isinstance(parsed, (list, tuple)):
                    text = "\n".join(str(item) for item in parsed)
            except (ValueError, SyntaxError):
                pass
        for pattern in _SCAFFOLD_PATTERNS:
            text = pattern.sub(" ", text)
        fragments = [f.strip() for f in re.split(r"\n{1,}", text) if f.strip()]
        return fragments or ([text.strip()] if text.strip() else [])

    def is_adapted(self) -> bool:
        """True when the adaptation mechanism is active."""
        return not settings.disable_memory_adaptation

    def classify(self, chunk: str):
        """Classify a memory chunk. Returns ``(is_malicious, reason, confidence)``.

        With adaptation disabled the raw chunk goes to the shared detector
        unmodified — the un-adapted configuration the leave-one-out row measures.
        """
        from sanitizers.multimodal import TextSanitizer

        if settings.disable_memory_adaptation:
            result = TextSanitizer().sanitize(chunk)
            return result.is_malicious, f"[unadapted] {result.reason}", result.confidence

        fragments = self.normalize_fragments(chunk)
        if not fragments:
            return False, "Empty memory chunk after normalization", 1.0

        detector = self._checkpoint
        worst_conf = 0.0
        worst_reason = "No fragment flagged"

        for fragment in fragments:
            if detector is not None:
                try:
                    raw = detector(fragment)[0]
                    is_injection = raw["label"] == "INJECTION"
                    score = float(raw["score"])
                    flagged = is_injection and score >= settings.detector_threshold
                    if flagged:
                        return True, (
                            f"Memory-adapted detector: INJECTION "
                            f"(confidence={score:.3f}) on fragment {fragment[:60]!r}"
                        ), score
                    if is_injection and score > worst_conf:
                        worst_conf, worst_reason = score, "below threshold"
                    continue
                except Exception as exc:
                    logger.warning(f"Memory detector failed on a fragment: {exc}")

            # No dedicated checkpoint: shared detector over the normalized text.
            result = TextSanitizer().sanitize(fragment)
            if result.is_malicious:
                return True, f"Shared detector on normalized fragment: {result.reason}", result.confidence
            worst_conf = max(worst_conf, float(result.confidence or 0.0))

        return False, worst_reason, worst_conf


memory_detector = MemoryBoundaryDetector()
