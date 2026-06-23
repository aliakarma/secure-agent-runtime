"""
Pluggable prompt-injection detector backends.

The TextSanitizer historically hard-loaded a local fine-tuned DistilBERT. This
module abstracts the detector so the runtime can swap in stronger, purpose-built
models without touching the sanitizer logic:

  * ``distilbert``   — local fine-tuned DistilBERT (ships in repo; default).
  * ``promptguard2`` — Meta Llama Prompt Guard 2 (86M / 22M), purpose-built for
                       prompt-injection + jailbreak detection on untrusted input.
  * ``deberta-pi``   — ProtectAI deberta-v3-base-prompt-injection-v2.
  * ``ensemble``     — max-pool over whichever of the above load successfully.

Every backend exposes the Hugging Face ``text-classification`` pipeline call
shape — ``detector(text) -> [{"label": str, "score": float}]`` — where ``label``
is normalised to ``"INJECTION"`` / ``"SAFE"``, so TextSanitizer's existing
label/threshold handling works unchanged.

Loading is lazy and fail-soft: a backend that is not downloaded simply does not
register, and ``build_detector`` falls back to the next best available one
(unless ``STRICT_SECURITY=1``).
"""

from __future__ import annotations

import os
from typing import Callable, List, Optional, Tuple

from logging_config import get_logger

logger = get_logger(__name__)

# label-id 1 is the "injection / malicious / unsafe" class across all three
# model families (DistilBERT id2label, Prompt Guard 2, DeBERTa-PI).
_INJECTION_LABELS = {"INJECTION", "LABEL_1", "JAILBREAK", "UNSAFE", "MALICIOUS"}


def _normalise_label(label: str) -> str:
    return "INJECTION" if str(label).upper() in _INJECTION_LABELS else "SAFE"


def _load_pipeline(model: str, *, local: bool = False):
    """Load a HF text-classification pipeline (CPU). Returns the callable or None."""
    from transformers import pipeline, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model)
    # DistilBERT tokenizers emit token_type_ids the model head does not accept.
    try:
        tokenizer.model_input_names = [n for n in tokenizer.model_input_names if n != "token_type_ids"]
    except Exception:
        pass
    return pipeline("text-classification", model=model, tokenizer=tokenizer, device=-1, truncation=True)


class Detector:
    """Wraps a single HF pipeline, normalising the output label."""

    def __init__(self, name: str, pipe: Callable):
        self.name = name
        self._pipe = pipe

    def __call__(self, text: str):
        raw = self._pipe(str(text))[0]
        return [{"label": _normalise_label(raw["label"]), "score": float(raw["score"])}]

    def injection_prob(self, text: str) -> float:
        r = self(text)[0]
        return r["score"] if r["label"] == "INJECTION" else 1.0 - r["score"]


class EnsembleDetector:
    """Max-pool ensemble: injection if any member is confident it is."""

    def __init__(self, members: List[Detector]):
        self.members = members
        self.name = "ensemble[" + "+".join(m.name for m in members) + "]"

    def __call__(self, text: str):
        best_p = 0.0
        for m in self.members:
            best_p = max(best_p, m.injection_prob(text))
        if best_p >= 0.5:
            return [{"label": "INJECTION", "score": best_p}]
        return [{"label": "SAFE", "score": 1.0 - best_p}]


def _try(name: str, loader) -> Optional[Detector]:
    try:
        pipe = loader()
        logger.info(f"Detector backend loaded: {name}")
        return Detector(name, pipe)
    except Exception as e:  # not downloaded / offline / incompatible
        logger.warning(f"Detector backend '{name}' unavailable: {e}")
        return None


def build_detector(
    backend: str,
    *,
    local_distilbert_path: str = "./models/local_prompt_detector",
    promptguard_model: str = "meta-llama/Llama-Prompt-Guard-2-86M",
    deberta_pi_model: str = "protectai/deberta-v3-base-prompt-injection-v2",
) -> Tuple[Optional[object], str, Optional[str]]:
    """Return ``(detector, active_name, error)`` for the requested backend.

    Falls back to the local DistilBERT, then to None (keyword-only), so the
    server keeps running even if a heavy model is not present.
    """
    backend = (backend or "distilbert").lower()

    loaders = {
        "distilbert": lambda: _try("distilbert", lambda: _load_pipeline(local_distilbert_path, local=True)),
        "promptguard2": lambda: _try("promptguard2", lambda: _load_pipeline(promptguard_model)),
        "deberta-pi": lambda: _try("deberta-pi", lambda: _load_pipeline(deberta_pi_model)),
    }

    if backend == "ensemble":
        members = [d for d in (loaders["distilbert"](), loaders["promptguard2"](), loaders["deberta-pi"]()) if d]
        if members:
            return EnsembleDetector(members), EnsembleDetector(members).name, None
        return None, "none", "no ensemble members could be loaded"

    primary = loaders.get(backend, loaders["distilbert"])()
    if primary is not None:
        return primary, primary.name, None

    # Fallback chain: requested → distilbert → none
    if backend != "distilbert":
        fb = loaders["distilbert"]()
        if fb is not None:
            return fb, fb.name, f"requested '{backend}' unavailable; fell back to distilbert"
    return None, "none", f"detector backend '{backend}' could not be loaded"
