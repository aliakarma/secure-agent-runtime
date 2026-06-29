"""
Input normalisation for obfuscation-resistant detection.

Adaptive attackers hide instructions behind encodings a capable LLM still
decodes: base64, leetspeak, and Unicode homoglyphs. A defense that scans the
*raw* text misses them (the 16.8% adaptive residual). This module decodes those
encodings so the detection layer (DistilBERT classifier + pre-LLM regex) can be
run over the normalised text as well.

The SAME function is used by the deterministic susceptible-model oracle (to model
what a capable LLM would obey) and by the defense (to detect it). That coupling
is deliberate and disclosed: it tests whether normalising-before-detection closes
the obfuscation gap. Residual successes after normalisation are attacks using
encodings not covered here (e.g. ROT13, hex, payload-splitting).
"""

from __future__ import annotations

import base64 as _b64
import re
import unicodedata as _ud
from typing import List

_LEET = str.maketrans({
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s",
    "$": "s", "7": "t", "+": "t", "8": "b", "9": "g", "|": "l",
})

_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "Β": "B", "Η": "H", "Κ": "K", "Μ": "M",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "υ": "u",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def decode_variants(text: str) -> List[str]:
    """Return decoded/normalised variants of ``text`` (excluding the raw text).

    Covers: base64-decoded blobs, NFKD + homoglyph normalisation, and a
    leetspeak-folded copy. Callers typically scan ``[text, *decode_variants(text)]``.
    """
    if not text:
        return []
    variants: List[str] = []

    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            dec = _b64.b64decode(blob, validate=True).decode("utf-8")
        except Exception:
            continue
        if dec and sum(c.isalpha() for c in dec) >= 4:
            variants.append(dec)

    norm = _ud.normalize("NFKD", text).translate(_HOMOGLYPH_TABLE)
    if norm != text:
        variants.append(norm)
    leet = norm.translate(_LEET)
    if leet != norm:
        variants.append(leet)

    return variants


def normalised_union(text: str) -> str:
    """Raw text plus all decoded variants, newline-joined (for scanning)."""
    return "\n".join([text, *decode_variants(text)])
