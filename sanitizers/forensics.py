"""
Image forensics: metadata extraction + LSB steganalysis.

Replaces two previously weak mechanisms:

  * EXIF was read only for JPEG via the private ``_getexif`` and only string
    tags — missing PNG ``tEXt``/``zTXt``/``iTXt`` chunks, XMP and image
    comments, which are classic places to hide prompt-injection text.
  * "Steganalysis" was ``file_size > 5 MB`` — not steganalysis at all.

This module does real metadata harvesting across formats and a real (if
lightweight) chi-square LSB steganalysis test.
"""

from __future__ import annotations

import os
from typing import Dict, List, Any

from logging_config import get_logger

logger = get_logger(__name__)


def extract_metadata_text(image_path: str) -> List[str]:
    """Harvest human-readable metadata from an image across formats.

    Returns a list of ``"key: value"`` strings (EXIF tags, PNG text chunks,
    XMP, comments) so the caller can scan them for hidden instructions.
    """
    out: List[str] = []
    try:
        from PIL import Image, ExifTags
    except Exception:
        return out
    if not os.path.exists(image_path):
        return out
    try:
        img = Image.open(image_path)
    except Exception:
        return out

    # 1) EXIF (works for JPEG/TIFF/WebP and some PNG via the public getexif()).
    try:
        exif = img.getexif()
        if exif:
            for tag, value in exif.items():
                name = ExifTags.TAGS.get(tag, str(tag))
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", "replace")
                    except Exception:
                        continue
                if isinstance(value, str) and value.strip():
                    out.append(f"exif:{name}: {value.strip()}")
    except Exception:
        pass

    # 2) PNG text chunks (tEXt / zTXt / iTXt) live in img.text.
    try:
        png_text = getattr(img, "text", None)
        if isinstance(png_text, dict):
            for k, v in png_text.items():
                if isinstance(v, str) and v.strip():
                    out.append(f"png-text:{k}: {v.strip()}")
    except Exception:
        pass

    # 3) XMP packets and generic comments stashed in img.info.
    try:
        info = getattr(img, "info", {}) or {}
        for key in ("xmp", "XML:com.adobe.xmp", "comment", "Comment", "Description"):
            val = info.get(key)
            if isinstance(val, bytes):
                val = val.decode("utf-8", "replace")
            if isinstance(val, str) and val.strip():
                out.append(f"{key}: {val.strip()[:2000]}")
    except Exception:
        pass

    return out


def chi_square_lsb(image_path: str) -> Dict[str, Any]:
    """Lightweight chi-square LSB steganalysis.

    Sequential LSB embedding makes the two values of each (2i, 2i+1) pair
    equiprobable, which a chi-square test against that expectation detects.
    Returns ``{suspected, score, method, reason}`` where ``score`` in [0,1] is
    the embedding likelihood (1 - p_value of "clean").
    """
    result = {"suspected": False, "score": 0.0, "method": "chi-square-lsb", "reason": "not analysed"}
    if not os.path.exists(image_path):
        return result
    try:
        import numpy as np
        from PIL import Image
        from scipy.stats import chisquare
    except Exception as e:
        result["reason"] = f"steganalysis deps unavailable: {e}"
        return result

    try:
        img = Image.open(image_path).convert("L")
        arr = np.asarray(img).ravel()
        if arr.size < 256:
            result["reason"] = "image too small to analyse"
            return result

        # Histogram of all 256 values; pair them as (2i, 2i+1).
        hist = np.bincount(arr, minlength=256).astype(float)
        even = hist[0::2]
        odd = hist[1::2]
        expected = (even + odd) / 2.0
        mask = expected > 5  # chi-square validity: expected count >= 5
        if mask.sum() < 8:
            result["reason"] = "insufficient populated bins"
            return result

        observed = even[mask]
        exp = expected[mask]
        # Re-scale observed to the same total as expected to satisfy chisquare.
        observed = observed * (exp.sum() / max(observed.sum(), 1e-9))
        stat, p_value = chisquare(observed, exp)
        embedding_likelihood = float(max(0.0, min(1.0, 1.0 - p_value)))
        result.update({
            "suspected": embedding_likelihood > 0.95,
            "score": round(embedding_likelihood, 4),
            "reason": f"chi-square p_value={p_value:.4g}",
        })
        return result
    except Exception as e:
        result["reason"] = f"analysis error: {e}"
        return result


def analyse_image(image_path: str) -> Dict[str, Any]:
    """Full forensic report: metadata + steganalysis."""
    metadata = extract_metadata_text(image_path)
    stego = chi_square_lsb(image_path)
    return {
        "path": os.path.basename(image_path),
        "metadata": metadata,
        "metadata_count": len(metadata),
        "steganalysis": stego,
    }
