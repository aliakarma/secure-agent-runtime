"""
Paper §7.2 / Table 6 — contamination audit.

A defense whose detector was trained on its own test distribution would report
perfect recall and mean nothing by it. Because the detector is fine-tuned rather
than off-the-shelf, the burden of excluding that possibility is ours, and
freezing order is an assurance rather than a proof — so the two corpora are
audited against each other directly.

Three checks, in increasing tolerance:

  1. **Exact match** — SHA-256 of normalized text.
  2. **Near-duplicate** — MinHash Jaccard over character 5-grams, flagged at 0.80.
  3. **Semantic similarity** — sentence-embedding cosine, flagged at 0.90.

The same three checks run between the BIPIA-derived fine-tuning split and the
mapped InjecAgent cases, because both target indirect injection and share
phrasing conventions.

Semantic similarity needs sentence-transformers; without it the audit still runs
the first two checks and says plainly that the third was skipped, rather than
reporting a pass it did not perform.

    python scripts/run_contamination_audit.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.paper_common import DATASETS, compare_to_paper, emit, load_json, run_manifest

MINHASH_THRESHOLD = 0.80
COSINE_THRESHOLD = 0.90
NUM_PERM = 128
SHINGLE = 5


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).lower()).strip()


def shingles(text: str, k: int = SHINGLE) -> Set[str]:
    norm = normalize(text)
    if len(norm) < k:
        return {norm} if norm else set()
    return {norm[i:i + k] for i in range(len(norm) - k + 1)}


def minhash_signature(text: str, num_perm: int = NUM_PERM) -> List[int]:
    """Cheap MinHash: num_perm independent hashes of the shingle set."""
    grams = shingles(text)
    if not grams:
        return [0] * num_perm
    signature = []
    for seed in range(num_perm):
        best = min(
            int(hashlib.blake2b(f"{seed}:{g}".encode(), digest_size=8).hexdigest(), 16)
            for g in grams
        )
        signature.append(best)
    return signature


def estimated_jaccard(sig_a: List[int], sig_b: List[int]) -> float:
    if not sig_a or not sig_b:
        return 0.0
    return sum(1 for a, b in zip(sig_a, sig_b) if a == b) / len(sig_a)


def load_embedder():
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except Exception:
        return None


def audit(corpus_a: List[str], corpus_b: List[str], label: str) -> Dict[str, Any]:
    print(f"\n  {label}: {len(corpus_a)} x {len(corpus_b)} = {len(corpus_a) * len(corpus_b):,} pairs")

    # 1) Exact match on normalized text.
    hashes_a = {hashlib.sha256(normalize(t).encode()).hexdigest(): t for t in corpus_a}
    exact = [t for t in corpus_b
             if hashlib.sha256(normalize(t).encode()).hexdigest() in hashes_a]
    print(f"    exact matches: {len(exact)}")

    # 2) Near-duplicate via MinHash.
    print("    computing MinHash signatures ...", flush=True)
    sigs_a = [minhash_signature(t) for t in corpus_a]
    sigs_b = [minhash_signature(t) for t in corpus_b]
    max_jaccard, flagged_near = 0.0, []
    for i, sig_b in enumerate(sigs_b):
        for j, sig_a in enumerate(sigs_a):
            score = estimated_jaccard(sig_a, sig_b)
            if score > max_jaccard:
                max_jaccard = score
            if score >= MINHASH_THRESHOLD:
                flagged_near.append({"b_index": i, "a_index": j, "jaccard": round(score, 4)})
    print(f"    near-duplicates >= {MINHASH_THRESHOLD}: {len(flagged_near)} "
          f"(max observed {max_jaccard:.3f})")

    # 3) Semantic similarity.
    embedder = load_embedder()
    semantic: Dict[str, Any]
    if embedder is None:
        semantic = {
            "performed": False,
            "reason": "sentence-transformers unavailable; install it to run this check",
        }
        print("    semantic check SKIPPED (sentence-transformers not installed)")
    else:
        import numpy as np
        emb_a = embedder.encode(corpus_a, normalize_embeddings=True, show_progress_bar=False)
        emb_b = embedder.encode(corpus_b, normalize_embeddings=True, show_progress_bar=False)
        similarity = np.asarray(emb_b) @ np.asarray(emb_a).T
        max_cosine = float(similarity.max()) if similarity.size else 0.0
        flagged = [
            {"b_index": int(i), "a_index": int(j), "cosine": round(float(similarity[i, j]), 4)}
            for i, j in zip(*(similarity >= COSINE_THRESHOLD).nonzero())
        ]
        semantic = {
            "performed": True,
            "threshold": COSINE_THRESHOLD,
            "flagged": len(flagged),
            "max_observed": round(max_cosine, 4),
            "pairs": flagged[:20],
        }
        print(f"    semantic >= {COSINE_THRESHOLD}: {len(flagged)} (max observed {max_cosine:.3f})")

    return {
        "label": label,
        "n_a": len(corpus_a),
        "n_b": len(corpus_b),
        "pairs_checked": len(corpus_a) * len(corpus_b),
        "exact": {"threshold": None, "flagged": len(exact)},
        "near_duplicate": {
            "threshold": MINHASH_THRESHOLD,
            "flagged": len(flagged_near),
            "max_observed": round(max_jaccard, 4),
            "pairs": flagged_near[:20],
        },
        "semantic": semantic,
        "clean": len(exact) == 0 and len(flagged_near) == 0
                 and (not semantic.get("performed") or semantic.get("flagged") == 0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Paper Table 6: contamination audit")
    parser.add_argument("--finetune", default="finetune_corpus.json")
    parser.add_argument("--attacks", default="attacks.json")
    parser.add_argument("--benign", default="benign_requests.json")
    parser.add_argument("--injecagent", default="injecagent_cases.json")
    args = parser.parse_args()

    finetune_path = DATASETS / args.finetune
    if not finetune_path.exists():
        raise SystemExit(
            f"Missing {finetune_path.relative_to(PROJECT_ROOT)}. "
            "Build it first: python scripts/build_finetune_corpus.py"
        )

    finetune = load_json(finetune_path)
    finetune_texts = [r["text"] for r in finetune]
    injection_texts = [r["text"] for r in finetune if r.get("label") == 1]

    attacks = [a["prompt"] for a in load_json(DATASETS / args.attacks)]
    benign = [b["prompt"] for b in load_json(DATASETS / args.benign)]

    print(f"\n{'=' * 72}\n  CONTAMINATION AUDIT\n{'=' * 72}")
    audits = [
        audit(finetune_texts, attacks, "fine-tuning corpus vs. 100-attack evaluation corpus"),
        audit(finetune_texts, benign, "fine-tuning corpus vs. 96-request benign corpus"),
    ]

    injec_path = DATASETS / args.injecagent
    if injec_path.exists():
        cases = load_json(injec_path)
        case_texts = [
            str(c.get("user_instruction") or c.get("attacker_instruction") or "")
            for c in cases
        ]
        audits.append(audit(injection_texts, case_texts,
                            "BIPIA-derived fine-tuning split vs. mapped InjecAgent cases"))
    else:
        print(f"\n  (skipping InjecAgent audit — {injec_path.name} absent)")

    emit("contamination_audit", {
        "experiment": "contamination_audit",
        "paper_section": "7.2 / Table 6",
        "manifest": run_manifest(minhash_threshold=MINHASH_THRESHOLD,
                                 cosine_threshold=COSINE_THRESHOLD,
                                 num_perm=NUM_PERM, shingle_size=SHINGLE),
        "audits": audits,
        "all_clean": all(a["clean"] for a in audits),
        "paper_comparison": compare_to_paper("contamination_audit", {}),
    })

    print("\n" + "-" * 72)
    for a in audits:
        print(f"  {a['label']:<58} {'CLEAN' if a['clean'] else 'FLAGGED'}")
    print("-" * 72)


if __name__ == "__main__":
    main()
