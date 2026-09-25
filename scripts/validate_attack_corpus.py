"""
Validate and freeze the rebuilt attack corpus (see
``datasets/attack_corpus_spec/README.md``).

Checks the family and keyword-free counts, distinctness, carrier fields, the
keyword-free rule against ``triggers.txt``, the presence of a success criterion,
and decontamination against the detector fine-tuning corpus (exact, MinHash,
embedding). On PASS it writes ``datasets/attacks_rebuilt.json`` and records a
sha256 so the frozen corpus is checkable. Also generates the empty template.

    python scripts/validate_attack_corpus.py --make-template
    python scripts/validate_attack_corpus.py datasets/attack_corpus_spec/attacks_template.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
DATASETS = PROJECT_ROOT / "datasets"
SPEC = DATASETS / "attack_corpus_spec"

REQUIRED = {
    "direct_prompt_injection": {"n": 25, "kf": 11, "carrier": "user_turn"},
    "indirect_prompt_injection": {"n": 30, "kf": 15, "carrier": "tool_response",
                                  "tool": "search_flights", "field": "description"},
    "tool_output_poisoning": {"n": 20, "kf": 9, "carrier": "tool_response",
                              "tool": "reserve_hotel", "field": "notes"},
    "rag_memory_poisoning": {"n": 20, "kf": 8, "carrier": "memory"},
    "role_hijacking": {"n": 5, "kf": 3, "carrier": "user_turn"},
}
MINHASH_THRESHOLD, COSINE_THRESHOLD, SHINGLE, NUM_PERM = 0.80, 0.90, 5, 128


def triggers():
    return [t.strip().lower() for t in (SPEC / "triggers.txt").read_text(encoding="utf-8").splitlines() if t.strip()]


def make_template() -> None:
    SPEC.mkdir(parents=True, exist_ok=True)
    items = []
    for family, r in REQUIRED.items():
        for i in range(1, r["n"] + 1):
            kf = i <= r["kf"]
            item = {"id": f"{family}_{i}", "family": family, "carrier": r["carrier"],
                    "keyword_free": kf, "user_turn": "", "success": ""}
            if r["carrier"] == "tool_response":
                item.update(tool=r["tool"], field=r["field"], payload="")
            elif r["carrier"] == "memory":
                item["payload"] = ""
            items.append(item)
    out = SPEC / "attacks_template.json"
    out.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(items)} stubs -> {out.relative_to(PROJECT_ROOT)}")


def normalise(t: str) -> str:
    return re.sub(r"\s+", " ", str(t).lower()).strip()


def validate(path: Path) -> int:
    items = json.loads(path.read_text(encoding="utf-8"))
    errors, trg = [], triggers()

    by_family: dict = {}
    for it in items:
        by_family.setdefault(it.get("family"), []).append(it)

    for family, r in REQUIRED.items():
        group = by_family.get(family, [])
        if len(group) != r["n"]:
            errors.append(f"{family}: {len(group)} items, need {r['n']}")
        kf = sum(1 for it in group if it.get("keyword_free"))
        if kf != r["kf"]:
            errors.append(f"{family}: {kf} keyword-free, need {r['kf']}")
        for it in group:
            if it.get("carrier") != r["carrier"]:
                errors.append(f"{it['id']}: carrier {it.get('carrier')} != {r['carrier']}")
            if r["carrier"] == "tool_response" and (it.get("tool") != r["tool"] or it.get("field") != r["field"]):
                errors.append(f"{it['id']}: tool/field must be {r['tool']}/{r['field']}")

    for it in items:
        text = it.get("user_turn", "")
        payload = it.get("payload", "") if it.get("carrier") != "user_turn" else text
        if not text.strip():
            errors.append(f"{it['id']}: empty user_turn")
        if it.get("carrier") != "user_turn" and not str(payload).strip():
            errors.append(f"{it['id']}: empty payload")
        if not str(it.get("success", "")).strip():
            errors.append(f"{it['id']}: empty success criterion")
        has_trigger = any(t in normalise(payload) for t in trg)
        if it.get("keyword_free") and has_trigger:
            errors.append(f"{it['id']}: marked keyword_free but contains a trigger token")
        if not it.get("keyword_free") and not has_trigger:
            errors.append(f"{it['id']}: not keyword_free but contains no trigger token")

    for key in ("id", "user_turn"):
        seen = {}
        for it in items:
            v = normalise(it.get(key, ""))
            if v and v in seen:
                errors.append(f"duplicate {key}: {it['id']} == {seen[v]}")
            seen[v] = it["id"]
    payloads = {}
    for it in items:
        p = normalise(it.get("payload") or it.get("user_turn", ""))
        if p in payloads:
            errors.append(f"duplicate payload: {it['id']} == {payloads[p]}")
        payloads[p] = it["id"]

    # Decontamination against the detector fine-tuning corpus.
    ft = DATASETS / "finetune_corpus.json"
    if ft.exists() and not errors:
        errors += _decontaminate(items, json.loads(ft.read_text(encoding="utf-8")))
    elif not ft.exists():
        print("  (skipping decontamination: finetune_corpus.json not built)")

    if errors:
        print(f"FAIL ({len(errors)} problems):")
        for e in errors[:60]:
            print("  -", e)
        return 1

    out = DATASETS / "attacks_rebuilt.json"
    out.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    (DATASETS / "attacks_rebuilt.sha256").write_text(digest, encoding="utf-8")
    print(f"PASS: 100 items, 46 keyword-free.\n  wrote {out.relative_to(PROJECT_ROOT)}\n  sha256 {digest}")
    return 0


def _decontaminate(items, ft_corpus) -> list:
    try:
        from datasketch import MinHash, MinHashLSH
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("  (skipping decontamination: datasketch/sentence-transformers not installed)")
        return []
    ref = [r["text"] for r in ft_corpus]

    def shingles(t):
        t = normalise(t)
        return {t[i:i + SHINGLE] for i in range(max(1, len(t) - SHINGLE + 1))}

    def mh(s):
        m = MinHash(num_perm=NUM_PERM)
        for x in s:
            m.update(x.encode())
        return m

    lsh = MinHashLSH(threshold=MINHASH_THRESHOLD, num_perm=NUM_PERM)
    ref_sh = [shingles(t) for t in ref]
    for i, s in enumerate(ref_sh):
        lsh.insert(str(i), mh(s))
    ref_hashes = {hashlib.sha256(normalise(t).encode()).hexdigest() for t in ref}
    enc = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    ref_emb = enc.encode(ref, batch_size=128, normalize_embeddings=True, show_progress_bar=False)

    problems, texts = [], []
    for it in items:
        texts.append((it["id"], it.get("payload") or it.get("user_turn", "")))
    cand_emb = enc.encode([t for _, t in texts], batch_size=128, normalize_embeddings=True, show_progress_bar=False)
    for (cid, text), emb in zip(texts, cand_emb):
        if hashlib.sha256(normalise(text).encode()).hexdigest() in ref_hashes:
            problems.append(f"{cid}: exact match with fine-tuning corpus")
            continue
        sh = shingles(text)
        for key in lsh.query(mh(sh)):
            j = int(key)
            if len(sh & ref_sh[j]) / max(1, len(sh | ref_sh[j])) >= MINHASH_THRESHOLD:
                problems.append(f"{cid}: near-duplicate of a fine-tuning prompt")
                break
        else:
            if float((emb @ ref_emb.T).max()) >= COSINE_THRESHOLD:
                problems.append(f"{cid}: embedding cosine >= {COSINE_THRESHOLD} with a fine-tuning prompt")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate/freeze the rebuilt attack corpus")
    parser.add_argument("path", nargs="?", help="filled template to validate")
    parser.add_argument("--make-template", action="store_true")
    args = parser.parse_args()
    if args.make_template or not args.path:
        make_template()
        if not args.path:
            return
    raise SystemExit(validate(Path(args.path)))


if __name__ == "__main__":
    main()
