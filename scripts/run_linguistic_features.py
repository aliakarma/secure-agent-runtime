"""
Paper §6.4 / Table ling-features — injection detection as a language task.

Tags the attack and benign corpora with the seven features of
``sanitizers/linguistic_features.py`` (machine-tagged, decision D3), then reports,
per feature: prevalence, the detector's recall on attacks and false-positive rate
on benign requests when the feature is present vs absent, a logistic regression of
the detector's injection probability on the seven features (attack family a
covariate), and tests of the three pre-registered hypotheses:

    H1 recall is lower on keyword-free than keyword-bearing attacks
    H2 benign requests with directive mood AND an override expression have elevated FPR
    H3 with mood and override lexicon controlled, addressee (F2) adds little to the score

Needs the trained detector (``DETECTOR_PATH``). The attack side uses the rebuilt
attack corpus (``datasets/attacks_rebuilt.json``); until it exists the script tags
and reports the benign side and marks the attack-side rows pending, rather than
measuring on the corpus that is being replaced.

    python scripts/run_linguistic_features.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.paper_common import emit, run_manifest, wilson_ci  # noqa: E402
from sanitizers.linguistic_features import tag  # noqa: E402

DATASETS = PROJECT_ROOT / "datasets"
FEATURES = ["F1_directive_mood", "F2_addressee_model", "F3_instruction_override",
            "F4_authority_impersonation", "F5_external_target", "F6_keyword_bearing",
            "F7_grammatical_person"]


def _detector():
    from sanitizers.multimodal import TextSanitizer
    return TextSanitizer()


def _rate_by_feature(items, texts, is_flagged, feature):
    present = [f for it, f in zip(items, is_flagged) if it["_tags"][feature]]
    absent = [f for it, f in zip(items, is_flagged) if not it["_tags"][feature]]

    def r(xs):
        if not xs:
            return {"n": 0, "rate_pct": None, "ci_pct": [None, None]}
        k = sum(xs)
        lo, hi = wilson_ci(k, len(xs))
        return {"n": len(xs), "rate_pct": round(100 * k / len(xs), 2),
                "ci_pct": [round(100 * lo, 2), round(100 * hi, 2)]}
    return {"present": r(present), "absent": r(absent)}


def _logreg(rows, labels):
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        return {"error": "scikit-learn/numpy unavailable"}
    X = np.array([[int(r[f]) for f in FEATURES] for r in rows], dtype=float)
    y = np.array(labels, dtype=float)
    if len(set(labels)) < 2:
        return {"error": "single class"}
    model = LogisticRegression(max_iter=1000).fit(X, y)
    return {f: round(float(c), 4) for f, c in zip(FEATURES, model.coef_[0])} | {
        "intercept": round(float(model.intercept_[0]), 4)}


def main() -> None:
    det = _detector()
    benign = json.loads((DATASETS / "benign_requests.json").read_text(encoding="utf-8"))
    for b in benign:
        b["_tags"] = tag(b["prompt"])
    ben_flag = [det.sanitize(b["prompt"]).is_malicious for b in benign]

    attack_path = DATASETS / "attacks_rebuilt.json"
    if not attack_path.exists():
        attack_path = DATASETS / "attacks.json"

    attack_section = None
    if attack_path.exists():
        attacks = json.loads(attack_path.read_text(encoding="utf-8"))
        for a in attacks:
            text = a.get("payload") or a.get("prompt") or a.get("user_turn") or ""
            a["_tags"] = tag(text)
            a["_text"] = text
        atk_flag = [det.sanitize(a["_text"]).is_malicious for a in attacks]

        prevalence = {f: {"attacks": sum(a["_tags"][f] for a in attacks),
                          "benign": sum(b["_tags"][f] for b in benign)} for f in FEATURES}
        recall = {f: _rate_by_feature(attacks, [a["_text"] for a in attacks], atk_flag, f)
                  for f in FEATURES}
        fpr = {f: _rate_by_feature(benign, [b["prompt"] for b in benign], ben_flag, f)
               for f in FEATURES}

        kf = [a for a, fl in zip(attacks, atk_flag) if a.get("keyword_free")]
        kf_flag = [fl for a, fl in zip(attacks, atk_flag) if a.get("keyword_free")]
        kb_flag = [fl for a, fl in zip(attacks, atk_flag) if not a.get("keyword_free")]
        from scipy.stats import fisher_exact
        h1 = fisher_exact([[sum(kf_flag), len(kf_flag) - sum(kf_flag)],
                           [sum(kb_flag), len(kb_flag) - sum(kb_flag)]])
        rows = [a["_tags"] for a in attacks] + [b["_tags"] for b in benign]
        labels = [1] * len(attacks) + [0] * len(benign)
        attack_section = {
            "prevalence": prevalence,
            "recall_by_feature": recall,
            "fpr_by_feature": fpr,
            "logistic_regression": _logreg(rows, labels),
            "H1_keyword_free_lower_recall": {"kf_recall_pct": round(100 * sum(kf_flag) / len(kf_flag), 2) if kf_flag else None,
                                             "kb_recall_pct": round(100 * sum(kb_flag) / len(kb_flag), 2) if kb_flag else None,
                                             "fisher_p": round(float(h1[1]), 4)},
        }
    else:
        print("  Attack dataset absent: reporting benign-side tagging only; "
              "attack-side rows pending.")

    emit("linguistic_features", {
        "experiment": "linguistic_features",
        "paper_section": "6.4 / Table ling-features",
        "manifest": run_manifest(tagging="machine (sanitizers/linguistic_features.py, decision D3)"),
        "benign_prevalence": {f: sum(b["_tags"][f] for b in benign) for f in FEATURES},
        "benign_person": {p: sum(1 for b in benign if b["_tags"]["F7_person"] == p)
                          for p in ("first", "second", "mixed", "impersonal")},
        "attack_section": attack_section,
        "attack_side_pending": attack_section is None,
    })
    print("  benign feature prevalence:", {f: sum(b["_tags"][f] for b in benign) for f in FEATURES})


if __name__ == "__main__":
    main()
