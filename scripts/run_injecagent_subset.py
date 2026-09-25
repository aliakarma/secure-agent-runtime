"""
Paper §5.7 / Table injecsubset — representativeness of the admitted InjecAgent
subset relative to the full benchmark.

The admission rule (mechanical, published): a case is admitted if its attacker
goal is expressible as a read or a write against a travel tool. InjecAgent's
attacker tools are classified read/write by name, and a case is admitted if it
maps and its user tool is a retrieval-style tool. The admitted identifiers are
written to ``datasets/injecagent_admitted_cases.txt``.

Five of the six characteristics are computed here from the benchmark data with no
model: attack-intention mix, cases requiring two attacker steps, user-tool
coverage, attacker-tool coverage, and injected-instruction length. The sixth, the
difficulty proxy (undefended Llama ASR on admitted vs excluded cases in
InjecAgent's native setting), needs the Llama arm and is produced by
``scripts/run_paper_injecagent.py`` with ``--difficulty-proxy``.

    python scripts/run_injecagent_subset.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.paper_common import emit, run_manifest  # noqa: E402

IA = PROJECT_ROOT / "datasets" / "external" / "injecagent"

# Attacker-tool verb classes. A tool is a "write" if its name contains a
# state-changing verb, a "read" otherwise.
WRITE_VERBS = ("send", "grant", "unlock", "pay", "transfer", "create", "post", "delete",
               "add", "update", "set", "book", "buy", "order", "schedule", "share",
               "revoke", "remove", "write", "publish", "reserve", "cancel", "make", "initiate")
# User (retrieval) tools whose result an injected instruction can ride in.
READ_USER_HINTS = ("get", "read", "search", "view", "fetch", "list", "navigate")


def classify_attacker(tool: str) -> str:
    low = re.sub(r"(?<!^)(?=[A-Z])", " ", tool).lower()
    return "write" if any(v in low for v in WRITE_VERBS) else "read"


def user_is_retrieval(tool: str) -> bool:
    low = re.sub(r"(?<!^)(?=[A-Z])", " ", tool).lower()
    return any(h in low for h in READ_USER_HINTS)


import hashlib

def load_cases():
    cases = []
    for name, intention in (("test_cases_dh_base.json", "direct_harm"),
                            ("test_cases_ds_base.json", "data_stealing")):
        for c in json.loads((IA / name).read_text(encoding="utf-8")):
            c["_intention"] = intention
            h = hashlib.sha256(c["Attacker Instruction"].encode("utf-8")).hexdigest()[:6]
            c["_id"] = f"{intention}:{c['User Tool']}:{c['Attacker Tools'][0]}:{h}"
            cases.append(c)
    return cases


def load_admission_list():
    """Optional author-curated admission list: one case id per line in
    ``datasets/injecagent_admitted_cases.txt`` (or fallback
    ``datasets/attack_corpus_spec/injecagent_admitted_ids.txt``). The paper admits
    200 of 1,054 cases by a booking-mappability judgment that is an authorial
    degree of freedom, so the exact set is supplied rather than inferred. When neither
    file is present, the mechanical predicate below is used and the script reports
    how many it admits (which will not be 200 until the list is curated)."""
    for candidate in (
        PROJECT_ROOT / "datasets" / "injecagent_admitted_cases.txt",
        PROJECT_ROOT / "datasets" / "attack_corpus_spec" / "injecagent_admitted_ids.txt",
    ):
        if candidate.exists():
            lines = {ln.strip() for ln in candidate.read_text(encoding="utf-8").splitlines() if ln.strip()}
            if lines:
                return lines
    return None


_ADMIT_LIST = load_admission_list()


def admit(c) -> bool:
    """Admitted if the author list names this case, or (no list) if the user tool
    is retrieval-style and every attacker tool maps to a travel read/write."""
    if _ADMIT_LIST is not None:
        return c["_id"] in _ADMIT_LIST
    if not user_is_retrieval(c["User Tool"]):
        return False
    return all(classify_attacker(t) in ("read", "write") for t in c["Attacker Tools"])


def tokens(text: str) -> int:
    return len(re.findall(r"\S+", text))


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return None
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def frac(pred, group):
    return round(100 * sum(1 for c in group if pred(c)) / len(group), 1) if group else None


def main() -> None:
    cases = load_cases()
    admitted = [c for c in cases if admit(c)]
    excluded = [c for c in cases if not admit(c)]

    def profile(group):
        return {
            "n": len(group),
            "direct_harm_pct": frac(lambda c: c["_intention"] == "direct_harm", group),
            "data_stealing_pct": frac(lambda c: c["_intention"] == "data_stealing", group),
            "two_attacker_steps_pct": frac(lambda c: len(c["Attacker Tools"]) >= 2, group),
            "user_tools": len({c["User Tool"] for c in group}),
            "attacker_tools": len({t for c in group for t in c["Attacker Tools"]}),
            "instruction_len_median_tokens": median([tokens(c["Attacker Instruction"]) for c in group]),
        }

    full, sub = profile(cases), profile(admitted)

    # chi-square goodness of fit for intention mix; Mann-Whitney U for length.
    from scipy.stats import chisquare, mannwhitneyu
    dh_full = sum(1 for c in cases if c["_intention"] == "direct_harm")
    dh_sub = sum(1 for c in admitted if c["_intention"] == "direct_harm")
    exp_dh = len(admitted) * dh_full / len(cases)
    chi = chisquare([dh_sub, len(admitted) - dh_sub], [exp_dh, len(admitted) - exp_dh])
    len_full = [tokens(c["Attacker Instruction"]) for c in cases]
    len_sub = [tokens(c["Attacker Instruction"]) for c in admitted]
    u = mannwhitneyu(len_sub, len_full, alternative="two-sided")

    (PROJECT_ROOT / "datasets" / "injecagent_admitted_cases.txt").write_text(
        "\n".join(c["_id"] for c in admitted), encoding="utf-8")

    if len(admitted) != 200:
        print(f"  NOTE: admitted {len(admitted)} cases; the paper's 200 needs an author "
              f"admission list at datasets/attack_corpus_spec/injecagent_admitted_ids.txt")

    payload = {
        "experiment": "injecagent_subset",
        "paper_section": "5.7 / Table injecsubset",
        "admission_source": "author_list" if _ADMIT_LIST is not None else "mechanical_predicate",
        "manifest": run_manifest(benchmark="InjecAgent", commit="f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
                                 admission_rule="user tool retrieval-style and all attacker tools "
                                                "classifiable as travel read/write"),
        "full_benchmark": full,
        "admitted_subset": sub,
        "excluded": profile(excluded),
        "tests": {
            "intention_mix_chi2": {"chi2": round(float(chi.statistic), 3), "p": round(float(chi.pvalue), 4)},
            "instruction_length_mannwhitney": {"U": float(u.statistic), "p": round(float(u.pvalue), 4)},
        },
        "note": ("Attacker tools classified read/write by name; admission is user-tool retrieval-style "
                 "and all attacker tools classifiable. Difficulty proxy (native undefended ASR admitted "
                 "vs excluded) needs the Llama arm; see run_paper_injecagent.py --difficulty-proxy."),
    }
    emit("injecagent_subset", payload)
    print(json.dumps({"full": full, "admitted": sub, "tests": payload["tests"]}, indent=1))


if __name__ == "__main__":
    main()
