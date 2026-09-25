"""Recompute every derived statistic in the manuscript from its reported counts.

Covers the paired statistics of Table `tab:effects` (Newcombe interval, Cohen's h,
exact McNemar p, exact power, n80), the Wilson intervals of Tables `tab:attrib`,
`tab:primary`, and `tab:multiturn`, the Fisher and minimum-McNemar tests of
Table `tab:sensitivity`, the session-level compounding of Section `sec:tiers`,
and the trust-score arithmetic of Section `sec:trust`.

Edit COUNTS below when measured values replace the manuscript's [U]/[TBM]
entries, rerun, and copy the output into the tables:

    python scripts/derived_stats.py
"""
from math import asin, sqrt

import numpy as np
from scipy.stats import binom, fisher_exact, norm

Z = norm.ppf(0.975)
NMAX = 3000  # largest corpus size searched for n80

# (label, weaker-configuration count, stronger-configuration count, n)
COUNTS = [
    ("Detector: heuristic vs DistilBERT (G)", 11, 2, 100),
    ("Placement: perimeter vs five-point, trust off (L)", 15, 7, 100),
    ("Stateful: five-point trust off vs full (L)", 7, 3, 100),
    ("Undefended vs input side (L)", 27, 9, 100),
    ("Input side vs full (L)", 9, 3, 100),
    ("Undefended vs boundary marking only (G)", 14, 12, 100),
    ("Heuristic pipeline: BM off vs on (G)", 13, 11, 100),
    ("Full runtime: BM off vs on (G)", 3, 2, 100),
    ("Undefended vs heuristic pipeline, BM off (G)", 14, 13, 100),
    ("- structural unrolling (FPR, L)", 6, 2, 96),
    ("- content-hash deduplication (FPR, L)", 4, 2, 96),
    ("- memory-hook adaptation (FPR, L)", 10, 2, 96),
    ("- output rules (ASR, L)", 8, 3, 100),
    ("- trust engine (ASR, L)", 7, 3, 100),
]
LOO = ["- structural unrolling (FPR, L)", "- content-hash deduplication (FPR, L)",
       "- memory-hook adaptation (FPR, L)", "- output rules (ASR, L)", "- trust engine (ASR, L)"]


def wilson(x, n):
    p = x / n
    denom = 1 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / denom
    half = Z * sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def newcombe_paired(a, b, c, d):
    """Newcombe (1998) method 10, difference of paired proportions (weaker - stronger)."""
    n = a + b + c + d
    p1, p2 = (a + b) / n, (a + c) / n
    l1, u1 = wilson(a + b, n)
    l2, u2 = wilson(a + c, n)
    e, f, g, h = a + b, c + d, a + c, b + d
    phi = 0.0 if min(e, f, g, h) == 0 else (a * d - b * c) / sqrt(e * f * g * h)
    lo = sqrt(max(0.0, (p1 - l1) ** 2 - 2 * phi * (p1 - l1) * (u2 - p2) + (u2 - p2) ** 2))
    hi = sqrt(max(0.0, (u1 - p1) ** 2 - 2 * phi * (u1 - p1) * (p2 - l2) + (p2 - l2) ** 2))
    return p1 - p2, p1 - p2 - lo, p1 - p2 + hi


def mcnemar_exact(b, c):
    m = b + c
    return 1.0 if m == 0 else min(1.0, 2 * binom.cdf(min(b, c), m, 0.5))


_KCRIT = np.full(NMAX + 1, -1)
for _m in range(1, NMAX + 1):
    _ok = np.nonzero(2 * binom.cdf(np.arange(_m + 1), _m, 0.5) <= 0.05)[0]
    _KCRIT[_m] = _ok[-1] if _ok.size else -1


def power_curve(pib, pic):
    """Exact McNemar power (manuscript Equation eq:power) for n = 0..NMAX."""
    pd = pib + pic
    theta = pib / pd
    rej = np.zeros(NMAX + 1)
    for m in range(1, NMAX + 1):
        k = _KCRIT[m]
        if k >= 0:
            rej[m] = min(1.0, binom.cdf(k, m, theta) + binom.sf(m - k - 1, m, theta))
    ms = np.arange(NMAX + 1)
    return np.array([0.0] + [float(np.dot(binom.pmf(ms[: n + 1], n, pd), rej[: n + 1]))
                             for n in range(1, NMAX + 1)])


def n80(curve):
    bad = np.nonzero(curve[5:] < 0.80)[0]
    first = (bad[-1] + 5 + 1) if bad.size else 5
    return first if first <= NMAX else None


def holm(pvals):
    order = sorted(range(len(pvals)), key=lambda i: pvals[i])
    adj, run = [0.0] * len(pvals), 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (len(pvals) - rank) * pvals[i]))
        adj[i] = run
    return adj


def main():
    print("== Paired statistics (Table tab:effects) ==")
    loo_p = {}
    for label, weak, strong, n in COUNTS:
        b, c, a = weak - strong, 0, strong
        d = n - a - b - c
        diff, lo, hi = newcombe_paired(a, b, c, d)
        h = abs(2 * asin(sqrt(weak / n)) - 2 * asin(sqrt(strong / n)))
        p = mcnemar_exact(b, c)
        curve0 = power_curve(b / n, 0.0)
        curve1 = power_curve(b / n + 0.01, 0.01)
        if label in LOO:
            loo_p[label] = p
        print(f"{label:52s} {weak}/{strong}  d={100 * diff:.1f} [{100 * lo:.1f}, {100 * hi:.1f}]"
              f"  h={h:.2f}  p={p:.3g}  power={curve0[n]:.2f}  n80={n80(curve0)}/{n80(curve1)}")
    adj = holm(list(loo_p.values()))
    print("Holm-adjusted leave-one-out p:", {k: round(v, 3) for k, v in zip(loo_p, adj)})

    print("\n== Trust-weight sensitivity (Table tab:sensitivity), FPR vs equal weighting 1/96 ==")
    for name, k in [("Policy-heavy", 6), ("History-heavy", 3), ("Source-heavy", 2), ("Retrieval-heavy", 4)]:
        d = k - 1
        print(f"{name:16s} Fisher p={fisher_exact([[1, 95], [k, 96 - k]])[1]:.3f}"
              f"  min McNemar p={min(1.0, 2 * 0.5 ** d):.3f}")

    print("\n== Session-level compounding (Section sec:tiers) ==")
    for f in (0.01, 0.021):
        p0, p1 = (1 - f) ** 20, 20 * f * (1 - f) ** 19
        print(f"f={f}: P(lose writes in 20 turns)={1 - p0:.3f}  P(two registrations)={1 - p0 - p1:.3f}")

    print("\n== Trust arithmetic (Section sec:trust; T rounded to 4 decimals) ==")
    for name, (s, pp, hh, r) in {
        "clean user turn, H=1": (0.5, 1, 1.0, 1), "poisoned tool, first registration": (0.3, 0, 0.3, 1),
        "clean user turn, H=0.3": (0.5, 1, 0.3, 1), "poisoned tool, second registration": (0.3, 0, 0.09, 1),
        "flagged user turn, second registration": (0.5, 0, 0.09, 1), "flagged user turn, first": (0.5, 0, 0.3, 1),
        "retrieved fragment, r=0.79": (0.4, 1, 1.0, 0.79)}.items():
        t = round(0.25 * (s + pp + hh + r), 4)
        print(f"{name:40s} T={t:.4f} {'HIGH' if t >= 0.8 else 'MEDIUM' if t >= 0.4 else 'LOW'}")


if __name__ == "__main__":
    main()
