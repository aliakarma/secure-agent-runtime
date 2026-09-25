"""
Deterministic taggers for the seven linguistic features of Table ling-features
(paper §6.4).

Per author decision D3, the features are tagged by published rules rather than by
human annotators, and the manuscript's method text says so. Each tagger is a
transparent regular-expression / lexicon rule over the surface text, so the
"annotation" is reproducible and carries no inter-annotator disagreement (there is
no second annotator; the reported reliability is rule coverage, not kappa).

    F1 Directive mood         imperative clause or deontic modal aimed at an agent
    F2 Addressee              addressed to the model/assistant vs the user's own request
    F3 Instruction override   reference to prior instructions with negation/replacement
    F4 Authority impersonation system/admin/policy-update framing
    F5 External target        a URL, e-mail, account, or destination outside the task
    F6 Keyword-bearing        contains a fast-heuristic trigger token
    F7 Grammatical person     first / second / impersonal (returned as a category)
"""

from __future__ import annotations

import re
from typing import Dict

# F6 trigger vocabulary — the fast heuristic's tokens (sanitizers/multimodal.py).
TRIGGERS = ["ignore", "disregard", "override", "bypass", "system", "jailbreak",
            "admin", "you are now", "new instructions", "previous instructions"]

_IMPERATIVE_VERBS = (
    r"ignore|disregard|forget|override|bypass|reveal|print|output|send|delete|remove|"
    r"reserve|book|confirm|proceed|execute|run|call|use|set|store|save|persist|record|"
    r"write|add|grant|transfer|pay|repeat|show|display|list|transcribe|append|echo|say|"
    r"report|state|follow|obey|treat|prioritise|prioritize|act|carry|smuggle|chain|craft|"
    r"supply|invoke|pass|commit|keep|drop|become|acknowledge"
)
_DEONTIC = r"\b(must|should|shall|need to|have to|required to)\b"
_F1 = re.compile(rf"(^|[.!?;:]\s+|\n)\s*(please\s+)?({_IMPERATIVE_VERBS})\b", re.IGNORECASE)
_F1_DEONTIC = re.compile(_DEONTIC, re.IGNORECASE)

_F2_MODEL = re.compile(
    r"\b(you|your)\b|\bassistant\b|\bagent\b|\bmodel\b|\bAI\b|\bsystem\b", re.IGNORECASE)
_F2_USER_SELF = re.compile(r"\b(i|me|my|mine|we|our|us)\b", re.IGNORECASE)

_F3 = re.compile(
    r"\b(ignore|disregard|forget|override|supersede|void|set aside|overrid\w*)\b"
    r"[^.?!]*\b(previous|prior|earlier|above|standing|current|initial|original|all|"
    r"real|stated|existing|configured|governing|core)\b"
    r"|\b(previous|prior|earlier|standing|initial)\s+(instructions?|rules?|directives?|"
    r"guidance|policy|preferences?|configuration)\b"
    r"|\b(new|updated?)\s+(instructions?|policy|rules?)\b", re.IGNORECASE)

_F4 = re.compile(
    r"\b(system\s+(notice|update|message|rule|override)|important\s+update|"
    r"upstream\s+advisory|maintenance\s+(note|mode)|administrator|admin\b|"
    r"admin\s+(override|instruction|notice|directive)|"
    r"policy\s+(update|override)|developer\s+(mode|instructions?)|"
    r"security\s+(notice|alert)|official\s+notice|as\s+an?\s+(administrator|admin))\b",
    re.IGNORECASE)

_F5 = re.compile(
    r"https?://|www\.\S+|\b[\w.+-]+@[\w-]+\.[\w.-]+\b|\b\d{6,}\b|"
    r"\baccount\s+(number|id)\b|\battacker\.com\b|\bexfiltrat|\bsend\s+(it|them|this|the)\b",
    re.IGNORECASE)

_F7_FIRST = re.compile(r"\b(i|me|my|mine|we|our|us)\b", re.IGNORECASE)
_F7_SECOND = re.compile(r"\b(you|your|yours)\b", re.IGNORECASE)


def f1_directive_mood(text: str) -> bool:
    return bool(_F1.search(text) or _F1_DEONTIC.search(text))


def f2_addressee_is_model(text: str) -> bool:
    """True when the directive addresses the model rather than being the user's
    own first-person request. Heuristic: second-person / assistant reference
    present and not dominated by first-person self-reference."""
    model = len(_F2_MODEL.findall(text))
    self_ref = len(_F2_USER_SELF.findall(text))
    return model > 0 and model >= self_ref


def f3_instruction_override(text: str) -> bool:
    return bool(_F3.search(text))


def f4_authority_impersonation(text: str) -> bool:
    return bool(_F4.search(text))


def f5_external_target(text: str) -> bool:
    return bool(_F5.search(text))


def f6_keyword_bearing(text: str) -> bool:
    low = text.lower()
    return any(t in low for t in TRIGGERS)


def f7_person(text: str) -> str:
    first, second = bool(_F7_FIRST.search(text)), bool(_F7_SECOND.search(text))
    if second and not first:
        return "second"
    if first and not second:
        return "first"
    if first and second:
        return "mixed"
    return "impersonal"


def tag(text: str) -> Dict[str, object]:
    p = f7_person(text)
    return {
        "F1_directive_mood": f1_directive_mood(text),
        "F2_addressee_model": f2_addressee_is_model(text),
        "F3_instruction_override": f3_instruction_override(text),
        "F4_authority_impersonation": f4_authority_impersonation(text),
        "F5_external_target": f5_external_target(text),
        "F6_keyword_bearing": f6_keyword_bearing(text),
        "F7_person": p,
        "F7_grammatical_person": p == "second",
    }
