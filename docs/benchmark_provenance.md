# Benchmark Provenance

## Overview

The SECURED evaluation benchmark is a controlled, manually inspectable dataset
for assessing prompt-injection resilience in a multi-agent travel booking system.

## Attack Dataset (`datasets/attacks.json`)

| Family | Count | Description |
|--------|-------|-------------|
| Prompt Injection | 20 | Direct system-prompt override and policy bypass attempts |
| Indirect Injection | 20 | Instructions embedded in tool outputs, RAG chunks, or context |
| Tool Misuse | 20 | Attempts to enumerate, invoke, or abuse internal tools |
| Memory Poisoning | 20 | Adversarial content injected into persistent memory / RAG |
| Role Override | 20 | Jailbreak and DAN-style persona substitution attacks |

**Total: 100 attacks**

### Removed Families

The following families were removed as too synthetic or difficult to justify
methodologically:

- Encoding Attacks (base64, rot13, unicode obfuscation)
- Recursive Reasoning Attacks (multi-step reasoning jailbreaks)
- Long-Context Attacks (needle-in-haystack ultra-long prompts)
- Multilingual Attacks (exotic language bypass attempts)

The full 450-attack version is preserved at
`archived_results/datasets/attacks_full_450.json`.

### Construction Method

Attacks were selected by stratified sampling from the archived full dataset:
up to 20 examples per family, preserving difficulty and target-node diversity.
Each entry includes `id`, `type`, `family`, `prompt`, `description`,
`expected_violation`, `target_node`, `category`, and `risk_level`.

## Benign Dataset (`datasets/benign_requests.json`)

**Total: 100 benign travel booking requests**

Covers flight search, hotel reservation, multi-leg itineraries, and general
greeting queries. Used for false-positive rate (FPR) measurement.

## Manual Validation Subset (`datasets/manual_validation_subset.json`)

**Total: 27 human-reviewed cases**

Curated mock-output pairs (compromised vs. defended) covering all violation
categories. Used to validate the deterministic judge (`scripts/judge.py`) before
full benchmark runs. See `scripts/evaluate_policy_validation.py`.

## Evasion Dataset (`datasets/evasion_attacks.json`)

**Total: 25 evasion variants**

Subset of realistic evasion techniques (synonym substitution, roleplay
rephrasing, indirect injection rewording). Encoding and exotic multilingual
variants were removed.

## Evaluation Flow

```
Attack Prompt → Runtime System → Sanitizers → Output → Neutral Judge → Metrics
```

The judge (`scripts/judge.py`) uses deterministic regex-based policy violation
detection and refusal/sanitization markers. It has no knowledge of attack IDs,
config labels, or desired outcomes.
