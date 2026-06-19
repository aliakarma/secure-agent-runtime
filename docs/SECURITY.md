# Security Hardening & Threat Model

This document records the security posture of the Secure Agent Runtime and the
hardening applied across the application, the agent pipeline, and the dashboard.
It is intended for reviewers and for the thesis "implementation security"
discussion.

## Threat model

The runtime defends an autonomous multi-agent LLM system against:

1. **Direct prompt injection** in user input.
2. **Indirect / multimodal injection** hidden in uploaded images, PDFs, audio,
   video (OCR text, transcripts, EXIF/PDF metadata, embedded JavaScript).
3. **Tool / RAG poisoning** — compromised tool outputs or memory chunks.
4. **Confused-deputy** escalation across the Supervisor↔Worker boundary.
5. **Application-level attacks** on the API surface itself (LFI, unauthenticated
   access, resource exhaustion, cross-session data leakage, secret exposure).

## Application-layer controls

| Control | Implementation |
|---------|----------------|
| Authentication | `config.py` + `require_auth` dependency; `Authorization: Bearer` / `X-API-Token`, constant-time compare (`hmac.compare_digest`). Mandatory in production (startup fails if `API_TOKEN` unset). |
| CORS | `CORSMiddleware` with an explicit `ALLOWED_ORIGINS` allow-list; same-origin only by default. |
| Body-size limit | `BodySizeLimitMiddleware` rejects oversized requests (413); uploads are streamed with a running byte cap. |
| Upload validation | Suffix allow-list (415 on mismatch); files written to a sandboxed `uploads/` dir, never the research corpus. |
| Path-traversal / LFI | `_resolve_safe_path` resolves `realpath` and requires containment within allowed dirs; arbitrary `file_path` is rejected (and disabled entirely in production). |
| Cross-session leakage | Telemetry is session-scopable (`get_events(session_id=…)`); trust/provenance keyed and bounded per session. |
| Secret exposure | `.dockerignore` excludes `.env`, model weights, datasets, and result trees from images; `.env` is git-ignored. Rotate any key that ever sat in a shared tree. |
| Resource bounds | Trust engine, provenance ledger, and event buffer are thread-safe with LRU/ring-buffer eviction — no unbounded growth. |

## Pipeline-layer controls

- **No classifier bypass.** Multimodal structural markers are *stripped* and the
  content is always classified — a fake `[image ocr]` tag can no longer skip
  detection. Raw user text and raw extracted content are classified separately
  at the ingestion boundary (clean, no OOD markers); the assembled enriched
  prompt is re-checked with the deterministic regex layer only, gated by the
  unforgeable, server-set `input_pre_scanned` flag.
- **Unconditional regex barrier.** The Pre-LLM sanitizer strips unsafe spans at
  HIGH trust too, so a classifier miss no longer reaches the LLM untouched.
- **Fail-closed mode.** `STRICT_SECURITY=1` makes classifier/extractor failures
  block rather than silently degrade to keyword heuristics.
- **De-circularized benchmark.** Tools no longer emit injection payloads keyed to
  benchmark tokens (e.g. "hackville"). Indirect-injection simulation is opt-in
  (`SIMULATE_TOOL_POISONING=1`) using a generic, held-out payload pool, so the
  secured/baseline gap measures behaviour, not vocabulary overlap.

## Residual risks (documented, not yet closed in code)

- In-process state is bounded but not shared across workers — use Redis for
  horizontal scale.
- Robustness claims require the strengthened, multi-seed, adaptive-adversary
  evaluation (see README → *Strengthened evaluation protocol*). The detector's
  recall on heavy paraphrase/encoding is bounded by its training distribution.
