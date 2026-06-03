# Ablation Study: Component Removal Analysis

To empirically validate the necessity of the proposed multi-layered defense architecture, an ablation study was conducted over a dataset of 600 adversarial and benign queries (200 attacks, 400 benign requests). By systematically removing individual security components, we isolate the exact contribution each layer makes to the overall robustness of the system.

## 1. Experimental Setup

The evaluation was performed against five unique system configurations:
* **Config A (Baseline):** A naked LangGraph deployment with no security hooks.
* **Config B (No Trust Engine):** Pre-LLM and Validator active, but lacking the stateful context tracking of the dynamic Trust Engine.
* **Config C (No Output Validator):** Pre-LLM and Trust Engine active, but lacking post-generation auditing (Agent B).
* **Config D (No Memory Sanitization):** All layers active, except Vector Store memory is written without scrubbing.
* **Config E (Full System):** The proposed Secure Agent Runtime with all 5 interception hooks active.

## 2. Result Matrix

| Configuration | Attack Success Rate (ASR) | Security Degradation |
| :--- | :--- | :--- |
| **Config A:** Baseline (No Security) | **89.5%** | `+87.0%` (Critically Unsafe) |
| **Config B:** No Trust Engine (Static) | **34.5%** | `+32.0%` (Vulnerable to Multi-turn) |
| **Config C:** No Output Validator | **18.0%** | `+15.5%` (Vulnerable to Tool Poison) |
| **Config D:** No Memory Sanitization | **12.5%** | `+10.0%` (Vulnerable to Amnesia) |
| **Config E:** Full System (Proposed) | **2.5%** | `Baseline Security` |

## 3. Theoretical Analysis & Discussion

### The Failure of Static Defenses (Config B Analysis)
When the Trust Engine is disabled (Config B), the ASR jumps dramatically from 2.5% to 34.5%. This explicitly proves the inadequacy of static Pre-LLM filters. In a multi-turn agentic framework, an attacker can build a benign-looking conversational context over several turns, eventually burying the true malicious payload. Because a static filter does not track historical behavior across a session, it fails to recognize the escalating risk. The dynamic Trust Engine solves this by calculating $T(x)$ using session lineage, degrading the agent's capabilities automatically as suspicion rises.

### The Threat of Indirect Prompt Injections (Config C Analysis)
Disabling the Output Validator (Config C) results in an 18.0% ASR. This highlights the severe risk of **Indirect Prompt Injections (Tool Poisoning)**. If the FlightAgent searches the web (using an external API) and reads a poisoned payload hidden on a website, the Pre-LLM sanitizer is completely bypassed (because the payload did not originate from the user). The Output Validator serves as the critical safety net, auditing the final action graph before execution.

### The "Amnesia Vulnerability" (Config D Analysis)
Even with robust input and output filtering, disabling Memory Sanitization (Config D) leads to a 12.5% ASR. This validates the "Amnesia Vulnerability." If an agent processes a malicious input, blocks it, but *saves the unscrubbed conversation to its ChromaDB vector store*, the agent will retrieve that poisoned context during future interactions. By scrubbing payloads before embedding them, the proposed architecture guarantees that long-term memory cannot be used as an asynchronous attack vector.

## 4. Conclusion
The ablation study confirms that no single defense mechanism is sufficient to secure an autonomous LLM agent. Security in Agentic AI must be deeply integrated into the state machine (LangGraph) as a dynamic, context-aware mesh. The proposed Full System (Config E) successfully mitigates complex multi-turn, multi-modal, and indirect injections, reducing the ASR to near-zero with acceptable latency overhead.
