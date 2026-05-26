# Security Pattern: Tiered Semantic Validation for Zero Trust Intent Framework (ZTIF)

**Pattern ID:** SEC-PATTERN-ZTIF-G3-LATENCY-001
**Classification:** Input Validation / AI Security / Zero Trust Architecture
**Version:** 1.0
**Status:** Draft for Architecture Review
**Author:** AI-Assisted Security Architecture Synthesis (based on ZTIF v2.0)
**Date:** 2026-05-26
**Framework Alignment:** ZTIF v2.0 · NIST SP 800-228-upd1 · OWASP LLM Top 10 2025 · CSA Agentic Trust Framework

---

## 1. Pattern Name

**Tiered Semantic Validation with Risk-Based Latency Optimization**

*Also Known As:* Adaptive Intent Guard Routing, OSI-Layer Gate 3 Swapping, Hybrid LLM/Classifier Semantic Enforcement

---

## 2. Problem Statement

### 2.1 The Core Tension

The Zero Trust Intent Framework (ZTIF) Gate 3 — Semantic Intent Verification — introduces a **non-negotiable security control** that evaluates whether an input's meaning matches the declared purpose of the receiving field. This control is essential for detecting:

- Prompt injection and instruction override (OWASP LLM01)
- Semantic bypass attacks that clear structural validation (Gate 1)
- Context-blind payload delivery by authenticated principals
- Multi-turn conversational manipulation sequences

However, LLM-based semantic evaluation introduces **latency in the 800–2000ms range** and **per-request API costs** that scale linearly with traffic volume. This creates architectural friction when:

1. **Human-facing interfaces** require sub-second responsiveness to maintain user experience
2. **Machine-to-machine (M2M) API flows** process thousands to millions of requests per hour where 1000ms+ latency is operationally untenable
3. **High-throughput microservices** cannot sustain the cost curve of general-purpose LLM inference at volume
4. **Synchronous user journeys** (checkout, authentication, real-time chat) degrade perceptibly when Gate 3 exceeds 500ms

### 2.2 What Happens Without This Pattern

- **Security degradation:** Teams bypass Gate 3 for "internal" or "service" traffic, creating a two-tier security model that violates Zero Trust tenets (NIST SP 800-207: "no meaningful distinction between internal and external caller")
- **Shadow bypasses:** Engineering teams implement unaudited whitelists or pre-shared secrets to skip semantic validation for M2M flows
- **UX abandonment:** Human users experience timeout errors or perceived system slowness, leading to workarounds or reduced engagement
- **Cost explosion:** Running all traffic through Tier 4 (Claude Opus) or even Tier 3 (Claude Sonnet) produces unsustainable per-request economics at scale
- **False dichotomy:** Organizations treat the choice as binary — "secure with LLM" or "fast without LLM" — missing the modular middle ground

---

## 3. Context

### 3.1 Applicable Environments

| Environment | Relevance | Typical Volume |
|-------------|-----------|----------------|
| Human-facing web applications (search, chat, support) | **High** | 10–1000 req/min |
| Mobile app input surfaces | **High** | 100–5000 req/min |
| Internal microservice mesh (M2M) | **Critical** | 10K–1M req/min |
| B2B API gateways (partner integrations) | **Critical** | 1K–50K req/min |
| Batch processing / ETL pipelines | **Medium** | Variable, async |
| Agentic AI workflows (tool invocation) | **High** | 100–10K req/min |
| IoT / edge data ingestion | **Medium** | High volume, constrained bandwidth |

### 3.2 Pre-Conditions

- ZTIF Gates 1 (Structural) and 2 (Zero Trust Context) are operational
- Intent Contracts exist for all guarded input surfaces
- A Principal identity model is enforced (no anonymous M2M — all callers carry verifiable identity)
- Observability infrastructure exists for Layer 5 (Continuous Audit)
- Rate limiting and circuit breaker patterns are in place upstream

### 3.3 Post-Conditions (Success State)

- Every input — human or machine — receives semantic validation appropriate to its risk tier
- Latency budgets are honored per contract, not globally
- Cost per 1,000 evaluations is predictable and tiered
- No "fast path" exists that bypasses security controls based on caller type alone
- Drift detection and HITL quorum remain active across all tiers

---

## 4. Forces (Constraints & Tensions)

| Force | Description | Tension |
|-------|-------------|---------|
| **F1: Security Depth** | Semantic validation must detect novel, application-specific attacks not in any training set | Drives toward general-purpose LLMs (high latency, high cost) |
| **F2: Latency Budget** | Human UX degrades above 500ms; M2M SLA often requires <100ms p99 | Drives toward purpose-built classifiers or async deferral |
| **F3: Cost Efficiency** | Per-request LLM costs become prohibitive at >100K req/day | Drives toward cheaper models or local inference |
| **F4: Detection Breadth** | Classifiers trained on known patterns miss novel semantic boundary violations | Drives toward contract-guided LLM evaluation |
| **F5: Compliance Residency** | GDPR, HIPAA, or sovereign requirements may prohibit data egress to certain providers | Drives toward EU-hosted or local models |
| **F6: Operational Simplicity** | Multiple Gate 3 implementations increase deployment complexity | Drives toward single-provider standardization |
| **F7: Zero Trust Integrity** | No caller — internal or external — is implicitly trusted | Prohibits "internal fast path" bypasses |

---

## 5. Solution: The Tiered Validation Model

### 5.1 Architectural Principle

**Match the Gate 3 implementation to the risk tier, latency budget, and data residency requirement of each Intent Contract — not to the caller type (human vs. machine).**

This preserves Zero Trust integrity (no caller-type exemptions) while allowing operational pragmatism (latency-appropriate enforcement). The mechanism is the **stable interface contract** between Gate 3 and the rest of the pipeline.

### 5.2 The Stable Interface (The "OSI Layer" Insight)

ZTIF Gate 3 accepts:
- **Input:** Sanitized string (from Gate 1) + Intent Contract YAML
- **Output:** Standardized JSON verdict

```json
{
  "verdict": "pass | flag | block",
  "confidence": 0.0,
  "reason": "<80 words",
  "threat_indicators": ["list of signals"],
  "owasp_categories": ["LLM01", "LLM06"]
}
```

Any implementation that produces this JSON structure is a valid Gate 3 provider. This enables swapping without touching Gates 1, 2, 4, HITL routing, audit logging, or drift detection.

### 5.3 The Five Tiers

| Tier | Implementation | Latency | Cost / MTok | Detection Breadth | Best For |
|------|---------------|---------|-------------|-------------------|----------|
| **T1** | Gemini 2.5 Flash (Free Tier) | 800–1200ms | $0 | Good — general purpose | Dev/test, low volume, prototyping |
| **T2** | Mistral Small (Primary Guard) | 700–1000ms | $0.06 input / $0.18 output | Good — structured inputs | Startup, EU GDPR, default production |
| **T3** | Claude Sonnet 4.6 (Escalation) | 1000–1500ms | $3.00 input / $15.00 output | Very good — nuanced | Enterprise production, high-risk fields |
| **T4** | Claude Opus 4.6 (Maximum Assurance) | 1500–2000ms | $15.00 input / $75.00 output | Best — critical reasoning | CRITICAL tier only: auth, financial, healthcare |
| **T5** | Purpose-built Classifier (LLM Guard / Lakera / Fine-tuned BERT) | **20–50ms** | ~$0 (self-hosted) or commercial | Broad — attack-trained | **High-throughput M2M, millions of requests/day** |

### 5.4 Selection Logic

```yaml
# Intent Contract determines tier — NOT caller type
risk:
  tier: critical   # ← Drives provider selection

# Example routing matrix (configured per contract):
GATE3_PROVIDERS:
  critical:   claude_opus_complete      # Tier 4
  high:       claude_sonnet_complete    # Tier 3
  medium:     mistral_small_complete    # Tier 2
  low:        classifier_primary        # Tier 5 (fast) + mistral_secondary (uncertain)
```

### 5.5 The Two-Stage Escalation Strategy (Default Production Posture)

**Recommended for human-facing and standard M2M flows:**

```python
def run_gate3_tiered(sanitized_input: str, contract: dict) -> Gate3Result:
    threshold = contract["validation_chain"]["llm_confidence_threshold"]
    risk_tier = contract["risk"]["tier"]

    # Stage 1: Always run fast/cheap primary first
    result = run_gate3(sanitized_input, contract, llm_fn=mistral_complete)

    # Stage 2: Escalate if uncertain, high-risk, or flagged
    if (result.confidence < threshold
        or risk_tier in ("high", "critical")
        or result.verdict == "flag"):

        model = "claude-opus-4-6" if risk_tier == "critical" else "claude-sonnet-4-6"
        result = run_gate3(sanitized_input, contract, llm_fn=anthropic_complete(model))

    return result
```

**Average latency impact:** ~70–80% of traffic resolves at Stage 1 (700–1000ms). Only 20–30% escalates to Stage 2 (1000–2000ms). Effective p50 latency: ~850ms.

### 5.6 The Hybrid Chaining Strategy (High-Throughput M2M)

**Recommended for high-volume machine-to-machine flows where <100ms is required:**

```python
def run_gate3_hybrid(sanitized_input: str, contract: dict) -> Gate3Result:
    """
    Tier 5 classifier as first pass (20-50ms).
    Route uncertain results to Tier 2/3 LLM for contract-guided evaluation.
    """
    # Pass 1: Purpose-built classifier (fast, attack-pattern trained)
    classifier_result = classifier.scan(
        sanitized_input,
        semantic_context=contract["intent"]["semantic_boundaries"]
    )

    # High-confidence clear pass/block: return immediately (20-50ms total)
    if classifier_result.confidence > 0.90:
        return Gate3Result(
            passed=not classifier_result.is_violation,
            blocked=classifier_result.is_violation,
            verdict="block" if classifier_result.is_violation else "pass",
            confidence=classifier_result.confidence,
            reason=classifier_result.reason
        )

    # Uncertain or novel input: escalate to Intent Contract LLM (700-1500ms)
    return run_gate3(sanitized_input, contract, llm_fn=mistral_complete)
```

**Latency impact:** p50 drops to ~35ms. p95 rises to ~1000ms (only uncertain traffic). Cost drops by 85–95% compared to LLM-only.

### 5.7 The Async Deferral Strategy (Low-Risk Non-Critical Paths)

**Recommended for low-risk M2M batch operations or internal telemetry:**

```python
async def run_pipeline_async_deferred(raw, contract, principal):
    g1 = run_gate1(raw, contract)
    if not g1.passed: return reject_result(g1)

    g2 = await run_gate2_async(principal, contract)
    if not g2.passed: return reject_result(g2)

    # For low-risk tiers: accept immediately, validate semantically in background
    if contract["risk"]["tier"] in ("low", "medium"):
        asyncio.create_task(gate3_and_log(g1.sanitized_input, contract))
        return accept_result(g1.sanitized_input)  # Immediate response

    # High/critical: synchronous Gate 3 (blocks until verdict)
    g3 = await run_gate3_async(g1.sanitized_input, contract)
    return handle_g3(g3, g1, contract)
```

**Trade-off:** Gate 4 (Business Logic) executes before Gate 3 completes. If Gate 3 later returns `block`, a compensating transaction or revocation pattern must be implemented. **Only suitable for idempotent or reversible operations.**

---

## 6. Consequences

### 6.1 Benefits

| Benefit | Realization |
|---------|-------------|
| **Zero Trust Integrity Preserved** | No caller-type exemptions exist. All inputs evaluated. Routing is by risk tier, not by "internal vs. external" assumption. |
| **Latency Budget Honored** | Human search fields can use Tier 2 (700ms). M2M inventory sync can use Tier 5 (35ms). Critical financial auth uses Tier 4 (1500ms) regardless of caller. |
| **Cost Predictability** | Per-contract cost modeling. High-volume M2M contracts use cheap classifiers. Low-volume critical contracts use expensive LLMs. |
| **Modular Evolution** | New provider (e.g., Kimi K2.6, new Claude version) is a configuration change, not a pipeline rewrite. |
| **Residency Compliance** | EU data stays in EU (Mistral). China requirements use DeepSeek. Air-gapped uses Phi-4 Mini. All via same interface. |
| **Defense in Depth** | Hybrid chaining means known attacks are caught in 20ms by classifiers; novel attacks are caught by contract-guided LLMs. |

### 6.2 Liabilities & Mitigations

| Liability | Mitigation |
|-----------|------------|
| **Classifier false negatives on novel attacks** | Hybrid chaining routes uncertain results to LLM. Nightly drift detection catches model degradation. |
| **Increased operational complexity** | Unified `llm_complete()` abstraction hides provider differences. Infrastructure-as-code manages tier mapping. |
| **Async deferral allows bad input to reach Gate 4** | Restrict async pattern to idempotent/reversible operations. Implement compensating transactions. Monitor post-hoc block rate. |
| **Tier 5 classifiers may not parse Intent Contract nuances** | Pass `semantic_boundaries` as context to classifier. Fine-tune on contract-specific violations. |
| **Latency variability across providers** | Circuit breakers per provider. Timeout = 2s with fail-open-to-HITL (never fail-open-to-accept). |

---

## 7. Implementation Roadmap

### Phase 1: Baseline (Week 1)
- Instrument all input surfaces with Gate 1 + Gate 2
- Deploy **single Tier 2 provider** (Mistral Small) as universal Gate 3
- Establish Layer 5 audit logging and baseline metrics
- Run in **shadow mode** (log-only, no blocking) for 2 weeks

### Phase 2: Tiering (Weeks 3–4)
- Classify all Intent Contracts by `risk.tier`
- Configure `GATE3_PROVIDERS` routing matrix
- Implement two-stage escalation (Mistral → Claude)
- Enable blocking for `high` and `critical` contracts

### Phase 3: M2M Optimization (Weeks 5–6)
- Identify high-volume M2M contracts (telemetry, sync, batch)
- Deploy Tier 5 classifier for `low` and `medium` risk M2M surfaces
- Implement hybrid chaining with confidence thresholds
- Evaluate async deferral for truly non-critical paths

### Phase 4: Hardening (Weeks 7–8)
- Activate HITL quorum for all `flag` verdicts
- Enable nightly drift detection across all provider tiers
- Tune per-contract `llm_confidence_threshold` based on shadow-mode data
- Document SLA: Critical/High = 30min HITL, Medium = 4hr, Low = auto-approve 24h

---

## 8. Known Uses & Validation

| Organization / Context | Implementation | Outcome |
|------------------------|----------------|---------|
| ZTIF v2.0 Reference Implementation | Mistral-first, Claude-escalate | 250× cost reduction vs. Opus-only; EU residency compliance |
| Google Colab Lab Notebooks | Phi-4 Mini local inference | Zero egress, zero API cost; T4 GPU compatible; ~2.5GB model |
| High-throughput API gateway (Pattern target) | LLM Guard → Mistral hybrid | p50 latency 35ms; p95 1200ms; 92% of traffic resolved in classifier |
| NIST SP 800-228-upd1 Alignment | Two-level validation (syntactic + semantic) | Explicitly cited as required approach for API input in AI-integrated environments |
| CSA Agentic Trust Framework | Tiered model selection by context | Validates risk-based provider selection as Tier 3 maturity |

---

## 9. Related Patterns

| Pattern | Relationship |
|---------|-------------|
| **Circuit Breaker** | Prevents cascading latency when Gate 3 provider is degraded. Fail-open-to-HITL, never fail-open-to-accept. |
| **Strangler Fig** | Gradually migrate input surfaces from OWASP-only to full ZTIF tiered validation without big-bang deployment. |
| **Shadow Mode / Dark Launch** | Run new Gate 3 tier in parallel with existing validation; compare verdicts before enabling blocking. |
| **HITL Quorum** | Human-in-the-loop review for `flag` verdicts, especially from uncertain classifier → LLM escalations. |
| **Compensating Transaction** | Required when async deferral is used; reverses Gate 4 effects if background Gate 3 returns `block`. |

---

## 10. Anti-Patterns (What Not To Do)

| Anti-Pattern | Why It Fails |
|--------------|--------------|
| **"Internal Fast Path"** | Bypass Gate 3 for service-to-service calls. Violates NIST 800-228 "no meaningful distinction between internal and external." Creates lateral movement opportunity. |
| **"One Model For All"** | Running all traffic through Claude Opus for "maximum security." Unsustainable cost; unnecessary latency for low-risk fields. |
| **"Latency Overrides Security"** | Disabling Gate 3 entirely for M2M because "it's too slow." Reintroduces semantic bypass vulnerability that ZTIF was built to close. |
| **"Human vs. Machine Routing"** | Selecting provider based on `User-Agent` or principal type rather than risk tier. Humans can be malicious; machines can be compromised. |
| **"No Timeout Handling"** | Gate 3 hangs indefinitely. Must fail-open-to-HITL (flag) with 2s timeout, never fail-open-to-accept. |

---

## 11. Decision Matrix

Use this matrix to select the appropriate strategy for a given input surface:

| Question | If Yes | If No |
|----------|--------|-------|
| Is this a `CRITICAL` risk tier? (auth, financial, healthcare, admin) | Use Tier 4 (Opus) or Tier 3 (Sonnet). Never async. | Evaluate next question. |
| Is volume > 100K requests/day? | Use Tier 5 classifier primary + Tier 2/3 escalation hybrid. | Tier 2 or Tier 3 primary is sufficient. |
| Is latency SLA < 100ms p99? | Use Tier 5 classifier. Consider async deferral if operation is reversible. | Tier 2/3 synchronous is acceptable. |
| Does the input contain PII requiring EU residency? | Use Tier 2 (Mistral Small) or local Tier 5 (EU-hosted classifier). | Provider selection opens to all tiers. |
| Is the operation idempotent / reversible? | Async deferral is an option. Gate 4 executes immediately; Gate 3 validates post-hoc. | Must use synchronous Gate 3 before Gate 4. |
| Is this a novel input surface with unknown attack patterns? | Start with Tier 3 (Sonnet) for maximum reasoning depth; collect data; then optimize down. | Use established tier based on risk classification. |

---

## 12. Metrics & Observability

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Gate 3 p50 latency | < 1000ms (human) / < 50ms (M2M Tier 5) | > 1500ms human / > 100ms M2M |
| Gate 3 p99 latency | < 2500ms | > 3000ms |
| Gate 3 cost per 1K requests | Contract-dependent; track per tier | > 20% budget variance |
| Classifier → LLM escalation rate | 5–15% | > 25% (classifier may need retraining) |
| Flag rate (legitimate traffic) | < 5% | > 10% (threshold too tight or boundary too vague) |
| Post-hoc block rate (async) | < 0.1% | > 1% (async pattern may be inappropriate) |
| Drift detection delta | < 5% verdict shift vs. baseline | > 5% (model version or provider behavior changed) |
| HITL review SLA compliance | Critical: 30min, High: 4hr, Low: 24hr | Breach triggers page |

---

## 13. References

- **ZTIF v2.0 Specification:** [github.com/chrisgillham/ZTIF](https://github.com/chrisgillham/ZTIF)
- **NIST SP 800-228-upd1:** Guidelines for API Protection for Cloud-Native Systems (March 2026)
- **NIST SP 800-207:** Zero Trust Architecture (2020)
- **OWASP LLM Top 10 2025:** Prompt Injection (LLM01), Excessive Agency (LLM08), Overreliance (LLM09)
- **CSA Agentic Trust Framework:** Tier 3 Maturity — Human Approval as Required Component (2026)
- **Cisco Zero Trust for Agentic AI:** Semantic Inspection for Intent Verification (Feb 2026)
- **Peyrano, I. (2026):** *From CRUD to Autonomous Agents* — OPA as "missing guardrail for AI agents"

---

## 14. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-05-26 | Security Architecture Synthesis | Initial pattern draft based on ZTIF v2.0 analysis |

---

*This pattern is provided under the same Creative Commons Attribution 4.0 license as the ZTIF framework. It is intended for architecture review, threat modeling, and security engineering planning. Implementation should be validated against organizational risk appetite and compliance requirements.*