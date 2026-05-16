---

# Zero Trust Intent Framework (ZTIF) • Lab 3

### Zero Trust Input Validation with AI-Augmented Semantic Analysis

This lab operationalizes the Zero Trust Intent Framework (`ZTIF-IC-001`), moving beyond traditional syntactic validation to enforce continuous semantic verification at the application layer.

---

## Meta Profiles

* **Course:** Agentic AI Security
* **Lab Number:** 3 of 3
* **Total Points:** 100 points (20% of course grade)
* **Format:** 3-week individual lab with peer review gate
* **Deliverable:** GitHub Pull Request + Google Colab notebook + written analysis
* **Prerequisites:** Lab 1 (Prompt Security), Lab 2 (HITL Framework setup)

---

## Learning Objectives

By the end of this lab, you will be able to:

* Articulate why structural OWASP validation alone is insufficient in Zero Trust and AI-integrated architectures.
* Author a formal Zero Trust Intent Contract in YAML that defines the semantic boundaries of an input surface.
* Build and deploy a 4-gate input validation pipeline integrating OWASP controls, ZT policy enforcement, and LLM semantic analysis.
* Integrate the LLM guard verdict with a Discord HITL (Human-in-the-Loop) notification channel.
* Evaluate validation pipeline coverage against OWASP LLM Top 10 and MITRE ATLAS threat categories.
* Write defensible test cases (pass, flag, block) that serve as executable security controls.

---

## Background & Motivation

Traditional input validation secures the syntactic layer — does this string match an expected pattern? Zero Trust architecture demands more: every request must be verified continuously, not assumed legitimate.

With LLM components now embedded in application pipelines, a new attack surface has emerged: semantic bypass attacks that pass all structural checks but violate intent. This lab operationalizes the Zero Trust Intent Framework (`ZTIF-IC-001`), which adds two validation layers on top of OWASP controls:

The Intent Contract is the governing document for Layer 3. It formally declares what an input surface is for, who is allowed to use it, and what the LLM should flag as out-of-scope. Writing a well-formed contract is the core skill this lab develops.

> [!IMPORTANT]
> **KEY INSIGHT:** A well-formed payload that violates semantic intent — e.g., sending *"ignore previous instructions"* to a product search field — is invisible to regex and schema validators. The LLM guard operates at the meaning layer where traditional validators cannot reach.

---

## Execution Logs & Matrix Layouts

### Pipeline Gate Architecture

| Gate Name | What It Checks | On Failure | Status |
| --- | --- | --- | --- |
| **Gate 1: Structural Validation** | OWASP schema, type, length, encoding checks | `reject_400` | ✓ |
| **Gate 2: ZT Context Validation** | Principal identity, device posture, rate limits via PDP | `reject_403` + anomaly log | ✓ |
| **Gate 3: LLM Semantic Validation** | Claude evaluates intent against the Contract | `flag` → HITL | `block` → `reject_422` | ✓ |
| **Gate 4: Business Logic Validation** | Domain-specific rules enforcement | `reject_422` | ✓ |

### Telemetry Execution Stream

```text
▶ Run 1/4: Initializing ZTIF-IC-001 Pipeline...
[███████████████] 100% Core engine active.
[✅] Gate 1: Structural syntax match confirmed.
[✅] Gate 2: Context policy evaluation cleared.
[❌] Gate 3: Semantic evaluation failed -> Intent violation detected in payload.
[▶] HITL Alert dispatched to Discord channel. Status: PENDING_REVIEW

```

---

## Resources & References

### Required Reading

* **OWASP Input Validation Cheat Sheet** — [owasp.org/cheat-sheets](https://www.google.com/search?q=https://owasp.org/cheat-sheets)
* **NIST SP 800-207: Zero Trust Architecture** — [nvlpubs.nist.gov](https://nvlpubs.nist.gov)
* **OWASP LLM Top 10 2025** — [owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org/www-project-top-10-for-large-language-model-applications)
* **MITRE ATLAS: Adversarial ML Threat Matrix** — [atlas.mitre.org](https://atlas.mitre.org)
* **ZTIF-IC-001 Schema Reference** — [github.com/ztif/ztif-intent-contracts](https://www.google.com/search?q=https://github.com/ztif/ztif-intent-contracts)

### Document Metadata

* **Framework:** Zero Trust Intent Framework (`ZTIF-IC-001`)
* **Author:** Chris Gillham
