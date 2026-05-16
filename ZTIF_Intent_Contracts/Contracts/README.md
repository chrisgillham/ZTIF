# ZTIF Intent Contract Examples
## Common Website Input Fields

**Framework:** Zero Trust Intent Framework (ZTIF) v2.0  
**Schema:** ZTIF-IC-001 v2.0  
**Author:** Chris Gillham  
**Repository:** [github.com/chrisgillham/ZTIF](https://github.com/chrisgillham/ZTIF)  
**License:** CC BY 4.0

---

This directory contains ready-to-use Intent Contract examples for the most common
website and web application input fields. Each contract follows the full
[ZTIF-IC-001 schema](../docs/schema-reference.html) and includes:

- Threat Story Method fields (`declared_purpose`, `threat_scenario`, `semantic_boundaries`)
- Gate 1 structural validation rules (`gate1_rules`, `blocked_patterns`)
- Gate 3 LLM guard configuration (`risk_tier`, `llm_confidence_threshold`)
- Gate 2 access control (`allowed_principals`, `aal_required`, `rate_limit_rpm`)
- HITL quorum settings (`hitl_on_flag`, `hitl_sla_minutes`)
- OWASP LLM Top 10 compliance mappings (`compliance_mappings`)
- Labeled test cases for drift detection probe sets (`test_cases`)

---

## Naming Convention

All contracts follow the format:

```
ZTIF-IC-{DOMAIN}-{FIELD}-{SEQ}.yaml
```

| Segment | Description | Examples |
|---|---|---|
| `ZTIF-IC` | Fixed prefix — Zero Trust Intent Framework Intent Contract | — |
| `{DOMAIN}` | Functional domain of the endpoint | `CONTACT`, `AUTH`, `CHAT`, `PAYMENT` |
| `{FIELD}` | Logical field name being governed | `MESSAGE`, `USERNAME`, `TICKET` |
| `{SEQ}` | Three-digit sequence for versioning within domain+field | `001`, `002` |

---

## Contract Index

| Contract ID | File | Field | Endpoint | Risk Tier | Primary Threat |
|---|---|---|---|---|---|
| ZTIF-IC-CONTACT-MESSAGE-001 | [ZTIF-IC-CONTACT-MESSAGE-001.yaml](ZTIF-IC-CONTACT-MESSAGE-001.yaml) | `message` | `/api/v1/contact` | LOW | Staff phishing via contact form |
| ZTIF-IC-SEARCH-QUERY-001 | [ZTIF-IC-SEARCH-QUERY-001.yaml](ZTIF-IC-SEARCH-QUERY-001.yaml) | `q` | `/api/v1/search` | LOW | SQLi, AI ranking injection |
| ZTIF-IC-AUTH-USERNAME-001 | [ZTIF-IC-AUTH-USERNAME-001.yaml](ZTIF-IC-AUTH-USERNAME-001.yaml) | `username` | `/api/v1/auth/register` | MEDIUM | Impersonation, homoglyph spoofing |
| ZTIF-IC-PROFILE-BIO-001 | [ZTIF-IC-PROFILE-BIO-001.yaml](ZTIF-IC-PROFILE-BIO-001.yaml) | `bio` | `/api/v1/profile/update` | MEDIUM | Indirect prompt injection, phishing |
| ZTIF-IC-CONTENT-REVIEW-001 | [ZTIF-IC-CONTENT-REVIEW-001.yaml](ZTIF-IC-CONTENT-REVIEW-001.yaml) | `review_body` | `/api/v1/reviews/submit` | MEDIUM | Astroturfing, moderation injection |
| ZTIF-IC-SUPPORT-TICKET-001 | [ZTIF-IC-SUPPORT-TICKET-001.yaml](ZTIF-IC-SUPPORT-TICKET-001.yaml) | `ticket_body` | `/api/v1/support/tickets` | HIGH | AI triage manipulation, social engineering |
| ZTIF-IC-CHAT-MESSAGE-001 | [ZTIF-IC-CHAT-MESSAGE-001.yaml](ZTIF-IC-CHAT-MESSAGE-001.yaml) | `message` | `/api/v1/chat/send` | HIGH | Prompt injection, jailbreak, data exfil |
| ZTIF-IC-UPLOAD-DESCRIPTION-001 | [ZTIF-IC-UPLOAD-DESCRIPTION-001.yaml](ZTIF-IC-UPLOAD-DESCRIPTION-001.yaml) | `file_description` | `/api/v1/upload/submit` | HIGH | Indirect injection via AI categorization |
| ZTIF-IC-AUTH-PWRESET-001 | [ZTIF-IC-AUTH-PWRESET-001.yaml](ZTIF-IC-AUTH-PWRESET-001.yaml) | `email` | `/api/v1/auth/password-reset/request` | HIGH | Header injection, account enumeration |
| ZTIF-IC-PAYMENT-ADDRESS-001 | [ZTIF-IC-PAYMENT-ADDRESS-001.yaml](ZTIF-IC-PAYMENT-ADDRESS-001.yaml) | `billing_address_line1` | `/api/v1/billing/update-address` | HIGH | SQLi, AVS bypass injection |

---

## Risk Tier Distribution

```
LOW      ██░░░░░░░░  2 contracts  (CONTACT-MESSAGE, SEARCH-QUERY)
MEDIUM   ███░░░░░░░  3 contracts  (AUTH-USERNAME, PROFILE-BIO, CONTENT-REVIEW)
HIGH     █████░░░░░  5 contracts  (CHAT-MESSAGE, SUPPORT-TICKET, UPLOAD-DESCRIPTION, AUTH-PWRESET, PAYMENT-ADDRESS)
CRITICAL ─           0 contracts  (see financial/ subdirectory)
```

---

## How to Use These Contracts

### 1. Copy and adapt

Each contract is a starting point. Copy the closest match to your use case,
update `contract_id`, `field_name`, `endpoint`, and `declared_purpose`, then
refine `semantic_boundaries` using the Threat Story Method.

Increment the sequence if you have multiple contracts for the same domain+field:

```
ZTIF-IC-CHAT-MESSAGE-001.yaml   ← internal customer support bot
ZTIF-IC-CHAT-MESSAGE-002.yaml   ← public-facing sales assistant
```

### 2. Establish your baseline

Load the contract's `test_cases` into the ZTIF drift detector as your probe set.
Run Cell 3 in `ZTIF_Gate3_Drift_Detector.ipynb` with `ESTABLISH_MODE=True`
to set the behavioral baseline for your chosen Gate 3 model.

### 3. Wire into your pipeline

```python
from ztif.gate3 import run_gate3
from ztif.contracts import load_contract

contract = load_contract("ZTIF-IC-CHAT-MESSAGE-001")
result   = run_gate3(user_input, contract)

if result.verdict == "block":
    return 403
elif result.verdict == "flag":
    route_to_hitl(user_input, contract, result)
else:
    pass_to_gate4(user_input)
```

### 4. Version and review

- Increment `version` on any change to `semantic_boundaries`
- Update `last_reviewed` after each quarterly security review
- Add `notes` documenting the reason for any boundary change
- Never delete old versions — maintain a git history

---

## Threat Story Method Quick Reference

Every contract's core is built from three sentences:

```yaml
# Sentence 1 → declared_purpose
"This field is for [what legitimate users submit to accomplish what goal]."

# Sentence 2 → threat_scenario
"A malicious actor might try to [specific attack vector in this context]."

# Sentence 3 → semantic_boundaries (one item per "flag if..." condition)
"The LLM should flag any input that [specific boundary violation]."
```

---

## Risk Tier Guidance for Common Fields

| Field Type | Default Tier | Elevate to HIGH if... |
|---|---|---|
| Contact form | LOW | Form feeds AI auto-responder |
| Site search | LOW | Results use RAG or AI summarization |
| Username | MEDIUM | Platform has community or marketplace |
| Profile bio | MEDIUM | Bio feeds AI matching or recommendations |
| Product review | MEDIUM | Reviews train recommendation models |
| Support ticket | HIGH | AI triage agent with routing authority |
| AI chat | HIGH | Always — direct LLM interaction surface |
| File description | HIGH | Downstream AI categorization agent |
| Auth fields | HIGH | Injection targets email/SMS dispatch |
| Payment fields | HIGH | PCI DSS scope + processor API injection |

---

## Contributing

To add a new contract example:

1. Copy the closest existing contract as a template
2. Follow the naming convention: `ZTIF-IC-{DOMAIN}-{FIELD}-{SEQ}.yaml`
3. Complete all required fields per the [schema reference](../docs/schema-reference.html)
4. Include at minimum 5 test cases: 2 ALLOW, 1 REVIEW, 2 BLOCK
5. Add a `notes` section explaining the field's specific threat model
6. Open a pull request with a description of what input surface this covers

---

*Zero Trust Intent Framework (ZTIF) v2.0 · CC BY 4.0 · Chris Gillham · May 2026*
