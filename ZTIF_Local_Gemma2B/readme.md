# 🛡️ ZT Intent Contract Framework
## Interactive Lab Notebook — Google Gemma-2-2B-it Edition

---

| Field | Value |
| :--- | :--- |
| **Notebook ID** | ZTIF-IC-001 |
| **Framework** | ZT Intent Contract Framework v1.3 |
| **Model** | `google/gemma-2-2b-it` (4-bit quantized, on-device) |
| **Author** | Chris Gillham |
| **Cost Model** | ✅ Zero API cost — fully local inference |
| **Latency Model** | ✅ Zero external latency — no network calls for inference |
| **OWASP Coverage** | LLM01 · LLM02 · LLM06 · LLM08 |
| **GPU Requirement** | T4 16 GB (free Colab tier sufficient) |
| **HuggingFace Access** | ⚠️ Requires acceptance of Gemma license at hf.co/google/gemma-2-2b-it |

---

## 📋 Lab Overview

This notebook implements the **Zero Trust Input Validation Framework** using Google's **Gemma 2B Instruct** model running entirely on-device (T4 GPU).

Unlike API-based guardrail solutions, this lab demonstrates a **zero-cost, zero-latency** enforcement layer suitable for:
- Edge deployments where API calls are prohibited
- High-throughput pipelines where per-token billing is cost-prohibitive
- Air-gapped or sovereign cloud environments
- Proof-of-concept Zero Trust AI architectures
