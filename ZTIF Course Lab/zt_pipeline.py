"""
================================================================================
zt_pipeline.py — Zero Trust Intent Framework Pipeline
Zero Trust Intent Framework (ZTIF)
Author: Chris Gillham
================================================================================

USAGE — Copy into your project:
    cp zt_pipeline.py   your_project/security/zt_pipeline.py
    cp contracts/       your_project/security/contracts/

IMPORT:
    from security.zt_pipeline import ZTPipeline, ContractLoader, PipelineResult

QUICKSTART:
    pipeline = ZTPipeline.from_contracts_dir("security/contracts/")
    result   = pipeline.run(
        contract_id = "ZTIF-IC-SEARCH-QUERY-001",
        user_input  = "SELECT * FROM users",
        context     = {"user_id": "u123", "role": "customer", "ip": "10.0.0.1"},
    )
    if result.verdict == "BLOCK":
        raise PermissionError(result.block_reason)

PIPELINE ARCHITECTURE:
    Input
      │
      ├─[Gate 1]─ Structural Validation   (regex, OWASP patterns, NFKC, length)
      ├─[Gate 2]─ Zero Trust Context      (principal, role, MFA, risk score)
      ├─[Gate 3]─ LLM Semantic Guard      (Anthropic Claude — pass/flag/block)
      └─[Gate 4]─ Business Logic Rules    (contract-defined post-processing)
      │
      └─ PipelineResult  (verdict, gate_results, audit_record, latency_ms)

CONTRACT YAML FORMAT (contracts/ZTIF-IC-*.yaml):
    contract_id: ZTIF-IC-SEARCH-QUERY-001
    version: "1.0"
    risk_tier: high                          # low | medium | high | critical
    status: active                           # draft | active | deprecated
    description: "Product search input validation"
    semantic_boundaries:
      - "Must not contain SQL keywords (SELECT, DROP, INSERT, UPDATE)"
      - "Must not contain prompt injection attempts"
      - "Maximum 500 characters"
    gate1:
      max_length: 500
      blocked_patterns:
        - pattern: "(?i)(SELECT|DROP|INSERT|UPDATE|DELETE|UNION)\\s"
          label: SQLi
          severity: CRITICAL
        - pattern: "(?i)ignore\\s+(previous|above)\\s+instructions"
          label: prompt_injection
          severity: CRITICAL
      flag_patterns:
        - pattern: "(?i)(exec|eval|system)\\s*\\("
          label: code_exec_attempt
          severity: HIGH
    gate2:
      required_roles: []                     # empty = any authenticated user
      require_mfa: false
      min_trust_score: 40
      block_anonymous: true
    gate3:
      enabled: true
      model: "claude-sonnet-4-20250514"
      system_prompt_extra: ""               # appended to base guard system prompt
    gate4:
      rules: []                             # list of {name, condition, action}
    test_cases:
      - name: "Normal product search"
        input: "blue running shoes size 10"
        expected_verdict: PASS
      - name: "SQL injection attempt"
        input: "' OR 1=1 -- SELECT * FROM users"
        expected_verdict: BLOCK
      - name: "Borderline keyword"
        input: "drop shipping business model"
        expected_verdict: FLAG

AUDIT RECORD SCHEMA (emitted after every run):
    {
      "audit_id":      "ZTP-1716...-AB3C",
      "timestamp":     "2026-05-18T...",
      "contract_id":   "ZTIF-IC-SEARCH-QUERY-001",
      "verdict":       "BLOCK",
      "gate_verdicts": {"gate1": "BLOCK", "gate2": "PASS", "gate3": "SKIP", "gate4": "SKIP"},
      "latency_ms":    45,
      "user_id":       "u123",
      "input_hash":    "sha256:...",         # never log raw input in prod
      "block_reason":  "SQLi pattern matched: ...",
      "flags":         [],
    }
================================================================================
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
import logging
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml  # pip install pyyaml

# Optional: Anthropic SDK for Gate 3
try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

logger = logging.getLogger("zt_pipeline")


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES — Contract + Results
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class BlockedPattern:
    pattern: str
    label:   str
    severity: str = "HIGH"
    _compiled: Any = field(default=None, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE | re.UNICODE)

    def matches(self, text: str) -> bool:
        return bool(self._compiled.search(text))


@dataclass
class TestCase:
    name:             str
    input:            str
    expected_verdict: str           # PASS | FLAG | BLOCK
    context:          Dict = field(default_factory=dict)


@dataclass
class IntentContract:
    """
    Parsed representation of a ZTIF Intent Contract YAML file.
    Loaded by ContractLoader — do not instantiate directly.
    """
    contract_id:         str
    version:             str
    risk_tier:           str        # low | medium | high | critical
    status:              str        # draft | active | deprecated
    description:         str
    semantic_boundaries: List[str]

    # Gate 1 — Structural
    max_length:          int
    blocked_patterns:    List[BlockedPattern]
    flag_patterns:       List[BlockedPattern]

    # Gate 2 — Zero Trust Context
    required_roles:      List[str]
    require_mfa:         bool
    min_trust_score:     int
    block_anonymous:     bool

    # Gate 3 — LLM Semantic
    gate3_enabled:       bool
    gate3_model:         str
    gate3_system_extra:  str

    # Gate 4 — Business Logic
    gate4_rules:         List[Dict]

    # Test Cases
    test_cases:          List[TestCase]

    @property
    def is_active(self) -> bool:
        return self.status == "active"


@dataclass
class GateResult:
    gate:         str           # gate1 | gate2 | gate3 | gate4
    verdict:      str           # PASS | FLAG | BLOCK | SKIP | ERROR
    reason:       str = ""
    details:      Dict = field(default_factory=dict)
    latency_ms:   int  = 0


@dataclass
class PipelineResult:
    """
    The complete output of ZTPipeline.run().
    Use result.verdict to gate your application logic.
    """
    verdict:      str           # PASS | FLAG | BLOCK | ERROR
    contract_id:  str
    gate_results: List[GateResult]
    audit_record: Dict
    latency_ms:   int
    block_reason: str  = ""
    flags:        List[str] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.verdict == "BLOCK"

    @property
    def is_flagged(self) -> bool:
        return self.verdict == "FLAG"

    @property
    def is_passed(self) -> bool:
        return self.verdict == "PASS"

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["gate_results"] = [asdict(g) for g in self.gate_results]
        return d


# ══════════════════════════════════════════════════════════════════════════════
# CONTRACT LOADER
# ══════════════════════════════════════════════════════════════════════════════

class ContractLoader:
    """
    Loads and parses ZTIF Intent Contract YAML files.

    Usage:
        loader    = ContractLoader("security/contracts/")
        contracts = loader.load_all()
        contract  = loader.load_one("ZTIF-IC-SEARCH-QUERY-001")
    """

    def __init__(self, contracts_dir: str = "contracts/"):
        self.contracts_dir = Path(contracts_dir)
        self._cache: Dict[str, IntentContract] = {}

    def load_all(self, skip_inactive: bool = True) -> Dict[str, IntentContract]:
        """Load all contract YAMLs from the contracts directory."""
        if not self.contracts_dir.exists():
            raise FileNotFoundError(
                f"Contracts directory not found: {self.contracts_dir}\n"
                f"Copy your contracts/ folder to this path or pass the correct path to ContractLoader()."
            )

        loaded = {}
        for yaml_file in sorted(self.contracts_dir.glob("ZTIF-IC-*.yaml")):
            try:
                contract = self._parse_file(yaml_file)
                if skip_inactive and not contract.is_active:
                    logger.debug("Skipping inactive contract: %s (%s)", contract.contract_id, contract.status)
                    continue
                loaded[contract.contract_id] = contract
                self._cache[contract.contract_id] = contract
                logger.debug("Loaded contract: %s (risk_tier=%s)", contract.contract_id, contract.risk_tier)
            except Exception as exc:
                logger.error("Failed to load %s: %s", yaml_file.name, exc)

        logger.info("ContractLoader: %d contract(s) loaded from %s", len(loaded), self.contracts_dir)
        return loaded

    def load_one(self, contract_id: str) -> IntentContract:
        """Load a single contract by ID. Uses cache if already loaded."""
        if contract_id in self._cache:
            return self._cache[contract_id]

        candidates = list(self.contracts_dir.glob(f"{contract_id}*.yaml"))
        if not candidates:
            # Try exact match with or without prefix
            candidates = list(self.contracts_dir.glob(f"*{contract_id}*.yaml"))
        if not candidates:
            raise FileNotFoundError(f"No contract file found for ID: {contract_id}")

        contract = self._parse_file(candidates[0])
        self._cache[contract.contract_id] = contract
        return contract

    def _parse_file(self, path: Path) -> IntentContract:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        g1 = raw.get("gate1", {})
        g2 = raw.get("gate2", {})
        g3 = raw.get("gate3", {})
        g4 = raw.get("gate4", {})

        blocked_patterns = [
            BlockedPattern(p["pattern"], p.get("label", "unnamed"), p.get("severity", "HIGH"))
            for p in g1.get("blocked_patterns", [])
        ]
        flag_patterns = [
            BlockedPattern(p["pattern"], p.get("label", "unnamed"), p.get("severity", "MEDIUM"))
            for p in g1.get("flag_patterns", [])
        ]
        test_cases = [
            TestCase(
                name=tc["name"],
                input=tc["input"],
                expected_verdict=tc["expected_verdict"].upper(),
                context=tc.get("context", {}),
            )
            for tc in raw.get("test_cases", [])
        ]

        return IntentContract(
            contract_id         = raw["contract_id"],
            version             = str(raw.get("version", "1.0")),
            risk_tier           = raw.get("risk_tier", "medium").lower(),
            status              = raw.get("status", "active").lower(),
            description         = raw.get("description", ""),
            semantic_boundaries = raw.get("semantic_boundaries", []),
            max_length          = g1.get("max_length", 2000),
            blocked_patterns    = blocked_patterns,
            flag_patterns       = flag_patterns,
            required_roles      = g2.get("required_roles", []),
            require_mfa         = bool(g2.get("require_mfa", False)),
            min_trust_score     = int(g2.get("min_trust_score", 0)),
            block_anonymous     = bool(g2.get("block_anonymous", True)),
            gate3_enabled       = bool(g3.get("enabled", True)),
            gate3_model         = g3.get("model", "claude-sonnet-4-20250514"),
            gate3_system_extra  = g3.get("system_prompt_extra", ""),
            gate4_rules         = g4.get("rules", []),
            test_cases          = test_cases,
        )


# ══════════════════════════════════════════════════════════════════════════════
# GATE IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════════════════

class Gate(ABC):
    """Base class for all ZTIF pipeline gates."""

    @abstractmethod
    def run(
        self,
        user_input:  str,
        contract:    IntentContract,
        context:     Dict,
        prior_gates: List[GateResult],
    ) -> GateResult:
        ...


# ── Gate 1: Structural Validation ─────────────────────────────────────────────
class Gate1Structural(Gate):
    """
    Fast, zero-latency structural validation.

    Checks:
      - NFKC Unicode normalization (prevents homoglyph attacks)
      - Max length enforcement
      - Null bytes and control characters
      - Blocked pattern regex matching (BLOCK)
      - Flag pattern regex matching (FLAG)

    Never calls an external service — runs in microseconds.
    Corresponds to: OWASP LLM01 (Prompt Injection), LLM06 (Sensitive Info Disclosure)
    """

    def run(self, user_input, contract, context, prior_gates) -> GateResult:
        t0 = time.monotonic()

        # ── NFKC normalization — detect homoglyphs ────────────────────────────
        normalized = unicodedata.normalize("NFKC", user_input)
        if normalized != user_input:
            logger.debug("[Gate1] Input normalized via NFKC")

        text = normalized

        # ── Null bytes and dangerous control characters ───────────────────────
        if "\x00" in text or any(c in text for c in ["\x01", "\x02", "\x03"]):
            return GateResult(
                gate="gate1", verdict="BLOCK",
                reason="Null byte or control character detected",
                details={"check": "control_chars"},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── Length check ──────────────────────────────────────────────────────
        if len(text) > contract.max_length:
            return GateResult(
                gate="gate1", verdict="BLOCK",
                reason=f"Input exceeds max length ({len(text)} > {contract.max_length})",
                details={"length": len(text), "max": contract.max_length},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── Blocked patterns → immediate BLOCK ───────────────────────────────
        for bp in contract.blocked_patterns:
            if bp.matches(text):
                return GateResult(
                    gate="gate1", verdict="BLOCK",
                    reason=f"Blocked pattern matched: [{bp.label}] (severity={bp.severity})",
                    details={"pattern_label": bp.label, "severity": bp.severity},
                    latency_ms=int((time.monotonic() - t0) * 1000),
                )

        # ── Flag patterns → FLAG (continues through pipeline) ────────────────
        matched_flags = []
        for fp in contract.flag_patterns:
            if fp.matches(text):
                matched_flags.append(fp.label)

        if matched_flags:
            return GateResult(
                gate="gate1", verdict="FLAG",
                reason=f"Flag pattern(s) matched: {', '.join(matched_flags)}",
                details={"flag_labels": matched_flags},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        return GateResult(
            gate="gate1", verdict="PASS",
            latency_ms=int((time.monotonic() - t0) * 1000),
        )


# ── Gate 2: Zero Trust Context ─────────────────────────────────────────────────
class Gate2ZeroTrustContext(Gate):
    """
    Zero Trust principal and context evaluation.

    Checks:
      - Anonymous request blocking (configurable per contract)
      - Role-based access (contract.required_roles)
      - MFA requirement enforcement
      - Trust score threshold (0–100 from identity provider / device)
      - IP reputation flag (passed in context)

    Context dict expected keys (all optional with safe defaults):
      user_id:      str   — None = anonymous
      role:         str   — "customer" | "admin" | ...
      mfa_verified: bool  — whether MFA was satisfied for this session
      trust_score:  int   — 0–100 from identity/device posture
      ip_flagged:   bool  — true if IP is in threat intelligence blocklist
    """

    def run(self, user_input, contract, context, prior_gates) -> GateResult:
        t0       = time.monotonic()
        user_id  = context.get("user_id")
        role     = context.get("role", "anonymous")
        mfa      = context.get("mfa_verified", False)
        score    = int(context.get("trust_score", 50))
        ip_flag  = context.get("ip_flagged", False)

        # ── Anonymous block ───────────────────────────────────────────────────
        if contract.block_anonymous and not user_id:
            return GateResult(
                gate="gate2", verdict="BLOCK",
                reason="Anonymous request blocked by contract policy",
                details={"block_anonymous": True},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── Required role check ───────────────────────────────────────────────
        if contract.required_roles and role not in contract.required_roles:
            return GateResult(
                gate="gate2", verdict="BLOCK",
                reason=f"Role '{role}' not in required roles: {contract.required_roles}",
                details={"role": role, "required_roles": contract.required_roles},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── MFA requirement ───────────────────────────────────────────────────
        if contract.require_mfa and not mfa:
            return GateResult(
                gate="gate2", verdict="BLOCK",
                reason="MFA required by contract but not verified for this session",
                details={"require_mfa": True, "mfa_verified": False},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── Trust score threshold ─────────────────────────────────────────────
        if score < contract.min_trust_score:
            return GateResult(
                gate="gate2", verdict="BLOCK",
                reason=f"Trust score {score} below contract minimum {contract.min_trust_score}",
                details={"trust_score": score, "min_trust_score": contract.min_trust_score},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── Flagged IP — FLAG, don't block (let Gate 3 decide) ───────────────
        if ip_flag:
            return GateResult(
                gate="gate2", verdict="FLAG",
                reason="Request originated from a flagged IP address",
                details={"ip_flagged": True},
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        return GateResult(
            gate="gate2", verdict="PASS",
            details={"user_id": user_id, "role": role, "trust_score": score},
            latency_ms=int((time.monotonic() - t0) * 1000),
        )


# ── Gate 3: LLM Semantic Guard ────────────────────────────────────────────────
class Gate3LLMSemantic(Gate):
    """
    Semantic understanding via Claude.

    Sends the user input against the contract's semantic boundaries to
    Claude and receives a structured verdict: PASS / FLAG / BLOCK.

    Only runs when:
      - contract.gate3_enabled is True
      - ANTHROPIC_API_KEY is set
      - Prior gates have not already BLOCKed

    The LLM prompt is constructed from:
      - A fixed ZTIF system prompt (below)
      - contract.semantic_boundaries
      - contract.gate3_system_extra (per-contract additions)
      - The user input

    Response format enforced via prompt:
        VERDICT: PASS|FLAG|BLOCK
        REASON: <one-line explanation>
        BOUNDARY_VIOLATED: <boundary text or NONE>
    """

    # Base system prompt — stable across all contracts
    BASE_SYSTEM_PROMPT = """You are a Zero Trust Intent Guard for an application security pipeline.
Your job is to evaluate user input against a set of semantic boundaries defined in an Intent Contract.

You MUST respond in EXACTLY this format (no extra text before or after):
VERDICT: PASS
REASON: <one sentence>
BOUNDARY_VIOLATED: NONE

OR if the input violates a boundary:
VERDICT: BLOCK
REASON: <one sentence explaining the violation>
BOUNDARY_VIOLATED: <exact boundary text that was violated>

OR if the input is borderline or ambiguous:
VERDICT: FLAG
REASON: <one sentence>
BOUNDARY_VIOLATED: <boundary text or NONE>

Rules:
- BLOCK when the input clearly and unambiguously violates a defined boundary.
- FLAG when the input is potentially in violation but context is ambiguous.
- PASS when the input clearly satisfies all boundaries.
- Base your decision ONLY on the stated boundaries. Do not invent new rules.
- Be precise and consistent. Do not add markdown, JSON, or any other formatting.
"""

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client  = None

        if self._api_key and _ANTHROPIC_AVAILABLE:
            self._client = anthropic.Anthropic(api_key=self._api_key)

    def run(self, user_input, contract, context, prior_gates) -> GateResult:
        t0 = time.monotonic()

        # ── Skip if disabled or no API key ────────────────────────────────────
        if not contract.gate3_enabled:
            return GateResult(gate="gate3", verdict="SKIP", reason="Gate 3 disabled by contract")

        if not self._client:
            reason = "Gate 3 skipped: anthropic SDK not installed" if not _ANTHROPIC_AVAILABLE \
                     else "Gate 3 skipped: ANTHROPIC_API_KEY not set"
            logger.warning("[Gate3] %s", reason)
            return GateResult(gate="gate3", verdict="SKIP", reason=reason)

        # ── Build boundary list for the prompt ───────────────────────────────
        boundaries_text = "\n".join(
            f"  {i+1}. {b}" for i, b in enumerate(contract.semantic_boundaries)
        )

        extra = f"\n\nAdditional contract guidance:\n{contract.gate3_system_extra}" \
                if contract.gate3_system_extra.strip() else ""

        system_prompt = self.BASE_SYSTEM_PROMPT + extra

        user_prompt = f"""Contract ID: {contract.contract_id}
Risk Tier: {contract.risk_tier}

Semantic Boundaries:
{boundaries_text}

User Input to Evaluate:
\"\"\"{user_input}\"\"\"

Evaluate the user input against ALL semantic boundaries listed above and respond in the required format."""

        # ── Call Claude ───────────────────────────────────────────────────────
        try:
            response = self._client.messages.create(
                model=contract.gate3_model,
                max_tokens=200,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            raw_text = response.content[0].text.strip()
        except Exception as exc:
            logger.error("[Gate3] API call failed: %s", exc)
            return GateResult(
                gate="gate3", verdict="ERROR",
                reason=f"LLM API error: {exc}",
                latency_ms=int((time.monotonic() - t0) * 1000),
            )

        # ── Parse LLM response ────────────────────────────────────────────────
        verdict, reason, boundary = self._parse_response(raw_text)

        return GateResult(
            gate="gate3", verdict=verdict,
            reason=reason,
            details={"boundary_violated": boundary, "raw_response": raw_text},
            latency_ms=int((time.monotonic() - t0) * 1000),
        )

    @staticmethod
    def _parse_response(text: str) -> Tuple[str, str, str]:
        """Parse the structured LLM response into (verdict, reason, boundary)."""
        verdict  = "FLAG"   # safe default if parse fails
        reason   = ""
        boundary = "NONE"

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("VERDICT:"):
                v = line.split(":", 1)[1].strip().upper()
                if v in ("PASS", "FLAG", "BLOCK"):
                    verdict = v
            elif line.startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()
            elif line.startswith("BOUNDARY_VIOLATED:"):
                boundary = line.split(":", 1)[1].strip()

        if not reason:
            reason = f"LLM returned verdict={verdict} (unparseable response)"

        return verdict, reason, boundary


# ── Gate 4: Business Logic Rules ──────────────────────────────────────────────
class Gate4BusinessLogic(Gate):
    """
    Contract-defined post-processing rules.

    Rules are defined in the contract YAML under gate4.rules as:
      rules:
        - name: "Block if prior gates flagged and risk_tier is critical"
          condition: "flagged_count > 0 and risk_tier == 'critical'"
          action: "BLOCK"
          reason: "Critical contract: any flag escalates to block"

    Condition variables available:
      flagged_count  — number of prior gates that returned FLAG
      block_count    — number of prior gates that returned BLOCK
      risk_tier      — contract.risk_tier string
      user_role      — context['role']
      trust_score    — context['trust_score']
      gate1_verdict  — verdict string from gate1
      gate3_verdict  — verdict string from gate3

    Rules are evaluated in order; first match wins.
    """

    def run(self, user_input, contract, context, prior_gates) -> GateResult:
        t0 = time.monotonic()

        if not contract.gate4_rules:
            return GateResult(gate="gate4", verdict="SKIP", reason="No Gate 4 rules defined")

        # Build evaluation namespace
        verdict_map = {g.gate: g.verdict for g in prior_gates}
        eval_ns = {
            "flagged_count":  sum(1 for g in prior_gates if g.verdict == "FLAG"),
            "block_count":    sum(1 for g in prior_gates if g.verdict == "BLOCK"),
            "risk_tier":      contract.risk_tier,
            "user_role":      context.get("role", "anonymous"),
            "trust_score":    int(context.get("trust_score", 50)),
            "gate1_verdict":  verdict_map.get("gate1", "SKIP"),
            "gate2_verdict":  verdict_map.get("gate2", "SKIP"),
            "gate3_verdict":  verdict_map.get("gate3", "SKIP"),
        }

        for rule in contract.gate4_rules:
            try:
                condition_met = bool(eval(rule.get("condition", "False"), {"__builtins__": {}}, eval_ns))
            except Exception as exc:
                logger.warning("[Gate4] Rule '%s' condition eval failed: %s", rule.get("name"), exc)
                continue

            if condition_met:
                action = rule.get("action", "FLAG").upper()
                reason = rule.get("reason", f"Gate 4 rule fired: {rule.get('name', 'unnamed')}")
                return GateResult(
                    gate="gate4", verdict=action,
                    reason=reason,
                    details={"rule_name": rule.get("name"), "condition": rule.get("condition")},
                    latency_ms=int((time.monotonic() - t0) * 1000),
                )

        return GateResult(
            gate="gate4", verdict="PASS",
            reason="No Gate 4 rules matched",
            latency_ms=int((time.monotonic() - t0) * 1000),
        )


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class ZTPipeline:
    """
    Zero Trust Intent Framework Pipeline.

    Orchestrates all four gates and produces a final PipelineResult
    with a single authoritative verdict and a complete audit record.

    Usage:
        # From contracts directory
        pipeline = ZTPipeline.from_contracts_dir("security/contracts/")

        # Run against a specific contract
        result = pipeline.run(
            contract_id = "ZTIF-IC-SEARCH-QUERY-001",
            user_input  = request.POST["q"],
            context     = {
                "user_id":      current_user.id,
                "role":         current_user.role,
                "mfa_verified": session.mfa_verified,
                "trust_score":  session.trust_score,
                "ip_flagged":   threat_intel.is_flagged(request.remote_ip),
            },
        )

        if result.is_blocked:
            logger.warning("Request blocked: %s", result.block_reason)
            return HttpResponse(status=403)

        if result.is_flagged:
            # Route to human review queue
            hitl_queue.submit(result.audit_record)
    """

    def __init__(
        self,
        contracts:     Dict[str, IntentContract],
        anthropic_key: Optional[str] = None,
        audit_handler: Optional[Any] = None,
    ):
        """
        Parameters
        ----------
        contracts     : Dict mapping contract_id → IntentContract (from ContractLoader)
        anthropic_key : Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
        audit_handler : Callable[[dict], None] — receives audit record after each run.
                        Defaults to structured stdout logging.
        """
        self.contracts     = contracts
        self.audit_handler = audit_handler or self._default_audit_handler

        self._gates = [
            Gate1Structural(),
            Gate2ZeroTrustContext(),
            Gate3LLMSemantic(api_key=anthropic_key),
            Gate4BusinessLogic(),
        ]

    @classmethod
    def from_contracts_dir(
        cls,
        contracts_dir:  str = "contracts/",
        anthropic_key:  Optional[str] = None,
        audit_handler:  Optional[Any] = None,
        skip_inactive:  bool = True,
    ) -> "ZTPipeline":
        """Convenience factory — loads contracts and returns a ready pipeline."""
        loader    = ContractLoader(contracts_dir)
        contracts = loader.load_all(skip_inactive=skip_inactive)
        return cls(contracts=contracts, anthropic_key=anthropic_key, audit_handler=audit_handler)

    @classmethod
    def from_single_contract(
        cls,
        contract_path:  str,
        anthropic_key:  Optional[str] = None,
    ) -> "ZTPipeline":
        """Load a single contract file directly — useful in unit tests."""
        loader   = ContractLoader(str(Path(contract_path).parent))
        contract = loader._parse_file(Path(contract_path))
        return cls(contracts={contract.contract_id: contract}, anthropic_key=anthropic_key)

    def run(
        self,
        contract_id: str,
        user_input:  str,
        context:     Optional[Dict] = None,
    ) -> PipelineResult:
        """
        Run the four-gate pipeline for a single user input.

        Parameters
        ----------
        contract_id : The ZTIF contract ID (e.g. "ZTIF-IC-SEARCH-QUERY-001")
        user_input  : The raw user-supplied string to validate
        context     : Dict with caller context (user_id, role, trust_score, etc.)

        Returns
        -------
        PipelineResult with .verdict, .is_blocked, .is_flagged, .audit_record
        """
        pipeline_start = time.monotonic()
        context        = context or {}
        audit_id       = self._make_audit_id()

        # ── Resolve contract ──────────────────────────────────────────────────
        contract = self.contracts.get(contract_id)
        if not contract:
            err_result = self._error_result(
                contract_id, audit_id,
                f"Contract '{contract_id}' not found. Available: {list(self.contracts.keys())}",
            )
            self.audit_handler(err_result.audit_record)
            return err_result

        # ── Run gates in sequence ─────────────────────────────────────────────
        gate_results: List[GateResult] = []
        final_verdict = "PASS"
        block_reason  = ""
        flags: List[str] = []

        for gate in self._gates:
            result = gate.run(user_input, contract, context, gate_results)
            gate_results.append(result)

            if result.verdict == "BLOCK":
                final_verdict = "BLOCK"
                block_reason  = result.reason
                break   # fail-fast — no need to evaluate subsequent gates

            if result.verdict == "FLAG":
                final_verdict = "FLAG"
                flags.append(f"{result.gate}: {result.reason}")
                # Continue — flags accumulate, do not stop the chain

        total_ms = int((time.monotonic() - pipeline_start) * 1000)

        # ── Build audit record ────────────────────────────────────────────────
        audit_record = self._build_audit_record(
            audit_id, contract, user_input, context,
            gate_results, final_verdict, block_reason, flags, total_ms,
        )

        result = PipelineResult(
            verdict      = final_verdict,
            contract_id  = contract_id,
            gate_results = gate_results,
            audit_record = audit_record,
            latency_ms   = total_ms,
            block_reason = block_reason,
            flags        = flags,
        )

        self.audit_handler(audit_record)
        return result

    def run_test_suite(
        self,
        contract_id: str,
        verbose:     bool = False,
        fail_on_flag: bool = False,
    ) -> Dict:
        """
        Execute the test_cases defined in a contract.
        Used by run_guard_tests.py and CI/CD gate.

        Returns a summary dict with pass/fail/error counts and per-case results.
        """
        contract = self.contracts.get(contract_id)
        if not contract:
            raise ValueError(f"Contract not found: {contract_id}")

        summary = {
            "contract_id": contract_id,
            "total":       len(contract.test_cases),
            "passed":      0,
            "failed":      0,
            "errors":      0,
            "results":     [],
        }

        for tc in contract.test_cases:
            result   = self.run(contract_id, tc.input, tc.context)
            expected = tc.expected_verdict
            actual   = result.verdict

            # FLAG may be treated as failure in strict CI mode
            if fail_on_flag and actual == "FLAG":
                outcome = "FAIL" if expected == "PASS" else "PASS"
            else:
                outcome = "PASS" if actual == expected else "FAIL"

            if outcome == "PASS":
                summary["passed"] += 1
            elif result.verdict == "ERROR":
                summary["errors"] += 1
                outcome = "ERROR"
            else:
                summary["failed"] += 1

            case_detail = {
                "name":     tc.name,
                "input":    tc.input[:80] + ("..." if len(tc.input) > 80 else ""),
                "expected": expected,
                "actual":   actual,
                "outcome":  outcome,
                "latency_ms": result.latency_ms,
            }
            summary["results"].append(case_detail)

            if verbose:
                icon = "✅" if outcome == "PASS" else ("⚠️" if outcome == "ERROR" else "❌")
                print(f"  {icon}  [{outcome}] {tc.name}")
                print(f"       Expected={expected}  Got={actual}  ({result.latency_ms}ms)")
                if outcome == "FAIL":
                    print(f"       Reason: {result.block_reason or ', '.join(result.flags)}")

        summary["pass_rate"] = (
            round(summary["passed"] / summary["total"] * 100, 1) if summary["total"] else 0
        )
        return summary

    # ── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _make_audit_id() -> str:
        import secrets
        return f"ZTP-{int(time.time() * 1000)}-{secrets.token_hex(3).upper()}"

    @staticmethod
    def _build_audit_record(
        audit_id, contract, user_input, context,
        gate_results, verdict, block_reason, flags, total_ms,
    ) -> Dict:
        # Hash input — never log raw user input in production audit records
        input_hash = "sha256:" + hashlib.sha256(user_input.encode()).hexdigest()[:16]

        return {
            "audit_id":     audit_id,
            "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "contract_id":  contract.contract_id,
            "version":      contract.version,
            "risk_tier":    contract.risk_tier,
            "verdict":      verdict,
            "block_reason": block_reason,
            "flags":        flags,
            "gate_verdicts": {g.gate: g.verdict for g in gate_results},
            "gate_latency_ms": {g.gate: g.latency_ms for g in gate_results},
            "total_latency_ms": total_ms,
            "user_id":      context.get("user_id"),
            "user_role":    context.get("role", "anonymous"),
            "trust_score":  context.get("trust_score"),
            "input_hash":   input_hash,
            "input_length": len(user_input),
        }

    @staticmethod
    def _error_result(contract_id: str, audit_id: str, reason: str) -> PipelineResult:
        return PipelineResult(
            verdict      = "ERROR",
            contract_id  = contract_id,
            gate_results = [],
            audit_record = {
                "audit_id":   audit_id,
                "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "contract_id": contract_id,
                "verdict":    "ERROR",
                "reason":     reason,
            },
            latency_ms   = 0,
            block_reason = reason,
        )

    @staticmethod
    def _default_audit_handler(audit_record: Dict) -> None:
        verdict = audit_record.get("verdict", "?")
        if verdict == "BLOCK":
            logger.warning("[ZTIF-AUDIT] %s", json.dumps(audit_record))
        elif verdict in ("FLAG", "ERROR"):
            logger.info("[ZTIF-AUDIT] %s", json.dumps(audit_record))
        else:
            logger.debug("[ZTIF-AUDIT] %s", json.dumps(audit_record))


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT HANDLERS — Plug in as audit_handler= to ZTPipeline()
# ══════════════════════════════════════════════════════════════════════════════

class SplunkHECAuditHandler:
    """
    Sends audit records to Splunk HTTP Event Collector.

    Usage:
        handler  = SplunkHECAuditHandler(url=..., token=...)
        pipeline = ZTPipeline(contracts, audit_handler=handler)
    """

    def __init__(self, url: str, token: str, source: str = "ztif:pipeline", index: str = "security"):
        self.url    = url
        self.token  = token
        self.source = source
        self.index  = index

    def __call__(self, audit_record: Dict) -> None:
        import urllib.request
        body = json.dumps({
            "time":       int(time.time()),
            "sourcetype": "_json",
            "source":     self.source,
            "index":      self.index,
            "event":      audit_record,
        }).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Authorization": f"Splunk {self.token}", "Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=3)
        except Exception as exc:
            logger.error("[SplunkHEC] Emit failed: %s", exc)


class FileAuditHandler:
    """
    Appends NDJSON audit records to a local file.

    Usage:
        handler  = FileAuditHandler("logs/ztif_audit.ndjson")
        pipeline = ZTPipeline(contracts, audit_handler=handler)
    """

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, audit_record: Dict) -> None:
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit_record) + "\n")


class MultiAuditHandler:
    """
    Fan-out to multiple audit handlers simultaneously.

    Usage:
        handler = MultiAuditHandler([splunk_handler, file_handler])
    """

    def __init__(self, handlers: List):
        self.handlers = handlers

    def __call__(self, audit_record: Dict) -> None:
        for h in self.handlers:
            try:
                h(audit_record)
            except Exception as exc:
                logger.error("[MultiAuditHandler] Handler %s failed: %s", h, exc)


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# Mirrors the interface of ZTIF Course Lab/run_guard_tests.py
# so this file can be used as a drop-in replacement or companion.
# ══════════════════════════════════════════════════════════════════════════════

def _cli_main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ZTIF Pipeline — Run guard tests against Intent Contracts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test a specific contract
  python zt_pipeline.py --contract-id ZTIF-IC-SEARCH-QUERY-001 --verbose

  # Test all high-risk contracts
  python zt_pipeline.py --risk-tier high --verbose

  # Test all contracts; treat FLAG verdicts as failures (CI mode)
  python zt_pipeline.py --all --fail-on-flag

  # Interactive single input test
  python zt_pipeline.py --contract-id ZTIF-IC-SEARCH-QUERY-001 --input "hello world"
        """,
    )
    parser.add_argument("--contracts-dir",  default="contracts/",           help="Path to contracts/ directory")
    parser.add_argument("--contract-id",    default=None,                   help="Run tests for a specific contract ID")
    parser.add_argument("--risk-tier",      default=None,                   choices=["low","medium","high","critical"], help="Run all contracts of this risk tier")
    parser.add_argument("--all",            action="store_true",            help="Run all active contracts")
    parser.add_argument("--fail-on-flag",   action="store_true",            help="Treat FLAG verdict as test failure (strict CI mode)")
    parser.add_argument("--verbose",        action="store_true",            help="Print per-test-case results")
    parser.add_argument("--input",          default=None,                   help="Run a single input string against --contract-id instead of test cases")
    parser.add_argument("--output-json",    default=None,                   help="Write results JSON to this file")
    parser.add_argument("--audit-file",     default=None,                   help="Append NDJSON audit records to this file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    # ── Audit handler ─────────────────────────────────────────────────────────
    audit_handler = FileAuditHandler(args.audit_file) if args.audit_file else None

    # ── Load pipeline ─────────────────────────────────────────────────────────
    try:
        pipeline = ZTPipeline.from_contracts_dir(
            contracts_dir = args.contracts_dir,
            audit_handler = audit_handler,
        )
    except FileNotFoundError as e:
        print(f"❌  {e}")
        raise SystemExit(1)

    print(f"\n🔒 ZTIF Pipeline — Zero Trust Intent Framework")
    print(f"   Contracts loaded: {len(pipeline.contracts)}")
    print(f"   Contracts dir   : {args.contracts_dir}")
    print()

    # ── Single-input mode ─────────────────────────────────────────────────────
    if args.input:
        if not args.contract_id:
            print("❌  --input requires --contract-id")
            raise SystemExit(1)
        result = pipeline.run(args.contract_id, args.input)
        icon   = {"PASS": "✅", "FLAG": "⚠️", "BLOCK": "🚫", "ERROR": "💥"}.get(result.verdict, "?")
        print(f"{icon}  Verdict: {result.verdict}")
        if result.block_reason:
            print(f"   Reason : {result.block_reason}")
        for flag in result.flags:
            print(f"   Flag   : {flag}")
        for g in result.gate_results:
            print(f"   [{g.gate}] {g.verdict} — {g.reason} ({g.latency_ms}ms)")
        print(f"   Total  : {result.latency_ms}ms")
        raise SystemExit(0 if result.verdict in ("PASS", "FLAG") else 1)

    # ── Test suite mode ───────────────────────────────────────────────────────
    contract_ids = []
    if args.contract_id:
        contract_ids = [args.contract_id]
    elif args.risk_tier:
        contract_ids = [cid for cid, c in pipeline.contracts.items() if c.risk_tier == args.risk_tier]
        if not contract_ids:
            print(f"⚠️   No active contracts found for risk_tier={args.risk_tier}")
            raise SystemExit(0)
    else:
        contract_ids = list(pipeline.contracts.keys())

    all_summaries = []
    total_failed  = 0

    for cid in contract_ids:
        print(f"📋  Testing: {cid}")
        summary = pipeline.run_test_suite(cid, verbose=args.verbose, fail_on_flag=args.fail_on_flag)
        all_summaries.append(summary)
        total_failed += summary["failed"] + summary["errors"]

        icon = "✅" if summary["failed"] == 0 and summary["errors"] == 0 else "❌"
        print(f"    {icon}  {summary['passed']}/{summary['total']} passed  ({summary['pass_rate']}%)  "
              f"{summary['failed']} failed  {summary['errors']} errors\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("=" * 60)
    print(f"  Contracts tested : {len(contract_ids)}")
    total_cases  = sum(s["total"] for s in all_summaries)
    total_passed = sum(s["passed"] for s in all_summaries)
    print(f"  Test cases       : {total_cases}")
    print(f"  Passed           : {total_passed}")
    print(f"  Failed / Errors  : {total_failed}")
    final_icon = "✅ ALL PASS" if total_failed == 0 else "❌ FAILURES DETECTED"
    print(f"  Result           : {final_icon}")
    print("=" * 60)

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(all_summaries, f, indent=2)
        print(f"\n  Results written to: {args.output_json}")

    raise SystemExit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    _cli_main()
