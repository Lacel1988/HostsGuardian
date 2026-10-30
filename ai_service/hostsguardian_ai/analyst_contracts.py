from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .schemas import Contract, Outcome

Route = Literal["direct", "retrieval", "investigation", "ambiguous", "unsupported"]


class AnalystRequest(Contract):
    question: str = Field(min_length=1, max_length=512)
    language: Literal["en", "hu"] | None = None
    previous_response_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    session_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")

    @field_validator("question")
    @classmethod
    def printable_question(cls, value):
        if not value.strip() or not all(c.isprintable() for c in value):
            raise ValueError("A printable question is required")
        return value


class EvidenceRecord(Contract):
    evidence_id: str = Field(min_length=1, max_length=128)
    kind: Literal["verified_operational", "live_unverified", "approved_documentation", "synthetic", "unknown"]
    source_reference: str = Field(min_length=1, max_length=512)
    timestamp: AwareDatetime
    content: str = Field(min_length=1, max_length=2048)
    source_id: str | None = Field(default=None, max_length=64)
    chunk_id: str | None = Field(default=None, max_length=64)
    corpus_version: str | None = Field(default=None, max_length=64)
    policy_revision: int | None = Field(default=None, ge=0)
    verification: Literal["verified", "unverified", "fixture"]
    limitations: tuple[str, ...] = Field(default=(), max_length=8)
    received_at: AwareDatetime | None = None
    source_timestamp: AwareDatetime | None = None
    valid_until: AwareDatetime | None = None
    freshness: Literal["fresh","stale","unknown"] = "unknown"
    network_scope: str | None = Field(default=None,max_length=128)
    device_id: str | None = Field(default=None,max_length=64)
    binding_state: Literal["fresh_reported","stale","unvalidated","ambiguous","missing"] | None = None
    instance_id: str | None = Field(default=None,max_length=128)
    fact_type: Literal["engine_health","dns_status","policy_status","binding_status","activity_summary"] | None = None
    facts: dict[str,bool|int|str|None] = Field(default_factory=dict,max_length=16)

    @model_validator(mode="after")
    def verification_boundary(self):
        if self.source_reference.startswith("fixture://") and self.kind != "synthetic":
            raise ValueError("Fixture sources cannot be operational evidence")
        if self.source_reference.startswith("corpus://") and self.kind != "approved_documentation":
            raise ValueError("Corpus approval cannot become operational evidence")
        if self.kind == "synthetic" and self.verification != "fixture":
            raise ValueError("Synthetic evidence must be identified as fixture")
        if self.kind == "approved_documentation" and self.verification != "unverified":
            raise ValueError("Ingestion approval is not operational verification")
        if self.kind == "verified_operational" and self.verification != "verified":
            raise ValueError("Operational verification missing")
        if self.kind == "live_unverified" and self.verification != "unverified":
            raise ValueError("Unverified live source cannot become a verified finding")
        if self.kind == "verified_operational" and self.fact_type == "binding_status":
            raise ValueError("An authenticated binding report cannot prove physical identity")
        return self


class Passage(Contract):
    evidence_id: str = Field(min_length=1, max_length=128)
    quote: str = Field(min_length=1, max_length=512)

    @field_validator("quote")
    @classmethod
    def meaningful_quote(cls, value):
        if not any(c.isalnum() for c in value):
            raise ValueError("A meaningful source passage is required")
        return value


class ModelSelection(Contract):
    selections: tuple[Passage, ...] = Field(min_length=1, max_length=3)


class ClauseSelection(Contract):
    claim_ids: tuple[str, ...] = Field(min_length=1, max_length=3)


class DiagnosticSummary(Contract):
    synthetic_items: int = Field(ge=0, le=24)
    documentation_items: int = Field(ge=0, le=24)
    observed_policy_revisions: tuple[int, ...] = Field(default=(), max_length=24)
    conflicting_evidence: bool
    operational_enforcement: Literal["unknown"] = "unknown"
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=24)


class DiagnosticHypothesis(Contract):
    hypothesis_id: str = Field(min_length=1, max_length=64)
    status: Literal["unconfirmed"] = "unconfirmed"
    basis: Literal["general_networking_knowledge", "documentation"]
    statement: str = Field(min_length=1, max_length=512)
    verification_step: str = Field(min_length=1, max_length=512)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=4)

    @model_validator(mode="after")
    def honest_basis(self):
        if (self.basis == "documentation") != bool(self.evidence_ids):
            raise ValueError("Hypothesis basis and evidence references disagree")
        return self


class DiagnosticFailure(Contract):
    source: str = Field(pattern=r"^[a-z_]{1,64}$")
    status: Outcome
    reason_code: str | None = Field(default=None, max_length=128)
    limitation: str | None = Field(default=None, max_length=512)
    available_evidence_ids: tuple[str, ...] = Field(default=(), max_length=24)


class AnalystResponse(Contract):
    schema_version: Literal[1] = 1
    route: Route
    language: Literal["en", "hu"]
    detail: Literal["simple", "standard", "technical"]
    status: Literal["answered", "partial", "unknown", "clarification", "refused"]
    answer: str = Field(max_length=5000)
    passages: tuple[Passage, ...] = Field(default=(), max_length=3)
    evidence: tuple[EvidenceRecord, ...] = Field(default=(), max_length=24)
    verified_findings: tuple[Passage, ...] = Field(default=(), max_length=3)
    inferences: tuple[str, ...] = Field(default=(), max_length=8)
    unknowns: tuple[str, ...] = Field(default=(), max_length=24)
    next_steps: tuple[str, ...] = Field(default=(), max_length=4)
    limitations: tuple[str, ...] = Field(default=(), max_length=24)
    tools_used: tuple[str, ...] = Field(default=(), max_length=6)
    tool_calls: int = Field(ge=0, le=6)
    retries: int = Field(ge=0, le=2)
    llm_calls: int = Field(ge=0, le=1)
    transitions: tuple[str, ...] = Field(max_length=24)
    diagnostic_summary: DiagnosticSummary | None = None
    claim_ids: tuple[str, ...] = Field(default=(), max_length=3)
    generation_validated: bool = False
    hypotheses: tuple[DiagnosticHypothesis, ...] = Field(default=(), max_length=4)
    failures: tuple[DiagnosticFailure, ...] = Field(default=(), max_length=12)
    response_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    session_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    context_response_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    response_intent: Literal["summary", "failure_reason", "causes", "verification", "technical"] = "summary"

    @model_validator(mode="after")
    def citations(self):
        ledger = {e.evidence_id: e for e in self.evidence}
        if len(ledger) != len(self.evidence):
            raise ValueError("Duplicate evidence")
        for passage in self.passages + self.verified_findings:
            if passage.evidence_id not in ledger or passage.quote not in ledger[passage.evidence_id].content:
                raise ValueError("Fabricated citation or passage")
        for finding in self.verified_findings:
            if ledger[finding.evidence_id].kind != "verified_operational":
                raise ValueError("Unverified content cannot support verified findings")
        if self.diagnostic_summary and any(ref not in ledger for ref in self.diagnostic_summary.evidence_ids):
            raise ValueError("Summary references missing evidence")
        if self.claim_ids:
            from .knowledge import CLAUSES
            catalog = {clause.key: clause for clause in CLAUSES}
            if len(set(self.claim_ids)) != len(self.claim_ids):
                raise ValueError("Duplicate explanation clause")
            for key in self.claim_ids:
                if key not in catalog:
                    raise ValueError("Unknown explanation clause")
                clause = catalog[key]
                if not any(p.quote == clause.anchor and ledger[p.evidence_id].kind == "approved_documentation" for p in self.passages):
                    raise ValueError("Explanation has no validated source support")
                if (clause.hu if self.language == "hu" else clause.en) not in self.answer:
                    raise ValueError("Explanation language/content mismatch")
        for hypothesis in self.hypotheses:
            if any(ref not in ledger or ledger[ref].kind != "approved_documentation" for ref in hypothesis.evidence_ids):
                raise ValueError("Unknown hypothesis support")
        for failure in self.failures:
            if any(ref not in ledger for ref in failure.available_evidence_ids):
                raise ValueError("Unknown failure evidence")
        return self
