from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Outcome(StrEnum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid_response"
    TIMEOUT = "timeout"
    INSUFFICIENT = "insufficient_evidence"


class ToolName(StrEnum):
    ENGINE = "engine_status"
    POLICY = "policy_status"
    DEVICE = "device_identity_status"
    ACTIVITY = "dns_activity_summary"


class Evidence(Contract):
    schema_version: Literal[1] = 1
    evidence_id: str = Field(min_length=1, max_length=128)
    source_component: str = Field(min_length=1, max_length=128)
    timestamp: AwareDatetime
    observation: str = Field(min_length=1, max_length=2048)
    verification: Literal["verified", "unverified", "fixture"]
    policy_revision: int | None = Field(default=None, ge=0)
    source_reference: str = Field(min_length=1, max_length=512)
    limitation: str | None = Field(default=None, max_length=512)


class ToolResult(Contract):
    schema_version: Literal[1] = 1
    tool: ToolName
    outcome: Outcome
    evidence: tuple[Evidence, ...] = Field(default=(), max_length=16)
    limitation: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def evidence_consistency(self):
        if self.outcome == Outcome.SUCCESS and not self.evidence:
            raise ValueError("Success requires evidence")
        if self.outcome != Outcome.SUCCESS and any(e.verification == "verified" for e in self.evidence):
            raise ValueError("Failed reads cannot supply verified evidence")
        return self


class InvestigationRequest(Contract):
    # Explicit commands are deliberate: no free-form prompt can select arbitrary tools.
    query: str = Field(min_length=1, max_length=256)


class Finding(Contract):
    observation: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class InvestigationResponse(Contract):
    schema_version: Literal[1] = 1
    route: Literal["diagnostic", "unsupported"]
    evidence: tuple[Evidence, ...] = ()
    verified_findings: tuple[Finding, ...] = ()
    inferences: tuple[Finding, ...] = ()
    unknowns: tuple[str, ...] = ()
    recommended_next_steps: tuple[str, ...] = ()
    tool_calls: int = 0
    retry_rounds: int = 0

    @model_validator(mode="after")
    def preserve_verification(self):
        lookup = {e.evidence_id: e for e in self.evidence}
        if len(lookup) != len(self.evidence):
            raise ValueError("Duplicate evidence identifiers")
        for finding in self.verified_findings:
            if any(ref not in lookup or lookup[ref].verification != "verified"
                   for ref in finding.evidence_ids):
                raise ValueError("Verified findings require verified evidence")
        for finding in self.inferences:
            if any(ref not in lookup for ref in finding.evidence_ids):
                raise ValueError("Inference references unknown evidence")
        return self
