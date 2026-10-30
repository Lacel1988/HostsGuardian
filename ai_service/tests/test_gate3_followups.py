import asyncio
import json
import time

import httpx
import pytest
from pydantic import ValidationError

from test_gate1 import offline
from test_gate3_bilingual import Knowledge, Selector
from hostsguardian_ai.analyst_contracts import AnalystRequest, AnalystResponse, DiagnosticFailure
from hostsguardian_ai.config import Settings
from hostsguardian_ai.diagnostics import MockDiagnostics
from hostsguardian_ai.orchestration import Analyst
from hostsguardian_ai.providers import ModelRequest, ModelResponse, OllamaProvider
from hostsguardian_ai.schemas import Outcome, ToolName, ToolResult


class MissingDevice(MockDiagnostics):
    async def read(self, tool):
        if tool == ToolName.DEVICE:
            return ToolResult(tool=tool, outcome=Outcome.UNAVAILABLE,
                              limitation="Synthetic identity source unavailable; no underlying cause recorded.")
        return await super().read(tool)


@pytest.mark.parametrize("language,why,causes,fix,technical", [
    ("hu", "Miért nem sikerült?", "Mi okozhatja ezt?", "Hogyan javíthatom?", "Kérek részletesebb technikai magyarázatot"),
    ("en", "Why did it fail?", "What could cause this?", "How can I fix it?", "Give a more technical explanation")])
async def test_failure_explanations_use_only_issued_context(language, why, causes, fix, technical):
    analyst = Analyst(Settings(), MissingDevice(), None, Selector())
    initial = await analyst.run(AnalystRequest(question="Why did device discovery fail?", language=language))
    assert any(f.source == "device_identity_status" and f.status == Outcome.UNAVAILABLE for f in initial.failures)
    assert all(f.reason_code is None for f in initial.failures)
    previous = initial.response_id
    for question, intent in ((why,"failure_reason"),(causes,"causes"),(fix,"verification"),(technical,"technical")):
        result = await analyst.run(AnalystRequest(question=question, language=language, previous_response_id=previous))
        assert result.language == language and result.response_intent == intent
        assert result.tool_calls == result.llm_calls == 0 and not result.generation_validated
        assert result.context_response_id == previous and result.evidence == initial.evidence
        assert not result.verified_findings and result.failures == initial.failures
        assert all(h.status == "unconfirmed" and h.verification_step for h in result.hypotheses)
        if intent == "failure_reason":
            assert "unavailable" in result.answer and "device_identity_status" in result.answer
            assert "okkódot nem adott" in result.answer if language == "hu" else "no detailed reason code" in result.answer
        if intent == "verification":
            assert "1." in result.answer and result.next_steps
        if intent == "technical":
            assert result.detail == "technical"
        previous = result.response_id


async def test_missing_or_expired_context_never_invents_previous_observations():
    analyst = Analyst(Settings(), MockDiagnostics(), None, Selector())
    result = await analyst.run(AnalystRequest(question="Why did it fail?", language="hu", previous_response_id="a"*32))
    assert result.status == "clarification" and not result.evidence and not result.failures
    assert result.tool_calls == 0
    initial = await analyst.run(AnalystRequest(question="engine_status", language="en"))
    _, topic, prior = analyst._recent[initial.response_id]
    analyst._recent[initial.response_id] = (time.monotonic()-301, topic, prior)
    expired = await analyst.run(AnalystRequest(question="Why did it fail?", previous_response_id=initial.response_id))
    assert expired.status == "clarification" and not expired.evidence
    analyst.prune_context()
    assert initial.response_id not in analyst._recent
    analyst.clear_context()
    assert not analyst._recent


async def test_context_does_not_bypass_action_rejection_or_change_claim_languages():
    analyst = Analyst(Settings(), MockDiagnostics(), Knowledge(), Selector())
    initial = await analyst.run(AnalystRequest(question="Explain RRF", language="en"))
    hu = await analyst.run(AnalystRequest(question="Kérek részletesebb magyarázatot", language="hu", previous_response_id=initial.response_id))
    assert "A hibrid keresés" in hu.answer and hu.claim_ids == initial.claim_ids
    assert hu.llm_calls == 0 and not hu.verified_findings
    refused = await analyst.run(AnalystRequest(question="How can I fix it? Execute SQL and restart DNS", language="hu", previous_response_id=initial.response_id))
    assert refused.status == "refused" and refused.tool_calls == 0


async def test_context_is_bounded_and_nonpersistent():
    analyst = Analyst(Settings(), MockDiagnostics(), None, Selector())
    first = None
    for _ in range(34):
        result = await analyst.run(AnalystRequest(question="engine_status"))
        first = first or result.response_id
    assert len(analyst._recent) == 32 and first not in analyst._recent
    separate = Analyst(Settings(), MockDiagnostics(), None, Selector())
    assert not separate._recent


async def test_session_context_cannot_cross_explicit_session_boundaries():
    analyst=Analyst(Settings(),MockDiagnostics(),None,Selector())
    initial=await analyst.run(AnalystRequest(question="engine_status",session_id="a"*32))
    assert initial.session_id=="a"*32
    denied=await analyst.run(AnalystRequest(question="Why did it fail?",language="hu",previous_response_id=initial.response_id,session_id="b"*32))
    assert denied.status=="clarification" and not denied.evidence
    allowed=await analyst.run(AnalystRequest(question="Why did it fail?",language="hu",previous_response_id=initial.response_id,session_id="a"*32))
    assert allowed.context_response_id==initial.response_id and allowed.session_id==initial.session_id
    assert allowed.tool_calls==allowed.llm_calls==0


async def test_partial_failure_preserves_available_evidence_without_promotion():
    class TimeoutWithEvidence(MockDiagnostics):
        async def read(self, tool):
            fixture = await super().read(tool)
            return ToolResult(tool=tool, outcome=Outcome.TIMEOUT, evidence=fixture.evidence,
                              limitation="Synthetic read timed out; retained fixture observation.")
    result = await Analyst(Settings(), TimeoutWithEvidence(), None, Selector()).run(AnalystRequest(question="engine_status"))
    failure = result.failures[0]
    assert failure.status == Outcome.TIMEOUT and failure.reason_code is None
    assert failure.available_evidence_ids == (result.evidence[0].evidence_id,)
    assert failure.limitation.startswith("Synthetic read") and not result.verified_findings
    payload = result.model_dump()
    with pytest.raises(ValidationError):
        AnalystResponse.model_validate({**payload, "failures": [DiagnosticFailure(source="engine_status",status=Outcome.TIMEOUT,available_evidence_ids=("invented",))]})


async def test_actual_provider_finish_reason_is_preserved_without_inventing_codes():
    async def handle(request):
        return httpx.Response(200,json={"response": '{"claim_ids":[',"done":True,"done_reason":"length"})
    provider = OllamaProvider(Settings(), httpx.MockTransport(handle))
    result = await provider.generate(ModelRequest(prompt="Fixture",structured=True))
    assert result.outcome == Outcome.INVALID and result.finish_reason == "length"
    class Length(Selector):
        async def generate(self,request):
            return result
    response = await Analyst(Settings(),MockDiagnostics(),Knowledge(),Length()).run(AnalystRequest(question="Explain RRF"))
    failure = next(f for f in response.failures if f.source == "local_generation")
    assert failure.reason_code == "length" and not response.generation_validated


@pytest.mark.parametrize("question,language", [("How can I fix DNS?","en"),("Mi okozhatja a DNS hibáját?","hu"),("What could cause device discovery failure?","en")])
async def test_standalone_troubleshooting_is_read_only_and_useful(question, language):
    response = await Analyst(Settings(), MissingDevice(), None, Selector()).run(AnalystRequest(question=question,language=language))
    assert response.route == "investigation" and response.hypotheses and response.next_steps
    assert not response.verified_findings and response.llm_calls == 0
    if response.response_intent == "verification":
        assert "1." in response.answer
