import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from test_gate1 import offline
from hostsguardian_ai.analyst_contracts import AnalystRequest, AnalystResponse, DiagnosticHypothesis, EvidenceRecord
from hostsguardian_ai.config import Settings
from hostsguardian_ai.diagnostics import MockDiagnostics
from hostsguardian_ai.knowledge import CLAUSES, knowledge_query, select_clauses
from hostsguardian_ai.orchestration import Analyst
from hostsguardian_ai.providers import MockProvider, ModelResponse
from hostsguardian_ai.retrieval.contracts import Chunk, RankedChunk, RetrievalResponse
from hostsguardian_ai.schemas import Outcome
from hostsguardian_ai.hypotheses import diagnostic_hypotheses


class Knowledge:
    async def search(self, request):
        content = "Hybrid retrieval combines BM25 keyword ranking and semantic embedding similarity. Reciprocal Rank Fusion adds reciprocal rank contributions from each ranking."
        chunk = Chunk(source_id="a"*64, chunk_id="b"*64, content=content,
            source_reference="corpus://public/retrieval.md", title="Hybrid retrieval", category="reference",
            timestamp=datetime(2026, 10, 30, tzinfo=timezone.utc), start=0, end=len(content))
        return RetrievalResponse(outcome="success", corpus_version="c"*64, results=(RankedChunk(
            chunk=chunk, corpus_version="c"*64, fusion_score=.03),))


class Selector(MockProvider):
    def __init__(self):
        self.prompts = []
    async def generate(self, request):
        assert request.output_schema["additionalProperties"] is False
        self.prompts.append(request.prompt)
        return ModelResponse(provider="mock", outcome=Outcome.SUCCESS,
                             text=json.dumps({"claim_ids": ["fusion", "rrf"]}))


@pytest.mark.parametrize("question", ["Explain hybrid RAG and RRF", "Mi az RRF?"])
async def test_explicit_language_precedes_question_without_permission_change(question):
    provider = Selector()
    analyst = Analyst(Settings(), MockDiagnostics(), Knowledge(), provider)
    hu = await analyst.run(AnalystRequest(question=question, language="hu"))
    en = await analyst.run(AnalystRequest(question=question, language="en"))
    assert hu.language == "hu" and en.language == "en"
    assert "A hibrid keresés" in hu.answer and "Hybrid search" not in hu.answer
    assert "Hybrid search" in en.answer and "A hibrid keresés" not in en.answer
    assert hu.claim_ids == en.claim_ids and hu.evidence == en.evidence
    assert hu.tools_used == en.tools_used == ("knowledge_retrieval",)
    assert provider.prompts[0] == provider.prompts[1]
    assert hu.generation_validated and en.generation_validated
    assert not hu.verified_findings and not en.verified_findings


async def test_rendered_claim_must_have_exact_support_and_matching_language():
    result = await Analyst(Settings(), MockDiagnostics(), Knowledge(), Selector()).run(
        AnalystRequest(question="Explain RRF", language="hu"))
    payload = result.model_dump(mode="json")
    for changes in ({"claim_ids": ["invented"]}, {"passages": []}, {"answer": "An unrelated English claim."}, {"language": "en"}):
        with pytest.raises(ValidationError):
            AnalystResponse.model_validate({**payload, **changes})


def test_bilingual_normalization_is_bounded_and_domain_specific():
    assert knowledge_query("Mi az RRF?") == knowledge_query("Explain hybrid RAG and RRF")
    assert knowledge_query("Magyarázd el a DNS szabályzatot") == knowledge_query("Explain DNS policy")
    assert len(knowledge_query("unknown "*100)) <= 256
    assert "policy" in knowledge_query("DNS policy")
    with pytest.raises(ValueError):
        select_clauses(["invented"], [])


@pytest.mark.parametrize("language", ["hu", "en"])
async def test_language_never_grants_write_permissions(language):
    result = await Analyst(Settings(), MockDiagnostics(), Knowledge(), Selector()).run(
        AnalystRequest(question="Delete policy and execute SQL", language=language))
    assert result.status == "refused" and result.tool_calls == result.llm_calls == 0


async def test_unapproved_model_claim_is_rejected_with_uncertainty():
    class Bad(Selector):
        async def generate(self, request):
            return ModelResponse(provider="mock", outcome=Outcome.SUCCESS, text='{"claim_ids":["verified_enforcement"]}')
    response = await Analyst(Settings(), MockDiagnostics(), Knowledge(), Bad()).run(
        AnalystRequest(question="Explain RRF", language="hu"))
    assert not response.generation_validated and not response.claim_ids
    assert not response.verified_findings and response.status == "partial"


def test_invalid_explicit_language_rejected():
    with pytest.raises(ValidationError):
        AnalystRequest(question="Explain RRF", language="auto")


async def test_missing_evidence_still_allows_labeled_useful_hypotheses_in_ui_language():
    class Missing:
        async def read(self, tool):
            from hostsguardian_ai.schemas import ToolResult
            return ToolResult(tool=tool, outcome=Outcome.UNAVAILABLE)
    analyst = Analyst(Settings(), Missing(), None, Selector())
    hu = await analyst.run(AnalystRequest(question="Why is YouTube not blocked on my TV?", language="hu"))
    en = await analyst.run(AnalystRequest(question="Why is YouTube not blocked on my TV?", language="en"))
    assert hu.status == en.status == "unknown"
    assert hu.hypotheses and en.hypotheses and not hu.verified_findings
    assert [h.hypothesis_id for h in hu.hypotheses] == [h.hypothesis_id for h in en.hypotheses]
    assert hu.tools_used == en.tools_used and hu.tool_calls == en.tool_calls
    assert "Nem igazolt lehetőségek" in hu.answer and "Unconfirmed possibilities" in en.answer
    assert all(h.status == "unconfirmed" and h.basis == "general_networking_knowledge" and not h.evidence_ids for h in hu.hypotheses)
    assert all(h.verification_step for h in hu.hypotheses) and hu.next_steps
    assert not hu.generation_validated and hu.llm_calls == 0


def test_hypotheses_never_invent_citations_confidence_or_contradict_verified_input():
    base = dict(hypothesis_id="test", basis="general_networking_knowledge", statement="Possible issue.", verification_step="Inspect existing status.")
    for extras in ({"confidence": 0.99}, {"evidence_ids": ["made-up"]}, {"status": "verified"}):
        with pytest.raises(ValidationError):
            DiagnosticHypothesis(**{**base, **extras})
    verified = EvidenceRecord(evidence_id="verified1", kind="verified_operational", verification="verified",
        source_reference="approved-adapter://status", timestamp=datetime.now(timezone.utc), content="Verified observation.")
    assert diagnostic_hypotheses("Why is DNS failing?", "hu", [verified], "technical") == ()


async def test_unrelated_reference_cannot_support_generated_claim():
    class WrongKnowledge(Knowledge):
        async def search(self, request):
            result = await super().search(request)
            chunk = result.results[0].chunk.model_copy(update={"content": "Unrelated material; no approved clause is supported."})
            return result.model_copy(update={"results": (result.results[0].model_copy(update={"chunk": chunk}),)})
    response = await Analyst(Settings(), MockDiagnostics(), WrongKnowledge(), Selector()).run(
        AnalystRequest(question="Explain RRF", language="hu"))
    assert not response.claim_ids and not response.generation_validated


async def test_small_context_and_claim_allowlist_remain_bounded():
    class FirstOnly(Selector):
        async def generate(self, request):
            data = json.loads(request.prompt.split("\n", 1)[1])
            assert len(json.dumps(data, ensure_ascii=False)) <= 512
            allowed = request.output_schema["properties"]["claim_ids"]["items"]["enum"]
            return ModelResponse(provider="mock", outcome=Outcome.SUCCESS, text=json.dumps({"claim_ids": [allowed[0]]}))
    result = await Analyst(Settings(generation_context_chars=512), MockDiagnostics(), Knowledge(), FirstOnly()).run(
        AnalystRequest(question="Explain RRF", language="hu"))
    assert result.generation_validated and result.passages
