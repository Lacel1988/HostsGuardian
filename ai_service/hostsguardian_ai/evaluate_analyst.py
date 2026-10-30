"""Gate 3 evaluator: missing real generation is explicitly incomplete acceptance."""
import argparse
import asyncio
import json
from pathlib import Path
import statistics
import threading
import time

import numpy as np
import psutil

from .workflow import build_adaptive_workflow
from .analyst_contracts import AnalystRequest
from .config import Settings
from .diagnostics import MockDiagnostics
from .providers import OllamaProvider
from .retrieval.embeddings import LocalEmbedder
from .retrieval.index import load
from .retrieval.service import RetrievalService
from .retrieval.corpus import canonical, digest
from .schemas import Outcome, ToolName, ToolResult


class ScenarioDiagnostics(MockDiagnostics):
    def __init__(self, scenario):
        self.scenario = scenario

    async def read(self, tool):
        if self.scenario == "unavailable":
            return ToolResult(tool=tool, outcome=Outcome.UNAVAILABLE)
        result = await super().read(tool)
        if self.scenario == "conflict":
            return result.model_copy(update={"evidence": (result.evidence[0].model_copy(update={
                "policy_revision": 8 if tool == ToolName.DEVICE else 7}),)})
        return result


class MeasuredOllama(OllamaProvider):
    """Evaluation artifacts only; normal application provider never logs contents."""
    def __init__(self, settings):
        super().__init__(settings)
        self.measurements = []

    async def _request(self, method, path, payload=None, timeout=None):
        started = time.perf_counter()
        result = await super()._request(method, path, payload, timeout)
        if path == "/api/generate":
            self.measurements.append({"wall_ms": (time.perf_counter()-started)*1000,
                "prompt_tokens": result.get("prompt_eval_count"), "output_tokens": result.get("eval_count"),
                "total_duration_ns": result.get("total_duration"), "load_duration_ns": result.get("load_duration"),
                "done_reason": result.get("done_reason"), "raw_output": result.get("response")})
        return result


async def evaluate(args):
    data = json.loads(args.cases.read_text(encoding="utf-8"))
    settings = Settings()
    embedder = LocalEmbedder(args.model_path)
    stop, memory, runtime_memory, combined_memory = threading.Event(), [0], [0], [0]
    parent = psutil.Process()
    runtime = psutil.Process(args.ollama_pid) if args.ollama_pid else None
    def sample():
        while not stop.is_set():
            processes = [parent, *parent.children(recursive=True)]
            total = 0
            for process in processes:
                try:
                    total += process.memory_info().rss
                except psutil.Error:
                    pass
            memory[0] = max(memory[0], total)
            runtime_total = 0
            if runtime is not None:
                try:
                    for process in [runtime, *runtime.children(recursive=True)]:
                        try:
                            runtime_total += process.memory_info().rss
                        except psutil.Error:
                            pass
                except psutil.Error:
                    pass
            runtime_memory[0] = max(runtime_memory[0], runtime_total)
            combined_memory[0] = max(combined_memory[0], total + runtime_total)
            stop.wait(.02)
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    try:
        retrieval = RetrievalService(load(args.index, embedder.identifier), embedder)
        provider = MeasuredOllama(settings)
        available = await provider.availability() == Outcome.SUCCESS
        results, timings = [], []
        review = json.loads(args.review.read_text(encoding="utf-8")) if args.review else {}
        for case in data["cases"]:
            scenario = case.get("scenario")
            analyst = build_adaptive_workflow(settings, ScenarioDiagnostics(scenario),
                                             None if scenario == "unavailable" else retrieval, provider)
            start = time.perf_counter()
            measurement_start = len(provider.measurements)
            response = await analyst.run(AnalystRequest(question=case["question"], language=case.get("response_language", case["language"])))
            timings.append((time.perf_counter() - start) * 1000)
            expected_tools = [t.value for t in ToolName] if case["route"] == "investigation" else []
            if case["route"] == "direct":
                expected_tools = [{"policy_status": "policy_status", "What is the device identity status?": "device_identity_status"}.get(case["question"], "engine_status")]
            elif case["route"] in ("retrieval", "investigation"):
                expected_tools.append("knowledge_retrieval")
                if case["route"] == "investigation" and scenario != "unavailable":
                    expected_tools.append("structured_diagnostic_summary")
            ledger = {e.evidence_id: e for e in response.evidence}
            citations = all(p.evidence_id in ledger and p.quote in ledger[p.evidence_id].content for p in response.passages)
            results.append({"question": case["question"], "route_correct": response.route == case["route"],
                "tool_selection_correct": list(response.tools_used) == expected_tools,
                "adaptation_correct": response.language == case.get("response_language", case["language"]) and response.detail == case["detail"],
                "status_correct": "status" not in case or response.status == case["status"],
                "citation_integrity": citations, "status": response.status, "route": response.route,
                "llm_calls": response.llm_calls, "latency_ms": timings[-1], "passages": len(response.passages),
                "generation_validated": response.llm_calls == 1 and response.generation_validated,
                "response": response.model_dump(mode="json"),
                "response_sha256": digest(canonical(response.model_dump(mode="json"))),
                "generation_measurements": provider.measurements[measurement_start:]})
        mean = lambda key: statistics.mean(row[key] for row in results)
        rejected = [row for row in results if row["route"] == "unsupported"]
        unknown = [row for row, case in zip(results, data["cases"]) if "status" in case]
        metrics = {"routing_accuracy": mean("route_correct"), "tool_selection_accuracy": mean("tool_selection_correct"),
            "citation_integrity": mean("citation_integrity"), "adaptation_accuracy": mean("adaptation_correct"),
            "unsupported_rejection": statistics.mean(r["status"] == "refused" and r["llm_calls"] == 0 for r in rejected),
            "unknown_correctness": statistics.mean(r["status_correct"] for r in unknown),
            "workflow_p95_ms": float(np.percentile(timings, 95)), "peak_tree_rss_mib": memory[0] / 1048576,
            "llm_invocation_frequency": statistics.mean(r["llm_calls"] for r in results),
            "real_generation_cases": sum(r["generation_validated"] for r in results),
            "real_grounding_accuracy": None, "real_generation_latency_ms": None,
            "ollama_peak_rss_mib": runtime_memory[0] / 1048576,
            "combined_peak_rss_mib": combined_memory[0] / 1048576}
        generation_times = [m["wall_ms"] for row in results for m in row["generation_measurements"]]
        if generation_times:
            metrics["real_generation_latency_ms"] = statistics.mean(generation_times)
            metrics["real_generation_p95_ms"] = float(np.percentile(generation_times, 95))
        reviewed = []
        for row in results:
            judgement = review.get(row["response_sha256"])
            if available and row["llm_calls"] == 1 and type(judgement) is bool:
                reviewed.append(judgement and row["generation_validated"])
        attempts = [row for row in results if row["llm_calls"] == 1]
        bilingual = {row["response"]["language"] for row in attempts}
        if len(reviewed) == len(attempts) and len(reviewed) >= data["thresholds"]["real_generation_cases"] and bilingual == {"en", "hu"}:
            metrics["real_grounding_accuracy"] = statistics.mean(reviewed)
        thresholds = data["thresholds"]
        checks = {k: (value <= thresholds[k] if k in ("workflow_p95_ms", "peak_tree_rss_mib") else value >= thresholds[k])
                  for k, value in metrics.items() if k in thresholds and value is not None}
        # Automatic quotation validation proves attribution, not semantic answer correctness.
        # A real-run per-question grounding review is required before accepting this metric.
        checks["real_grounding_review"] = metrics["real_grounding_accuracy"] is not None
        outcome = {"schema_version": 1, "decision": "PASS" if all(checks.values()) else "NO-GO", "real_model_available": available,
            "model_identifier": settings.model, "cases": len(results), "metrics": metrics,
            "thresholds": thresholds, "checks": checks, "results": results,
            "limitation": "Quoted-source integrity is not grounded-answer accuracy. Unreviewed or unavailable real generation leaves acceptance incomplete."}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(outcome, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({k: outcome[k] for k in ("decision", "real_model_available", "metrics", "checks")}))
        return outcome
    finally:
        stop.set()
        sampler.join(timeout=1)
        embedder.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cases", "model-path", "index", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--review", type=Path, help="Trusted review mapping response_sha256 to grounded-answer correctness boolean")
    parser.add_argument("--ollama-pid", type=int, help="Dedicated Ollama parent PID for separate and combined RSS measurements")
    args = parser.parse_args()
    asyncio.run(evaluate(args))


if __name__ == "__main__":
    main()
