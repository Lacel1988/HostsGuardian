"""Reproducible offline real-model evaluation; never invoked by API startup."""
import argparse
import asyncio
import json
from pathlib import Path
import statistics
import threading
import time

import numpy as np
import psutil

from .contracts import RetrievalRequest
from .corpus import Manifest
from .embeddings import LocalEmbedder
from .index import load, rebuild
from .service import RetrievalService


async def evaluate(data: Path, model: Path, output: Path, index: Path):
    queries = json.loads((data / "queries.json").read_text(encoding="utf-8"))
    manifest = Manifest.model_validate_json((data / "manifest.json").read_bytes())
    stop, peak = threading.Event(), [0]
    parent = psutil.Process()

    def sample():
        while not stop.is_set():
            total = 0
            for process in [parent, *parent.children(recursive=True)]:
                try:
                    total += process.memory_info().rss
                except psutil.Error:
                    pass
            peak[0] = max(peak[0], total)
            stop.wait(0.02)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    embedder = None
    started = time.perf_counter()
    try:
        embedder = LocalEmbedder(model, timeout=15)
        index_start = time.perf_counter()
        snapshot = await rebuild(data / "corpus", manifest, embedder, index)
        index_seconds = time.perf_counter() - index_start
        # Verify repeat embeddings and atomic persisted rebuild agree within float tolerance.
        first = await embedder.embed(("A repeatable local embedding.",))
        second = await embedder.embed(("A repeatable local embedding.",))
        reproducible = bool(np.allclose(first, second, rtol=0, atol=1e-7))
        service = RetrievalService(load(index, embedder.identifier, snapshot.corpus_version), embedder)
        metrics, judgments = {}, {}
        for mode in ("lexical", "semantic", "hybrid"):
            recalls, reciprocal, latencies, details = [], [], [], []
            for item in queries["positive"]:
                for repetition in range(3):
                    query_start = time.perf_counter()
                    result = await service.search_mode(RetrievalRequest(query=item["query"], top_k=queries["top_k"]), mode)
                    latencies.append((time.perf_counter() - query_start) * 1000)
                names = [r.chunk.source_reference.rsplit("/", 1)[1] for r in result.results]
                relevant = set(item["relevant"])
                recalls.append(len(set(names) & relevant) / len(relevant))
                reciprocal.append(next((1 / (i + 1) for i, name in enumerate(names) if name in relevant), 0))
                details.append({"query": item["query"], "relevant": item["relevant"], "returned": names})
            unknowns = []
            for query in queries["unknown"]:
                result = await service.search_mode(RetrievalRequest(query=query, top_k=3), mode)
                unknowns.append(result.outcome == "insufficient_evidence" and not result.results)
            metrics[mode] = {"recall_at_3": statistics.mean(recalls), "mrr_at_3": statistics.mean(reciprocal),
                "warm_p50_ms": statistics.median(latencies), "warm_p95_ms": float(np.percentile(latencies, 95)),
                "unknown_empty_rate": statistics.mean(unknowns)}
            judgments[mode] = details
        stop.set()
        sampler.join(timeout=1)
        thresholds = queries["thresholds"]
        checks = {f"{mode}_{metric}": metrics[mode][metric] >= thresholds[f"{mode}_{metric}"]
                  for mode in metrics for metric in ("recall_at_3", "mrr_at_3")}
        checks.update({f"{mode}_unknown": values["unknown_empty_rate"] >= thresholds["unknown_empty_rate"]
                       for mode, values in metrics.items()})
        checks.update({f"{mode}_latency": values["warm_p95_ms"] <= thresholds["warm_p95_ms"]
                       for mode, values in metrics.items()})
        checks.update(index_latency=index_seconds <= thresholds["index_seconds"],
                      memory=peak[0] / 1048576 <= thresholds["peak_tree_rss_mib"], reproducibility=reproducible)
        result = {"schema_version": 1, "real_model": True, "model": embedder.identifier,
            "dimension": embedder.dimension, "corpus_version": snapshot.corpus_version,
            "documents": len(manifest.sources), "chunks": len(snapshot.chunks), "positive_queries": len(queries["positive"]),
            "unknown_queries": len(queries["unknown"]), "top_k": queries["top_k"], "thresholds": thresholds,
            "metrics": metrics, "index_seconds": index_seconds, "index_bytes": index.stat().st_size,
            "peak_tree_rss_mib": peak[0] / 1048576, "elapsed_seconds": time.perf_counter() - started,
            "checks": checks, "pass": all(checks.values()), "judgments": judgments}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps({k: result[k] for k in ("pass", "metrics", "index_seconds", "peak_tree_rss_mib", "checks")}))
        return result
    finally:
        stop.set()
        sampler.join(timeout=1)
        if embedder is not None:
            embedder.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("data", "model", "output", "index"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(evaluate(args.data, args.model, args.output, args.index))
    raise SystemExit(0 if result["pass"] else 1)


if __name__ == "__main__":
    main()
