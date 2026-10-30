import asyncio
from typing import Protocol

import numpy as np
from rank_bm25 import BM25L

from .contracts import RankedChunk, RetrievalError, RetrievalRequest, RetrievalResponse, tokens
from .embeddings import Embedder, vectors
from .index import Snapshot, validate_snapshot


class Retrieval(Protocol):
    async def search(self, request: RetrievalRequest) -> RetrievalResponse: ...


def rrf(lexical: list[tuple[int, float]], semantic: list[tuple[int, float]], constant: int) -> dict[int, float]:
    if not 1 <= constant <= 1000:
        raise ValueError("Invalid RRF constant")
    scores = {}
    for ranking in (lexical, semantic):
        seen = set()
        for item, _ in ranking:
            if item in seen:
                continue
            seen.add(item)
            scores[item] = scores.get(item, 0) + 1 / (constant + len(seen))
    return scores


class RetrievalService:
    def __init__(self, snapshot: Snapshot, embedder: Embedder, rrf_constant=60,
                 min_similarity=0.35, timeout=10, concurrency=2):
        if snapshot.model_id != embedder.identifier or snapshot.dimension != embedder.dimension:
            raise RetrievalError("incompatible_index")
        if not 1 <= rrf_constant <= 1000 or not -1 <= min_similarity <= 1 or not 1 <= concurrency <= 16 or not 0 < timeout <= 120:
            raise ValueError("Invalid retrieval limits")
        self.snapshot, self.embedder = snapshot, embedder
        self.matrix = validate_snapshot(snapshot)
        # BM25L keeps positive IDF for small/single-document corpora. Okapi's
        # negative IDF floor can suppress exact matches in these approved corpora.
        self.bm25 = BM25L([tokens(c.content) for c in snapshot.chunks])
        self.rrf_constant, self.min_similarity = rrf_constant, min_similarity
        self.timeout, self.concurrency, self.active = timeout, concurrency, 0

    async def search(self, request: RetrievalRequest) -> RetrievalResponse:
        return await self.search_mode(request, "hybrid")

    async def search_mode(self, request: RetrievalRequest, mode: str) -> RetrievalResponse:
        # Internal mode selection supports evaluation, not model-controlled permissions.
        if mode not in ("hybrid", "lexical", "semantic"):
            raise ValueError("Unknown retrieval mode")
        request = RetrievalRequest.model_validate(request)
        if self.active >= self.concurrency:
            raise RetrievalError("embedding_busy")
        self.active += 1
        try:
            async with asyncio.timeout(self.timeout):
                return await self._search(request, mode)
        except TimeoutError:
            raise RetrievalError("embedding_timeout") from None
        finally:
            self.active -= 1

    async def _search(self, request, mode):
        chunks = self.snapshot.chunks
        candidates = [i for i, c in enumerate(chunks)
                      if (not request.filters.source_ids or c.source_id in request.filters.source_ids)
                      and (request.filters.category is None or c.category == request.filters.category)]
        lexical, semantic, limitations = [], [], []
        pool = min(100, max(20, request.top_k * 4))
        if mode != "semantic":
            scores = self.bm25.get_scores(tokens(request.query))
            lexical = [(i, float(scores[i])) for i in candidates if scores[i] > 0]
            lexical.sort(key=lambda pair: (-pair[1], chunks[pair[0]].chunk_id))
            lexical = lexical[:pool]
        if mode != "lexical" and candidates:
            try:
                query_vector = vectors(await self.embedder.embed((request.query,)), 1, self.embedder.dimension)[0]
                scores = self.matrix @ query_vector
                semantic = [(i, float(scores[i])) for i in candidates if scores[i] >= self.min_similarity]
                semantic.sort(key=lambda pair: (-pair[1], chunks[pair[0]].chunk_id))
                semantic = semantic[:pool]
            except RetrievalError as exc:
                if mode == "semantic" or exc.code == "embedding_busy":
                    raise
                limitations.append(exc.code + ": semantic branch unavailable; lexical results only")
        fused = rrf(lexical, semantic, self.rrf_constant)
        ordered = sorted(fused, key=lambda i: (-fused[i], chunks[i].chunk_id))[:request.top_k]
        lex, vec = dict(lexical), dict(semantic)
        results = tuple(RankedChunk(chunk=chunks[i], corpus_version=self.snapshot.corpus_version,
                        lexical_score=lex.get(i), vector_score=vec.get(i), fusion_score=fused[i]) for i in ordered)
        outcome = "partial" if limitations else "success" if results else "insufficient_evidence"
        if not results:
            limitations.append("No candidates meet the lexical/similarity criteria; operational truth remains unknown.")
        return RetrievalResponse(outcome=outcome, corpus_version=self.snapshot.corpus_version,
                                 results=results, limitations=tuple(limitations))
