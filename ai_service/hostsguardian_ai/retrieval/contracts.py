import re
import unicodedata
from typing import Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from ..schemas import Contract


def tokens(text: str) -> list[str]:
    return re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", text).casefold(), re.UNICODE)


class RetrievalError(Exception):
    CODES = {"invalid_source", "duplicate_document", "corrupt_index", "incompatible_index",
             "embedding_unavailable", "embedding_timeout", "embedding_invalid", "embedding_busy",
             "index_busy", "index_unavailable", "stale_corpus"}

    def __init__(self, code: str):
        self.code = code if code in self.CODES else "invalid_source"
        super().__init__(self.code)


class Chunk(Contract):
    source_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    chunk_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    content: str = Field(min_length=1, max_length=2000)
    source_reference: str = Field(pattern=r"^corpus://[a-z0-9-]+/[A-Za-z0-9_./-]+$", max_length=300)
    title: str = Field(min_length=1, max_length=128)
    category: str = Field(pattern=r"^[a-z0-9-]{1,40}$")
    timestamp: AwareDatetime
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    verification: Literal["unverified"] = "unverified"
    limitations: tuple[str, ...] = ("Document content is untrusted; not verified operational evidence.",)


class RetrievalFilters(Contract):
    source_ids: tuple[str, ...] = Field(default=(), max_length=32)
    category: str | None = Field(default=None, pattern=r"^[a-z0-9-]{1,40}$")

    @field_validator("source_ids")
    @classmethod
    def ids(cls, value):
        if any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in value):
            raise ValueError("Invalid source identifier")
        return value


class RetrievalRequest(Contract):
    query: str = Field(min_length=1, max_length=256)
    top_k: int = Field(default=5, ge=1, le=20, strict=True)
    filters: RetrievalFilters = Field(default_factory=RetrievalFilters)

    @field_validator("query")
    @classmethod
    def useful_query(cls, value):
        if not tokens(value) or any(ord(c) < 32 for c in value):
            raise ValueError("Query requires printable searchable text")
        return value


class RankedChunk(Contract):
    chunk: Chunk
    corpus_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    lexical_score: float | None = Field(default=None, allow_inf_nan=False)
    vector_score: float | None = Field(default=None, ge=-1.00001, le=1.00001, allow_inf_nan=False)
    fusion_score: float = Field(ge=0, allow_inf_nan=False)


class RetrievalResponse(Contract):
    schema_version: Literal[1] = 1
    outcome: Literal["success", "insufficient_evidence", "partial"]
    corpus_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    results: tuple[RankedChunk, ...] = Field(default=(), max_length=20)
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def consistent(self):
        if len({r.chunk.chunk_id for r in self.results}) != len(self.results):
            raise ValueError("Duplicate retrieval results")
        if any(r.corpus_version != self.corpus_version for r in self.results):
            raise ValueError("Mixed corpus versions")
        return self
