import asyncio
import json
import os
from pathlib import Path
import tempfile

import numpy as np
from pydantic import Field, ValidationError

from ..schemas import Contract
from .contracts import Chunk, RetrievalError
from .corpus import Manifest, canonical, digest, ingest
from .embeddings import Embedder, vectors


class Snapshot(Contract):
    schema_version: int = Field(default=1, ge=1, le=1)
    corpus_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    model_id: str = Field(min_length=1, max_length=256)
    dimension: int = Field(ge=1, le=1536)
    chunks: tuple[Chunk, ...] = Field(min_length=1, max_length=2000)
    embeddings: tuple[tuple[float, ...], ...] = Field(min_length=1, max_length=2000)


def validate_snapshot(snapshot: Snapshot) -> np.ndarray:
    ids = [c.chunk_id for c in snapshot.chunks]
    if len(set(ids)) != len(ids) or any(c.end - c.start != len(c.content) for c in snapshot.chunks):
        raise RetrievalError("corrupt_index")
    try:
        return vectors(snapshot.embeddings, len(snapshot.chunks), snapshot.dimension)
    except RetrievalError:
        raise RetrievalError("corrupt_index") from None


def save(path: Path, snapshot: Snapshot):
    validate_snapshot(snapshot)
    payload = snapshot.model_dump(mode="json")
    envelope = canonical({"checksum": digest(canonical(payload)), "snapshot": payload})
    if len(envelope) > 64 * 1024 * 1024:
        raise RetrievalError("corrupt_index")
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    temporary = None
    acquired = False
    try:
        lock.open("x").close()
        acquired = True
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".index-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(envelope)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except FileExistsError:
        raise RetrievalError("index_busy") from None
    finally:
        if acquired:
            lock.unlink(missing_ok=True)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load(path: Path, model_id: str | None = None, expected_version: str | None = None) -> Snapshot:
    if not path.is_file():
        raise RetrievalError("index_unavailable")
    try:
        with path.open("rb") as stream:
            raw = stream.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError()
        envelope = json.loads(raw)
        if set(envelope) != {"checksum", "snapshot"} or digest(canonical(envelope["snapshot"])) != envelope["checksum"]:
            raise ValueError()
        snapshot = Snapshot.model_validate(envelope["snapshot"])
        validate_snapshot(snapshot)
        if model_id is not None and snapshot.model_id != model_id:
            raise RetrievalError("incompatible_index")
        if expected_version is not None and snapshot.corpus_version != expected_version:
            raise RetrievalError("stale_corpus")
        return snapshot
    except RetrievalError:
        raise
    except (OSError, ValueError, TypeError, KeyError, ValidationError):
        raise RetrievalError("corrupt_index") from None


async def rebuild(root: Path, manifest: Manifest, embedder: Embedder, path: Path) -> Snapshot:
    # Complete rebuild makes update/deletion atomic; failures retain the old snapshot.
    chunks, version = ingest(root, manifest)
    batches = []
    for start in range(0, len(chunks), 16):
        batch = tuple(c.content for c in chunks[start:start + 16])
        batches.extend(vectors(await embedder.embed(batch), len(batch), embedder.dimension).tolist())
    snapshot = Snapshot(corpus_version=version, model_id=embedder.identifier, dimension=embedder.dimension,
                        chunks=chunks, embeddings=tuple(tuple(row) for row in batches))
    await asyncio.to_thread(save, path, snapshot)
    return snapshot
