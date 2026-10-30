import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

from pydantic import AwareDatetime, Field, model_validator

from ..schemas import Contract
from .contracts import Chunk, RetrievalError, tokens


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class Source(Contract):
    path: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    title: str = Field(min_length=1, max_length=128)
    category: str = Field(pattern=r"^[a-z0-9-]{1,40}$")
    timestamp: AwareDatetime
    approved: bool = Field(strict=True)


class Manifest(Contract):
    schema_version: int = Field(default=1, ge=1, le=1)
    namespace: str = Field(pattern=r"^[a-z0-9-]{1,40}$")
    chunk_size: int = Field(default=900, ge=80, le=2000)
    overlap: int = Field(default=120, ge=0, le=1000)
    sources: tuple[Source, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def safe_shape(self):
        if self.overlap >= self.chunk_size or len({s.path.casefold() for s in self.sources}) != len(self.sources):
            raise ValueError("Invalid manifest")
        return self


def approved_path(root: Path, relative: str) -> Path:
    # Restrict portable paths: no drives, UNC, alternate streams, dot segments or globs.
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", relative):
        raise RetrievalError("invalid_source")
    parts = PurePosixPath(relative).parts
    if not parts or any(p in (".", "..") or p.startswith(".") for p in relative.split("/")):
        raise RetrievalError("invalid_source")
    if PurePosixPath(relative).is_absolute() or Path(relative).suffix.lower() not in (".md", ".txt"):
        raise RetrievalError("invalid_source")
    root = root.resolve(strict=True)
    current = root
    for part in parts:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RetrievalError("invalid_source")
    if not current.resolve(strict=True).is_relative_to(root) or not current.is_file():
        raise RetrievalError("invalid_source")
    if any(word in current.name.casefold() for word in ("secret", "credential", "token", "password", ".log")):
        raise RetrievalError("invalid_source")
    return current


SECRET_PATTERN = re.compile(r"-----BEGIN .*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._-]{12,}|"
                            r"(?:api[_-]?key|password|credential|access[_-]?token)\s*[:=]\s*\S+", re.I)


def ingest(root: Path, manifest: Manifest) -> tuple[tuple[Chunk, ...], str]:
    chunks, hashes, total = [], set(), 0
    try:
        for source in sorted(manifest.sources, key=lambda s: s.path):
            if source.approved is not True:
                raise RetrievalError("invalid_source")
            path = approved_path(root, source.path)
            with path.open("rb") as stream:
                data = stream.read(262145)
            total += len(data)
            if len(data) > 262144 or total > 4194304 or digest(data) != source.sha256:
                raise RetrievalError("invalid_source")
            text = data.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
            if not tokens(text) or "\x00" in text or SECRET_PATTERN.search(text):
                raise RetrievalError("invalid_source")
            content_hash = digest(text.encode())
            if content_hash in hashes:
                raise RetrievalError("duplicate_document")
            hashes.add(content_hash)
            source_id = digest(canonical([manifest.namespace, source.path]))
            for start in range(0, len(text), manifest.chunk_size - manifest.overlap):
                content = text[start:start + manifest.chunk_size]
                if not tokens(content):
                    continue
                chunk_id = digest(canonical([source_id, content_hash, start, manifest.chunk_size, manifest.overlap]))
                chunks.append(Chunk(source_id=source_id, chunk_id=chunk_id, content=content,
                    source_reference=f"corpus://{manifest.namespace}/{source.path}", title=source.title,
                    category=source.category, timestamp=source.timestamp, start=start, end=start + len(content)))
                if len(chunks) > 2000:
                    raise RetrievalError("invalid_source")
                if start + manifest.chunk_size >= len(text):
                    break
        if not chunks:
            raise RetrievalError("invalid_source")
        manifest_data = manifest.model_dump(mode="json")
        manifest_data["sources"] = sorted(manifest_data["sources"], key=lambda s: s["path"])
        version = digest(canonical({"manifest": manifest_data,
                                    "chunks": [c.model_dump(mode="json") for c in chunks]}))
        return tuple(chunks), version
    except RetrievalError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise RetrievalError("invalid_source") from None
