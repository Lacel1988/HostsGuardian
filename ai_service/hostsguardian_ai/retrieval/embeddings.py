import asyncio
import hashlib
import multiprocessing as mp
import os
from pathlib import Path
import threading
from typing import Protocol

import numpy as np

from .contracts import RetrievalError
from .corpus import canonical, digest

MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DIMENSION = 384
FILES = ("config.json", "model.onnx", "special_tokens_map.json", "tokenizer.json", "tokenizer_config.json")


class Embedder(Protocol):
    identifier: str
    dimension: int
    async def embed(self, texts: tuple[str, ...]) -> np.ndarray: ...


def vectors(value, rows: int, dimension: int) -> np.ndarray:
    try:
        array = np.asarray(value, dtype=np.float32)
        if array.shape != (rows, dimension) or not np.isfinite(array).all():
            raise ValueError()
        norms = np.linalg.norm(array, axis=1, keepdims=True)
        if np.any(norms < 1e-9):
            raise ValueError()
        return array / norms
    except (ValueError, TypeError):
        raise RetrievalError("embedding_invalid") from None


def _worker(connection, model_path: str):
    # Model assets must already exist. Neither worker nor API ever downloads.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["DO_NOT_TRACK"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    os.environ["LANGSMITH_TRACING"] = "false"
    import socket
    def deny_network(*args, **kwargs):
        raise OSError("Embedding worker has no network permission")
    socket.socket.connect = deny_network
    socket.socket.connect_ex = deny_network
    socket.getaddrinfo = deny_network
    try:
        from loguru import logger
        logger.remove()
        from fastembed import TextEmbedding
        model = TextEmbedding(MODEL, specific_model_path=model_path, local_files_only=True,
                              threads=2, providers=["CPUExecutionProvider"])
        connection.send(("ready", None))
        while True:
            texts = connection.recv()
            if texts is None:
                break
            result = np.asarray(list(model.embed(texts, batch_size=16, parallel=None)), dtype=np.float32)
            connection.send(("ok", result))
    except Exception:
        try:
            connection.send(("error", None))
        except (OSError, EOFError):
            pass
    finally:
        connection.close()


class LocalEmbedder:
    dimension = DIMENSION

    def __init__(self, model_path: Path, timeout: float = 10):
        self.path = model_path
        self.timeout = timeout
        self._lock = threading.Lock()
        self._process = None
        self._connection = None
        try:
            file_hashes = []
            for name in FILES:
                path = model_path / name
                if not path.is_file() or path.is_symlink() or path.stat().st_size > 100_000_000:
                    raise OSError()
                hasher = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        hasher.update(block)
                file_hashes.append((name, hasher.hexdigest()))
            self.identifier = MODEL + ":" + digest(canonical(file_hashes))
        except OSError:
            raise RetrievalError("embedding_unavailable") from None

    def close(self):
        if self._process is not None:
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=2)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=2)
            self._process.close()
        if self._connection is not None:
            self._connection.close()
        self._process = self._connection = None

    def _receive(self):
        if not self._connection.poll(self.timeout):
            self.close()
            raise RetrievalError("embedding_timeout")
        try:
            status, data = self._connection.recv()
        except (OSError, EOFError):
            self.close()
            raise RetrievalError("embedding_unavailable") from None
        if status == "error":
            self.close()
            raise RetrievalError("embedding_unavailable")
        return data

    def _embed(self, texts):
        if not self._lock.acquire(blocking=False):
            raise RetrievalError("embedding_busy")
        try:
            if self._process is None:
                context = mp.get_context("spawn")
                self._connection, child = context.Pipe()
                self._process = context.Process(target=_worker, args=(child, str(self.path)), daemon=True)
                self._process.start()
                child.close()
                self._receive()
            self._connection.send(texts)
            return vectors(self._receive(), len(texts), self.dimension)
        except (BrokenPipeError, EOFError, OSError):
            self.close()
            raise RetrievalError("embedding_unavailable") from None
        finally:
            self._lock.release()

    async def embed(self, texts: tuple[str, ...]) -> np.ndarray:
        if not 1 <= len(texts) <= 16 or any(not t.strip() or len(t) > 2000 for t in texts):
            raise RetrievalError("embedding_invalid")
        # Cancellation does not release the lock while native code is still running.
        # The worker is terminated by its hard response deadline on a stall.
        return await asyncio.to_thread(self._embed, texts)
