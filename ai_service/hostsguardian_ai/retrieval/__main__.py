"""Offline administrative rebuild, never exposed through the query API."""
import argparse
import asyncio
from pathlib import Path

from pydantic import ValidationError

from .contracts import RetrievalError
from .corpus import Manifest
from .embeddings import LocalEmbedder
from .index import rebuild


async def build(args):
    embedder = None
    try:
        with args.manifest.open("rb") as stream:
            data = stream.read(131073)
        if len(data) > 131072:
            raise RetrievalError("invalid_source")
        manifest = Manifest.model_validate_json(data)
        embedder = LocalEmbedder(args.model, timeout=30)
        snapshot = await rebuild(args.root, manifest, embedder, args.index)
        print(f"Indexed {len(snapshot.chunks)} chunks; corpus_version={snapshot.corpus_version}")
    except (OSError, ValidationError):
        raise SystemExit("invalid_source") from None
    except RetrievalError as exc:
        raise SystemExit(exc.code) from None
    finally:
        if embedder is not None:
            embedder.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "manifest", "model", "index"):
        parser.add_argument("--" + name, type=Path, required=True)
    asyncio.run(build(parser.parse_args()))


if __name__ == "__main__":
    main()
