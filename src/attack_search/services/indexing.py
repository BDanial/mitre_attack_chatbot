"""Build, upload and publish a semantic snapshot without an HTTP dependency."""

import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

from attack_search.embeddings.client import create_embedding_client, embed_batch
from attack_search.embeddings.documents import build_documents
from attack_search.embeddings.profile import ALIAS, collection_name
from attack_search.progress import show_progress
from attack_search.storage.postgres import load_snapshot
from attack_search.storage.qdrant import (
    create_qdrant_client,
    missing_documents,
    prepare_collection,
    publish_alias,
    upsert_documents,
)


def index_documents(documents, collection: str, *, batch_size: int = 32, workers: int = 4) -> int:
    """Resume existing point IDs and process independent batches."""
    with closing(create_qdrant_client()) as qdrant:
        prepare_collection(qdrant, collection)
        completed = 0
        show_progress(0, len(documents), "Embedding / Qdrant")
        with create_embedding_client() as client:

            def upload_batch(batch):
                missing = missing_documents(qdrant, collection, batch)
                if missing:
                    vectors = embed_batch(
                        client, [doc["payload"]["embedding_text"] for doc in missing]
                    )
                    upsert_documents(qdrant, collection, missing, vectors)
                return len(batch), len(missing)

            batches = [
                documents[start : start + batch_size]
                for start in range(0, len(documents), batch_size)
            ]
            executor = ThreadPoolExecutor(max_workers=workers)
            try:
                for size, stored in executor.map(upload_batch, batches):
                    completed += size
                    show_progress(
                        completed, len(documents), f"Stored {stored}, resumed {size - stored}"
                    )
            finally:
                executor.shutdown(wait=True, cancel_futures=True)
        if sys.stdout.isatty():
            print()
        return qdrant.count(collection, exact=True).count


def run_index(
    database_url: str,
    *,
    dry_run: bool = False,
    limit: int | None = None,
    batch_size: int = 32,
    workers: int = 4,
) -> None:
    """Publish only a complete index that still matches PostgreSQL."""
    if batch_size < 1 or workers < 1 or (limit is not None and limit < 1):
        raise ValueError("batch-size, workers and limit must be positive")
    print("Reading PostgreSQL snapshot...", flush=True)
    tables, snapshot = load_snapshot(database_url)
    documents = build_documents(tables, snapshot)
    if not documents:
        raise ValueError("No documents to index")
    collection = collection_name(snapshot)
    counts = dict(sorted(Counter(doc["payload"]["type"] for doc in documents).items()))
    print(
        json.dumps(
            {
                "collection": collection,
                "snapshot": snapshot,
                "points": len(documents),
                "types": counts,
                "input_bytes": sum(len(d["payload"]["embedding_text"].encode()) for d in documents),
            },
            indent=2,
        ),
        flush=True,
    )
    if dry_run:
        return
    for key in ("OPENROUTER_API_KEY", "QDRANT_URL", "QDRANT_API_KEY"):
        if not os.environ.get(key):
            raise ValueError(f"Set {key} in the environment")
    count = index_documents(
        documents[:limit] if limit else documents,
        collection,
        batch_size=batch_size,
        workers=workers,
    )
    if limit:
        print(f"Sample uploaded. Collection contains {count:,} points; alias unchanged.")
        return
    if count != len(documents):
        raise ValueError("Final point count mismatch; alias unchanged")
    _, current_snapshot = load_snapshot(database_url)
    if current_snapshot != snapshot:
        raise ValueError(
            "PostgreSQL changed during indexing; alias unchanged. Rerun for the new snapshot."
        )
    publish_alias(collection)
    print(f"Verified {count:,} points. Ready: {ALIAS} -> {collection}", flush=True)
