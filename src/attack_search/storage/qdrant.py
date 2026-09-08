"""Collection management and writes; never delete old snapshot collections."""

import os
import re
from contextlib import closing

from qdrant_client import QdrantClient, models

from attack_search.embeddings.lexical import (
    LEXICAL_METADATA_KEY,
    LEXICAL_VECTOR,
    bm25_document,
    lexical_profile,
    lexical_text,
)
from attack_search.embeddings.profile import ALIAS, DIMENSIONS

KEYWORD_FIELDS = (
    "type",
    "db_table",
    "db_id",
    "document_id",
    "dataset_snapshot",
    "technique_ids",
    "technique_attack_ids",
    "active_technique_ids",
    "related_platforms",
)


def create_qdrant_client() -> QdrantClient:
    return QdrantClient(
        url=os.environ["QDRANT_URL"],
        api_key=os.environ["QDRANT_API_KEY"],
        timeout=60,
        cloud_inference=True,
    )


def prepare_collection(qdrant: QdrantClient, collection: str) -> None:
    if not qdrant.collection_exists(collection):
        qdrant.create_collection(
            collection,
            vectors_config=models.VectorParams(
                size=DIMENSIONS, distance=models.Distance.COSINE, on_disk=True
            ),
        )
    validate_dense_collection(qdrant, collection)
    indexed_fields = qdrant.get_collection(collection).payload_schema
    for field in KEYWORD_FIELDS:
        if field not in indexed_fields:
            qdrant.create_payload_index(
                collection, field, models.PayloadSchemaType.KEYWORD, wait=True
            )
    if "is_active" not in indexed_fields:
        qdrant.create_payload_index(
            collection, "is_active", models.PayloadSchemaType.BOOL, wait=True
        )


def validate_dense_collection(qdrant, collection: str, info=None) -> None:
    config = (info or qdrant.get_collection(collection)).config.params.vectors
    if (
        not isinstance(config, models.VectorParams)
        or config.size != DIMENSIONS
        or config.distance != models.Distance.COSINE
    ):
        raise ValueError("Existing Qdrant collection has incompatible vector configuration")


def lexical_manifest(documents: list[dict]) -> dict:
    snapshots = {doc["payload"]["dataset_snapshot"] for doc in documents}
    if len(snapshots) != 1:
        raise ValueError("Lexical index requires one nonempty document snapshot")
    if len({doc["id"] for doc in documents}) != len(documents):
        raise ValueError("Lexical document IDs must be unique")
    return {
        "profile": lexical_profile(),
        "dataset_snapshot": snapshots.pop(),
        "expected_points": len(documents),
    }


def prepare_lexical_collection(qdrant, collection: str, documents: list[dict]) -> None:
    """Add only the sparse schema and its manifest; preserve dense configuration."""
    manifest = lexical_manifest(documents)
    info = qdrant.get_collection(collection)
    validate_dense_collection(qdrant, collection, info)
    sparse = (info.config.params.sparse_vectors or {}).get(LEXICAL_VECTOR)
    previous = (info.config.metadata or {}).get(LEXICAL_METADATA_KEY)
    if sparse is not None:
        if sparse.modifier != models.Modifier.IDF or previous != manifest:
            raise ValueError("Existing lexical vector has an incompatible BM25 profile or snapshot")
        return
    if previous is not None and previous != manifest:
        raise ValueError("Existing lexical metadata has an incompatible BM25 profile or snapshot")
    qdrant.update_collection(
        collection,
        metadata={**(info.config.metadata or {}), LEXICAL_METADATA_KEY: manifest},
    )
    qdrant.create_vector_name(
        collection_name=collection,
        vector_name=LEXICAL_VECTOR,
        vector_name_config=models.SparseVectorNameConfig(
            sparse=models.SparseVectorConfig(modifier=models.Modifier.IDF)
        ),
    )


def require_native_bm25(qdrant) -> None:
    """The application supports native BM25 on Qdrant 1.19 or newer."""
    version = qdrant.info().version
    match = re.match(r"^(\d+)\.(\d+)(?:\.|$)", version)
    if match is None or tuple(map(int, match.groups())) < (1, 19):
        raise ValueError("Native BM25 indexing requires Qdrant server 1.19 or newer")


def ensure_lexical_ready(qdrant, collection: str, info=None) -> None:
    """Reject missing, incompatible or incomplete BM25 data before serving it."""
    info = info or qdrant.get_collection(collection)
    sparse = (info.config.params.sparse_vectors or {}).get(LEXICAL_VECTOR)
    manifest = (info.config.metadata or {}).get(LEXICAL_METADATA_KEY)
    if sparse is None or manifest is None:
        raise ValueError("Lexical index is not ready; run attack-search index-lexical")
    if (
        sparse.modifier != models.Modifier.IDF
        or not isinstance(manifest, dict)
        or manifest.get("profile") != lexical_profile()
        or not isinstance(manifest.get("dataset_snapshot"), str)
        or not manifest["dataset_snapshot"]
        or type(manifest.get("expected_points")) is not int
        or manifest["expected_points"] < 1
    ):
        raise ValueError("Lexical index has an incompatible BM25 profile or manifest")
    count = qdrant.count(collection, exact=True).count
    missing = qdrant.count(
        collection,
        count_filter=models.Filter(must_not=[models.HasVectorCondition(has_vector=LEXICAL_VECTOR)]),
        exact=True,
    ).count
    if count != manifest["expected_points"] or missing:
        raise ValueError("Lexical index is incomplete; rerun attack-search index-lexical")


def validate_document_snapshot(
    qdrant, collection: str, documents: list[dict], batch_size: int, *, progress=None
) -> None:
    """Read-only preflight for a backfill: validate every existing ID and payload."""
    lexical_manifest(documents)
    validate_dense_collection(qdrant, collection)
    if qdrant.count(collection, exact=True).count != len(documents):
        raise ValueError("Qdrant point count differs from PostgreSQL; run the full index first")
    dense_missing = qdrant.count(
        collection,
        count_filter=models.Filter(must_not=[models.HasVectorCondition(has_vector="")]),
        exact=True,
    ).count
    if dense_missing:
        raise ValueError("Existing Qdrant snapshot contains points without dense vectors")
    for start in range(0, len(documents), batch_size):
        batch = documents[start : start + batch_size]
        if missing_documents(qdrant, collection, batch):
            raise ValueError("Qdrant point IDs differ from PostgreSQL; run the full index first")
        for doc in batch:
            lexical_text(doc["payload"])
        if progress is not None:
            progress(start + len(batch), len(documents), "Verified PostgreSQL / Qdrant payloads")


def update_missing_lexical_vectors(qdrant, collection: str, batch: list[dict]) -> int:
    """Resume only absent sparse vectors; never upsert or replace point payloads."""
    existing = {
        str(point.id): point
        for point in qdrant.retrieve(
            collection,
            [doc["id"] for doc in batch],
            with_payload=True,
            with_vectors=[LEXICAL_VECTOR],
        )
    }
    updates = []
    for doc in batch:
        point = existing.get(doc["id"])
        if point is None or point.payload != doc["payload"]:
            raise ValueError(
                "Qdrant snapshot changed during lexical indexing; rerun the full index"
            )
        if not isinstance(point.vector, dict) or LEXICAL_VECTOR not in point.vector:
            updates.append(
                models.PointVectors(
                    id=doc["id"],
                    vector={LEXICAL_VECTOR: bm25_document(lexical_text(doc["payload"]))},
                )
            )
    if updates:
        qdrant.update_vectors(collection, updates, wait=True)
    return len(updates)


def missing_documents(qdrant, collection: str, batch: list[dict]) -> list[dict]:
    existing = {
        str(p.id): p
        for p in qdrant.retrieve(
            collection, [p["id"] for p in batch], with_payload=True, with_vectors=False
        )
    }
    for doc in batch:
        old = existing.get(doc["id"])
        if old and old.payload != doc["payload"]:
            raise ValueError(
                "Existing point payload differs; bump pipeline version before rebuilding"
            )
    return [doc for doc in batch if doc["id"] not in existing]


def upsert_documents(
    qdrant, collection: str, documents: list[dict], vectors: list[list[float]]
) -> None:
    if len(documents) != len(vectors):
        raise ValueError("Each document must have one vector")
    qdrant.upsert(
        collection,
        [
            models.PointStruct(id=doc["id"], vector=vector, payload=doc["payload"])
            for doc, vector in zip(documents, vectors)
        ],
        wait=True,
    )


def publish_alias(collection: str):
    with closing(create_qdrant_client()) as qdrant:
        previous = next((a for a in qdrant.get_aliases().aliases if a.alias_name == ALIAS), None)
        if previous and previous.collection_name == collection:
            return
        if previous and not previous.collection_name.startswith("attack_semantic_v"):
            raise ValueError("Refusing to replace an alias belonging to an unrelated collection")
        operations = []
        if previous:
            operations.append(
                models.DeleteAliasOperation(delete_alias=models.DeleteAlias(alias_name=ALIAS))
            )
        operations.append(
            models.CreateAliasOperation(
                create_alias=models.CreateAlias(collection_name=collection, alias_name=ALIAS)
            )
        )
        qdrant.update_collection_aliases(operations)
