"""Collection management and writes; never delete old snapshot collections."""

import os
from contextlib import closing

from qdrant_client import QdrantClient, models

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
        url=os.environ["QDRANT_URL"], api_key=os.environ["QDRANT_API_KEY"], timeout=60
    )


def prepare_collection(qdrant: QdrantClient, collection: str) -> None:
    if not qdrant.collection_exists(collection):
        qdrant.create_collection(
            collection,
            vectors_config=models.VectorParams(
                size=DIMENSIONS, distance=models.Distance.COSINE, on_disk=True
            ),
        )
    config = qdrant.get_collection(collection).config.params.vectors
    if (
        not isinstance(config, models.VectorParams)
        or config.size != DIMENSIONS
        or config.distance != models.Distance.COSINE
    ):
        raise ValueError("Existing Qdrant collection has incompatible vector configuration")
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
