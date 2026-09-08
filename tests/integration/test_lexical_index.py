"""Exercise real local Qdrant storage; only native server inference is substituted."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from qdrant_client import QdrantClient, models

from attack_search.embeddings.documents import build_documents
from attack_search.embeddings.lexical import LEXICAL_METADATA_KEY, LEXICAL_VECTOR
from attack_search.embeddings.profile import ALIAS, DIMENSIONS, collection_name
from attack_search.services.indexing import backfill_lexical_documents, run_index_lexical
from attack_search.storage.qdrant import (
    ensure_lexical_ready,
    lexical_manifest,
    prepare_collection,
    prepare_lexical_collection,
    upsert_documents,
)
from tests.fixtures import fixture


@pytest.fixture
def existing_dense(monkeypatch):
    qdrant = QdrantClient(":memory:")
    docs = build_documents(fixture(), "snapshot")[:3]
    collection = collection_name("snapshot")
    prepare_collection(qdrant, collection)
    upsert_documents(qdrant, collection, docs, [[1.0] * DIMENSIONS for _ in docs])
    qdrant.update_collection(collection, metadata={"unrelated": "preserved"})
    monkeypatch.setattr(qdrant, "info", lambda: SimpleNamespace(version="1.19.0"))
    infer = Mock(side_effect=lambda text: models.SparseVector(indices=[11, 23], values=[1.0, 2.0]))
    monkeypatch.setattr("attack_search.storage.qdrant.bm25_document", infer)
    monkeypatch.setattr("attack_search.services.indexing.show_progress", lambda *args: None)
    yield qdrant, docs, collection, infer
    qdrant.close()


def test_additive_backfill_preserves_dense_payload_ids_and_resumes(existing_dense):
    qdrant, docs, collection, infer = existing_dense
    before = qdrant.retrieve(collection, [d["id"] for d in docs], with_vectors=True)
    assert backfill_lexical_documents(qdrant, docs, collection, batch_size=2, workers=1) == 3
    after = qdrant.retrieve(collection, [d["id"] for d in docs], with_vectors=True)
    assert [point.id for point in after] == [point.id for point in before]
    for old, new in zip(before, after):
        assert new.payload == old.payload
        assert new.vector[""] == old.vector
        assert LEXICAL_VECTOR in new.vector
    assert qdrant.get_collection(collection).config.metadata["unrelated"] == "preserved"
    ensure_lexical_ready(qdrant, collection)
    assert backfill_lexical_documents(qdrant, docs, collection, workers=1) == 0
    assert infer.call_count == 3
    # The original unnamed dense query still works after sparse vectors are added.
    assert len(qdrant.query_points(collection, query=[1.0] * DIMENSIONS, limit=3).points) == 3


def test_interrupted_backfill_is_unready_and_resumes_missing_only(existing_dense, monkeypatch):
    qdrant, docs, collection, infer = existing_dense
    original = qdrant.update_vectors
    attempts = 0

    def interrupted(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts >= 2:
            raise RuntimeError("simulated connection interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(qdrant, "update_vectors", interrupted)
    with pytest.raises(RuntimeError, match="interruption"):
        backfill_lexical_documents(qdrant, docs, collection, batch_size=1, workers=1)
    with pytest.raises(ValueError, match="incomplete"):
        ensure_lexical_ready(qdrant, collection)
    monkeypatch.setattr(qdrant, "update_vectors", original)
    infer.reset_mock()
    assert backfill_lexical_documents(qdrant, docs, collection, batch_size=1, workers=1) == 2
    assert infer.call_count == 2
    ensure_lexical_ready(qdrant, collection)


def test_all_payloads_checked_before_any_schema_or_sparse_write(existing_dense):
    qdrant, docs, collection, infer = existing_dense
    docs[-1]["payload"]["title"] = "changed"
    with pytest.raises(ValueError, match="payload differs"):
        backfill_lexical_documents(qdrant, docs, collection, batch_size=1, workers=1)
    infer.assert_not_called()
    assert not qdrant.get_collection(collection).config.params.sparse_vectors


def test_dense_missing_is_rejected_before_sparse_write(existing_dense):
    qdrant, docs, collection, infer = existing_dense
    qdrant.delete_vectors(collection, [""], [docs[-1]["id"]], wait=True)
    with pytest.raises(ValueError, match="without dense vectors"):
        backfill_lexical_documents(qdrant, docs, collection, workers=1)
    infer.assert_not_called()


def test_wrong_count_is_rejected_before_sparse_write(existing_dense):
    qdrant, docs, collection, infer = existing_dense
    with pytest.raises(ValueError, match="point count"):
        backfill_lexical_documents(qdrant, docs[:-1], collection, workers=1)
    infer.assert_not_called()


def test_incompatible_existing_profile_is_never_relabelled(existing_dense):
    qdrant, docs, collection, infer = existing_dense
    prepare_lexical_collection(qdrant, collection, docs)
    bad = deepcopy(lexical_manifest(docs))
    bad["profile"]["options"]["language"] = "french"
    qdrant.update_collection(collection, metadata={LEXICAL_METADATA_KEY: bad})
    with pytest.raises(ValueError, match="incompatible"):
        backfill_lexical_documents(qdrant, docs, collection, workers=1)
    with pytest.raises(ValueError, match="incompatible"):
        ensure_lexical_ready(qdrant, collection)
    assert qdrant.get_collection(collection).config.metadata[LEXICAL_METADATA_KEY] == bad
    infer.assert_not_called()


def test_deleted_point_cannot_make_partial_index_look_ready(existing_dense):
    qdrant, docs, collection, _ = existing_dense
    backfill_lexical_documents(qdrant, docs, collection, workers=1)
    qdrant.delete(collection, [docs[-1]["id"]], wait=True)
    with pytest.raises(ValueError, match="incomplete"):
        ensure_lexical_ready(qdrant, collection)


def test_lexical_cli_rejects_unpublished_or_wrong_snapshot_without_writes(
    existing_dense, monkeypatch
):
    qdrant, docs, collection, infer = existing_dense
    for key in ("QDRANT_URL", "QDRANT_API_KEY"):
        monkeypatch.setenv(key, "unused")
    with (
        patch(
            "attack_search.services.indexing.load_snapshot", return_value=(fixture(), "snapshot")
        ),
        patch("attack_search.services.indexing.create_qdrant_client", return_value=qdrant),
        patch.object(qdrant, "close"),
    ):
        with pytest.raises(ValueError, match="alias does not match"):
            run_index_lexical("unused")
    infer.assert_not_called()
    assert not qdrant.get_collection(collection).config.params.sparse_vectors


def test_lexical_cli_succeeds_without_openrouter_or_alias_change(existing_dense, monkeypatch):
    qdrant, docs, collection, _ = existing_dense
    for key in ("QDRANT_URL", "QDRANT_API_KEY"):
        monkeypatch.setenv(key, "unused")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    qdrant.update_collection_aliases(
        [
            models.CreateAliasOperation(
                create_alias=models.CreateAlias(collection_name=collection, alias_name=ALIAS)
            )
        ]
    )
    with (
        patch(
            "attack_search.services.indexing.load_snapshot", return_value=(fixture(), "snapshot")
        ),
        patch("attack_search.services.indexing.build_documents", return_value=docs),
        patch("attack_search.services.indexing.create_qdrant_client", return_value=qdrant),
        patch("attack_search.services.indexing.create_embedding_client") as embedding,
        patch.object(qdrant, "update_collection_aliases") as aliases,
        patch.object(qdrant, "close"),
    ):
        run_index_lexical("unused", workers=1)
        embedding.assert_not_called()
        aliases.assert_not_called()
    ensure_lexical_ready(qdrant, collection)
