from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from qdrant_client import models

from attack_search.embeddings.lexical import (
    BM25_MODEL,
    LEXICAL_VECTOR,
    bm25_document,
    lexical_profile,
    lexical_text,
)
from attack_search.storage.qdrant import (
    create_qdrant_client,
    require_native_bm25,
    update_missing_lexical_vectors,
)


def test_document_uses_pinned_native_profile_and_fresh_options():
    document = bm25_document("PowerShell -EncodedCommand")
    assert document.model == BM25_MODEL
    assert models.Bm25Config.model_validate(document.options).language == "english"
    assert document.options == lexical_profile()["options"]
    document.options["language"] = "french"
    assert bm25_document("PowerShell").options["language"] == "english"
    assert (
        lexical_text(
            {"title": "PowerShell", "text": "Encoded commands", "embedding_text": "ignore"}
        )
        == "PowerShell\nEncoded commands"
    )
    assert lexical_text({"title": None, "text": "A behavior"}) == "A behavior"


@pytest.mark.parametrize("value", ["", "  ", None])
def test_empty_bm25_query_is_rejected(value):
    with pytest.raises(ValueError, match="empty"):
        bm25_document(value)


def test_only_missing_sparse_vectors_are_updated_with_native_documents():
    docs = [{"id": 1, "payload": {"title": "PowerShell", "text": "commands"}}]
    # Production document IDs are strings; use a UUID to match the model contract.
    docs[0]["id"] = "4b237ff4-5f72-4fd3-a776-e44a2cf856a2"
    qdrant = Mock()
    qdrant.retrieve.return_value = [
        SimpleNamespace(id=docs[0]["id"], payload=docs[0]["payload"], vector={})
    ]
    assert update_missing_lexical_vectors(qdrant, "snapshot", docs) == 1
    point = qdrant.update_vectors.call_args.args[1][0]
    assert set(point.vector) == {LEXICAL_VECTOR}
    assert isinstance(point.vector[LEXICAL_VECTOR], models.Document)
    qdrant.upsert.assert_not_called()
    assert qdrant.update_vectors.call_args.kwargs["wait"] is True
    assert qdrant.retrieve.call_args.kwargs["with_vectors"] == [LEXICAL_VECTOR]


def test_qdrant_client_passes_native_inference_to_the_server(monkeypatch):
    monkeypatch.setenv("QDRANT_URL", "https://unused.example")
    monkeypatch.setenv("QDRANT_API_KEY", "unused")
    with patch("attack_search.storage.qdrant.QdrantClient") as client:
        create_qdrant_client()
        assert client.call_args.kwargs["cloud_inference"] is True


@pytest.mark.parametrize("version", ["1.18.9", "0.1.0", "unexpected"])
def test_unsupported_server_is_rejected_before_indexing(version):
    qdrant = Mock()
    qdrant.info.return_value.version = version
    with pytest.raises(ValueError, match="1.19"):
        require_native_bm25(qdrant)
    qdrant.update_collection.assert_not_called()
