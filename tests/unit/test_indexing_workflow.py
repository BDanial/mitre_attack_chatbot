from unittest.mock import patch

import pytest

from attack_search.services.indexing import run_index, run_index_lexical
from tests.fixtures import fixture


def test_dry_run_never_opens_embedding_or_qdrant_clients():
    with (
        patch("attack_search.services.indexing.load_snapshot", return_value=(fixture(), "old")),
        patch("attack_search.services.indexing.index_documents") as upload,
        patch("attack_search.services.indexing.index_lexical_documents") as lexical,
        patch("attack_search.services.indexing.publish_alias") as publish,
    ):
        run_index("unused", dry_run=True)
        upload.assert_not_called()
        lexical.assert_not_called()
        publish.assert_not_called()


def test_changed_postgres_snapshot_prevents_alias_publication(monkeypatch):
    for key in ("OPENROUTER_API_KEY", "QDRANT_URL", "QDRANT_API_KEY"):
        monkeypatch.setenv(key, "unused")
    with (
        patch(
            "attack_search.services.indexing.load_snapshot",
            side_effect=[(fixture(), "old"), (fixture(), "new")],
        ),
        patch(
            "attack_search.services.indexing.index_documents",
            side_effect=lambda docs, *args, **kwargs: len(docs),
        ),
        patch("attack_search.services.indexing.index_lexical_documents"),
        patch("attack_search.services.indexing.publish_alias") as publish,
    ):
        with pytest.raises(ValueError, match="PostgreSQL changed"):
            run_index("unused")
        publish.assert_not_called()


def test_lexical_dry_run_never_opens_qdrant_or_embeddings():
    with (
        patch("attack_search.services.indexing.load_snapshot", return_value=(fixture(), "old")),
        patch("attack_search.services.indexing.create_qdrant_client") as qdrant,
        patch("attack_search.services.indexing.create_embedding_client") as embedding,
    ):
        run_index_lexical("unused", dry_run=True)
        qdrant.assert_not_called()
        embedding.assert_not_called()


def test_full_index_finishes_lexical_before_snapshot_recheck_and_publish(monkeypatch):
    events = []
    for key in ("OPENROUTER_API_KEY", "QDRANT_URL", "QDRANT_API_KEY"):
        monkeypatch.setenv(key, "unused")

    def snapshot(_):
        events.append("snapshot")
        return fixture(), "stable"

    with (
        patch("attack_search.services.indexing.load_snapshot", side_effect=snapshot),
        patch(
            "attack_search.services.indexing.index_documents",
            side_effect=lambda docs, *a, **kw: len(docs),
        ),
        patch(
            "attack_search.services.indexing.index_lexical_documents",
            side_effect=lambda *a, **kw: events.append("lexical"),
        ),
        patch(
            "attack_search.services.indexing.publish_alias",
            side_effect=lambda *a: events.append("publish"),
        ),
    ):
        run_index("unused")
    assert events == ["snapshot", "lexical", "snapshot", "publish"]


def test_failed_lexical_backfill_keeps_alias_unchanged(monkeypatch):
    for key in ("OPENROUTER_API_KEY", "QDRANT_URL", "QDRANT_API_KEY"):
        monkeypatch.setenv(key, "unused")
    with (
        patch("attack_search.services.indexing.load_snapshot", return_value=(fixture(), "stable")),
        patch(
            "attack_search.services.indexing.index_documents",
            side_effect=lambda docs, *a, **kw: len(docs),
        ),
        patch(
            "attack_search.services.indexing.index_lexical_documents",
            side_effect=ValueError("incomplete lexical"),
        ),
        patch("attack_search.services.indexing.publish_alias") as publish,
    ):
        with pytest.raises(ValueError, match="incomplete lexical"):
            run_index("unused")
        publish.assert_not_called()


def test_sample_index_never_starts_lexical_backfill_or_publishes(monkeypatch):
    for key in ("OPENROUTER_API_KEY", "QDRANT_URL", "QDRANT_API_KEY"):
        monkeypatch.setenv(key, "unused")
    with (
        patch("attack_search.services.indexing.load_snapshot", return_value=(fixture(), "stable")),
        patch("attack_search.services.indexing.index_documents", return_value=1),
        patch("attack_search.services.indexing.index_lexical_documents") as lexical,
        patch("attack_search.services.indexing.publish_alias") as publish,
    ):
        run_index("unused", limit=1)
        lexical.assert_not_called()
        publish.assert_not_called()
