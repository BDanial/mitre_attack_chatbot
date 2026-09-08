from unittest.mock import patch

import pytest

from attack_search.services.indexing import run_index
from tests.fixtures import fixture


def test_dry_run_never_opens_embedding_or_qdrant_clients():
    with (
        patch("attack_search.services.indexing.load_snapshot", return_value=(fixture(), "old")),
        patch("attack_search.services.indexing.index_documents") as upload,
        patch("attack_search.services.indexing.publish_alias") as publish,
    ):
        run_index("unused", dry_run=True)
        upload.assert_not_called()
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
        patch("attack_search.services.indexing.publish_alias") as publish,
    ):
        with pytest.raises(ValueError, match="PostgreSQL changed"):
            run_index("unused")
        publish.assert_not_called()
