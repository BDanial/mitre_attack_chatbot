import os
import unittest
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from qdrant_client import QdrantClient

from attack_search.embeddings.documents import build_documents
from attack_search.embeddings.profile import DIMENSIONS, collection_name
from attack_search.services.indexing import index_documents
from attack_search.storage.qdrant import publish_alias
from tests.fixtures import fixture


class QdrantIntegrationTests(unittest.TestCase):
    def test_local_upload_resume_alias_and_payload_guard(self):
        documents = build_documents(fixture(), "snapshot")
        name = collection_name("snapshot")
        with TemporaryDirectory() as folder:

            def factory():
                return QdrantClient(path=folder)

            with (
                patch("attack_search.services.indexing.create_qdrant_client", side_effect=factory),
                patch("attack_search.storage.qdrant.create_qdrant_client", side_effect=factory),
                patch("attack_search.services.indexing.create_embedding_client") as openai,
                patch("attack_search.services.indexing.show_progress"),
                patch.dict(
                    os.environ,
                    {
                        "QDRANT_URL": "http://unused",
                        "QDRANT_API_KEY": "unused",
                        "OPENROUTER_API_KEY": "unused",
                    },
                ),
            ):
                response = openai.return_value.__enter__.return_value.embeddings.create
                response.side_effect = lambda **kwargs: SimpleNamespace(
                    data=[
                        SimpleNamespace(index=i, embedding=[1.0] * DIMENSIONS)
                        for i in range(len(kwargs["input"]))
                    ]
                )
                self.assertEqual(index_documents(documents, name), len(documents))
                self.assertEqual(index_documents(documents, name), len(documents))
                self.assertEqual(response.call_count, 1)  # Resume makes no paid request.
                publish_alias(name)
                publish_alias(name)  # Idempotent publication.
                with_client = factory()
                try:
                    self.assertEqual(
                        with_client.count("attack_semantic", exact=True).count, len(documents)
                    )
                    stored = with_client.retrieve(name, [documents[0]["id"]], with_vectors=True)[0]
                    self.assertEqual(stored.payload, documents[0]["payload"])
                    self.assertEqual(len(stored.vector), DIMENSIONS)
                finally:
                    with_client.close()
                documents[0]["payload"]["title"] = "Unexpected changed payload"
                with self.assertRaisesRegex(ValueError, "payload differs"):
                    index_documents(documents, name)
