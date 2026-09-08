import math
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from attack_search.embeddings.client import embed_batch, embed_query
from attack_search.embeddings.profile import DIMENSIONS


class EmbeddingTests(unittest.TestCase):
    def client(self, rows):
        client = Mock()
        client.embeddings.create.return_value = SimpleNamespace(data=rows)
        return client

    def test_batch_order(self):
        client = self.client(
            [
                SimpleNamespace(index=1, embedding=[2.0] * DIMENSIONS),
                SimpleNamespace(index=0, embedding=[1.0] * DIMENSIONS),
            ]
        )
        vectors = embed_batch(client, ["first", "second"])
        self.assertEqual([v[0] for v in vectors], [1.0, 2.0])

    def test_aggregated_or_duplicate_response_rejected(self):
        for indices in ([0], [0, 0], [1, 2]):
            client = self.client(
                [SimpleNamespace(index=i, embedding=[1.0] * DIMENSIONS) for i in indices]
            )
            with self.assertRaises(ValueError):
                embed_batch(client, ["first", "second"])

    def test_bad_vectors(self):
        for vector in ([1.0], [0.0] * DIMENSIONS, [math.nan] * DIMENSIONS):
            with self.assertRaises(ValueError):
                embed_batch(self.client([SimpleNamespace(index=0, embedding=vector)]), ["text"])

    def test_query_formats(self):
        client = self.client([SimpleNamespace(index=0, embedding=[1.0] * DIMENSIONS)])
        embed_query(client, "query")
        self.assertEqual(
            client.embeddings.create.call_args.kwargs["input"],
            ["task: search result | query: query"],
        )
        embed_query(client, "question", question_answering=True)
        self.assertEqual(
            client.embeddings.create.call_args.kwargs["input"],
            ["task: question answering | query: question"],
        )
