"""Real local Qdrant retrieval and backend fusion with deterministic offline vectors."""

from contextlib import closing
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from qdrant_client import QdrantClient, models

from attack_search.embeddings.lexical import LEXICAL_METADATA_KEY, LEXICAL_VECTOR, lexical_profile
from attack_search.embeddings.profile import ALIAS, DIMENSIONS
from attack_search.search_contract import SearchRequest
from attack_search.services import search

COLLECTION = "attack_semantic_v1_hybrid_test"
FILTERS = {
    "types": ["attack-pattern", "behavior_example"],
    "technique_attack_ids": ["T1059.001"],
    "platforms": ["Windows"],
}


def dense(x, y):
    return [float(x), float(y)] + [0.0] * (DIMENSIONS - 2)


@pytest.fixture
def local_search(tmp_path, monkeypatch):
    folder = str(tmp_path / "qdrant")

    def client_factory():
        return QdrantClient(path=folder)

    with closing(client_factory()) as qdrant:
        qdrant.create_collection(
            COLLECTION,
            vectors_config=models.VectorParams(size=DIMENSIONS, distance=models.Distance.COSINE),
            sparse_vectors_config={
                LEXICAL_VECTOR: models.SparseVectorParams(modifier=models.Modifier.IDF)
            },
            metadata={
                LEXICAL_METADATA_KEY: {
                    "profile": lexical_profile(),
                    "dataset_snapshot": "offline",
                    "expected_points": 6,
                }
            },
        )
        base = {
            "is_active": True,
            "type": "attack-pattern",
            "technique_attack_ids": ["T1059.001"],
            "related_platforms": ["Windows"],
            "dataset_snapshot": "offline",
        }
        records = [
            (1, dense(1, 0), 1.0, {}),
            (2, dense(0, 1), 4.0, {"type": "behavior_example"}),
            (3, dense(1, 0), 100.0, {"is_active": False}),
            (4, dense(1, 0), 100.0, {"related_platforms": ["Linux"]}),
            (5, dense(1, 0), 100.0, {"type": "course-of-action"}),
            (6, dense(1, 0), 100.0, {"technique_attack_ids": ["T1003"]}),
        ]
        qdrant.upsert(
            COLLECTION,
            [
                models.PointStruct(
                    id=point_id,
                    vector={
                        "": vector,
                        LEXICAL_VECTOR: models.SparseVector(indices=[7], values=[term_weight]),
                    },
                    payload={**base, **override},
                )
                for point_id, vector, term_weight, override in records
            ],
            wait=True,
        )
        qdrant.update_collection_aliases(
            [
                models.CreateAliasOperation(
                    create_alias=models.CreateAlias(collection_name=COLLECTION, alias_name=ALIAS)
                )
            ]
        )
    embedding_factory = MagicMock()
    embed = Mock(return_value=dense(1, 0))
    bm25 = Mock(return_value=models.SparseVector(indices=[7], values=[1.0]))
    monkeypatch.setattr(search, "create_qdrant_client", client_factory)
    monkeypatch.setattr(search, "create_embedding_client", embedding_factory)
    monkeypatch.setattr(search, "embed_query", embed)
    # Only text-to-sparse inference is replaced; Qdrant retrieval, IDF, readiness,
    # filtering, weighting, pagination and fusion all run through the real client.
    monkeypatch.setattr(search, "bm25_document", bm25)
    return SimpleNamespace(
        factory=client_factory,
        embedding_factory=embedding_factory,
        embed=embed,
        bm25=bm25,
    )


def run_search(mode, **kwargs):
    return search.search_attack(
        SearchRequest.model_validate(
            {"mode": mode, "query": "PowerShell", "filters": FILTERS, **kwargs}
        )
    )


@pytest.mark.parametrize(
    ("mode", "weights", "expected", "score_kind"),
    [
        ("semantic", None, ["1", "2"], "cosine"),
        ("lexical", None, ["2", "1"], "bm25"),
        ("hybrid", {"semantic": 9, "lexical": 1}, ["1", "2"], "weighted_rrf"),
        ("hybrid", {"semantic": 1, "lexical": 9}, ["2", "1"], "weighted_rrf"),
    ],
)
def test_actual_qdrant_ranking_respects_modes_weights_and_all_filters(
    local_search, mode, weights, expected, score_kind
):
    result = run_search(mode, **({"weights": weights} if weights else {}))
    assert [point["id"] for point in result["points"]] == expected
    assert result["score_kind"] == score_kind
    assert all(point["payload"]["is_active"] for point in result["points"])
    if mode == "lexical":
        local_search.embed.assert_not_called()
        local_search.embedding_factory.assert_not_called()


def test_relative_weight_scaling_produces_identical_rank_and_scores(local_search):
    percent = run_search("hybrid", weights={"semantic": 70, "lexical": 30})
    fraction = run_search("hybrid", weights={"semantic": 0.7, "lexical": 0.3})
    assert [p["id"] for p in percent["points"]] == [p["id"] for p in fraction["points"]]
    assert [p["score"] for p in percent["points"]] == pytest.approx(
        [p["score"] for p in fraction["points"]]
    )
    assert percent["weights"] == pytest.approx({"semantic": 0.7, "lexical": 0.3})


def test_native_hybrid_pagination_and_deduplication(local_search):
    weights = {"semantic": 0.2, "lexical": 0.8}
    full = run_search("hybrid", weights=weights)
    first = run_search("hybrid", weights=weights, limit=1)
    second = run_search("hybrid", weights=weights, limit=1, offset=1)
    beyond = run_search("hybrid", weights=weights, limit=1, offset=2)
    assert first["points"] + second["points"] == full["points"]
    assert len({point["id"] for point in full["points"]}) == 2
    assert beyond["points"] == []


def test_empty_lexical_matches_return_empty_without_embedding(local_search):
    local_search.bm25.return_value = models.SparseVector(indices=[999], values=[1.0])
    result = run_search("lexical")
    assert result["points"] == []
    local_search.embed.assert_not_called()


def test_hybrid_preserves_dense_candidates_if_lexical_query_has_no_matches(local_search):
    local_search.bm25.return_value = models.SparseVector(indices=[999], values=[1.0])
    result = run_search("hybrid", weights={"semantic": 1, "lexical": 1})
    assert [point["id"] for point in result["points"]] == ["1", "2"]


def test_explicit_inactive_and_all_status_filters_work_in_actual_qdrant(local_search):
    inactive = run_search("lexical", filters={**FILTERS, "is_active": False})
    all_statuses = run_search("lexical", filters={**FILTERS, "is_active": None})
    assert [point["id"] for point in inactive["points"]] == ["3"]
    assert {point["id"] for point in all_statuses["points"]} == {"1", "2", "3"}


def test_actual_missing_sparse_vector_disables_lexical_before_paid_embedding(local_search):
    with closing(local_search.factory()) as qdrant:
        qdrant.delete_vectors(COLLECTION, vectors=[LEXICAL_VECTOR], points=[1], wait=True)
    with pytest.raises(search.SearchUnavailableError, match="Lexical index"):
        run_search("hybrid", weights={"semantic": 1, "lexical": 1})
    local_search.embed.assert_not_called()
    local_search.embedding_factory.assert_not_called()
    # The dense index remains usable while lexical backfill is incomplete.
    assert [point["id"] for point in run_search("semantic")["points"]] == ["1", "2"]
