"""Offline contracts for LLM-controlled lexical, semantic and hybrid retrieval."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from qdrant_client import models
from qdrant_client.http.exceptions import UnexpectedResponse

from attack_search.api import app as api
from attack_search.embeddings.lexical import LEXICAL_METADATA_KEY, LEXICAL_VECTOR, lexical_profile
from attack_search.embeddings.profile import ALIAS, DIMENSIONS
from attack_search.search_contract import (
    SEARCH_EXAMPLES,
    SearchFilters,
    SearchRequest,
    SearchWeights,
)
from attack_search.services import search

TEST_KEY = "offline-hybrid-key-at-least-16-characters"
AUTH = {"X-API-Key": TEST_KEY}
HYBRID = {
    "mode": "hybrid",
    "query": "encoded commands through PowerShell",
    "weights": {"semantic": 7, "lexical": 3},
}


@pytest.fixture
def search_clients(monkeypatch):
    qdrant = MagicMock()
    qdrant.get_aliases.return_value.aliases = [
        SimpleNamespace(alias_name=ALIAS, collection_name="attack_semantic_v1_offline")
    ]
    params = SimpleNamespace(
        vectors=models.VectorParams(size=DIMENSIONS, distance=models.Distance.COSINE),
        sparse_vectors={LEXICAL_VECTOR: models.SparseVectorParams(modifier=models.Modifier.IDF)},
    )
    info = SimpleNamespace(
        config=SimpleNamespace(
            params=params,
            metadata={
                LEXICAL_METADATA_KEY: {
                    "profile": lexical_profile(),
                    "dataset_snapshot": "offline",
                    "expected_points": 2,
                }
            },
        )
    )
    qdrant.get_collection.return_value = info
    qdrant.count.side_effect = lambda *args, **kwargs: SimpleNamespace(
        count=0 if kwargs.get("count_filter") else 2
    )
    qdrant.query_points.return_value.points = [
        SimpleNamespace(id=1, score=0.75, payload={"type": "attack-pattern"})
    ]
    qdrant.query_batch_points.return_value = [qdrant.query_points.return_value] * 2
    factory = Mock(return_value=qdrant)
    embedding_factory = MagicMock()
    embed = Mock(return_value=[1.0] + [0.0] * (DIMENSIONS - 1))
    monkeypatch.setattr(search, "create_qdrant_client", factory)
    monkeypatch.setattr(search, "create_embedding_client", embedding_factory)
    monkeypatch.setattr(search, "embed_query", embed)
    return SimpleNamespace(
        qdrant=qdrant,
        factory=factory,
        info=info,
        embedding_factory=embedding_factory,
        embed=embed,
    )


@pytest.mark.parametrize("body", SEARCH_EXAMPLES)
def test_llm_examples_are_valid_and_need_no_native_qdrant_syntax(body):
    request = SearchRequest.model_validate(body)
    assert request.mode in {"semantic", "lexical", "hybrid"}
    assert "must" not in body.get("filters", {})
    assert request.filters.is_active is True


@pytest.mark.parametrize("as_strings", [False, True])
def test_dify_nested_objects_accept_native_values_and_json_strings(as_strings):
    filters = {"types": ["attack-pattern"], "platforms": ["Windows"]}
    weights = {"semantic": 70, "lexical": 30}
    request = SearchRequest.model_validate(
        {
            **HYBRID,
            "filters": json.dumps(filters) if as_strings else filters,
            "weights": json.dumps(weights) if as_strings else weights,
        }
    )
    assert request.weights.normalized() == pytest.approx({"semantic": 0.7, "lexical": 0.3})
    assert request.filters.platforms == ["Windows"]


@pytest.mark.parametrize(
    "body",
    [
        {"query": "PowerShell"},
        {"mode": "bm25", "query": "PowerShell"},
        {"mode": "semantic", "query": "   "},
        {"mode": "semantic", "query": "پ" * 3501},
        {**HYBRID, "lexical_query": "پ" * 3501},
        {**HYBRID, "lexical_query": "   "},
        {"mode": "hybrid", "query": "PowerShell"},
        {**HYBRID, "weights": {"semantic": 0.7}},
        {**HYBRID, "weights": {"semantic": 0, "lexical": 1}},
        {**HYBRID, "weights": {"semantic": 1, "lexical": -1}},
        {**HYBRID, "weights": {"semantic": "0.7", "lexical": 0.3}},
        {**HYBRID, "weights": {"semantic": True, "lexical": 1}},
        {**HYBRID, "weights": {"semantic": 1, "lexical": 1, "unknown": 1}},
        {**HYBRID, "weights": "{broken"},
        {**HYBRID, "weights": "[]"},
        {**HYBRID, "mode": "semantic"},
        {**HYBRID, "mode": "lexical"},
        {"mode": "semantic", "query": "PowerShell", "lexical_query": "command"},
        {"mode": "lexical", "query": "PowerShell", "question_answering": True},
        {**HYBRID, "question_answering": "false"},
        {**HYBRID, "limit": 0},
        {**HYBRID, "limit": 51},
        {**HYBRID, "limit": "10"},
        {**HYBRID, "limit": True},
        {**HYBRID, "offset": -1},
        {**HYBRID, "offset": 1001},
        {**HYBRID, "filters": None},
        {**HYBRID, "filters": "[]"},
        {**HYBRID, "filters": "{broken"},
        {**HYBRID, "filters": {"is_active": "true"}},
        {**HYBRID, "filters": {"is_active": 1}},
        {**HYBRID, "filters": {"types": []}},
        {**HYBRID, "filters": {"types": ["technique"]}},
        {**HYBRID, "filters": {"technique_attack_ids": []}},
        {**HYBRID, "filters": {"technique_attack_ids": ["attack-pattern--stix-id"]}},
        {**HYBRID, "filters": {"technique_attack_ids": ["t1059.001"]}},
        {**HYBRID, "filters": {"platforms": []}},
        {**HYBRID, "filters": {"platforms": [" "]}},
        {**HYBRID, "filters": {"must": []}},
        {**HYBRID, "filter": {}},
        {**HYBRID, "collection": "other"},
        {**HYBRID, "vector": [1.0, 0.0]},
        {**HYBRID, "using": "arbitrary-vector"},
    ],
)
def test_invalid_llm_requests_return_tool_errors_without_service_execution(http_client, body):
    client, service = http_client
    response = client.post("/tools/search", headers=AUTH, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is False
    assert response.json()["error_type"] == "search_error"
    assert response.json()["detail"].startswith("Invalid search request:")
    service.assert_not_called()


@pytest.mark.parametrize("invalid", [float("inf"), float("-inf"), float("nan")])
def test_nonfinite_weights_are_rejected(invalid):
    with pytest.raises(ValidationError):
        SearchWeights(semantic=invalid, lexical=1)


def test_finite_weights_normalize_without_overflow_and_reject_lost_contribution():
    assert SearchWeights(semantic=1e308, lexical=1e308).normalized() == {
        "semantic": 0.5,
        "lexical": 0.5,
    }
    with pytest.raises(ValidationError):
        SearchWeights(semantic=1e-300, lexical=1e300)


def test_simple_filters_apply_and_across_fields_or_within_lists_and_map_payload_names():
    filters = SearchFilters(
        types=["attack-pattern", "behavior_example", "attack-pattern"],
        technique_attack_ids=["T1059", "T1059.001"],
        platforms=["Windows", "Linux"],
    )
    assert filters.to_qdrant_filter() == {
        "must": [
            {"key": "is_active", "match": {"value": True}},
            {"key": "type", "match": {"any": ["attack-pattern", "behavior_example"]}},
            {"key": "technique_attack_ids", "match": {"any": ["T1059", "T1059.001"]}},
            {"key": "related_platforms", "match": {"any": ["Windows", "Linux"]}},
        ]
    }


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({}, {"must": [{"key": "is_active", "match": {"value": True}}]}),
        ({"is_active": False}, {"must": [{"key": "is_active", "match": {"value": False}}]}),
        ({"is_active": None}, {}),
    ],
)
def test_default_active_and_explicit_historical_scope(filters, expected):
    assert SearchFilters.model_validate(filters).to_qdrant_filter() == expected


def test_lexical_uses_bm25_document_and_never_opens_embedding_client(search_clients):
    result = search.search_attack(SearchRequest(mode="lexical", query="powershell -EncodedCommand"))
    search_clients.embedding_factory.assert_not_called()
    search_clients.embed.assert_not_called()
    arguments = search_clients.qdrant.query_points.call_args.kwargs
    assert arguments["using"] == LEXICAL_VECTOR
    assert isinstance(arguments["query"], models.Document)
    assert arguments["query"].model == "Qdrant/bm25"
    assert arguments["query"].text == "powershell -EncodedCommand"
    assert arguments["query"].options == lexical_profile()["options"]
    assert "prefetch" not in arguments
    assert result["mode"] == "lexical"
    assert result["score_kind"] == "bm25"
    assert result["weights"] is None
    assert result["points"] == [{"id": "1", "score": 0.75, "payload": {"type": "attack-pattern"}}]
    search_clients.qdrant.close.assert_called_once()


def test_semantic_still_works_without_any_lexical_index(search_clients):
    search_clients.info.config.params.sparse_vectors = None
    search_clients.info.config.metadata = None
    result = search.search_attack(
        SearchRequest(mode="semantic", query="encoded command execution", question_answering=True)
    )
    search_clients.embed.assert_called_once_with(
        search_clients.embedding_factory.return_value.__enter__.return_value,
        "encoded command execution",
        question_answering=True,
    )
    search_clients.qdrant.count.assert_not_called()
    arguments = search_clients.qdrant.query_points.call_args.kwargs
    assert arguments["query"] == search_clients.embed.return_value
    assert "using" not in arguments
    assert "prefetch" not in arguments
    assert result["score_kind"] == "cosine"
    assert result["weights"] is None


@pytest.mark.parametrize("offset", [0, 105, 1000])
def test_hybrid_batches_queries_and_filters_then_applies_llm_weights(search_clients, offset):
    request = SearchRequest.model_validate(
        {
            **HYBRID,
            "lexical_query": "powershell -EncodedCommand",
            "filters": {"types": ["behavior_example"], "platforms": ["Windows"]},
            "question_answering": True,
            "limit": 5,
            "offset": offset,
        }
    )
    result = search.search_attack(request)
    arguments = search_clients.qdrant.query_batch_points.call_args.kwargs
    dense, sparse = arguments["requests"]
    assert dense.query == search_clients.embed.return_value
    assert dense.using is None
    assert sparse.query.text == "powershell -EncodedCommand"
    assert sparse.using == LEXICAL_VECTOR
    expected_filter = request.filters.to_qdrant_filter()
    assert dense.filter.model_dump(exclude_none=True) == expected_filter
    assert sparse.filter.model_dump(exclude_none=True) == expected_filter
    assert dense.limit == sparse.limit == max(100, offset + 5)
    assert dense.with_payload is sparse.with_payload is True
    assert dense.with_vector is sparse.with_vector is False
    assert dense.offset is sparse.offset is None
    assert result["limit"] == 5
    assert result["offset"] == offset
    if offset == 0:
        assert result["points"][0]["score"] == pytest.approx(1 / 61)
    else:
        assert result["points"] == []
    assert arguments["timeout"] == 10
    assert result["score_kind"] == "weighted_rrf"
    assert result["weights"] == pytest.approx({"semantic": 0.7, "lexical": 0.3})
    search_clients.embed.assert_called_once_with(
        search_clients.embedding_factory.return_value.__enter__.return_value,
        request.query,
        question_answering=True,
    )


def test_hybrid_without_lexical_override_uses_shared_query(search_clients):
    search.search_attack(SearchRequest.model_validate(HYBRID))
    query = search_clients.qdrant.query_batch_points.call_args.kwargs["requests"][1].query
    assert query.text == HYBRID["query"]


@pytest.mark.parametrize("mode", ["lexical", "hybrid"])
@pytest.mark.parametrize("missing", ["schema", "manifest", "sparse_points", "point_count"])
def test_incomplete_lexical_index_fails_before_embedding_or_query(search_clients, mode, missing):
    if missing == "schema":
        search_clients.info.config.params.sparse_vectors = {}
    elif missing == "manifest":
        search_clients.info.config.metadata = {}
    elif missing == "sparse_points":
        search_clients.qdrant.count.side_effect = lambda *args, **kwargs: SimpleNamespace(count=2)
    else:
        search_clients.qdrant.count.side_effect = lambda *args, **kwargs: SimpleNamespace(
            count=0 if kwargs.get("count_filter") else 1
        )
    body = HYBRID if mode == "hybrid" else {"mode": "lexical", "query": "PowerShell"}
    with pytest.raises(search.SearchUnavailableError, match="Lexical index"):
        search.search_attack(SearchRequest.model_validate(body))
    search_clients.embed.assert_not_called()
    search_clients.embedding_factory.assert_not_called()
    search_clients.qdrant.query_points.assert_not_called()
    search_clients.qdrant.query_batch_points.assert_not_called()
    search_clients.qdrant.close.assert_called_once()


def test_direct_service_revalidates_mutated_request_before_opening_clients(search_clients):
    request = SearchRequest.model_validate(HYBRID)
    request.limit = 500
    with pytest.raises(ValidationError):
        search.search_attack(request)
    search_clients.factory.assert_not_called()
    search_clients.embed.assert_not_called()


@pytest.fixture
def http_client(monkeypatch):
    monkeypatch.setattr(api, "load_environment", lambda: None)
    monkeypatch.setenv("API_KEY", TEST_KEY)
    service = Mock(
        return_value={
            "collection": "offline",
            "points": [],
            "limit": 10,
            "offset": 0,
            "mode": "hybrid",
            "score_kind": "weighted_rrf",
            "weights": {"semantic": 0.7, "lexical": 0.3},
        }
    )
    monkeypatch.setattr(api, "search_attack", service)
    with TestClient(api.create_app(), raise_server_exceptions=False) as client:
        yield client, service


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong-key"}])
def test_search_requires_authentication_before_running_service(http_client, headers):
    client, service = http_client
    response = client.post("/tools/search", headers=headers, json=HYBRID)
    assert response.status_code == 401
    service.assert_not_called()


def test_search_http_passes_typed_request_and_returns_fusion_metadata(http_client):
    client, service = http_client
    response = client.post("/tools/search", headers=AUTH, json=HYBRID)
    assert response.status_code == 200
    assert response.json() == service.return_value
    assert service.call_count == 1
    request = service.call_args.args[0]
    assert isinstance(request, SearchRequest)
    assert request.mode == "hybrid"
    assert request.weights.semantic == 7


def test_openapi_exposes_search_mode_examples_and_hides_legacy_tool(http_client):
    client, _ = http_client
    schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) == {"/tools/sql", "/tools/search"}
    assert schema["paths"]["/tools/search"]["post"]["operationId"] == "search_attack"
    contract = schema["components"]["schemas"]["SearchRequest"]
    assert set(contract["required"]) == {"mode", "query"}
    assert set(contract["properties"]["mode"]["enum"]) == {"semantic", "lexical", "hybrid"}
    for example in contract["examples"]:
        SearchRequest.model_validate(example)
    assert len(contract["examples"]) >= 3
    assert TEST_KEY not in json.dumps(schema)


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (RuntimeError("private provider token and URL"), 502),
        (search.SearchUnavailableError("private diagnostics"), 503),
        (
            UnexpectedResponse(
                status_code=503,
                reason_phrase="private reason",
                content=b"private provider token",
                headers={"api-key": "private secret"},
            ),
            502,
        ),
    ],
)
def test_search_failure_responses_do_not_expose_upstream_secrets(http_client, error, status):
    client, service = http_client
    service.side_effect = error
    response = client.post("/tools/search", headers=AUTH, json=HYBRID)
    assert response.status_code == status
    assert "private" not in response.text
    assert TEST_KEY not in response.text
