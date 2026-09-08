"""Offline contracts for the SQL and semantic tools; no credentials are needed."""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call

import pytest
from qdrant_client import models

from attack_search.embeddings.profile import ALIAS, DIMENSIONS
from attack_search.services import search


@pytest.fixture
def database(monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    cursor = connection.execute.return_value
    cursor.description = [SimpleNamespace(name="id")]
    cursor.fetchall.return_value = [(1,)]
    connect = Mock(return_value=connection)
    monkeypatch.setattr(search.psycopg, "connect", connect)
    return SimpleNamespace(connect=connect, connection=connection, cursor=cursor)


@pytest.mark.parametrize(
    "query",
    [
        "",
        "   ",
        "SELECT " + "x" * 20000,
        "SELECT FROM",
        "SELECT 1; SELECT 2",
        "DELETE FROM attack.nodes",
        "CREATE TABLE attack.unwanted (id integer)",
        "COPY attack.nodes TO STDOUT",
        "SET transaction_read_only = off",
        "WITH deleted AS (DELETE FROM attack.nodes RETURNING id) SELECT * FROM deleted",
        "WITH inserted AS (INSERT INTO attack.nodes(id) VALUES ('x') RETURNING id) "
        "SELECT * FROM inserted",
        "WITH updated AS (UPDATE attack.nodes SET name = 'x' RETURNING id) SELECT * FROM updated",
        "SELECT * INTO attack.unwanted FROM attack.nodes",
        "SELECT * FROM attack.nodes FOR UPDATE",
        "SELECT * FROM attack.nodes FOR SHARE",
        "WITH locked AS (SELECT * FROM attack.nodes FOR UPDATE) SELECT * FROM locked",
    ],
)
def test_sql_rejects_invalid_or_non_read_queries_before_connecting(database, query):
    with pytest.raises(ValueError):
        search.query_sql(query, database_url="unused")
    database.connect.assert_not_called()


@pytest.mark.parametrize("limit", [0, -1, 501])
def test_sql_rejects_invalid_row_caps_before_connecting(database, limit):
    with pytest.raises(ValueError):
        search.query_sql("SELECT 1", database_url="unused", limit=limit)
    database.connect.assert_not_called()


def test_sql_uses_readonly_timeouts_and_server_limit_preserving_duplicate_columns(database):
    database.cursor.description = [SimpleNamespace(name="name"), SimpleNamespace(name="name")]
    database.cursor.fetchall.return_value = [("فارسی", None), ("second", 2), ("extra", 3)]

    result = search.query_sql(
        "SELECT name, NULL AS name FROM attack.nodes; -- user comment",
        database_url="postgresql://test.invalid/demo",
        limit=2,
    )

    database.connect.assert_called_once_with("postgresql://test.invalid/demo", connect_timeout=10)
    assert database.connection.execute.call_args_list[:4] == [
        call("SET TRANSACTION READ ONLY"),
        call("SET LOCAL statement_timeout = '5s'"),
        call("SET LOCAL lock_timeout = '1s'"),
        call("SET LOCAL search_path = pg_catalog, attack"),
    ]
    execution = database.connection.execute.call_args_list[-1]
    bounded_query = execution.args[0]
    assert bounded_query.startswith("SELECT * FROM (SELECT ")
    assert bounded_query.endswith(") AS tool_result LIMIT 3")
    assert "user comment" not in bounded_query
    assert execution.kwargs == {"prepare": True}
    assert result == {
        "columns": ["name", "name"],
        "rows": [["فارسی", None], ["second", 2]],
        "row_count": 2,
        "truncated": True,
    }
    database.connection.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "query",
    [
        "SELECT ';' AS separator; -- a literal semicolon is not another statement",
        "WITH choices AS (SELECT 1 AS id) SELECT id FROM choices",
        "SELECT 1 AS id UNION ALL SELECT 2 AS id",
    ],
)
def test_sql_accepts_readonly_ctes_unions_and_literal_semicolons(database, query):
    assert search.query_sql(query, database_url="unused")["rows"] == [[1]]
    database.connect.assert_called_once()


@pytest.mark.parametrize("rows", [[], [(1,)], [(1,), (2,)]])
def test_sql_truncated_is_false_without_an_extra_row(database, rows):
    database.cursor.fetchall.return_value = rows
    result = search.query_sql("SELECT id FROM attack.nodes", database_url="unused", limit=2)
    assert result["row_count"] == len(rows)
    assert result["truncated"] is False
    assert result["columns"] == ["id"]


@pytest.fixture
def semantic_clients(monkeypatch):
    qdrant = MagicMock()
    qdrant.get_aliases.return_value.aliases = [
        SimpleNamespace(alias_name="unrelated", collection_name="ignore-me"),
        SimpleNamespace(alias_name=ALIAS, collection_name="attack_semantic_v1_test"),
    ]
    qdrant.get_collection.return_value.config.params.vectors = models.VectorParams(
        size=DIMENSIONS, distance=models.Distance.COSINE
    )
    qdrant.query_points.return_value.points = [
        SimpleNamespace(id="test-point", score=0.75, payload={"type": "attack-pattern"})
    ]
    qdrant_factory = Mock(return_value=qdrant)
    embedding_factory = MagicMock()
    embed = Mock(return_value=[0.25] * DIMENSIONS)
    monkeypatch.setattr(search, "create_qdrant_client", qdrant_factory)
    monkeypatch.setattr(search, "create_embedding_client", embedding_factory)
    monkeypatch.setattr(search, "embed_query", embed)
    return SimpleNamespace(
        qdrant=qdrant,
        qdrant_factory=qdrant_factory,
        embedding_factory=embedding_factory,
        embed=embed,
    )


@pytest.mark.parametrize(
    "query_filter",
    [
        {"unknown": []},
        {"must": [{"key": "platforms", "match": {"value": "Windows"}}]},
        {"must": [{"key": "type", "match": {"value": 1}}]},
        {"must": [{"key": "is_active", "match": {"value": "true"}}]},
        {"must": [{"key": "is_active", "match": {"value": 1}}]},
        {"must": [{"key": "type", "match": {"any": [1, 2]}}]},
        {"must": [{"key": "type", "match": {"any": []}}]},
        {"must": [{"key": "type", "match": {"text": "technique"}}]},
        {"must": [{"key": "type", "range": {"gte": 1}}]},
        {"must": [{"has_id": [1]}]},
        {"must": [{"is_empty": {"key": "type"}}]},
        {"must_not": [{"should": [{"key": "parent_id", "match": {"value": "x"}}]}]},
        {"min_should": {"conditions": [{"key": "type", "match": {"value": 2}}], "min_count": 1}},
    ],
)
def test_invalid_filters_are_rejected_before_clients_or_embedding(semantic_clients, query_filter):
    with pytest.raises(ValueError):
        search.semantic_search("PowerShell", query_filter=query_filter)
    semantic_clients.qdrant_factory.assert_not_called()
    semantic_clients.embedding_factory.assert_not_called()
    semantic_clients.embed.assert_not_called()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"query": "   "},
        {"query": "پ" * 3501},
        {"query": "test", "limit": 0},
        {"query": "test", "limit": 51},
        {"query": "test", "offset": -1},
        {"query": "test", "offset": 1001},
    ],
)
def test_invalid_search_inputs_are_rejected_before_clients(semantic_clients, kwargs):
    with pytest.raises(ValueError):
        search.semantic_search(**kwargs)
    semantic_clients.qdrant_factory.assert_not_called()
    semantic_clients.embed.assert_not_called()


@pytest.mark.parametrize(
    ("query_filter", "expected"),
    [
        (None, {"must": [{"key": "is_active", "match": {"value": True}}]}),
        ({}, {}),
        (
            {"must": [{"key": "is_active", "match": {"value": False}}]},
            {"must": [{"key": "is_active", "match": {"value": False}}]},
        ),
    ],
)
def test_default_active_filter_does_not_override_historical_scope(
    semantic_clients, query_filter, expected
):
    search.semantic_search("PowerShell", query_filter=query_filter)
    used_filter = semantic_clients.qdrant.query_points.call_args.kwargs["query_filter"]
    assert used_filter.model_dump(exclude_none=True) == expected


def test_nested_keyword_logic_and_raw_query_are_forwarded_without_rewriting(semantic_clients):
    query_filter = {
        "must": {"key": "is_active", "match": {"value": True}},
        "should": [
            {"must": [{"key": "type", "match": {"any": ["attack-pattern", "behavior_example"]}}]}
        ],
        "must_not": [{"key": "db_table", "match": {"value": "relationships"}}],
        "min_should": {
            "conditions": [{"key": "related_platforms", "match": {"except": ["Linux"]}}],
            "min_count": 1,
        },
    }
    result = search.semantic_search(
        "تشخیص PowerShell -EncodedCommand",
        query_filter=query_filter,
        question_answering=True,
        limit=5,
        offset=10,
    )

    semantic_clients.embed.assert_called_once_with(
        semantic_clients.embedding_factory.return_value.__enter__.return_value,
        "تشخیص PowerShell -EncodedCommand",
        question_answering=True,
    )
    semantic_clients.qdrant.get_aliases.assert_called_once()
    semantic_clients.qdrant.get_collection.assert_called_once_with("attack_semantic_v1_test")
    arguments = semantic_clients.qdrant.query_points.call_args.kwargs
    assert arguments["collection_name"] == "attack_semantic_v1_test"
    assert arguments["query"] == semantic_clients.embed.return_value
    assert arguments["query_filter"].model_dump(exclude_none=True, by_alias=True) == query_filter
    assert arguments["limit"] == 5
    assert arguments["offset"] == 10
    assert arguments["with_payload"] is True
    assert arguments["with_vectors"] is False
    assert arguments["timeout"] == 10
    assert result == {
        "collection": "attack_semantic_v1_test",
        "points": [{"id": "test-point", "score": 0.75, "payload": {"type": "attack-pattern"}}],
        "limit": 5,
        "offset": 10,
    }
    semantic_clients.qdrant.close.assert_called_once()


@pytest.mark.parametrize(
    "configuration", ["missing_alias", "wrong_size", "wrong_distance", "named"]
)
def test_missing_or_incompatible_collection_prevents_embedding(semantic_clients, configuration):
    if configuration == "missing_alias":
        semantic_clients.qdrant.get_aliases.return_value.aliases = []
    else:
        vectors = models.VectorParams(
            size=128 if configuration == "wrong_size" else DIMENSIONS,
            distance=models.Distance.DOT
            if configuration == "wrong_distance"
            else models.Distance.COSINE,
        )
        semantic_clients.qdrant.get_collection.return_value.config.params.vectors = (
            {"named": vectors} if configuration == "named" else vectors
        )
    with pytest.raises(RuntimeError):
        search.semantic_search("PowerShell")
    semantic_clients.embedding_factory.assert_not_called()
    semantic_clients.embed.assert_not_called()
    semantic_clients.qdrant.query_points.assert_not_called()
    semantic_clients.qdrant.close.assert_called_once()


def test_valid_empty_search_is_not_an_error(semantic_clients):
    semantic_clients.qdrant.query_points.return_value.points = []
    assert search.semantic_search("no match")["points"] == []
