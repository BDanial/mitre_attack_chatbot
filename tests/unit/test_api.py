"""HTTP and OpenAPI contracts tested without opening external connections."""

import json
from unittest.mock import Mock

import psycopg
import pytest
from fastapi.testclient import TestClient
from qdrant_client.http.exceptions import UnexpectedResponse

from attack_search.api import app as api
from attack_search.services.search import SearchInputError

TEST_KEY = "offline-test-key-at-least-16-characters"
AUTH = {"X-API-Key": TEST_KEY}


@pytest.fixture
def configured_app(monkeypatch):
    monkeypatch.setattr(api, "load_environment", lambda: None)
    monkeypatch.setenv("API_KEY", TEST_KEY)
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused-owner.invalid/database")
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://unused-reader.invalid/database")
    monkeypatch.setenv("API_BASE_URL", "https://search.example.test/")
    sql = Mock(return_value={"columns": ["id"], "rows": [[1]], "row_count": 1, "truncated": False})
    semantic = Mock(return_value={"collection": "test", "points": [], "limit": 10, "offset": 0})
    search = Mock(
        return_value={
            "collection": "test",
            "points": [],
            "limit": 10,
            "offset": 0,
            "mode": "lexical",
            "score_kind": "bm25",
            "weights": None,
        }
    )
    monkeypatch.setattr(api, "query_sql", sql)
    monkeypatch.setattr(api, "semantic_search", semantic)
    monkeypatch.setattr(api, "search_attack", search)
    return api.create_app(), sql, semantic, search


@pytest.fixture
def client(configured_app):
    with TestClient(configured_app[0], raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.mark.parametrize("endpoint", ["/tools/sql", "/tools/semantic-search"])
@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong-key"}])
def test_authentication_rejects_before_service_execution(client, configured_app, endpoint, headers):
    response = client.post(endpoint, headers=headers, json={"query": "SELECT 1"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key"}
    configured_app[1].assert_not_called()
    configured_app[2].assert_not_called()


def test_primary_search_authentication_stays_non_2xx(client, configured_app):
    response = client.post("/tools/search", json={"mode": "lexical", "query": "PowerShell"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing API key"}
    configured_app[3].assert_not_called()


@pytest.mark.parametrize("key", [None, "", "too-short", "replace-me"])
def test_missing_or_weak_api_key_fails_closed(monkeypatch, key):
    monkeypatch.setattr(api, "load_environment", lambda: None)
    if key is None:
        monkeypatch.delenv("API_KEY", raising=False)
    else:
        monkeypatch.setenv("API_KEY", key)
    with pytest.raises(RuntimeError, match="API_KEY"):
        api.create_app()


def test_sql_response_preserves_duplicate_columns_nulls_and_unicode(client, configured_app):
    configured_app[1].return_value = {
        "columns": ["name", "name"],
        "rows": [["فارسی", None]],
        "row_count": 1,
        "truncated": False,
    }
    response = client.post("/tools/sql", headers=AUTH, json={"query": "SELECT 1", "limit": 3})
    assert response.status_code == 200
    assert response.json() == configured_app[1].return_value
    configured_app[1].assert_called_once_with(
        "SELECT 1", database_url="postgresql://unused-reader.invalid/database", limit=3
    )


def test_sql_without_connection_configuration_returns_503(monkeypatch, configured_app):
    monkeypatch.delenv("API_DATABASE_URL")
    monkeypatch.delenv("DATABASE_URL")
    with TestClient(api.create_app()) as test_client:
        response = test_client.post("/tools/sql", headers=AUTH, json={"query": "SELECT 1"})
    assert response.status_code == 503
    configured_app[1].assert_not_called()


def test_openapi_has_two_stable_tools_header_security_and_server(client):
    schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) == {"/tools/sql", "/tools/search"}
    assert schema["servers"] == [{"url": "https://search.example.test"}]
    assert schema["paths"]["/tools/sql"]["post"]["operationId"] == "query_sql"
    assert schema["paths"]["/tools/search"]["post"]["operationId"] == "search_attack"
    sql_success_schema = schema["paths"]["/tools/sql"]["post"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert {item["$ref"] for item in sql_success_schema["anyOf"]} == {
        "#/components/schemas/SQLResponse",
        "#/components/schemas/SQLErrorResponse",
    }
    search_success_schema = schema["paths"]["/tools/search"]["post"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert {item["$ref"] for item in search_success_schema["anyOf"]} == {
        "#/components/schemas/SearchResponse",
        "#/components/schemas/SearchErrorResponse",
    }
    schemes = schema["components"]["securitySchemes"]
    for path in schema["paths"].values():
        security = path["post"]["security"]
        assert len(security) == 1
        scheme_name = next(iter(security[0]))
        assert schemes[scheme_name] == {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    assert TEST_KEY not in json.dumps(schema)


@pytest.mark.parametrize("as_string", [False, True])
def test_semantic_accepts_native_or_json_string_filter(client, configured_app, as_string):
    query_filter = {"must": [{"key": "type", "match": {"value": "attack-pattern"}}]}
    response = client.post(
        "/tools/semantic-search",
        headers=AUTH,
        json={
            "query": "تشخیص PowerShell",
            "filter": json.dumps(query_filter) if as_string else query_filter,
            "limit": 5,
            "offset": 2,
            "question_answering": True,
        },
    )
    assert response.status_code == 200
    configured_app[2].assert_called_once_with(
        "تشخیص PowerShell", query_filter=query_filter, limit=5, offset=2, question_answering=True
    )


@pytest.mark.parametrize(
    ("extra_body", "expected_filter"),
    [
        ({}, {"must": [{"key": "is_active", "match": {"value": True}}]}),
        ({"filter": {}}, {}),
        ({"filter": "{}"}, {}),
    ],
)
def test_semantic_default_and_explicit_all_status_filters(
    client, configured_app, extra_body, expected_filter
):
    response = client.post(
        "/tools/semantic-search", headers=AUTH, json={"query": "PowerShell", **extra_body}
    )
    assert response.status_code == 200
    assert configured_app[2].call_args.kwargs["query_filter"] == expected_filter


@pytest.mark.parametrize(
    ("endpoint", "body"),
    [
        ("/tools/sql", {"query": "   "}),
        ("/tools/sql", {"query": "SELECT 1", "limit": 501}),
        ("/tools/sql", {"query": "SELECT 1", "database_url": "untrusted"}),
        ("/tools/semantic-search", {"query": "PowerShell", "filter": "{broken"}),
        ("/tools/semantic-search", {"query": "PowerShell", "filter": "[]"}),
        ("/tools/semantic-search", {"query": "PowerShell", "filter": None}),
        ("/tools/semantic-search", {"query": "PowerShell", "limit": 51}),
        ("/tools/semantic-search", {"query": "PowerShell", "offset": -1}),
        ("/tools/semantic-search", {"query": "PowerShell", "collection": "other"}),
        ("/tools/semantic-search", {"query": "PowerShell", "vector": [1, 2]}),
    ],
)
def test_invalid_request_contracts_do_not_call_services(client, configured_app, endpoint, body):
    assert client.post(endpoint, headers=AUTH, json=body).status_code == 422
    configured_app[1].assert_not_called()
    configured_app[2].assert_not_called()


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (psycopg.errors.QueryCanceled("private SQL details"), 504),
        (psycopg.OperationalError("postgresql://private-user:private-secret@private-host"), 503),
    ],
)
def test_sql_errors_return_safe_status_and_no_upstream_details(
    client, configured_app, error, expected_status
):
    configured_app[1].side_effect = error
    response = client.post("/tools/sql", headers=AUTH, json={"query": "SELECT 1"})
    assert response.status_code == expected_status
    assert "private" not in response.text
    assert TEST_KEY not in response.text


def test_sql_primary_diagnostic_is_returned_without_context(client, configured_app):
    configured_app[1].side_effect = psycopg.errors.UndefinedColumn(
        "private raw error",
        info={
            psycopg.pq.DiagnosticField.MESSAGE_PRIMARY: b'column "bad_column" does not exist',
            psycopg.pq.DiagnosticField.MESSAGE_DETAIL: b"private detail",
            psycopg.pq.DiagnosticField.CONTEXT: b"private context",
        },
    )
    response = client.post("/tools/sql", headers=AUTH, json={"query": "SELECT bad_column"})
    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error_type": "sql_error",
        "detail": 'column "bad_column" does not exist',
        "sqlstate": "42703",
    }


def test_sql_primary_diagnostic_redacts_configured_secrets_and_caps_length(client, configured_app):
    configured_app[1].side_effect = psycopg.errors.UndefinedColumn(
        info={psycopg.pq.DiagnosticField.MESSAGE_PRIMARY: (TEST_KEY + " " + "x" * 1200).encode()}
    )
    response = client.post("/tools/sql", headers=AUTH, json={"query": "SELECT 1"})
    assert response.status_code == 200
    assert TEST_KEY not in response.text
    assert response.json()["detail"].startswith("[REDACTED]")
    assert len(response.json()["detail"]) == 1000


def test_primary_search_validation_error_is_returned_as_tool_result(client, configured_app):
    response = client.post(
        "/tools/search",
        headers=AUTH,
        json={"mode": "hybrid", "query": "PowerShell"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert response.json()["error_type"] == "search_error"
    assert "weights" in response.json()["detail"]
    configured_app[3].assert_not_called()


def test_primary_search_input_error_is_returned_as_tool_result(client, configured_app):
    configured_app[3].side_effect = SearchInputError("Invalid search request")
    response = client.post(
        "/tools/search", headers=AUTH, json={"mode": "lexical", "query": "PowerShell"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error_type": "search_error",
        "detail": "Invalid search request",
    }


@pytest.mark.parametrize("status", [400, 503])
def test_primary_search_qdrant_errors_distinguish_recoverable_from_upstream(
    client, configured_app, status
):
    configured_app[3].side_effect = UnexpectedResponse(
        status_code=status,
        reason_phrase="private reason",
        content=json.dumps({"status": {"error": "Wrong input: invalid vector name"}}).encode(),
        headers={"api-key": "private key"},
    )
    response = client.post(
        "/tools/search", headers=AUTH, json={"mode": "lexical", "query": "PowerShell"}
    )
    if status == 400:
        assert response.status_code == 200
        assert response.json() == {
            "ok": False,
            "error_type": "search_error",
            "detail": "Wrong input: invalid vector name",
        }
    else:
        assert response.status_code == 502
        assert response.json() == {"detail": "Wrong input: invalid vector name"}


@pytest.mark.parametrize("status", [400, 401, 503])
def test_qdrant_errors_do_not_expose_headers_or_response_body(client, configured_app, status):
    configured_app[2].side_effect = UnexpectedResponse(
        status_code=status,
        reason_phrase="private-reason",
        content=b"private-provider-body",
        headers={"api-key": "private-provider-key"},
    )
    response = client.post("/tools/semantic-search", headers=AUTH, json={"query": "PowerShell"})
    assert response.status_code == (400 if status == 400 else 502)
    assert response.json() == {"detail": "Qdrant request failed"}
    assert "private" not in response.text


@pytest.mark.parametrize("status", [400, 404, 503])
def test_qdrant_json_error_returns_message(client, configured_app, status):
    configured_app[2].side_effect = UnexpectedResponse(
        status_code=status,
        reason_phrase="private reason",
        content=json.dumps(
            {"status": {"error": "Wrong input: invalid vector name"}, "extra": "private details"}
        ).encode(),
        headers={"api-key": "private key"},
    )
    response = client.post("/tools/semantic-search", headers=AUTH, json={"query": "PowerShell"})
    assert response.status_code == (400 if status == 400 else 502)
    assert response.json() == {"detail": "Wrong input: invalid vector name"}


@pytest.mark.parametrize("body", [[], None, {"status": "error"}, {"status": {"error": {}}}])
def test_qdrant_unrecognized_json_uses_generic_message(client, configured_app, body):
    configured_app[2].side_effect = UnexpectedResponse(
        status_code=400, reason_phrase="private", content=json.dumps(body).encode(), headers={}
    )
    response = client.post("/tools/semantic-search", headers=AUTH, json={"query": "PowerShell"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Qdrant request failed"}


def test_qdrant_error_redacts_secret_and_caps_length(client, configured_app):
    configured_app[2].side_effect = UnexpectedResponse(
        status_code=400,
        reason_phrase="private",
        content=json.dumps({"status": {"error": TEST_KEY + " " + "x" * 1200}}).encode(),
        headers={},
    )
    response = client.post("/tools/semantic-search", headers=AUTH, json={"query": "PowerShell"})
    assert response.status_code == 400
    assert TEST_KEY not in response.text
    assert response.json()["detail"].startswith("[REDACTED]")
    assert len(response.json()["detail"]) == 1000


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError])
def test_generic_provider_failure_does_not_expose_secrets(client, configured_app, error_type):
    configured_app[2].side_effect = error_type("private provider credentials and traceback")
    response = client.post("/tools/semantic-search", headers=AUTH, json={"query": "PowerShell"})
    assert response.status_code == 502
    assert response.json() == {"detail": "Search service is unavailable"}


def test_known_sql_input_error_is_returned_as_tool_result(client, configured_app):
    configured_app[1].side_effect = SearchInputError("Only SELECT queries are allowed")
    response = client.post("/tools/sql", headers=AUTH, json={"query": "DELETE FROM attack.nodes"})
    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error_type": "sql_error",
        "detail": "Only SELECT queries are allowed",
        "sqlstate": None,
    }
