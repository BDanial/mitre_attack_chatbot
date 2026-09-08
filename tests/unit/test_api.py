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
    monkeypatch.setattr(api, "query_sql", sql)
    monkeypatch.setattr(api, "semantic_search", semantic)
    return api.create_app(), sql, semantic


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
    assert set(schema["paths"]) == {"/tools/sql", "/tools/semantic-search"}
    assert schema["servers"] == [{"url": "https://search.example.test"}]
    assert schema["paths"]["/tools/sql"]["post"]["operationId"] == "query_sql"
    assert schema["paths"]["/tools/semantic-search"]["post"]["operationId"] == "semantic_search"
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
        (psycopg.errors.UndefinedTable("private schema details"), 400),
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


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError])
def test_generic_provider_failure_does_not_expose_secrets(client, configured_app, error_type):
    configured_app[2].side_effect = error_type("private provider credentials and traceback")
    response = client.post("/tools/semantic-search", headers=AUTH, json={"query": "PowerShell"})
    assert response.status_code == 502
    assert response.json() == {"detail": "Search service is unavailable"}


def test_known_input_error_is_returned_as_400(client, configured_app):
    configured_app[1].side_effect = SearchInputError("Only SELECT queries are allowed")
    response = client.post("/tools/sql", headers=AUTH, json={"query": "DELETE FROM attack.nodes"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Only SELECT queries are allowed"}
