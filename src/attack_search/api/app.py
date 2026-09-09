"""Run: uvicorn attack_search.api.app:create_app --factory --host 127.0.0.1"""

import json
import os
import secrets
from typing import Annotated

import psycopg
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from qdrant_client.http.exceptions import UnexpectedResponse

from attack_search import __version__
from attack_search.api.models import (
    SearchRequest,
    SearchResponse,
    SemanticRequest,
    SemanticResponse,
    SQLRequest,
    SQLResponse,
)
from attack_search.config import load_environment
from attack_search.search_contract import SEARCH_EXAMPLES
from attack_search.services.search import (
    SearchInputError,
    SearchUnavailableError,
    query_sql,
    search_attack,
    semantic_search,
)


def create_app() -> FastAPI:
    load_environment()
    api_key = os.environ.get("API_KEY", "")
    if len(api_key) < 16 or api_key == "replace-me":
        raise RuntimeError("Set API_KEY to a random secret of at least 16 characters")
    database_url = os.environ.get("API_DATABASE_URL") or os.environ.get("DATABASE_URL")
    app = FastAPI(
        title="ATT&CK Search Tools",
        version=__version__,
        description="Read-only SQL and semantic, lexical or weighted hybrid search for Enterprise ATT&CK.",
        servers=[{"url": os.environ.get("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")}],
    )
    key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def authenticate(key: Annotated[str | None, Security(key_header)] = None):
        if key is None or not secrets.compare_digest(key.encode(), api_key.encode()):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    @app.post(
        "/tools/sql",
        operation_id="query_sql",
        response_model=SQLResponse,
        dependencies=[Depends(authenticate)],
        summary="Query ATT&CK with read-only PostgreSQL",
        description="Use for exact IDs, graph joins, counts and lists. One SELECT or read-only CTE; "
        "qualify tables with attack. Row cap 500 and statement timeout 5 seconds.",
    )
    def sql_tool(body: SQLRequest):
        if not database_url:
            raise HTTPException(status_code=503, detail="SQL connection is not configured")
        return query_sql(body.query, database_url=database_url, limit=body.limit)

    @app.post(
        "/tools/search",
        operation_id="search_attack",
        response_model=SearchResponse,
        dependencies=[Depends(authenticate)],
        summary="Search ATT&CK by meaning, keywords, or both",
        description="Choose mode: semantic for meaning, lexical for English words/commands, hybrid "
        "for both. Always send query. Hybrid requires weights, e.g. semantic=0.7, lexical=0.3; "
        "optional lexical_query gives English keywords for a Persian query. Use simple filters "
        "(types, technique_attack_ids, platforms, is_active); never write Qdrant syntax or vectors. "
        "Omitted filters search active records. Results are evidence chunks, not complete lists. "
        "Use query_sql for exact counts and graph relationships. Only semantic/hybrid calls OpenRouter.",
    )
    def search_tool(
        body: Annotated[
            SearchRequest,
            Body(
                openapi_examples={
                    example["mode"]: {"summary": example["mode"], "value": example}
                    for example in SEARCH_EXAMPLES
                }
            ),
        ],
    ):
        return search_attack(body)

    @app.post(
        "/tools/semantic-search",
        include_in_schema=False,
        operation_id="semantic_search",
        response_model=SemanticResponse,
        dependencies=[Depends(authenticate)],
        summary="Search ATT&CK semantic evidence",
        description="Embed raw query text and search the published Qdrant collection. Filter by type "
        "and indexed metadata. Technique STIX IDs are PostgreSQL IDs, not Qdrant point UUIDs. "
        "Results are chunks, not complete entity lists. Query embedding can incur a charge.",
    )
    def semantic_tool(body: SemanticRequest):
        return semantic_search(
            body.query,
            query_filter=body.filter,
            limit=body.limit,
            offset=body.offset,
            question_answering=body.question_answering,
        )

    @app.exception_handler(SearchInputError)
    async def invalid_query(request: Request, exc: SearchInputError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(SearchUnavailableError)
    async def unavailable_index(request: Request, exc: SearchUnavailableError):
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Search index is unavailable or incompatible. Verify the published "
                "index; run attack-search index-lexical for lexical/hybrid readiness."
            },
        )

    @app.exception_handler(psycopg.Error)
    async def database_error(request: Request, exc: psycopg.Error):
        if isinstance(exc, psycopg.errors.QueryCanceled):
            return JSONResponse(status_code=504, content={"detail": "SQL exceeded its time limit"})
        if isinstance(exc, psycopg.OperationalError):
            return JSONResponse(status_code=503, content={"detail": "SQL service is unavailable"})
        # Return only the primary SQL diagnostic, never connection/context/traceback text.
        detail = exc.diag.message_primary or "SQL was rejected; check syntax, names and permissions"
        for name in (
            "DATABASE_URL",
            "API_DATABASE_URL",
            "API_KEY",
            "OPENROUTER_API_KEY",
            "QDRANT_API_KEY",
        ):
            secret = os.environ.get(name)
            if secret:
                detail = detail.replace(secret, "[REDACTED]")
        return JSONResponse(
            status_code=400,
            content={
                "detail": detail[:1000],
                "sqlstate": exc.sqlstate,
            },
        )

    @app.exception_handler(UnexpectedResponse)
    async def qdrant_error(request: Request, exc: UnexpectedResponse):
        status = 400 if exc.status_code == 400 else 502
        detail = "Qdrant request failed"
        try:
            body = json.loads(exc.content)
            remote_status = body.get("status") if isinstance(body, dict) else None
            message = remote_status.get("error") if isinstance(remote_status, dict) else None
            if isinstance(message, str) and message.strip():
                detail = message
        except (ValueError, TypeError):
            pass  # A proxy may return HTML or malformed JSON; never expose its raw body.
        for name in (
            "DATABASE_URL",
            "API_DATABASE_URL",
            "API_KEY",
            "OPENROUTER_API_KEY",
            "QDRANT_API_KEY",
        ):
            secret = os.environ.get(name)
            if secret:
                detail = detail.replace(secret, "[REDACTED]")
        return JSONResponse(status_code=status, content={"detail": detail[:1000]})

    @app.exception_handler(Exception)
    async def service_error(request: Request, exc: Exception):
        # Never forward database URLs, provider messages, headers or tracebacks.
        return JSONResponse(status_code=502, content={"detail": "Search service is unavailable"})

    return app
