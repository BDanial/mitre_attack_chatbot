"""Run: uvicorn attack_search.api.app:create_app --factory --host 127.0.0.1"""

import os
import secrets
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from qdrant_client.http.exceptions import UnexpectedResponse

from attack_search.api.models import (
    SemanticRequest,
    SemanticResponse,
    SQLRequest,
    SQLResponse,
)
from attack_search.config import load_environment
from attack_search.services.search import SearchInputError, query_sql, semantic_search


def create_app() -> FastAPI:
    load_environment()
    api_key = os.environ.get("API_KEY", "")
    if len(api_key) < 16 or api_key == "replace-me":
        raise RuntimeError("Set API_KEY to a random secret of at least 16 characters")
    database_url = os.environ.get("API_DATABASE_URL") or os.environ.get("DATABASE_URL")
    app = FastAPI(
        title="ATT&CK Search Tools",
        version="0.1.0",
        description="Read-only SQL and semantic search tools for Enterprise ATT&CK.",
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
        "/tools/semantic-search",
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

    @app.exception_handler(psycopg.Error)
    async def database_error(request: Request, exc: psycopg.Error):
        if isinstance(exc, psycopg.errors.QueryCanceled):
            return JSONResponse(status_code=504, content={"detail": "SQL exceeded its time limit"})
        if isinstance(exc, psycopg.OperationalError):
            return JSONResponse(status_code=503, content={"detail": "SQL service is unavailable"})
        return JSONResponse(
            status_code=400,
            content={
                "detail": "SQL was rejected; check syntax, names and permissions",
                "sqlstate": exc.sqlstate,
            },
        )

    @app.exception_handler(UnexpectedResponse)
    async def qdrant_error(request: Request, exc: UnexpectedResponse):
        status = 400 if exc.status_code == 400 else 502
        return JSONResponse(status_code=status, content={"detail": "Qdrant request failed"})

    @app.exception_handler(Exception)
    async def service_error(request: Request, exc: Exception):
        # Never forward database URLs, provider messages, headers or tracebacks.
        return JSONResponse(status_code=502, content={"detail": "Search service is unavailable"})

    return app
