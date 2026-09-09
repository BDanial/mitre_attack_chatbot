"""Small request and response contracts, also used to generate OpenAPI."""

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from attack_search.search_contract import SearchRequest as SearchRequest


class SQLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query: str = Field(min_length=1, max_length=20000, description="One PostgreSQL SELECT or CTE.")
    limit: int = Field(default=100, ge=1, le=500, description="Maximum returned rows.")


class SQLResponse(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    truncated: bool


class SQLErrorResponse(BaseModel):
    """Recoverable SQL feedback returned as HTTP 200 so tool hosts preserve it."""

    ok: Literal[False] = False
    error_type: Literal["sql_error"] = "sql_error"
    detail: str
    sqlstate: str | None = None


class SemanticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query: str = Field(
        min_length=1, max_length=7000, description="Raw search text; no task prefix."
    )
    filter: dict[str, Any] = Field(
        default_factory=lambda: {"must": [{"key": "is_active", "match": {"value": True}}]},
        description="Native Qdrant match filter. Omitted: active only. Empty object: all statuses.",
    )
    limit: int = Field(default=10, ge=1, le=50)
    offset: int = Field(default=0, ge=0, le=1000)
    question_answering: bool = Field(
        default=False, description="Use the question-answering prefix."
    )

    @field_validator("filter", mode="before")
    @classmethod
    def parse_filter_string(cls, value):
        # Some tool clients send object parameters as JSON strings.
        return json.loads(value) if isinstance(value, str) else value


class SearchPoint(BaseModel):
    id: str
    score: float
    payload: dict[str, Any]


class SemanticResponse(BaseModel):
    collection: str
    points: list[SearchPoint]
    limit: int
    offset: int


class SearchResponse(SemanticResponse):
    mode: Literal["semantic", "lexical", "hybrid"]
    score_kind: Literal["cosine", "bm25", "weighted_rrf"]
    weights: dict[str, float] | None


class SearchErrorResponse(BaseModel):
    """Recoverable search feedback returned as HTTP 200 so tool hosts preserve it."""

    ok: Literal[False] = False
    error_type: Literal["search_error"] = "search_error"
    detail: str
