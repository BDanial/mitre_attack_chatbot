"""Two read-only search tools. SQL still requires a least-privilege database role."""

from contextlib import closing

import psycopg
from pglast import ast, parse_sql
from pglast.parser import ParseError
from pglast.stream import RawStream
from pglast.visitors import Visitor
from pydantic import ValidationError
from qdrant_client import models

from attack_search.embeddings.client import create_embedding_client, embed_query
from attack_search.embeddings.lexical import LEXICAL_VECTOR, bm25_document
from attack_search.embeddings.profile import ALIAS, DIMENSIONS
from attack_search.search_contract import SearchRequest
from attack_search.storage.qdrant import (
    KEYWORD_FIELDS,
    create_qdrant_client,
    ensure_lexical_ready,
)


class SearchInputError(ValueError):
    """A safe validation message that may be returned to a tool caller."""


class SearchUnavailableError(RuntimeError):
    """A known missing index, distinct from an empty search or upstream failure."""


class _SelectOnly(Visitor):
    """Reject write statements even inside a CTE; this is not a function sandbox."""

    def visit(self, ancestors, node):
        if type(node).__name__.endswith("Stmt") and not isinstance(
            node, (ast.RawStmt, ast.SelectStmt)
        ):
            raise SearchInputError("Only SELECT queries and read-only CTEs are allowed")
        if isinstance(node, ast.SelectStmt) and (node.intoClause or node.lockingClause):
            raise SearchInputError("SELECT INTO and row-locking clauses are not allowed")


def query_sql(query: str, *, database_url: str, limit: int = 100) -> dict:
    """Run one bounded SELECT. Return columns separately to preserve duplicate names."""
    if not query.strip() or len(query) > 20000 or not 1 <= limit <= 500:
        raise SearchInputError("SQL must be 1-20000 characters; limit must be 1-500")
    try:
        statements = parse_sql(query)
    except ParseError as exc:
        raise SearchInputError("Invalid PostgreSQL query syntax") from exc
    if len(statements) != 1 or not isinstance(statements[0].stmt, ast.SelectStmt):
        raise SearchInputError("Provide exactly one SELECT query or read-only CTE")
    _SelectOnly()(statements)
    # Reprint the parsed statement to remove trailing semicolons and comments safely.
    select = RawStream()(statements[0].stmt)
    bounded = f"SELECT * FROM ({select}) AS tool_result LIMIT {limit + 1}"
    with psycopg.connect(database_url, connect_timeout=10) as connection:
        connection.execute("SET TRANSACTION READ ONLY")
        connection.execute("SET LOCAL statement_timeout = '5s'")
        connection.execute("SET LOCAL lock_timeout = '1s'")
        connection.execute("SET LOCAL search_path = pg_catalog, attack")
        cursor = connection.execute(bounded, prepare=True)
        columns = [column.name for column in cursor.description]
        rows = cursor.fetchall()
    return {
        "columns": columns,
        "rows": [list(row) for row in rows[:limit]],
        "row_count": min(len(rows), limit),
        "truncated": len(rows) > limit,
    }


def _validate_filter(query_filter: dict) -> models.Filter:
    try:
        parsed = models.Filter.model_validate(query_filter)
    except ValidationError as exc:
        raise SearchInputError("Invalid Qdrant filter structure") from exc

    def check(condition):
        if isinstance(condition, models.Filter):
            for group in (condition.must, condition.should, condition.must_not):
                if group is None:
                    continue
                for item in group if isinstance(group, list) else [group]:
                    check(item)
            if condition.min_should:
                for item in condition.min_should.conditions:
                    check(item)
        elif isinstance(condition, models.FieldCondition):
            if condition.key not in (*KEYWORD_FIELDS, "is_active"):
                raise SearchInputError(f"Payload field is not filterable: {condition.key}")
            if condition.key == "is_active":
                valid = isinstance(condition.match, models.MatchValue) and isinstance(
                    condition.match.value, bool
                )
            else:
                match = condition.match
                if isinstance(match, models.MatchValue):
                    values = [match.value]
                elif isinstance(match, models.MatchAny):
                    values = match.any
                elif isinstance(match, models.MatchExcept):
                    values = match.except_
                else:
                    values = []
                valid = bool(values) and all(isinstance(value, str) for value in values)
            fields = condition.model_dump(exclude_none=True)
            if not valid or set(fields) != {"key", "match"}:
                raise SearchInputError(
                    "Use keyword match filters, or a Boolean match for is_active"
                )
        else:
            raise SearchInputError(
                "Only indexed field matches and logical filter groups are supported"
            )

    check(parsed)
    return parsed


def semantic_search(
    query: str,
    *,
    query_filter: dict | None = None,
    limit: int = 10,
    offset: int = 0,
    question_answering: bool = False,
) -> dict:
    """Embed text and search the published collection; never accept a collection or vector."""
    if not query.strip() or len(query.encode("utf-8")) > 7000:
        raise SearchInputError("Search text must be non-empty and at most 7000 UTF-8 bytes")
    if not 1 <= limit <= 50 or not 0 <= offset <= 1000:
        raise SearchInputError("Search limit must be 1-50; offset must be 0-1000")
    if query_filter is None:
        query_filter = {"must": [{"key": "is_active", "match": {"value": True}}]}
    parsed_filter = _validate_filter(query_filter)
    with closing(create_qdrant_client()) as qdrant:
        collection = next(
            (a.collection_name for a in qdrant.get_aliases().aliases if a.alias_name == ALIAS), None
        )
        if collection is None:
            raise RuntimeError("Published semantic collection is unavailable")
        vectors = qdrant.get_collection(collection).config.params.vectors
        if not isinstance(vectors, models.VectorParams) or (
            vectors.size != DIMENSIONS or vectors.distance != models.Distance.COSINE
        ):
            raise RuntimeError("Published vector configuration does not match the query profile")
        with create_embedding_client() as client:
            vector = embed_query(client, query, question_answering=question_answering)
        result = qdrant.query_points(
            collection_name=collection,
            query=vector,
            query_filter=parsed_filter,
            limit=limit,
            offset=offset,
            with_payload=True,
            with_vectors=False,
            timeout=10,
        )
    return {
        "collection": collection,
        "points": [
            {"id": str(point.id), "score": point.score, "payload": point.payload}
            for point in result.points
        ],
        "limit": limit,
        "offset": offset,
    }


def search_attack(request: SearchRequest) -> dict:
    """Choose one retrieval mode; build all Qdrant queries inside the service."""
    # Revalidate even direct service calls, before opening either remote client.
    request = SearchRequest.model_validate(request.model_dump())
    query_filter = _validate_filter(request.filters.to_qdrant_filter())
    weights = request.weights.normalized() if request.weights else None
    with closing(create_qdrant_client()) as qdrant:
        collection = next(
            (a.collection_name for a in qdrant.get_aliases().aliases if a.alias_name == ALIAS), None
        )
        if collection is None:
            raise SearchUnavailableError("Published search collection is unavailable")
        info = qdrant.get_collection(collection)
        vectors = info.config.params.vectors
        if not isinstance(vectors, models.VectorParams) or (
            vectors.size != DIMENSIONS or vectors.distance != models.Distance.COSINE
        ):
            raise SearchUnavailableError("Published vector configuration is incompatible")
        if request.mode != "semantic":
            try:
                ensure_lexical_ready(qdrant, collection, info=info)
            except ValueError as exc:
                raise SearchUnavailableError(
                    "Lexical index is unavailable or incomplete; run attack-search index-lexical"
                ) from exc

        arguments = {
            "collection_name": collection,
            "query_filter": query_filter,
            "limit": request.limit,
            "offset": request.offset,
            "with_payload": True,
            "with_vectors": False,
            "timeout": 10,
        }
        if request.mode != "lexical":
            with create_embedding_client() as client:
                dense = embed_query(
                    client, request.query, question_answering=request.question_answering
                )
        if request.mode != "semantic":
            sparse = bm25_document(request.lexical_query or request.query)

        if request.mode == "semantic":
            arguments["query"] = dense
        elif request.mode == "lexical":
            arguments.update(query=sparse, using=LEXICAL_VECTOR)
        else:
            candidates = max(100, request.offset + request.limit)
            ranked = qdrant.query_batch_points(
                collection_name=collection,
                requests=[
                    models.QueryRequest(
                        query=dense,
                        filter=query_filter,
                        limit=candidates,
                        with_payload=True,
                        with_vector=False,
                    ),
                    models.QueryRequest(
                        query=sparse,
                        using=LEXICAL_VECTOR,
                        filter=query_filter,
                        limit=candidates,
                        with_payload=True,
                        with_vector=False,
                    ),
                ],
                timeout=10,
            )
            if len(ranked) != 2:
                raise RuntimeError("Hybrid search requires both retrieval responses")
            points = weighted_rrf(ranked, [weights["semantic"], weights["lexical"]])
            points = points[request.offset : request.offset + request.limit]
        if request.mode != "hybrid":
            result = qdrant.query_points(**arguments)
            points = [
                {"id": str(point.id), "score": point.score, "payload": point.payload}
                for point in result.points
            ]
    return {
        "collection": collection,
        "points": points,
        "limit": request.limit,
        "offset": request.offset,
        "mode": request.mode,
        "score_kind": {"semantic": "cosine", "lexical": "bm25", "hybrid": "weighted_rrf"}[
            request.mode
        ],
        "weights": weights,
    }


def weighted_rrf(ranked: list, weights: list[float]) -> list[dict]:
    """Fuse Qdrant rankings as sum(weight / (60 + one-based rank)).

    Apply coefficients to reciprocal ranks directly. Qdrant's native weighted
    RRF rescales ranks inside the denominator, which has different semantics.
    """
    fused = {}
    for response, weight in zip(ranked, weights):
        seen = set()
        for rank, point in enumerate(response.points, start=1):
            key = str(point.id)
            if key in seen:
                continue
            seen.add(key)
            item = fused.setdefault(key, {"id": key, "score": 0.0, "payload": point.payload})
            item["score"] += weight / (60 + rank)
    return sorted(fused.values(), key=lambda item: (-item["score"], item["id"]))
