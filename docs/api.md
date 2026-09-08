# Search API and Dify Setup

The API exposes two tools with a shared API key. It does not generate the final chatbot answer.
The LLM chooses a tool, supplies its query, and uses the returned data as evidence.

| Tool operation ID | HTTP route | Purpose |
| --- | --- | --- |
| `query_sql` | `POST /tools/sql` | Exact records, relationships, counts and lists in PostgreSQL |
| `semantic_search` | `POST /tools/semantic-search` | Text similarity search in the published Qdrant collection |

Implementation: [two search functions](../src/attack_search/services/search.py),
[HTTP routes and authentication](../src/attack_search/api/app.py),
[request/response models](../src/attack_search/api/models.py).
For intent and filter selection, use the [orchestrator guide](orchestrator/semantic-search.md).

## 1. Start locally

Run from the project root:

```shell
uv sync --locked
uv run uvicorn attack_search.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

The application factory loads `.env` without overwriting existing environment values. It does
not connect to either database at startup. Imports do not load secrets or start a server.

| Environment value | Purpose |
| --- | --- |
| `API_KEY` | Random shared key, at least 16 characters. Missing/short keys prevent startup |
| `API_BASE_URL` | URL in OpenAPI `servers`; defaults to `http://127.0.0.1:8000` |
| `API_DATABASE_URL` | Optional restricted PostgreSQL connection for the SQL tool |
| `DATABASE_URL` | Local-demo SQL fallback when `API_DATABASE_URL` is empty or absent |
| `OPENROUTER_API_KEY` | Query embedding credential |
| `QDRANT_URL`, `QDRANT_API_KEY` | Vector search credentials |

The current workspace has a generated `API_KEY` in its private `.env`. New checkouts must supply
their own secret. Never put this key in source code, a query, the LLM prompt, or a shared schema.

- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI document: `http://127.0.0.1:8000/openapi.json`
- Both POST routes require the `X-API-Key` header. Missing or incorrect keys return HTTP 401.

The documentation routes are intentionally public and contain no credentials or query results.
In Swagger, use **Authorize** to set the key before testing. Restart after changing environment
values such as the API key, SQL connection, or public base URL.

## 2. SQL tool

Request body:

```json
{
  "query": "SELECT attack_id, name FROM attack.techniques WHERE attack_id = 'T1059.001'",
  "limit": 100
}
```

Example response:

```json
{
  "columns": ["attack_id", "name"],
  "rows": [["T1059.001", "PowerShell"]],
  "row_count": 1,
  "truncated": false
}
```

`rows` is an array of arrays, in `columns` order. This preserves duplicate column names, nulls,
and JSON values without silently overwriting a dictionary key. Prefer explicit SQL aliases for
readability. `row_count` is the number returned, not the total number in the database.

The tool accepts one PostgreSQL SELECT, including read-only CTEs. It rejects multiple statements,
writable CTEs, SELECT INTO, and row locks. The parser understands comments and quoted semicolons;
it is not a simple string-prefix check. The query is placed inside a SELECT with a server-side
`LIMIT` of the requested number plus one, so `truncated` can be computed without returning the
whole result. The maximum limit is 500; the default is 100. Query text is capped at 20,000 characters.

Each request has its own connection and read-only transaction, a 5-second statement timeout,
a 1-second lock timeout, and a 10-second connection timeout. Qualify names with `attack`.
This is a demo-scale connection model; there is no application connection pool or SQL pagination
protocol. Add an explicit ORDER BY and SQL pagination when requesting further pages. A caller's
own LIMIT still applies; `truncated=false` is not a promise that the query covers the whole dataset.

### Important deployment boundary

**Do not expose an owner/admin database connection to an internet-facing LLM tool.** Set
`API_DATABASE_URL` to a separate role that can read only the intended ATT&CK tables/views, cannot
write or create objects, and has no unnecessary function privileges. Keep the owner connection
for import jobs. Creating this role is a database-administration step; the API does not create it.

SELECT can call functions. PostgreSQL read-only mode and the syntax guard do not prevent every
possible side effect, resource use, or data disclosure allowed by that database role. The key
authenticates the caller; it does not turn arbitrary SQL into a complete security sandbox.
[PostgreSQL read-only rules](https://www.postgresql.org/docs/current/sql-set-transaction.html)

The row cap does not bound the bytes in an individual cell. Before public hosting, also set
request/response size limits, concurrency/rate limits, HTTPS, and network access controls at the
deployment boundary. This change does not publish a server or modify database roles.

## 3. Semantic-search tool

The caller supplies natural-language text plus a native Qdrant **filter**. It does not supply
vectors, a collection name, or an arbitrary Qdrant operation. The service embeds the text using
the existing OpenRouter client and searches the current `attack_semantic` alias target.

```json
{
  "query": "Attackers run encoded commands using PowerShell",
  "filter": {
    "must": [
      {"key": "is_active", "match": {"value": true}},
      {"key": "type", "match": {"any": ["attack-pattern", "behavior_example"]}}
    ]
  },
  "limit": 10,
  "offset": 0,
  "question_answering": false
}
```

The response contains `collection`, `points`, `limit`, and `offset`. Each point has its UUID,
similarity `score`, and the original `payload`, including PostgreSQL IDs, type, text, related
techniques, and `dataset_snapshot`. Vectors are not returned. A successful empty search returns
`points: []`; it is not an error. This endpoint does not join PostgreSQL rows or generate an answer.

| Input | Behavior |
| --- | --- |
| `query` | Non-empty raw text, at most 7,000 UTF-8 bytes; do not add a task prefix yourself |
| `filter` omitted | Default filter is `is_active=true` |
| `filter: {}` | Explicitly search all statuses; no hidden active-only filter is added |
| `filter` as a JSON string | Also accepted for clients that serialize object parameters as strings |
| `limit` | Default 10; allowed 1–50 |
| `offset` | Default 0; allowed 0–1,000; each request embeds the query again |
| `question_answering` | False uses the search-result prefix; true uses the question-answering prefix |

Filters support keyword `match.value`, `match.any`, `match.except`, Boolean `is_active` matches,
and nested `must`, `should`, `must_not`, and `min_should` logic. Empty match-any/except lists are
rejected. Other native Qdrant conditions are intentionally outside this small tool contract.
Structural validation and indexed-field checks happen before the embedding call.

Allowed keyword fields: `type`, `db_table`, `db_id`, `document_id`, `dataset_snapshot`,
`technique_ids`, `technique_attack_ids`, `active_technique_ids`, `related_platforms`.
The only Boolean field is `is_active`. Tactic fields, `platforms`, and analytic/component IDs
are payload-only: resolve those constraints through SQL first. See the
[routing and filter guide](orchestrator/semantic-search.md#8-filters-that-work-on-the-current-collection).

The service pins the resolved physical collection for one search and checks the vector size and
distance before embedding. It does not recompute the PostgreSQL source fingerprint, perform graph
resolution, group chunks, or rerank evidence. Follow the orchestrator guide for those decisions.
Coordinate refreshes using the [maintenance procedure](operations.md#refresh-a-published-snapshot).
Do not combine separate SQL and semantic calls across a dataset refresh. The tools do not provide
a shared transaction or an automatic cross-database snapshot guarantee.

Embedding queries can incur OpenRouter charges. There is no query cache. The Qdrant search timeout
is 10 seconds; connection/provider operations have their own existing client timeouts and retries,
so total HTTP duration can be longer. Configure Dify and proxy timeouts accordingly.

## 4. Add the tools to Dify

1. Host the API at an HTTPS address reachable by the Dify backend. Set `API_BASE_URL` to that
   address and restart. A localhost address on your computer is not reachable from Dify Cloud;
   in a container, localhost normally refers to that container itself.
2. Open `/openapi.json` and import its URL or document into Dify's custom-tool configuration.
   The schema contains a `servers` URL, request/response schemas, and two stable operation IDs:
   `query_sql` and `semantic_search`.
3. Configure API-key authentication with header name **`X-API-Key`** and the value from your
   private `.env`. Use the raw key with a custom/no prefix; do not add `Bearer `.
4. Test SQL with `SELECT 1 AS ok`. Test semantic search with a short behavior query and a type
   filter. Then attach the tools and the orchestrator guide to the agent.
5. Keep the API key in Dify's credential configuration, not in the tool's natural-language input.

The schema's key-header security comes from FastAPI's API-key dependency. Dify's current custom
tool code supports a server URL and custom header authentication.
[FastAPI security](https://fastapi.tiangolo.com/reference/security/),
[Dify OpenAPI parser](https://github.com/langgenius/dify/blob/main/api/core/tools/utils/parser.py),
[Dify custom-tool request handling](https://github.com/langgenius/dify/blob/main/api/core/tools/custom_tool/tool.py)

Local OpenAPI and HTTP checks are not the same as a Dify import test. This repository does not
contain a configured Dify workspace, a deployed public URL, or a tested Dify conversation yet.

## 5. Error contract

| HTTP status | Meaning |
| --- | --- |
| 400 | Rejected SQL, unsupported filter, or other safe tool-input error |
| 401 | Missing or incorrect `X-API-Key` |
| 422 | Request-body validation failed; for example an empty query or invalid limit |
| 503 | SQL connection is missing or unavailable |
| 504 | SQL statement timeout |
| 502 | Upstream/search service failure |

Do not treat an error as “no matching evidence.” Raw provider messages, database URLs, headers,
and tracebacks are not returned in tool responses. SQL errors include their SQLSTATE where available,
but not the original database error text. Only deliberate input-validation messages are exposed.

## 6. Tests

```shell
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
```

The normal test suite uses local/mocked services and does not spend embedding credits or write
to the cloud databases. Live smoke checks, when performed, are separate from those offline tests.

Checks on 8 September 2026: all 115 offline tests passed; Ruff passed. Two deprecation warnings
come from the installed Starlette test-client dependencies, not failed assertions. Live requests
through FastAPI's test client returned HTTP 200 for both tools. SQL reported `transaction_read_only=on`
and `statement_timeout=5s`; a capped three-row query returned two rows with `truncated=true`.
One real query embedding and Qdrant search ranked `T1059.001` first for the encoded-PowerShell
example. This is a smoke check, not a retrieval-quality benchmark or a Dify integration test.
