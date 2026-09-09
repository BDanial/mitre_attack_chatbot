# Search API and Dify Setup

The API exposes two tools with a shared API key. It does not generate the final chatbot answer.
The LLM chooses a tool, supplies its query, and uses the returned data as evidence.

| Tool operation ID | HTTP route | Purpose |
| --- | --- | --- |
| `query_sql` | `POST /tools/sql` | Exact records, relationships, counts and lists in PostgreSQL |
| `search_attack` | `POST /tools/search` | Semantic, lexical BM25, or weighted hybrid search chosen by the LLM |

Implementation: [search functions](../src/attack_search/services/search.py),
[HTTP routes and authentication](../src/attack_search/api/app.py),
[request/response models](../src/attack_search/api/models.py).
Start with the [LLM tool guide](orchestrator/llm-tool-guide.md) for copyable system
instructions and complete JSON examples. Use the [orchestrator guide](orchestrator/semantic-search.md)
for graph resolution and evidence policy. Qdrant server and client 1.19+ are required for the hybrid index.

For an LLM reading every documentation file, follow the [documentation map](README.md).
Only the two tools above are agent capabilities. Deployment commands and the explicitly labeled
legacy section below are host/developer reference, not additional tools.

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
| `OPENROUTER_API_KEY` | Semantic/hybrid query embedding credential; lexical mode makes no OpenRouter call |
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

## 3. Search tool: semantic, lexical, and hybrid

Call `search_attack` (`POST /tools/search`) with plain text and simple filters. The LLM selects
the mode and, for hybrid, the relative weights. The backend creates every Qdrant request; the
LLM does not send a vector, collection name, `must`, `match`, prefetch, or fusion syntax.

```json
{
  "mode": "hybrid",
  "query": "Attackers run encoded commands using PowerShell",
  "lexical_query": "PowerShell EncodedCommand",
  "weights": {"semantic": 0.7, "lexical": 0.3},
  "filters": {
    "types": ["attack-pattern", "behavior_example"],
    "platforms": ["Windows"]
  },
  "limit": 10,
  "offset": 0,
  "question_answering": false
}
```

### Modes and weighting

| `mode` | What the backend executes | LLM input |
| --- | --- | --- |
| `semantic` | Dense cosine search using OpenRouter query embedding | Natural-language `query`; omit `weights` and `lexical_query` |
| `lexical` | Native Qdrant BM25 search over `lexical_bm25_v1` | Keyword `query`, usually English; omit `weights` and `lexical_query` |
| `hybrid` | Both Qdrant searches, fused by the backend using weighted RRF with `k=60` | `query` plus required `weights`; optional `lexical_query` for different keyword wording |

Lexical mode never calls OpenRouter. The English corpus uses BM25 token matching, not exact
substring, exact phrase, or Boolean query syntax. For literal text conditions, use SQL `ILIKE`
or another explicit PostgreSQL text condition. Keep commands and product names in the query;
do not expect a Persian keyword to match its English translation automatically.

For hybrid, both weights must be finite positive numbers. The server normalizes them to sum
to one: `{ "semantic": 7, "lexical": 3 }` is equivalent to 0.7/0.3. Zero weights are rejected;
choose a single mode when only one retriever is wanted. Weighted RRF combines ranks,
not raw BM25 and cosine scores. The numbers express relative rank contributions, not a calibrated
percentage of semantic meaning or probability of correctness.

Both hybrid branches receive the same filters and each retrieves `max(100, offset + limit)`
candidates through one Qdrant batch-query request. The backend deduplicates by point ID and scores
each candidate as `semantic_weight / (60 + semantic_rank) + lexical_weight / (60 + lexical_rank)`.
Ranks start at one; an absent candidate contributes zero for that branch. Equal scores are ordered
by point ID. Pagination is applied after fusion. This applies the LLM coefficients directly to
reciprocal ranks; it is intentionally different from Qdrant's native rank-rescaling weighted RRF.
This bounded candidate pool is not exhaustive. Increasing offset above the first candidate pool
can change the fusion ranking; pagination does not provide a frozen search snapshot.

### Request fields and simple filters

| Input | Behavior |
| --- | --- |
| `mode` | Required: `semantic`, `lexical`, or `hybrid` |
| `query` | Required non-empty raw text, at most 7,000 UTF-8 bytes; no task prefix |
| `lexical_query` | Optional non-empty keyword text, at most 7,000 UTF-8 bytes; hybrid only. If omitted, BM25 uses `query` |
| `weights` | Required only for hybrid: exactly `semantic` and `lexical`, both finite and positive |
| `filters` | Optional simple object below; omitted or `{}` means active points |
| `limit` | Default 10; integer 1–50 |
| `offset` | Default 0; integer 0–1,000 |
| `question_answering` | Default false; only changes the dense embedding prefix. True is invalid in lexical mode |

`filters` and `weights` also accept JSON-encoded object strings for clients that serialize
nested parameters as strings. Prefer normal JSON objects. Unknown fields are rejected.

| Field within `filters` | Meaning |
| --- | --- |
| `is_active` | `true` by default; `false` selects inactive points; JSON `null` includes all statuses |
| `types` | List of exact evidence types: `attack-pattern`, `behavior_example`, `course-of-action`, `mitigates`, `x-mitre-detection-strategy`, `x-mitre-analytic` |
| `technique_attack_ids` | List of exact technique display codes such as `T1059.001`; a parent does not include its children |
| `platforms` | List of exact source platform names such as `Windows`, `Linux`, `macOS`; maps to inherited `related_platforms` |

Different filter categories are combined with AND; values inside one list are OR. Omit a list
for no restriction; an empty list is invalid. Codes and platform names are case-sensitive.
A technique-code filter matches all types of evidence linked to that technique; add `types`
when you want only technique descriptions or only defenses.

`platforms` means related-technique context, not an analytic's own applicability. A linked
technique code and a platform may come from different related techniques on one point.
`is_active` checks the point; code links include all statuses and do not prove an active graph
path. Resolve strict same-technique, current-edge, analytic-platform, tactic, or log constraints
through SQL and verify the returned sources. The simple tool does not expose arbitrary payload filters.

### Response and operational behavior

The response contains `collection`, `points`, `limit`, `offset`, `mode`, `score_kind`, and
`weights`. `score_kind` is `cosine`, `bm25`, or `weighted_rrf`; `weights` contains normalized
weights for hybrid and is `null` for either single mode. Each point contains `id`, `score`,
and the original `payload`, including source IDs, type, chunk text, provenance, and snapshot.
Raw vectors are not returned. A successful empty result has `points: []`.

The service resolves and pins the physical collection for the request. Lexical and hybrid
require the matching BM25 profile and complete sparse index; an incomplete index returns 503
with an actionable readiness message. For an existing dense snapshot, run
`uv run attack-search index-lexical`. Semantic mode remains usable with the original dense index.
See [operations](operations.md#add-lexical-search-to-an-existing-snapshot).

The endpoint does not join PostgreSQL, expand hierarchies, group chunks, or generate an answer.
Scores have different meanings between modes and are never confidence percentages. Keep source
verification and evidence grouping in the orchestrator. Do not combine SQL and search results
across a [dataset refresh](operations.md#refresh-a-published-snapshot); there is no shared transaction.

Semantic and hybrid requests can incur OpenRouter charges. There is no query cache. The Qdrant
search timeout is 10 seconds; provider operations and retries can make overall HTTP latency longer.
Set Dify and proxy timeouts accordingly.

### Host/developer compatibility only: the original semantic endpoint

`POST /tools/semantic-search` remains available for existing clients, with the original
request/response shape below. Do not select this route as an agent reading this document.
It is hidden from OpenAPI so a new LLM sees only `query_sql`
and `search_attack`. The following native `filter` examples belong only to this legacy route,
not to the new tool's plural `filters` field.

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
   `query_sql` and `search_attack`. Re-import the schema and remove the old `semantic_search`
   tool from an existing agent configuration.
3. Configure API-key authentication with header name **`X-API-Key`** and the value from your
   private `.env`. Use the raw key with a custom/no prefix; do not add `Bearer `.
4. Test SQL with `SELECT 1 AS ok`. Test all three search modes using the JSON examples in the
   [LLM guide](orchestrator/llm-tool-guide.md). Attach its system instructions to the
   agent. The entire docs folder can be supplied as reference; use the [documentation map](README.md)
   to distinguish current tool instructions from storage and host-only material.
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
| 503 | SQL connection is missing/unavailable, or lexical/hybrid index is not ready |
| 504 | SQL statement timeout |
| 502 | Upstream/search service failure |

Do not treat an error as “no matching evidence.” Raw provider messages, database URLs, headers,
and tracebacks are not returned in tool responses. SQL errors include their SQLSTATE where available,
and the primary PostgreSQL SQL-error message in `detail` (up to 1,000 characters, with configured
credentials redacted). Diagnostic context, extra detail, raw exception text, and tracebacks are
not exposed. Connection failures and timeouts retain generic messages.

Qdrant HTTP errors return the JSON `status.error` string in `detail`, capped at 1,000 characters
with configured credentials redacted. Unrecognized/non-JSON responses retain the generic message;
raw bodies and headers are never forwarded. Upstream HTTP 400 maps to 400; other Qdrant HTTP
errors map to 502.

## 6. Tests

```shell
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
```

The normal test suite uses local/mocked services and does not spend embedding credits or write
to the cloud databases. Live smoke checks, when performed, are separate from those offline tests.

Hybrid checks on 8 September 2026: all 225 offline tests passed. Two deprecation warnings come from
the installed Starlette test-client dependencies, not failed assertions. After the English
documentation revision, 20 current search/SQL JSON examples and one explicitly labeled legacy
example validated against the request models. All 28 SQL recipes parsed successfully, and
101 relative file-link targets resolved. These documentation checks were offline.

Live requests through FastAPI's test client returned HTTP 200 for SQL, lexical, semantic, and hybrid
with 70/30 and 30/70 weights. For `execute encoded PowerShell commands` with lexical keywords
`PowerShell EncodedCommand`, the lexical-heavy hybrid ranked the `T1059.001` technique chunk first;
the semantic-heavy hybrid ranked a `T1027.010` behavior chunk first. The weights therefore affected
the actual ranking, not just response metadata. This is a smoke check, not a retrieval-quality
benchmark or a hosted Dify integration test.

The live index contained 23,240 points with BM25 vectors, and dense-vector/payload hashes for five
sampled points matched the pre-upgrade hashes. Earlier SQL checks also confirmed
`transaction_read_only=on`, `statement_timeout=5s`, and capped results with `truncated=true`.
