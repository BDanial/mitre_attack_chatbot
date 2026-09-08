# Operations and Development Guide

**Audience: human hosts and developers.** These commands are not tools available to the answering
LLM. Reading this file does not authorize ingestion, index changes, deployment, or credential access.
For answering questions, use only `query_sql` and `search_attack`; see the
[documentation map](README.md) and [LLM tool guide](orchestrator/llm-tool-guide.md).

## Install and configure

Run commands from the project root with Python 3.10+ and uv. Python 3.12 is the verified environment.
The hybrid index requires Qdrant server and client 1.19 or newer.

```shell
uv sync --locked
uv run attack-search --help
```

For a new checkout, copy `.env.example` to `.env` and fill in the values. Keep an existing `.env`.
The CLI loads the file after parsing arguments. Imports and `--help` do not load secrets or make
network requests. `.env` is excluded from Git and the distribution package.

| Variable | Purpose | Required for |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL connection string | Ingest and index; hidden prompt if absent |
| `OPENROUTER_API_KEY` | OpenRouter credential | Missing dense embeddings and semantic/hybrid queries; not lexical-only work |
| `QDRANT_URL` | Qdrant service URL | Live indexing and vector search |
| `QDRANT_API_KEY` | Qdrant credential | Live indexing and vector search |
| `ATTACK_DATA_DIR` | Local data directory | Optional; defaults to `./data` |
| `API_KEY` | Shared `X-API-Key` secret | Required to start the API |
| `API_BASE_URL` | Reachable server URL in OpenAPI | Optional for local use; set before Dify import |
| `API_DATABASE_URL` | Restricted SQL-tool connection | Use before public exposure; local fallback is `DATABASE_URL` |

Existing environment values override `.env` values. An explicit `--env-file` must exist.
Relative data paths are resolved from the working directory. Example from another directory:

```shell
attack-search --env-file /absolute/path/to/project/.env index --dry-run
```

Use an absolute `ATTACK_DATA_DIR` or `ingest --data-dir` when running ingestion outside the project.
The supplied `CLUSTER_ENDPOINT` can remain in the local `.env`, but the application uses `QDRANT_URL`.

## Commands and side effects

| Command after `uv run attack-search` | Reads | Writes |
| --- | --- | --- |
| `ingest --download` | MITRE source URL | Raw/processed JSON and seven PostgreSQL tables |
| `ingest` | Prepared JSON files | Seven PostgreSQL tables |
| `index --dry-run` | PostgreSQL | Nothing |
| `index-lexical --dry-run` | PostgreSQL | Nothing |
| `index-lexical` | PostgreSQL and published Qdrant snapshot | Adds sparse schema/manifest and missing BM25 vectors; preserves dense vectors, IDs, payloads and alias |
| `index --limit 32` | PostgreSQL and existing Qdrant points | Up to 32 points; no alias publication |
| `index` | PostgreSQL and existing Qdrant points | Missing dense points, BM25 vectors, and completed index alias |

Generating missing dense embeddings calls OpenRouter and may incur charges. Every model batch is checked for count,
index order, dimension, finite values, and nonzero vectors.
`--batch-size` defaults to 32 and `--workers` to 4. Reduce workers for a small cluster:

```shell
uv run attack-search index --batch-size 32 --workers 1
```

The PostgreSQL import runs in one transaction. It uses COPY and a transaction-level advisory lock.
It only refreshes tables in `storage.postgres.TABLE_COLUMNS`. Raw and processed files are written
before the database import; filesystem writes are not part of the SQL transaction.

## Upgrade an existing semantic index to lexical and hybrid

Keep the same `.env`, PostgreSQL snapshot, and published `attack_semantic` alias. Run:

```shell
uv run attack-search index-lexical --dry-run
uv run attack-search index-lexical --batch-size 256 --workers 4
```

The dry run is a PostgreSQL preview only. The actual job validates every existing point ID and
full payload, dense-vector presence, and exact count before writing. It records the versioned
BM25 profile in collection metadata, creates `lexical_bm25_v1` with the vector-name creation API,
then uses `update_vectors` to add only missing sparse vectors. It never re-embeds dense vectors,
replaces payloads, imports PostgreSQL, or changes the alias. Native BM25 runs in Qdrant without
an OpenRouter key, a local model download, or a FastEmbed dependency.

If interrupted, rerun the same command. Completed sparse vectors are reused. Defaults are batches
of 128 and four workers; reduce workers if connectivity or cluster capacity requires it.
After backfill the job rechecks PostgreSQL, alias, every payload, and sparse completion. Do not
refresh the source concurrently. The API rejects lexical/hybrid with HTTP 503 while the sparse
schema/profile or vector coverage is incomplete; semantic search remains available.

Future full `index` runs build dense and BM25 data before publishing. `index --limit` remains a
dense sample only and does not promise lexical readiness. Changes to lexical tokenization or text
recipe require a new sparse vector name/profile; do not relabel incompatible existing vectors.

Restart the API after updating code and re-import OpenAPI into Dify. The new tool is
`search_attack` at `/tools/search`; the old `/tools/semantic-search` route remains available to
existing clients but is omitted from the new OpenAPI. Attach the
[Persian tool instructions and examples](orchestrator/llm-tool-guide.md) to the LLM.

## Refresh a published snapshot

1. Pause retrieval that resolves Qdrant IDs against PostgreSQL, or use application maintenance mode.
2. Run `ingest --download` to prepare and import the new source snapshot.
3. Run `index --dry-run` and review counts and the target collection name.
4. Run `index`. It completes dense and BM25 vectors and re-reads PostgreSQL before publishing the alias.
5. Check search results and source lookups, then resume application traffic.

The two search tools do not implement automatic maintenance mode or cross-database source checks.
PostgreSQL and Qdrant do not share a transaction. A write immediately after the final snapshot check
is still possible. Pause the API during refreshes; a future combined retrieval service should reject
source lookups when the database and point snapshots differ.
The import lock does not lock all possible writers or search readers.

Behavior IDs come from input order. A number may represent another example after a refresh.
Snapshot identity is therefore part of the Qdrant ID and payload. Old Qdrant collections are kept;
PostgreSQL does not keep multi-version source history.

## Resume a failed upload

Re-run `index` with the same data and profile. Existing point IDs and full payloads are checked.
Matching points do not need another embedding request. If an upload fails after embeddings were
returned, that failed batch may need to be embedded again.

An HTTP 507 response needs a cluster resource check. During the initial import, a later quota
check showed no current limit violation, and a run with one worker completed. This does not prove
the original cause. The application does not change quotas, delete data, or reduce dimensions.
See [Qdrant troubleshooting](https://qdrant.tech/documentation/common-errors/).

Unexpected payload differences stop indexing. Change the profile version when changing text or
metadata semantics. A different model or dimension also selects a new collection. Keep query
and document embeddings in the same model space.

## Development checks

```shell
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

Tests use synthetic records, mocked model responses and local Qdrant storage. They do not call
Neon, OpenRouter or Qdrant Cloud. The SQL schema is a package resource, so an installed wheel
can read it independently of the current directory.

Production code belongs in `src/attack_search`. CLI arguments belong in `cli.py`. Storage adapters
own database calls. `api/` contains HTTP models, authentication and routes that call the two functions
in `services/search.py`. See the [API guide](api.md) for local startup and Dify setup. Add workflow
exports under `integrations/dify/` when those artifacts exist.

## Cleanup and compatibility

| Previous entry point | Current command or location |
| --- | --- |
| `python main.py` | `uv run attack-search ingest --download` |
| `python build_database.py` | `uv run attack-search ingest` |
| `python embed_attack.py ...` | `uv run attack-search index ...` |
| `schema.sql` | `src/attack_search/storage/sql/attack.sql` |
| `DATABASE_SCHEMA.md` | `docs/appendices/postgresql.md` |
| `EMBEDDINGS.md` | This guide and `docs/appendices/qdrant.md` |
| `test_embed_attack.py` | `tests/unit/` and `tests/integration/` |

The obsolete SQLite file and duplicate root scripts were removed after a verified local backup.
The `.env`, IDE configuration and virtual environment were retained. Generated data and local caches
are ignored by Git. JSON files were moved with SHA-256 checks.

The refactor preserved the PostgreSQL schema, model profile, document IDs and payloads.
The complete prepared-document fingerprint remained:

```text
30afd303c917c7ea2c25129cb3edcce74445219bd3796026a11f4ddc864a3ddf
```

Schema SQL uses `CREATE TABLE IF NOT EXISTS`; it is not a migration framework. Add explicit migrations
when a future change needs to alter an existing database definition.
