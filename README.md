# MITRE ATT&CK Chatbot — Retrieval Backend

From a behavior description to ATT&CK techniques, mitigation guidance, and detection evidence.

A Python backend with PostgreSQL, Qdrant, Gemini embeddings through OpenRouter, and two
API-key-protected FastAPI tools. Built as a technical-assessment project, with readable code
and documented data models. The retrieval tools work today; the Dify chatbot is the next stage.

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Install the project](#install-the-project)
- [Configure your services](#configure-your-services)
- [Generate the files and load PostgreSQL](#generate-the-files-and-load-postgresql)
- [Build your Qdrant index](#build-your-qdrant-index)
- [Run and test the API](#run-and-test-the-api)
- [Run on your server](#run-on-your-server)
- [Connect Dify](#connect-dify)
- [Refresh data and resume indexing](#refresh-data-and-resume-indexing)
- [Project structure](#project-structure)
- [Tests and verification](#tests-and-verification)
- [Documentation](#documentation)
- [Scope and security](#scope-and-security)
- [Data source and attribution](#data-source-and-attribution)

## Overview

Security users often know what happened, but not the ATT&CK technique name:

> An attacker used PowerShell to execute encoded commands. Which technique fits this behavior?
> How can we detect or mitigate it?

This project provides the data and search tools needed to answer those questions with evidence.

| Capability | Status |
| --- | --- |
| Download and prepare Enterprise ATT&CK STIX | Implemented |
| Preserve behavior examples before removing actor/software nodes | Implemented |
| Load records and graph relationships into PostgreSQL | Implemented |
| Publish dense semantic and sparse BM25 vectors in Qdrant | Implemented |
| Read-only SQL and lexical/semantic/hybrid HTTP tools | Implemented |
| LLM chooses search mode and relative hybrid weights | Implemented |
| API-key authentication and generated OpenAPI schema | Implemented |
| Public deployment and a configured Dify chatbot | Not included yet |

**Verified snapshot:** ATT&CK 19.2, seven PostgreSQL tables, and 23,240 Qdrant points.
These figures describe the September 2026 review, not fixed counts for future downloads.

## Architecture

```mermaid
flowchart LR
    MITRE[MITRE Enterprise STIX] --> JSON[Three local JSON files]
    JSON --> PG[(PostgreSQL)]
    PG --> DOCS[Clean text and build chunks]
    DOCS --> EMB[OpenRouter embeddings]
    DOCS --> BM25[Qdrant native BM25]
    EMB --> QD[(Qdrant)]
    BM25 --> QD
    API[FastAPI search tools] -->|SQL| PG
    API -->|Semantic / lexical / weighted hybrid| QD
    DIFY[Future Dify agent] -.->|Authenticated tool calls| API
```

- **PostgreSQL** stores source records, descriptions, and graph relationships.
- **Qdrant** stores text chunks, vectors, and metadata that points back to PostgreSQL.
- **OpenRouter** generates document and query vectors with `google/gemini-embedding-2`.
- **FastAPI** exposes the two search functions. It does not generate the final chatbot answer.

Groups, Campaigns, Malware, and Tools are removed from the graph. Before removal, descriptions
from `uses` relationships are saved as behavior examples linked to techniques.

The retrieval index contains six evidence types:

| Type | What it represents |
| --- | --- |
| `attack-pattern` | A technique or sub-technique description |
| `behavior_example` | A real-world behavior description linked to one technique |
| `course-of-action` | General mitigation guidance |
| `mitigates` | A mitigation applied to a specific technique |
| `x-mitre-detection-strategy` | A detection approach, using linked analytic text when needed |
| `x-mitre-analytic` | Detection logic, with log-source and tuning metadata |

`detects` remains a PostgreSQL relationship, not a separate Qdrant point.
See the [orchestrator guide](docs/orchestrator/semantic-search.md) for graph paths and filter rules.

## Requirements

- Git.
- Python 3.10 or newer; Python 3.12 is the tested version.
- [uv](https://docs.astral.sh/uv/getting-started/installation/) for dependencies and commands.
- A PostgreSQL database you control.
- Qdrant server 1.19 or newer, with native BM25 support; upgrade older servers first.
  Weighted rank fusion is performed by the backend.
- An OpenRouter key with access and credit for `google/gemini-embedding-2`.

The project does not create a PostgreSQL server, a database account, or a Qdrant cluster.
Provision these first. For Qdrant setup, see the [official quickstart](https://qdrant.tech/documentation/quickstart/).

**Choose your path:** for empty databases, follow every setup step below. If PostgreSQL and
Qdrant are already populated with a matching snapshot, configure their connections and skip
to the additive lexical upgrade below, then [Run and test the API](#run-and-test-the-api).
Do not re-import data just to start the API.

## Install the project

```shell
git clone https://github.com/BDanial/mitre_attack_chatbot.git
cd mitre_attack_chatbot
uv sync --locked
```

Run project commands from this directory. `uv sync --locked` installs the locked dependencies
and creates the local virtual environment. Do not copy a Windows `.venv` to a Linux server.

For a **new checkout**, create your environment file:

Linux / macOS:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

**Keep an existing `.env`; do not overwrite credentials you have already configured.**

## Configure your services

Edit `.env` with your own values. The following values are placeholders, not working credentials:

```dotenv
DATABASE_URL=postgresql://IMPORT_USER:PASSWORD@YOUR_POSTGRES_HOST/YOUR_DATABASE?sslmode=require
OPENROUTER_API_KEY=YOUR_OPENROUTER_KEY
QDRANT_URL=https://YOUR_QDRANT_HOST:6333
QDRANT_API_KEY=YOUR_QDRANT_KEY
ATTACK_DATA_DIR=data

API_KEY=replace-me
API_BASE_URL=http://127.0.0.1:8000
API_DATABASE_URL=postgresql://READ_ONLY_USER:PASSWORD@YOUR_POSTGRES_HOST/YOUR_DATABASE?sslmode=require
```

Use the connection settings supplied by your provider, including its TLS requirements.
URL-encode special characters in PostgreSQL usernames/passwords. The example above assumes a
TLS-enabled PostgreSQL service; local server settings can differ.

| Variable | Used by | Required permissions or behavior |
| --- | --- | --- |
| `DATABASE_URL` | Import and indexing jobs | Import needs schema/table creation, row replacement, and COPY; indexing reads the source |
| `OPENROUTER_API_KEY` | Dense indexing and semantic/hybrid queries | Access to the configured embedding model; lexical search does not call OpenRouter |
| `QDRANT_URL` | Indexing and all text-search modes | Reachable Qdrant endpoint |
| `QDRANT_API_KEY` | Indexing and all text-search modes | Indexing needs collection/index creation, point writes, and alias updates |
| `ATTACK_DATA_DIR` | Data preparation | Optional; defaults to `./data` |
| `API_KEY` | FastAPI authentication | Random shared secret, at least 16 characters |
| `API_BASE_URL` | OpenAPI / Dify | Publicly reachable HTTPS URL when deployed |
| `API_DATABASE_URL` | SQL HTTP tool | A separate restricted SELECT-only role; local-demo fallback is `DATABASE_URL` |

Generate a random API key, then place it in your private `.env`:

```shell
uv run python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Do not share this output. `.env` is ignored by Git. Existing process environment values take
priority over the file. `GITHUB_TOKEN` is not needed to run the application or clone this public
repository, and `CLUSTER_ENDPOINT` is not used by the application.

## Generate the files and load PostgreSQL

### First import into your own database

Make sure `DATABASE_URL` points to the intended database, then run:

```shell
uv run attack-search ingest --download
```

This single command:

1. Downloads the latest Enterprise STIX bundle from MITRE's `master` branch.
2. Extracts behavior descriptions from `uses` relationships.
3. Removes Group, Campaign, Malware, and Tool nodes and their connected relationships.
4. Writes the three JSON files below.
5. Creates the PostgreSQL `attack` schema, tables, views, and indexes if missing.
6. Imports the prepared records into PostgreSQL and commits the transaction.

> **Data replacement:** this command replaces the contents of the seven importer-owned tables
> in the target `attack` schema. Use a dedicated database/schema and pause retrieval before
> refreshing an existing dataset. This is not an append-only import or a schema migration system.

### Generated files

| File | Purpose | Size in the reviewed snapshot |
| --- | --- | ---: |
| `data/raw/enterprise-attack.json` | Original downloaded STIX bundle | 45.88 MiB |
| `data/processed/enterprise-attack-filtered.json` | Retained graph nodes and relationships | 16.06 MiB |
| `data/processed/behavior-examples.json` | Extracted behavior descriptions with technique codes | 4.86 MiB |

These files are generated, so they are excluded from Git. Their sizes and record counts change
with the source release. The download reads the current branch, not a pinned ATT&CK release.
Archive the generated files when you need to reproduce a particular source snapshot.

The CLI currently combines downloading, file generation, and PostgreSQL import; it has no
separate download-only command. Files are saved **before** the database import, so an import
failure may still leave valid generated files on disk.

### Import the same prepared files again

To load existing processed files into a different PostgreSQL database, update `DATABASE_URL`
and run:

```shell
uv run attack-search ingest
```

For a different data directory:

```shell
uv run attack-search ingest --data-dir /absolute/path/to/data
```

That directory must contain both files under `processed/`. The raw file is not required for
this prepared-file import. To download into a custom directory, combine `--download` and
`--data-dir`.

**There is no manual JSON upload step.** The CLI reads local files and sends rows directly to the
PostgreSQL server configured by `DATABASE_URL`. It can run on your laptop or on your application
server, as long as it can reach that database. PostgreSQL is remote storage, not a directory to
which you copy the JSON files.

Successful output ends with:

```text
Committed ATT&CK snapshot to PostgreSQL (schema: attack).
```

Inspect `attack.techniques`, `attack.relationships`, and `attack.behavior_examples` in your SQL
client. PostgreSQL does not store vectors; that is the next step.

## Build your Qdrant index

### Preview without spending embedding credits

After the PostgreSQL import succeeds:

```shell
uv run attack-search index --dry-run
```

This reads PostgreSQL and reports the source fingerprint, expected collection name, point counts,
and input size. It makes **no OpenRouter or Qdrant requests**. It is a data preview, not a check
that your Qdrant credentials or embedding account work.

### Optional small upload

To test your embedding and Qdrant connections with a small sample:

```shell
uv run attack-search index --limit 32 --workers 1
```

This can incur embedding charges and writes sample points, but it **does not publish the alias**.
On a new cluster, the semantic-search API is not ready after only a sample upload.

### Build and publish the complete index

```shell
uv run attack-search index --workers 1
```

The indexer reads **PostgreSQL**, not the local JSON files. It cleans and chunks source text,
calls OpenRouter, creates a snapshot-specific Qdrant collection, creates payload indexes, and
uploads vectors with their metadata, and completes the named BM25 sparse vectors before publication.
There is no manual vector-file upload step.

The configured vector space is 3,072 dimensions with cosine distance. Every point contains its
type, text, PostgreSQL source table and ID, linked techniques, and source-snapshot identity.
One source row can produce several points.

A successful full run checks the exact point count, rechecks PostgreSQL, and publishes the alias:

```text
Ready: attack_semantic -> attack_semantic_v1_<snapshot-profile-hash>
```

The CLI also prints progress during import and indexing. `--workers 1` is a conservative starting
point; the code defaults to four workers and batches of 32. Increase concurrency only if your
provider and cluster capacity support it.

Embedding all documents has a cost. Check your provider balance and Qdrant capacity first.
Do not change the model, dimensions, or chunk recipe while reusing an old vector index.

### Upgrade an existing dense index to lexical and hybrid

For an already published, matching PostgreSQL/Qdrant snapshot:

```shell
uv run attack-search index-lexical
```

This resumable command adds `lexical_bm25_v1` sparse vectors to the existing points. It preserves
the physical collection, dense vectors, point IDs, and payloads and does not call OpenRouter.
It validates the source snapshot and marks lexical readiness only after all points are covered.
If interrupted, run the same command again. Do not refresh PostgreSQL during the upgrade.
See [operations](docs/operations.md#add-lexical-search-to-an-existing-snapshot) for details.

## Run and test the API

Once PostgreSQL and the published Qdrant index are ready:

```shell
uv run uvicorn attack_search.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

- Interactive documentation: `http://127.0.0.1:8000/docs`
- OpenAPI document: `http://127.0.0.1:8000/openapi.json`
- Authentication: `X-API-Key` header with your private `API_KEY` value.

Use **Authorize** in Swagger to set the key. If the port is occupied, choose another port and
update `API_BASE_URL` to match. API startup itself does not verify database connectivity.

| Endpoint | Operation ID | Input | Output |
| --- | --- | --- | --- |
| `POST /tools/sql` | `query_sql` | PostgreSQL SELECT/CTE and row limit | Columns, rows, row count, truncation flag |
| `POST /tools/search` | `search_attack` | Mode, text, simple filters, and hybrid weights | Ranked chunks, score kind, and metadata |

SQL request body:

```json
{
  "query": "SELECT attack_id, name FROM attack.techniques WHERE attack_id = 'T1059.001'",
  "limit": 10
}
```

Hybrid request body (the LLM chooses the mode and weights):

```json
{
  "mode": "hybrid",
  "query": "Attackers execute encoded commands using PowerShell",
  "lexical_query": "PowerShell EncodedCommand",
  "weights": {"semantic": 0.7, "lexical": 0.3},
  "filters": {
    "types": ["attack-pattern", "behavior_example"]
  },
  "limit": 5
}
```

The caller supplies ordinary JSON, without vectors or Qdrant syntax. Use `mode: "semantic"`
for meaning, `mode: "lexical"` for BM25 word matching, and `mode: "hybrid"` for weighted rank
fusion. Single-mode requests omit `weights` and `lexical_query`. Lexical mode never requests an
OpenRouter embedding. BM25 is token-based, not exact phrase or substring matching.

`filters` defaults to active points, including when `{}` is supplied. Set `filters.is_active`
to `null` for all statuses or `false` for inactive points. Hybrid weights are positive relative
weights normalized by the backend; 7/3 and 0.7/0.3 mean the same thing. They weight retrieval
ranks, not raw cosine and BM25 scores. Exact counts and complete lists belong in SQL.

The old `POST /tools/semantic-search` route remains for existing clients with its original native
`filter` contract. It is hidden from the new OpenAPI tool list; new agents use `search_attack`.

See the [API guide](docs/api.md) for limits, error responses, filter support, and both response formats.

## Run on your server

### Use the databases you already populated

On a new server:

```shell
git clone https://github.com/BDanial/mitre_attack_chatbot.git
cd mitre_attack_chatbot
uv sync --locked --no-dev
```

Create a **server-specific** `.env` with the existing PostgreSQL and Qdrant connections, the
OpenRouter key, and a fresh API secret. Use a restricted `API_DATABASE_URL` for the SQL tool.
Do not copy unrelated development or GitHub credentials to the server.

**The search API does not need the three local JSON files.** It reads PostgreSQL and Qdrant
directly. You also do not need to re-embed the data merely because the API moved to another server.

Start the same Uvicorn command as above from the project directory. For a public deployment,
place it behind an HTTPS reverse proxy and use a process manager such as systemd. Set
`API_BASE_URL` to the reachable HTTPS URL before importing the schema into Dify.
The Uvicorn command alone is not a complete production deployment.
[FastAPI deployment reference](https://fastapi.tiangolo.com/deployment/manually/)

### Use new databases instead

Provision your own empty PostgreSQL database and Qdrant instance, configure their credentials,
then run the [PostgreSQL import](#generate-the-files-and-load-postgresql) followed by
[Qdrant indexing](#build-your-qdrant-index). You may run these jobs on the server or from another
machine with network access to both services.

For later code updates in an existing checkout:

```shell
git pull --ff-only origin main
uv sync --locked --no-dev
```

Restart the API process after updating. Code updates do not automatically import data or rebuild
vectors; review changes to the embedding profile before serving an older index.

## Connect Dify

1. Deploy the API at a URL reachable from the **Dify backend**, not just your browser.
2. Set `API_BASE_URL` to that HTTPS URL and restart the API.
3. Import `/openapi.json` into Dify's custom-tool configuration.
4. Set API-key authentication: header `X-API-Key`, raw key value, no `Bearer` prefix.
5. Add `query_sql` and `search_attack` to the agent. Re-import the schema if it still lists `semantic_search`.
6. Copy the system instructions and examples from the [LLM tool guide](docs/orchestrator/llm-tool-guide.md).
   Use the [detailed orchestrator guide](docs/orchestrator/semantic-search.md) for graph/evidence policy.

A localhost URL is not reachable from Dify Cloud. From inside a container, localhost normally
points to that container. Keep API credentials in Dify's authentication settings, not in the
LLM prompt or tool query.

A deployed Dify workflow and an end-to-end chatbot evaluation are not included in this repository.
See the [Dify setup instructions](docs/api.md#4-add-the-tools-to-dify).

## Refresh data and resume indexing

**Keep PostgreSQL and Qdrant on the same source snapshot.** They do not share a transaction.

For an intentional data refresh:

1. Stop or pause retrieval traffic.
2. Run `uv run attack-search ingest --download`.
3. Run `uv run attack-search index --dry-run` and review the expected index.
4. Run `uv run attack-search index --workers 1` to complete and publish it.
5. Verify SQL lookups and all three search modes, then resume traffic.

The API does not provide automatic maintenance mode or cross-database snapshot checks.
Behavior-example row numbers can change after an import, so stale Qdrant references must not
be joined to a newer PostgreSQL source.

If indexing stops, rerun it with the **same source and profile**. The indexer checks existing point
IDs and full payloads and embeds only missing points. A failed upload after embedding may still
lead to repeated embedding charges. Old collections are retained; review storage use separately.

| Problem | What to check |
| --- | --- |
| Prepared files are missing | Run `ingest --download` for a deliberate new import, or point `--data-dir` at existing processed files |
| PostgreSQL import fails | Connection, TLS, schema permissions, and the target database; files may already have been generated |
| No published semantic alias | Complete a full `index` run; `--limit` does not publish |
| Embedding rate-limit or quota error | Provider access/balance and concurrency; retry with fewer workers |
| Qdrant rejects a payload filter | Use the indexed-field allowlist; resolve other constraints through SQL |
| Lexical or hybrid index is not ready | Run `index-lexical` on the matching existing snapshot, or finish a full `index` run |
| API returns 401 | Check the `X-API-Key` header and server `API_KEY` |
| Different counts from the examples | Check the downloaded release and active-versus-all-records policy |

More detail: [operations and refresh procedure](docs/operations.md).

## Project structure

```text
src/attack_search/
  api/                   FastAPI routes, authentication and request/response models
  ingestion/             STIX download, filtering and relational row preparation
  embeddings/            Text cleaning, chunk construction, model client and profile
  storage/               PostgreSQL and Qdrant adapters; SQL schema
  services/              Ingestion, indexing and the two search functions
  cli.py                 Command-line entry point
  config.py              Environment loading
  fingerprints.py        Deterministic snapshot/content hashes
  progress.py            Command-line progress output
tests/
  unit/                  Data, indexing, API and search-tool tests
  integration/           Local Qdrant tests
docs/                    Report, schemas, operations, API and orchestrator guides
data/
  raw/                   Generated source JSON; ignored by Git
  processed/             Generated filtered graph and examples; ignored by Git
.env.example             Public configuration template; no real credentials
pyproject.toml           Package metadata and dependencies
uv.lock                  Locked dependency versions
```

`.env`, `.venv/`, generated datasets, caches, and build artifacts are excluded from Git.
Database credentials, production data, and embeddings are not bundled with a clone.

## Tests and verification

Install development dependencies if you previously used `--no-dev`:

```shell
uv sync --locked
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

**Hybrid upgrade, 8 September 2026:** 225 offline tests passed, including lexical-only calls without
an embedding client, hybrid weight reversal, input validation, filters, and resumable indexing.
The tests use synthetic data, mocks, and local Qdrant storage; they do not write to cloud databases
or spend embedding credits.

Separate live smoke checks returned HTTP 200 for SQL, lexical, semantic, and hybrid calls with both
70/30 and 30/70 weights. Changing the weights changed the ranking. All 23,240 published points had
BM25 vectors; sampled dense-vector and payload hashes were unchanged after the additive upgrade.
These checks are not a broad retrieval-quality benchmark or a hosted Dify integration test.

The wheel includes the SQL schema. Generated JSON files and secrets are not included in either
the wheel or source distribution.

## Documentation

| Guide | What to use it for |
| --- | --- |
| [Documentation map](docs/README.md) | Read the whole docs folder without confusing tool inputs, storage fields, and host operations |
| [Project report](docs/report.md) | Design choices, the data-pipeline stage, and evaluation context |
| [PostgreSQL schema](docs/appendices/postgresql.md) | Tables, views, columns, keys, cardinalities, and text-to-SQL examples |
| [Qdrant schema](docs/appendices/qdrant.md) | Vector configuration, every payload field, source IDs, and inspected counts |
| [Orchestrator guide](docs/orchestrator/semantic-search.md) | Intent routing, valid filters, graph resolution, and evidence rules |
| [LLM tool guide](docs/orchestrator/llm-tool-guide.md) | Copyable system prompt, simple JSON calls, mode selection, and weights |
| [API and Dify setup](docs/api.md) | Endpoint contracts, authentication, limits, and tool import |
| [Operations guide](docs/operations.md) | Installation, refreshes, recovery, and development checks |
| [Local data guide](data/README.md) | Generated-file layout and regeneration |

## Scope and security

- This is an **Enterprise ATT&CK retrieval backend**, not a complete autonomous security product.
- No learned reranker, answer-generation model, or configured Dify workflow is included.
- Scores rank retrieval evidence; cosine, BM25, and weighted RRF have different scales and are not confidence percentages.
- Actor names may remain in behavior text, but removed actor nodes and original attribution links
  cannot be recovered as structured facts.
- SQL accepts guarded SELECT/CTE queries with a read-only transaction, row cap, and timeout.
  These safeguards are **not a complete arbitrary-SQL sandbox**: SELECT can still call functions.
- Before public hosting, use a separate least-privilege PostgreSQL role through `API_DATABASE_URL`.
  Never expose an import/owner account directly to an internet-facing LLM tool.
- Apply HTTPS, rate/concurrency limits, payload-size limits, and network restrictions at deployment.
  Use appropriately restricted credentials for the serving process.
- Treat retrieved text as evidence, not instructions. Keep secrets out of Git, logs, prompts,
  and tool results.

## Data source and attribution

Source data comes from the [official MITRE ATT&CK STIX repository](https://github.com/mitre-attack/attack-stix-data).
ATT&CK publishes its data in STIX for programmatic use.
[MITRE data and tools](https://attack.mitre.org/resources/attack-data-and-tools/)

This is an independent technical-assessment project, not an official MITRE service.
MITRE ATT&CK is a registered trademark of The MITRE Corporation. Review upstream data terms and
third-party dependency licenses before redistributing data or deploying the project.
