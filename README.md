# ATT&CK Semantic Search

A Python project that prepares MITRE Enterprise ATT&CK data for semantic search and question answering.
PostgreSQL stores source records and relationships. Qdrant stores searchable text, embeddings, and
references back to PostgreSQL.

**Current result:** ATT&CK 19.2, seven PostgreSQL tables, and 23,240 Qdrant points.
The data pipeline, embedding client, and two key-protected FastAPI search tools work today.
Public hosting and the Dify chatbot are the next stages.

[Project report](docs/report.md) · [PostgreSQL schema](docs/appendices/postgresql.md) ·
[Qdrant schema](docs/appendices/qdrant.md) · [Operations guide](docs/operations.md)

[Orchestrator search guide](docs/orchestrator/semantic-search.md): intent routing, supported filters,
graph relationships, and PostgreSQL evidence lookups for the semantic-search tool.

[API and Dify setup](docs/api.md): run the two tools locally and import their OpenAPI contract.

## Quick start

Use Python 3.10 or newer and [uv](https://docs.astral.sh/uv/). Python 3.12 is the tested environment.

```shell
uv sync --locked
```

Start the local API after setting `API_KEY` in `.env`:

```shell
uv run uvicorn attack_search.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

Open `/docs` to try the tools or `/openapi.json` for the Dify schema. Tool requests require
`X-API-Key`. Before public hosting, configure `API_DATABASE_URL` with a restricted read-only role;
the local-demo fallback uses `DATABASE_URL`. See the [API guide](docs/api.md).

Copy `.env.example` to `.env` and set your credentials. Keep an existing `.env`.
Commands load `.env` from the current working directory. Existing environment variables take priority.

```shell
# Read PostgreSQL and show the proposed index; no paid embedding requests.
uv run attack-search index --dry-run

# Download, prepare, and import a fresh snapshot into PostgreSQL.
uv run attack-search ingest --download

# Import prepared files without another download.
uv run attack-search ingest

# Embed missing points and publish the complete Qdrant snapshot.
uv run attack-search index
```

`ingest` replaces the seven generated tables in the `attack` schema. `index` can incur OpenRouter charges.
Read the [refresh procedure](docs/operations.md#refresh-a-published-snapshot) before changing live data.

## Project layout

```text
src/attack_search/
  cli.py                 Command-line arguments and exit codes
  config.py              Environment loading and local paths
  fingerprints.py        Stable JSON hashing
  progress.py            Terminal progress display
  ingestion/             STIX filtering and relational row preparation
  embeddings/            Text cleaning, documents, model client and profile
  storage/               PostgreSQL and Qdrant adapters; packaged SQL schema
  services/              Import, indexing and the two search functions
  api/                   Search routes, API-key authentication and HTTP models
tests/
  unit/                  Data preparation, model adapter and workflow tests
  integration/           Local Qdrant tests; no cloud account needed
docs/                    Report, operating guide and schema appendices
data/
  raw/                   Downloaded JSON; ignored by Git
  processed/             Prepared graph and examples; ignored by Git
```

HTTP routes call two search functions in `services/search.py`. Dify will call these tools after
hosting and configuration. The [report](docs/report.md#next-stages) records the earlier design.

## Development

```shell
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

Tests run offline with synthetic data and local Qdrant storage. The wheel includes the SQL schema.
After installation, `python -m attack_search --help` is also supported.

The refactor preserved all 23,240 document IDs and payloads.
See the [verification record](docs/report.md#results-and-checks) for checks and their limits.

## Data source

Data comes from the [official MITRE ATT&CK STIX repository](https://github.com/mitre-attack/attack-stix-data).
This is an independent demonstration project, not an official MITRE service. Source references and
marking definitions remain in PostgreSQL. Review the upstream terms when sharing the dataset.
