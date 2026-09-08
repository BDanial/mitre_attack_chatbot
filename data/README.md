# Local data

Generated data is excluded from Git and distribution packages.

- `raw/enterprise-attack.json`: the downloaded Enterprise STIX bundle.
- `processed/enterprise-attack-filtered.json`: retained nodes and relationships.
- `processed/behavior-examples.json`: descriptions extracted from `uses` relationships.

Create these files with `uv run attack-search ingest --download`. This command also
refreshes the PostgreSQL `attack` schema. A normal `ingest` reads the processed files.
The old SQLite `attack.db` is not part of the application; PostgreSQL is the source of truth.

Do not refresh PostgreSQL while a search service is resolving old Qdrant point IDs.
Read the [operations guide](../docs/operations.md) before refreshing a published snapshot.
