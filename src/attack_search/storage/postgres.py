"""Transactional PostgreSQL import and consistent read-only snapshots."""

import sys
from importlib.resources import files

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from attack_search.fingerprints import digest
from attack_search.progress import show_progress

# Fixed, importer-owned tables, listed in parent-before-child order.
TABLE_COLUMNS = {
    "nodes": "id, attack_id, type, name, description, deprecated, revoked, stix_json",
    "relationships": "id, source_id, target_id, relationship_type, description, deprecated, revoked, stix_json",
    "behavior_examples": "id, technique_id, text",
    "technique_tactics": "technique_id, tactic_id",
    "strategy_analytics": "strategy_id, analytic_id",
    "analytic_data_components": "analytic_id, data_component_id",
    "matrix_tactics": "matrix_id, tactic_id, position",
}


def save_rows(rows: dict[str, list[tuple]], database_url: str) -> None:
    """Refresh only the importer-owned tables in one PostgreSQL transaction."""
    total = sum(len(table_rows) for table_rows in rows.values())
    completed = 0
    report_every = max(1, total // 20)
    next_report = report_every
    show_progress(completed, total, "Connecting / preparing database")
    with psycopg.connect(database_url, connect_timeout=20, prepare_threshold=None) as connection:
        connection.execute("SET LOCAL lock_timeout = '20s'")
        connection.execute("SET LOCAL statement_timeout = '180s'")
        # Serialize this importer's runs; the lock ends with the transaction.
        connection.execute("SELECT pg_advisory_xact_lock(198731091)")
        connection.execute(
            files("attack_search.storage").joinpath("sql/attack.sql").read_text(encoding="utf-8"),
            prepare=False,
        )

        # Refresh only these generated tables. Any failure rolls back the snapshot.
        for table in reversed(TABLE_COLUMNS):
            connection.execute(sql.SQL("DELETE FROM attack.{}").format(sql.Identifier(table)))

        with connection.cursor() as cursor:
            for table, columns in TABLE_COLUMNS.items():
                statement = sql.SQL("COPY attack.{} ({}) FROM STDIN").format(
                    sql.Identifier(table),
                    sql.SQL(columns),
                )
                with cursor.copy(statement) as copy:
                    for row in rows[table]:
                        copy.write_row(row)
                        completed += 1
                        if completed >= next_report and completed < total:
                            show_progress(completed, total, f"Copying {table}")
                            next_report = completed + report_every
                show_progress(completed, total, f"Loaded {table}")

        if sys.stdout.isatty():
            print()
        print("Copy complete. Committing transaction...", flush=True)

    print("Committed ATT&CK snapshot to PostgreSQL (schema: attack).", flush=True)


def load_snapshot(database_url: str) -> tuple[dict, str]:
    """One consistent, read-only PostgreSQL snapshot; include numeric behavior IDs."""
    with psycopg.connect(database_url, row_factory=dict_row, connect_timeout=20) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout = '60s'")
        tables = {}
        for table, columns in TABLE_COLUMNS.items():
            statement = sql.SQL("SELECT {} FROM attack.{} ORDER BY {}").format(
                sql.SQL(columns),
                sql.Identifier(table),
                sql.SQL(columns.split(", stix_json")[0]),
            )
            tables[table] = conn.execute(statement).fetchall()
    return tables, digest(tables)
