"""Small command-line interface; services do not depend on argparse."""

import argparse
import sys
from pathlib import Path

from attack_search.config import get_data_directory, get_database_url, load_environment, safe_error
from attack_search.services.indexing import run_index
from attack_search.services.ingestion import run_ingest


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("Use a positive integer")
    return parsed


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack-search", description="Prepare and index MITRE ATT&CK data."
    )
    parser.add_argument(
        "--env-file", type=Path, help="Environment file (default: .env in the working directory)"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="Refresh PostgreSQL from prepared STIX data")
    ingest.add_argument(
        "--download",
        action="store_true",
        help="Download and prepare the latest Enterprise STIX first",
    )
    ingest.add_argument(
        "--data-dir", type=Path, help="Local data directory (default: ATTACK_DATA_DIR or ./data)"
    )

    index = commands.add_parser("index", help="Build a semantic snapshot in Qdrant")
    index.add_argument(
        "--dry-run",
        action="store_true",
        help="Read PostgreSQL only; no embedding or Qdrant requests",
    )
    index.add_argument(
        "--limit",
        type=positive_int,
        help="Upload a sample only; leave the published alias unchanged",
    )
    index.add_argument("--batch-size", type=positive_int, default=32)
    index.add_argument("--workers", type=positive_int, default=4)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    try:
        load_environment(args.env_file)
        database_url = get_database_url()
        if args.command == "ingest":
            data_dir = args.data_dir.resolve() if args.data_dir else get_data_directory()
            run_ingest(database_url, data_dir, download=args.download)
        else:
            run_index(
                database_url,
                dry_run=args.dry_run,
                limit=args.limit,
                batch_size=args.batch_size,
                workers=args.workers,
            )
    except Exception as exc:
        print(safe_error(exc), file=sys.stderr)
        return 1
    return 0
