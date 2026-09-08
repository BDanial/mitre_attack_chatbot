"""Offline download/import workflow; never expose this as a public chatbot tool."""

import json
from pathlib import Path

from attack_search.ingestion.rows import prepare_tables
from attack_search.ingestion.stix import download_attack_data, prepare_data, save_json
from attack_search.storage.postgres import save_rows


def run_ingest(database_url: str, data_dir: Path, *, download: bool = False) -> None:
    """Read prepared files, or download a new source, then import transactionally."""
    raw_dir = data_dir / "raw"
    processed_dir = data_dir / "processed"
    graph_path = processed_dir / "enterprise-attack-filtered.json"
    examples_path = processed_dir / "behavior-examples.json"

    if download:
        raw_dir.mkdir(parents=True, exist_ok=True)
        processed_dir.mkdir(parents=True, exist_ok=True)
        source = download_attack_data()
        bundle, examples = prepare_data(source)
        save_json(raw_dir / "enterprise-attack.json", source)
        save_json(graph_path, bundle)
        save_json(examples_path, examples)
        print(f"Downloaded objects: {len(source['objects']):,}", flush=True)
    else:
        if not graph_path.is_file() or not examples_path.is_file():
            raise ValueError(
                "Prepared files are missing; run 'attack-search ingest --download' first"
            )
        bundle = json.loads(graph_path.read_text(encoding="utf-8"))
        examples = json.loads(examples_path.read_text(encoding="utf-8"))

    print(f"Filtered graph objects: {len(bundle['objects']):,}", flush=True)
    print(f"Behavior examples: {len(examples):,}", flush=True)
    save_rows(prepare_tables(bundle, examples), database_url)
