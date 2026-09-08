"""Versioned vector-space settings; changes require a new index."""

from attack_search.fingerprints import digest

MODEL = "google/gemini-embedding-2"
DIMENSIONS = 3072
PIPELINE_VERSION = "1"
CHUNK_BYTES = 3000  # Conservative UTF-8 budget, not a tokenizer-specific token count.
ALIAS = "attack_semantic"
NODE_TYPES = {
    "attack-pattern",
    "course-of-action",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
}


def collection_name(snapshot: str) -> str:
    version = digest([snapshot, MODEL, DIMENSIONS, PIPELINE_VERSION, CHUNK_BYTES])[:20]
    return f"attack_semantic_v{PIPELINE_VERSION}_{version}"
