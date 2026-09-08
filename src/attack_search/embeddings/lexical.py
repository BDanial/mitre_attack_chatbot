"""Versioned native BM25 profile shared by indexing and queries.

Changing text construction or these options requires a new sparse vector name;
it does not change the existing dense embedding profile or point IDs.
"""

from qdrant_client import models

LEXICAL_VECTOR = "lexical_bm25_v1"
LEXICAL_METADATA_KEY = "attack_search_lexical"
BM25_MODEL = "Qdrant/bm25"


def lexical_profile() -> dict:
    """Return a fresh serializable profile, recorded in collection metadata."""
    return {
        "vector": LEXICAL_VECTOR,
        "model": BM25_MODEL,
        "text_fields": ["title", "text"],
        "options": {
            "k": 1.2,
            "b": 0.75,
            "avg_len": 256,
            "tokenizer": "word",
            "language": "english",
            "lowercase": True,
            "ascii_folding": False,
            "stemmer": {"type": "snowball", "language": "english"},
            "stopwords": "english",
        },
    }


def bm25_document(text: str) -> models.Document:
    """Ask Qdrant to generate BM25 on the server; no local embedding download."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("BM25 text must not be empty")
    return models.Document(text=text, model=BM25_MODEL, options=lexical_profile()["options"])


def lexical_text(payload: dict) -> str:
    """Index the human-readable title and chunk, without dense prompt labels."""
    text = "\n".join(payload[key] for key in ("title", "text") if payload.get(key))
    if not text.strip():
        raise ValueError("Document has no lexical text")
    return text
