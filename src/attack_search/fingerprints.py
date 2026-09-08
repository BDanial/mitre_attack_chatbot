"""Stable JSON fingerprints shared by storage and document identity."""

import json
from hashlib import sha256


def digest(value) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
