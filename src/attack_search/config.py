"""Explicit environment loading for CLI jobs and API startup."""

import json
import os
from getpass import getpass
from pathlib import Path

from dotenv import load_dotenv


def load_environment(env_file: Path | None = None) -> None:
    """Read the chosen file; deployment environment variables always take priority."""
    path = env_file if env_file is not None else Path.cwd() / ".env"
    if env_file is not None and not path.is_file():
        raise ValueError("The selected environment file does not exist")
    load_dotenv(path, override=False)


def get_database_url() -> str:
    """Keep interactive input in the CLI, never in a storage adapter."""
    url = os.environ.get("DATABASE_URL") or getpass("PostgreSQL URL (hidden): ")
    if not url.strip():
        raise ValueError("Set DATABASE_URL or enter a PostgreSQL connection URL")
    return url.strip()


def get_data_directory() -> Path:
    """Default to the working directory; ATTACK_DATA_DIR can be an absolute path."""
    return Path(os.environ.get("ATTACK_DATA_DIR", "data")).resolve()


def safe_error(exc: Exception) -> str:
    """Return a useful CLI error without headers, tracebacks or known credentials."""
    status = getattr(exc, "status_code", None)
    detail = (
        str(exc)
        if type(exc) is ValueError
        else ("Check paths, connectivity, credentials, quota and service availability.")
    )
    if status is not None and isinstance(getattr(exc, "content", None), bytes):
        try:
            remote_status = json.loads(exc.content).get("status", {})
            if isinstance(remote_status, dict) and remote_status.get("error"):
                detail = str(remote_status["error"])
        except (ValueError, AttributeError):
            pass
    for key in ("DATABASE_URL", "OPENROUTER_API_KEY", "QDRANT_API_KEY"):
        if os.environ.get(key):
            detail = detail.replace(os.environ[key], "[REDACTED]")
    return f"Failed: {type(exc).__name__} (status={status}). {detail[:1000]}"
