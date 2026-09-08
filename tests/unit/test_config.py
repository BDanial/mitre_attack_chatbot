import os

import pytest

from attack_search.config import load_environment, safe_error


def test_env_file_is_loaded_without_overriding_deployment_values(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(
        "OPENROUTER_API_KEY=file-key\nQDRANT_API_KEY=file-qdrant-key\n", encoding="utf-8"
    )
    monkeypatch.setenv("OPENROUTER_API_KEY", "deployment-key")
    monkeypatch.delenv("QDRANT_API_KEY", raising=False)
    load_environment(path)
    assert os.environ["OPENROUTER_API_KEY"] == "deployment-key"
    assert os.environ["QDRANT_API_KEY"] == "file-qdrant-key"


def test_explicit_missing_env_file_fails(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        load_environment(tmp_path / "missing.env")


def test_cli_error_redacts_configured_credentials(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "private-test-value")
    message = safe_error(ValueError("Invalid value: private-test-value"))
    assert "private-test-value" not in message
    assert "[REDACTED]" in message
