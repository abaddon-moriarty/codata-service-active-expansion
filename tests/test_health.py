import importlib
import os
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


def test_health_endpoint_returns_ok_when_required_env_are_present():
    env = {
        "CODATA_USERNAME": "demo-user",
        "CODATA_PASSWORD": "demo-password",
        "ANTICAPTCHA_API_KEY": "demo-anticaptcha-key",
        "SERVICE_API_KEY": "demo-service-key",
    }

    with patch.dict(os.environ, env, clear=False):
        import app.main as main_module

        importlib.reload(main_module)
        client = TestClient(main_module.app)
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["missing_env_vars"] == []


def test_env_example_file_exists():
    repo_root = Path(__file__).resolve().parents[1]
    assert (repo_root / ".env.example").exists()
