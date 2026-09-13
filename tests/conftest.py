import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

from gyra_user.app import create_app  # noqa: E402
from gyra_user.config import Settings  # noqa: E402
from gyra_user.db import init_engine  # noqa: E402


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        jwt_secret="test-secret-key-with-at-least-32-bytes",
        data_dir=str(tmp_path),
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        cookie_secure=False,
        auth_required=True,
        allow_local_login=True,
        allow_registration=True,
        cors_origins=[],
        providers=[],
    )


@pytest.fixture()
def client(settings):
    init_engine(settings.database_url)
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def registered_user(client):
    resp = client.post(
        "/api/v1/auth/local/register",
        json={
            "username": "alice",
            "password": "secret123",
            "email": "alice@example.com",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()
