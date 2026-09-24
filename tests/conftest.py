import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

# Settings are cached at import time, so configure the environment BEFORE importing `app`.
_TMP = Path(tempfile.mkdtemp(prefix="vault-test-"))
os.environ["VAULT_MASTER_KEY"] = secrets.token_hex(32)
os.environ["VAULT_DB_PATH"] = str(_TMP / "test.db")
os.environ["VAULT_BASE_URL"] = "http://testserver"
os.environ["VAULT_SWEEP_INTERVAL"] = "30"

from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.main import create_app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HUMAN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"


@pytest.fixture
def client():
    # Context manager so the lifespan (DB init, state, sweeper) runs.
    with TestClient(create_app(), headers={"User-Agent": HUMAN_UA}) as c:
        yield c


@pytest.fixture
def db_path() -> str:
    return get_settings().db_path


@pytest.fixture
def db(db_path):
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


@pytest.fixture
def make_secret(client):
    def _make(secret="s3cr3t-value", ttl=300, views=1):
        r = client.post("/api/secret", json={"secret": secret, "ttl_seconds": ttl, "max_views": views})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    return _make


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    """A real uvicorn process (1 worker = recommended config). Needed for genuine concurrency."""
    port = _free_port()
    db = tmp_path_factory.mktemp("live") / "live.db"
    env = {
        **os.environ,
        "VAULT_MASTER_KEY": secrets.token_hex(32),
        "VAULT_DB_PATH": str(db),
        "VAULT_BASE_URL": f"http://127.0.0.1:{port}",
        "VAULT_SWEEP_INTERVAL": "5",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--no-access-log"],
        env=env,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(base + "/health").status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("live server did not start")
    yield {"base": base, "db": str(db)}
    proc.terminate()
    proc.wait(10)


def row_count(db_path: str, sid: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM secrets WHERE id = ?", (sid,)).fetchone()[0]
    finally:
        conn.close()
