import time

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.repository import SecretRepository
from app.service import now_ms
from app.sweeper import sweep_once
from tests.conftest import HUMAN_UA, row_count


def _insert_raw(db, sid, expires_at, views=1):
    db.execute(
        "INSERT INTO secrets (id, ciphertext, iv, auth_tag, max_views, views_remaining, expires_at, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sid, b"\x00" * 8, b"\x00" * 12, b"\x00" * 16, views, views, expires_at, now_ms() - 10_000),
    )


def test_purge_removes_only_expired(client, db, db_path):
    _insert_raw(db, "aaaaaaaaaaaaaaa1", now_ms() - 1)
    _insert_raw(db, "aaaaaaaaaaaaaaa2", now_ms() + 60_000)
    n = SecretRepository(db_path).purge_expired(now_ms())
    assert n >= 1
    assert row_count(db_path, "aaaaaaaaaaaaaaa1") == 0
    assert row_count(db_path, "aaaaaaaaaaaaaaa2") == 1
    db.execute("DELETE FROM secrets WHERE id = 'aaaaaaaaaaaaaaa2'")


def test_sweep_once_checkpoints_without_error(client, db_path):
    assert sweep_once(SecretRepository(db_path)) >= 0


def test_expired_unreadable_before_sweep(client, make_secret, db):
    sid = make_secret("soon-gone", ttl=300)
    db.execute("UPDATE secrets SET expires_at = ? WHERE id = ?", (now_ms() - 1, sid))  # expired, not swept
    r = client.post(f"/api/secret/{sid}/burn")
    assert r.status_code == 404
    r = client.get(f"/view/{sid}")
    assert r.status_code == 404 and "text/html" in r.headers["content-type"]


def test_startup_purge(db, db_path):
    """A row that expired while the server was down is removed when the app starts."""
    _insert_raw(db, "bbbbbbbbbbbbbbb1", now_ms() - 5_000)
    assert row_count(db_path, "bbbbbbbbbbbbbbb1") == 1
    with TestClient(create_app(), headers={"User-Agent": HUMAN_UA}):
        assert row_count(db_path, "bbbbbbbbbbbbbbb1") == 0


def test_background_sweeper_live(live_server):
    """Real sweeper (5 s interval in the fixture) physically deletes an expired, never-read secret."""
    base, db = live_server["base"], live_server["db"]
    r = httpx.post(base + "/api/secret", json={"secret": "ttl-test", "ttl_seconds": 1, "max_views": 1})
    sid = r.json()["id"]
    assert row_count(db, sid) == 1
    deadline = time.time() + 15  # at most 2 intervals + slack
    while time.time() < deadline and row_count(db, sid):
        time.sleep(0.5)
    assert row_count(db, sid) == 0
    assert httpx.post(f"{base}/api/secret/{sid}/burn").status_code == 404
