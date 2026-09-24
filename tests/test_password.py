"""Stretch S2: optional password protection.

A wrong or missing password returns 401 and never consumes a view; 5 wrong guesses destroy the secret;
only a salted scrypt hash is stored.
"""
import os
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from app.db import init_db
from app.password import hash_password, verify_password
from app.service import MAX_PASSWORD_FAILURES
from tests.conftest import ROOT, row_count

NOT_FOUND = {"error": "Secret not found, expired, or already destroyed."}


def _create(client, secret="pw-protected-secret", password="correct horse", views=1):
    r = client.post("/api/secret", json={"secret": secret, "ttl_seconds": 300, "max_views": views, "password": password})
    assert r.status_code == 201, r.text
    return r.json()


def _state(db, sid):
    return db.execute("SELECT views_remaining, pw_failures FROM secrets WHERE id = ?", (sid,)).fetchone()


# --- hashing ---------------------------------------------------------------

def test_hash_and_verify():
    salt, h = hash_password("s3cret-pw")
    assert len(salt) == 16 and len(h) == 32
    assert verify_password("s3cret-pw", salt, h)
    assert not verify_password("s3cret-pW", salt, h)


def test_same_password_different_salt():
    (s1, h1), (s2, h2) = hash_password("same"), hash_password("same")
    assert s1 != s2 and h1 != h2


# --- API behaviour ---------------------------------------------------------

def test_create_response_keeps_contract(client):
    body = _create(client)
    assert set(body) == {"id", "view_url", "expires_at", "views_remaining"}  # password never echoed


def test_missing_password_401_not_consumed(client, db):
    sid = _create(client)["id"]
    for body in (None, {}, {"password": None}):
        r = client.post(f"/api/secret/{sid}/burn", json=body) if body is not None else client.post(f"/api/secret/{sid}/burn")
        assert r.status_code == 401 and r.json() == {"error": "Password required."}
    assert tuple(_state(db, sid)) == (1, 0)  # no view used, not counted as a wrong guess


def test_wrong_password_401_not_consumed(client, db):
    sid = _create(client)["id"]
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "wrong"})
    assert r.status_code == 401 and r.json() == {"error": "Incorrect password."}
    assert tuple(_state(db, sid)) == (1, 1)


def test_correct_password_reveals_once(client, db_path):
    sid = _create(client, secret="the-real-secret")["id"]
    client.post(f"/api/secret/{sid}/burn", json={"password": "nope"})
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "correct horse"})
    assert r.status_code == 200
    assert r.json() == {"secret": "the-real-secret", "views_remaining": 0, "burned": True}
    assert row_count(db_path, sid) == 0
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "correct horse"})
    assert r.status_code == 404 and r.json() == NOT_FOUND


def test_attempt_limit_destroys_secret(client, db_path):
    sid = _create(client)["id"]
    codes = [client.post(f"/api/secret/{sid}/burn", json={"password": f"guess{i}"}).status_code
             for i in range(MAX_PASSWORD_FAILURES)]
    assert codes == [401] * (MAX_PASSWORD_FAILURES - 1) + [404]
    assert row_count(db_path, sid) == 0
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "correct horse"})
    assert r.status_code == 404  # even the right password can't bring it back


def test_multi_view_with_password(client):
    sid = _create(client, views=2)["id"]
    ok = [client.post(f"/api/secret/{sid}/burn", json={"password": "correct horse"}) for _ in range(3)]
    assert [r.status_code for r in ok] == [200, 200, 404]


def test_unprotected_secret_ignores_password(client, make_secret):
    sid = make_secret("open")
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "anything"})
    assert r.status_code == 200 and r.json()["secret"] == "open"


def test_unknown_id_is_404_not_401(client):
    r = client.post("/api/secret/0123456789abcdef/burn", json={"password": "x"})
    assert r.status_code == 404 and r.json() == NOT_FOUND


@pytest.mark.parametrize("pw", ["", 123, True, ["x"], "x" * 1025], ids=["empty", "int", "bool", "list", "too-long"])
def test_invalid_password_on_create_400(client, pw):
    r = client.post("/api/secret", json={"secret": "x", "password": pw})
    assert r.status_code == 400


@pytest.mark.parametrize("body", [{"password": 1}, {"password": "x", "extra": 1}, {"pass": "x"}], ids=["int", "extra", "typo"])
def test_invalid_burn_body_400(client, body):
    sid = _create(client)["id"]
    r = client.post(f"/api/secret/{sid}/burn", json=body)
    assert r.status_code == 400


def test_malformed_burn_json_400(client):
    sid = _create(client)["id"]
    r = client.post(f"/api/secret/{sid}/burn", content=b"{bad", headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_bot_still_blocked(client, db):
    sid = _create(client)["id"]
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "correct horse"},
                    headers={"User-Agent": "Slackbot-LinkExpanding 1.0"})
    assert r.status_code == 403 and tuple(_state(db, sid)) == (1, 0)


def test_error_never_echoes_password(client):
    sid = _create(client)["id"]
    r = client.post(f"/api/secret/{sid}/burn", json={"password": "MY-GUESS-XYZ"})
    assert "MY-GUESS-XYZ" not in r.text


# --- storage ---------------------------------------------------------------

def test_password_never_stored(client, db, db_path):
    password = "plaintext-password-storage-check"
    sid = _create(client, password=password)["id"]
    row = db.execute("SELECT pw_salt, pw_hash FROM secrets WHERE id = ?", (sid,)).fetchone()
    assert len(row["pw_salt"]) == 16 and len(row["pw_hash"]) == 32
    for suffix in ("", "-wal"):
        path = db_path + suffix
        if os.path.exists(path):
            assert password.encode() not in open(path, "rb").read()


def test_view_page_shows_password_field_only_when_protected(client, make_secret):
    protected = client.get(f"/view/{_create(client)['id']}").text
    assert 'id="password"' in protected and "password-protected" in protected
    assert 'id="password"' not in client.get(f"/view/{make_secret()}").text


def test_view_page_never_consumes_or_counts(client, db):
    sid = _create(client)["id"]
    for _ in range(5):
        client.get(f"/view/{sid}")
    assert tuple(_state(db, sid)) == (1, 0)


def test_migration_adds_columns_to_old_database(tmp_path):
    old = tmp_path / "old.db"
    conn = sqlite3.connect(old)
    conn.execute("CREATE TABLE secrets (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, iv BLOB NOT NULL,"
                 " auth_tag BLOB NOT NULL, max_views INTEGER NOT NULL DEFAULT 1,"
                 " views_remaining INTEGER NOT NULL DEFAULT 1, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)")
    conn.execute("INSERT INTO secrets VALUES ('aaaaaaaaaaaaaaaa', x'00', x'00', x'00', 1, 1, 9999999999999, 0)")
    conn.commit()
    conn.close()
    init_db(str(old))
    init_db(str(old))  # idempotent
    conn = sqlite3.connect(old)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(secrets)")}
    assert {"pw_salt", "pw_hash", "pw_failures"} <= cols
    assert conn.execute("SELECT pw_hash, pw_failures FROM secrets").fetchone() == (None, 0)  # old rows unprotected
    conn.close()


# --- concurrency (real server) ---------------------------------------------

def _storm(base, sid, bodies):
    barrier = threading.Barrier(len(bodies))

    def hit(body):
        with httpx.Client(timeout=60) as c:
            barrier.wait()
            return c.post(f"{base}/api/secret/{sid}/burn", json=body)

    with ThreadPoolExecutor(len(bodies)) as ex:
        return list(ex.map(hit, bodies))


def test_concurrent_correct_passwords_one_reader(live_server):
    base, db = live_server["base"], live_server["db"]
    sid = httpx.post(base + "/api/secret", json={"secret": "race-pw", "ttl_seconds": 60, "password": "pw"}).json()["id"]
    codes = [r.status_code for r in _storm(base, sid, [{"password": "pw"}] * 20)]
    assert codes.count(200) == 1 and codes.count(404) == 19, codes
    assert row_count(db, sid) == 0


def test_concurrent_wrong_passwords_never_reveal(live_server):
    base, db = live_server["base"], live_server["db"]
    sid = httpx.post(base + "/api/secret", json={"secret": "guess-me", "ttl_seconds": 60, "password": "pw"}).json()["id"]
    rs = _storm(base, sid, [{"password": f"bad{i}"} for i in range(20)])
    assert all(r.status_code in (401, 404) for r in rs)
    assert all("guess-me" not in r.text for r in rs)
    assert row_count(db, sid) == 0  # the limit destroyed it


# --- CLI -------------------------------------------------------------------

def test_cli_password_from_env(live_server):
    base = live_server["base"]
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli" / "vault-cli"), "--server", base, "--password"],
        input=b"cli-protected\n", capture_output=True, timeout=30,
        env={**os.environ, "VAULT_PASSWORD": "env-pw"},
    )
    assert proc.returncode == 0, proc.stderr
    sid = proc.stdout.decode().strip().rsplit("/", 1)[1]
    assert httpx.post(f"{base}/api/secret/{sid}/burn").status_code == 401
    r = httpx.post(f"{base}/api/secret/{sid}/burn", json={"password": "env-pw"})
    assert r.status_code == 200 and r.json()["secret"] == "cli-protected"


def test_cli_password_without_terminal_fails_fast(live_server):
    """No terminal and no VAULT_PASSWORD: exit with a hint instead of hanging on getpass."""
    env = {k: v for k, v in os.environ.items() if k != "VAULT_PASSWORD"}
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli" / "vault-cli"), "--server", live_server["base"], "--password"],
        input=b"x\n", capture_output=True, timeout=15, env=env,
    )
    assert proc.returncode == 1 and b"VAULT_PASSWORD" in proc.stderr
