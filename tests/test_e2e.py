"""Stretch S3: end-to-end encryption.

The client encrypts with its own key; the server stores (and re-encrypts) only client ciphertext and
never receives the key, which lives in the link's #fragment. Python's AESGCM output (ciphertext||tag)
has the same layout as WebCrypto's, so these tests stand in for the browser.
"""
import base64
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.db import init_db
from tests.conftest import ROOT, row_count


def client_encrypt(plaintext: str):
    key, iv = AESGCM.generate_key(bit_length=256), os.urandom(12)
    payload = base64.b64encode(iv + AESGCM(key).encrypt(iv, plaintext.encode(), None)).decode()
    return payload, key


def client_decrypt(payload_b64: str, key: bytes) -> str:
    raw = base64.b64decode(payload_b64)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()


def test_round_trip_server_never_sees_plaintext(client, db_path):
    plaintext = "e2e-plaintext-never-on-server"
    payload, key = client_encrypt(plaintext)
    r = client.post("/api/secret", json={"secret": payload, "e2e": True, "ttl_seconds": 300})
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "view_url", "expires_at", "views_remaining"}  # contract unchanged
    assert "#" not in body["view_url"]  # the server can't build the key into the link: it never had it

    for suffix in ("", "-wal"):  # neither plaintext nor key reach the database
        p = Path(db_path + suffix)
        if p.exists():
            data = p.read_bytes()
            assert plaintext.encode() not in data and key not in data

    burn = client.post(f"/api/secret/{body['id']}/burn").json()
    assert burn["e2e"] is True and burn["burned"] is True
    assert burn["secret"] == payload            # the server only ever returns client ciphertext
    assert client_decrypt(burn["secret"], key) == plaintext


def test_burn_contract_unchanged_for_normal_secrets(client, make_secret):
    r = client.post(f"/api/secret/{make_secret()}/burn")
    assert set(r.json()) == {"secret", "views_remaining", "burned"}


def test_view_page_flags_e2e(client, make_secret):
    payload, _ = client_encrypt("x")
    sid = client.post("/api/secret", json={"secret": payload, "e2e": True}).json()["id"]
    page = client.get(f"/view/{sid}").text
    assert 'data-e2e="1"' in page and "End-to-end encrypted" in page
    assert "/static/js/e2e.js" in page
    assert 'data-e2e="1"' not in client.get(f"/view/{make_secret()}").text


@pytest.mark.parametrize("secret", ["not base64 !!", base64.b64encode(b"short").decode(), "QUJD==="],
                         ids=["not-base64", "too-short", "bad-padding"])
def test_invalid_e2e_payload_400(client, secret):
    r = client.post("/api/secret", json={"secret": secret, "e2e": True})
    assert r.status_code == 400


def test_e2e_must_be_bool(client):
    payload, _ = client_encrypt("x")
    assert client.post("/api/secret", json={"secret": payload, "e2e": "yes"}).status_code == 400


def test_e2e_with_password(client):
    payload, key = client_encrypt("both-layers")
    sid = client.post("/api/secret", json={"secret": payload, "e2e": True, "password": "pw"}).json()["id"]
    assert client.post(f"/api/secret/{sid}/burn").status_code == 401
    burn = client.post(f"/api/secret/{sid}/burn", json={"password": "pw"}).json()
    assert client_decrypt(burn["secret"], key) == "both-layers"


def test_e2e_race_one_reader(live_server):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    base, db = live_server["base"], live_server["db"]
    payload, key = client_encrypt("race-e2e")
    sid = httpx.post(base + "/api/secret", json={"secret": payload, "e2e": True, "ttl_seconds": 60}).json()["id"]
    barrier = threading.Barrier(20)

    def hit(_):
        with httpx.Client() as c:
            barrier.wait()
            return c.post(f"{base}/api/secret/{sid}/burn")

    with ThreadPoolExecutor(20) as ex:
        rs = list(ex.map(hit, range(20)))
    wins = [r for r in rs if r.status_code == 200]
    assert len(wins) == 1 and sum(r.status_code == 404 for r in rs) == 19
    assert client_decrypt(wins[0].json()["secret"], key) == "race-e2e"
    assert row_count(db, sid) == 0


def test_migration_adds_e2e_column(tmp_path):
    old = tmp_path / "old.db"
    conn = sqlite3.connect(old)
    conn.execute("CREATE TABLE secrets (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, iv BLOB NOT NULL,"
                 " auth_tag BLOB NOT NULL, max_views INTEGER NOT NULL DEFAULT 1,"
                 " views_remaining INTEGER NOT NULL DEFAULT 1, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,"
                 " pw_salt BLOB, pw_hash BLOB, pw_failures INTEGER NOT NULL DEFAULT 0)")  # an S2-era database
    conn.execute("INSERT INTO secrets (id, ciphertext, iv, auth_tag, expires_at, created_at)"
                 " VALUES ('aaaaaaaaaaaaaaaa', x'00', x'00', x'00', 9999999999999, 0)")
    conn.commit()
    conn.close()
    init_db(str(old))
    conn = sqlite3.connect(old)
    assert conn.execute("SELECT e2e FROM secrets").fetchone() == (0,)
    conn.close()


def test_cli_e2e_link_decrypts(live_server):
    base = live_server["base"]
    proc = subprocess.run([sys.executable, str(ROOT / "cli" / "vault-cli"), "--server", base, "--e2e"],
                          input="cli e2e secret ✓\n".encode(), capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    url = proc.stdout.decode().strip()
    path, frag = url.split("#", 1)
    assert frag.startswith("k=") and len(frag) == 2 + 43  # 32-byte key, base64url without padding
    key = base64.urlsafe_b64decode(frag[2:] + "=")
    sid = path.rsplit("/", 1)[1]
    burn = httpx.post(f"{base}/api/secret/{sid}/burn").json()
    assert burn["e2e"] is True
    assert client_decrypt(burn["secret"], key) == "cli e2e secret ✓"
