"""Stretch S1: audit fingerprint. Off by default; when on, returned once and never stored."""
import hashlib
from pathlib import Path

import pytest

from app.fingerprint import fingerprint


def _expected(pt: str) -> str:
    return "sha256:" + hashlib.sha256(pt.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("pt", ["hello", "пароль🔑", "line1\nline2", "a\u0000b"], ids=["ascii", "unicode", "multiline", "nul"])
def test_fingerprint_is_sha256_of_utf8(pt):
    assert fingerprint(pt) == _expected(pt)


def test_off_by_default_keeps_exact_contract(client):
    r = client.post("/api/secret", json={"secret": "x"})
    assert set(r.json()) == {"id", "view_url", "expires_at", "views_remaining"}


def test_view_page_has_no_fingerprint_flag_when_off(client, make_secret):
    assert "data-fingerprint" not in client.get(f"/view/{make_secret()}").text


@pytest.fixture
def fp_client(client, monkeypatch):
    monkeypatch.setattr(client.app.state.service, "fingerprint_enabled", True)
    return client


def test_returned_when_enabled(fp_client):
    secret = "my-database-password-xyz"
    r = fp_client.post("/api/secret", json={"secret": secret, "ttl_seconds": 300})
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "view_url", "expires_at", "views_remaining", "fingerprint"}
    assert body["fingerprint"] == _expected(secret)
    # burn still works normally and the recipient can verify the same hash
    burned = fp_client.post(f"/api/secret/{body['id']}/burn").json()
    assert fingerprint(burned["secret"]) == body["fingerprint"]


def test_fingerprint_never_stored(fp_client, db_path):
    secret = "fingerprint-storage-check-value"
    r = fp_client.post("/api/secret", json={"secret": secret})
    hex_digest = r.json()["fingerprint"].split(":", 1)[1]
    for suffix in ("", "-wal"):
        p = Path(db_path + suffix)
        if p.exists():
            data = p.read_bytes()
            assert hex_digest.encode() not in data
            assert bytes.fromhex(hex_digest) not in data


def test_view_page_flags_fingerprint_when_enabled(fp_client):
    sid = fp_client.post("/api/secret", json={"secret": "x"}).json()["id"]
    page = fp_client.get(f"/view/{sid}").text
    assert 'data-fingerprint="1"' in page
    assert "sha256:" not in page  # the page never contains the hash; the browser computes it after reveal
