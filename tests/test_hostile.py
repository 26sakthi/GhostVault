from pathlib import Path

import pytest

from app.config import get_settings

LIMIT = get_settings().max_body_bytes


def test_oversized_body_413(client):
    r = client.post("/api/secret", content=b'{"secret":"' + b"a" * (LIMIT + 10) + b'"}',
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json() == {"error": "Payload too large."}


def test_oversized_chunked_body_413(client):
    def chunks():
        yield b'{"secret":"'
        for _ in range(LIMIT // 1024 + 5):
            yield b"a" * 1024
        yield b'"}'

    r = client.post("/api/secret", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_secret_over_size_cap_400(client):
    too_big = "a" * (get_settings().max_secret_bytes + 1)
    r = client.post("/api/secret", json={"secret": too_big})
    assert r.status_code == 400


@pytest.mark.parametrize("raw", [
    b'{"secret": ' + b"[" * 5000 + b"]" * 5000 + b"}",  # deep nesting
    b'{"secret": "x", "ttl_seconds": 1' + b"0" * 400 + b"}",  # huge number
    b'{"secret": null, "ttl_seconds": null}',
    b"null",
    b"",
], ids=["deep-nesting", "huge-number", "nulls", "null", "empty"])
def test_weird_json_400(client, raw):
    r = client.post("/api/secret", content=raw, headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert "Traceback" not in r.text


@pytest.mark.parametrize("sid", ["..%2F..%2Fetc%2Fpasswd", "' OR 1=1 --", "%00", "0123456789abcdeg"])
def test_hostile_ids(client, sid):
    api = client.post(f"/api/secret/{sid}/burn")
    assert api.status_code == 404 and api.headers["content-type"].startswith("application/json")
    page = client.get(f"/view/{sid}")
    assert page.status_code == 404 and page.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("secret", ["emoji 🔐🗝️", "nul\u0000byte", "tab\tand\r\nnewlines", "ünïcödé ✓"])
def test_exact_round_trip(client, make_secret, secret):
    sid = make_secret(secret)
    assert client.post(f"/api/secret/{sid}/burn").json()["secret"] == secret


def test_script_secret_never_rendered(client, make_secret):
    sid = make_secret("<script>alert(1)</script>")
    page = client.get(f"/view/{sid}")
    assert "alert(1)" not in page.text


def test_error_channels(client):
    api = client.get("/api/nope")
    assert api.status_code == 404 and api.json() == {"error": "Secret not found, expired, or already destroyed."}
    page = client.get("/nope")
    assert page.status_code == 404 and "text/html" in page.headers["content-type"]
    assert "Secret unavailable" in page.text


def test_unhandled_api_error_is_generic(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("internal detail TOP-SECRET")

    monkeypatch.setattr(client.app.state.service, "create", boom)
    r = client.post("/api/secret", json={"secret": "TOP-SECRET"})
    assert r.status_code == 500 and r.json() == {"error": "Internal server error."}
    assert "TOP-SECRET" not in r.text and "Traceback" not in r.text


def test_unhandled_page_error_is_generic_html(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("internal detail")

    monkeypatch.setattr(client.app.state.service, "meta", boom)
    r = client.get("/view/0123456789abcdef")
    assert r.status_code == 500 and "text/html" in r.headers["content-type"]
    assert "Something went wrong" in r.text and "internal detail" not in r.text


@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/redoc"])
def test_docs_disabled(client, path):
    assert client.get(path).status_code == 404


def test_no_plaintext_on_disk(client, make_secret, db_path):
    needle = "my-database-password-xyz-ON-DISK-CHECK"
    for _ in range(5):
        make_secret(needle)
    for suffix in ("", "-wal"):
        p = Path(db_path + suffix)
        if p.exists():
            assert needle.encode() not in p.read_bytes()


def test_distinct_ivs(client, make_secret, db):
    for _ in range(50):
        make_secret("same")
    total, distinct = db.execute("SELECT COUNT(*), COUNT(DISTINCT iv) FROM secrets").fetchone()
    assert total == distinct
    lengths = [tuple(r) for r in db.execute("SELECT DISTINCT length(iv), length(auth_tag) FROM secrets")]
    assert lengths == [(12, 16)]
