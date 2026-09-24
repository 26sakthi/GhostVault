import re
import subprocess
import sys

import httpx
import pytest

from tests.conftest import ROOT, row_count

NOT_FOUND = {"error": "Secret not found, expired, or already destroyed."}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_happy_path(client, db_path):
    """Scenario A: 5-minute TTL, 1 view, decrypted once, then gone."""
    r = client.post("/api/secret", json={"secret": "my-database-password-xyz", "ttl_seconds": 300, "max_views": 1})
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "view_url", "expires_at", "views_remaining"}  # exact contract
    assert body["view_url"].endswith("/view/" + body["id"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", body["expires_at"])
    assert body["views_remaining"] == 1
    sid = body["id"]

    r = client.post(f"/api/secret/{sid}/burn")
    assert r.status_code == 200
    assert r.json() == {"secret": "my-database-password-xyz", "views_remaining": 0, "burned": True}

    r = client.post(f"/api/secret/{sid}/burn")
    assert r.status_code == 404 and r.json() == NOT_FOUND
    assert row_count(db_path, sid) == 0  # hard delete


def test_defaults(client):
    r = client.post("/api/secret", json={"secret": "x"})
    assert r.status_code == 201 and r.json()["views_remaining"] == 1


def test_multi_view(client, make_secret, db_path):
    sid = make_secret(views=3)
    results = [client.post(f"/api/secret/{sid}/burn") for _ in range(4)]
    assert [r.status_code for r in results] == [200, 200, 200, 404]
    assert [(r.json()["views_remaining"], r.json()["burned"]) for r in results[:3]] == [(2, False), (1, False), (0, True)]
    assert row_count(db_path, sid) == 0


@pytest.mark.parametrize("payload", [
    {},
    {"secret": ""},
    {"secret": "   "},
    {"secret": 123},
    {"secret": "x", "ttl_seconds": 0},
    {"secret": "x", "ttl_seconds": -1},
    {"secret": "x", "ttl_seconds": "60"},
    {"secret": "x", "ttl_seconds": True},
    {"secret": "x", "ttl_seconds": 1.5},
    {"secret": "x", "ttl_seconds": 10**9},
    {"secret": "x", "max_views": 0},
    {"secret": "x", "max_views": 101},
    {"secret": "x", "extra": 1},
    {"secret": None},
    [],
    "just a string",
])
def test_validation_400(client, payload):
    r = client.post("/api/secret", json=payload)
    assert r.status_code == 400, r.text
    assert set(r.json()) == {"error"}


def test_malformed_json_400(client):
    r = client.post("/api/secret", content=b"{bad", headers={"Content-Type": "application/json"})
    assert r.status_code == 400 and r.json() == {"error": "Invalid request: malformed JSON"}


def test_non_json_body_400(client):
    r = client.post("/api/secret", content=b"secret=abc", headers={"Content-Type": "text/plain"})
    assert r.status_code == 400


def test_validation_error_never_echoes_secret(client):
    r = client.post("/api/secret", json={"secret": "TOP-SECRET-VALUE", "ttl_seconds": -5})
    assert r.status_code == 400 and "TOP-SECRET-VALUE" not in r.text


def test_get_on_burn_405(client, make_secret):
    sid = make_secret()
    r = client.get(f"/api/secret/{sid}/burn")
    assert r.status_code == 405 and r.json() == {"error": "Method not allowed."}
    assert client.post(f"/api/secret/{sid}/burn").status_code == 200  # GET did not consume it


@pytest.mark.parametrize("sid", ["0123456789abcdef", "abc", "..%2F..%2Fx", "x" * 1000, "ABCDEF0123456789"],
                         ids=["unknown", "short", "traversal", "1000-chars", "uppercase"])
def test_unknown_or_bad_ids_404(client, sid):
    r = client.post(f"/api/secret/{sid}/burn")
    assert r.status_code == 404 and r.json() == NOT_FOUND


def test_cli_pipeline(live_server):
    """`echo secret | vault-cli` prints a working link (handout Part 10)."""
    base = live_server["base"]
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli" / "vault-cli"), "--server", base, "--ttl", "300"],
        input=b"line one\nline two\n",
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    url = proc.stdout.decode().strip()
    assert url.startswith(base + "/view/")
    sid = url.rsplit("/", 1)[1]
    r = httpx.post(f"{base}/api/secret/{sid}/burn")
    assert r.status_code == 200 and r.json()["secret"] == "line one\nline two"


def test_cli_empty_input(live_server):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli" / "vault-cli"), "--server", live_server["base"]],
        input=b"\n", capture_output=True, timeout=30,
    )
    assert proc.returncode == 1 and b"empty secret" in proc.stderr
