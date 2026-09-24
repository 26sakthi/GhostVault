import pytest

from tests.conftest import row_count

NOT_FOUND = {"error": "Secret not found, expired, or already destroyed."}


def _flip_first_byte(b: bytes) -> bytes:
    return bytes([b[0] ^ 0xFF]) + b[1:]


@pytest.mark.parametrize("column,mutate", [
    ("ciphertext", _flip_first_byte),
    ("auth_tag", _flip_first_byte),
    ("iv", _flip_first_byte),
    ("ciphertext", lambda b: b[:-1]),       # truncated
    ("ciphertext", lambda b: b""),          # emptied
    ("iv", lambda b: b""),                  # empty IV
    ("auth_tag", lambda b: b[:3]),          # 3-byte tag
])
def test_tampered_row_fails_cleanly(client, make_secret, db, db_path, column, mutate):
    sid = make_secret("tamper-me-please", views=3)
    original = db.execute(f"SELECT {column} FROM secrets WHERE id = ?", (sid,)).fetchone()[0]
    db.execute(f"UPDATE secrets SET {column} = ? WHERE id = ?", (mutate(bytes(original)), sid))

    r = client.post(f"/api/secret/{sid}/burn")
    assert r.status_code == 404 and r.json() == NOT_FOUND
    assert "Traceback" not in r.text and 'File "' not in r.text
    assert "tamper-me-please" not in r.text
    assert row_count(db_path, sid) == 0  # corrupted record destroyed


def test_swapped_rows_fail(client, make_secret, db, db_path):
    """AAD = id: moving one row's ciphertext/iv/tag into another row must not decrypt."""
    a, b = make_secret("secret-A"), make_secret("secret-B")
    ra = db.execute("SELECT ciphertext, iv, auth_tag FROM secrets WHERE id = ?", (a,)).fetchone()
    rb = db.execute("SELECT ciphertext, iv, auth_tag FROM secrets WHERE id = ?", (b,)).fetchone()
    db.execute("UPDATE secrets SET ciphertext = ?, iv = ?, auth_tag = ? WHERE id = ?", (*rb, a))
    db.execute("UPDATE secrets SET ciphertext = ?, iv = ?, auth_tag = ? WHERE id = ?", (*ra, b))
    for sid in (a, b):
        r = client.post(f"/api/secret/{sid}/burn")
        assert r.status_code == 404 and r.json() == NOT_FOUND
        assert row_count(db_path, sid) == 0
