from .db import get_conn

BURN_SQL = """
UPDATE secrets
   SET views_remaining = views_remaining - 1
 WHERE id = ? AND views_remaining > 0 AND expires_at > ?
RETURNING ciphertext, iv, auth_tag, views_remaining, e2e
"""


class SecretRepository:
    """All SQL lives here. Never sees plaintext."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _c(self):
        return get_conn(self.db_path)

    def insert(self, id, ct, iv, tag, max_views, expires_at, created_at,
               pw_salt=None, pw_hash=None, e2e=False) -> None:
        self._c().execute(
            "INSERT INTO secrets (id, ciphertext, iv, auth_tag, max_views, views_remaining, expires_at, created_at,"
            " pw_salt, pw_hash, e2e) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (id, ct, iv, tag, max_views, max_views, expires_at, created_at, pw_salt, pw_hash, int(e2e)),
        )

    def get_meta(self, id: str, now_ms: int):
        # Read-only: used by GET /view/{id}. Never mutates.
        return self._c().execute(
            "SELECT expires_at, views_remaining, pw_hash IS NOT NULL AS protected, e2e FROM secrets"
            " WHERE id = ? AND expires_at > ? AND views_remaining > 0",
            (id, now_ms),
        ).fetchone()

    def get_password(self, id: str, now_ms: int):
        # Read-only: checked BEFORE burn_atomic, so a wrong password never consumes a view.
        return self._c().execute(
            "SELECT pw_salt, pw_hash FROM secrets WHERE id = ? AND expires_at > ? AND views_remaining > 0",
            (id, now_ms),
        ).fetchone()

    def record_password_failure(self, id: str, max_failures: int) -> bool:
        """Count a wrong password; destroy the secret at the limit. Returns True if destroyed."""
        rows = self._c().execute(
            "UPDATE secrets SET pw_failures = pw_failures + 1 WHERE id = ? RETURNING pw_failures", (id,)
        ).fetchall()
        if rows and rows[0]["pw_failures"] >= max_failures:
            self.delete(id)
            return True
        return not rows  # row already gone

    def burn_atomic(self, id: str, now_ms: int):
        """Invariant: only one transaction can successfully consume the final available view."""
        conn = self._c()
        conn.execute("BEGIN IMMEDIATE")  # take SQLite's write lock up front
        try:
            rows = conn.execute(BURN_SQL, (id, now_ms)).fetchall()  # fully step RETURNING before COMMIT
            row = rows[0] if rows else None
            if row is not None and row["views_remaining"] == 0:
                conn.execute("DELETE FROM secrets WHERE id = ?", (id,))  # same transaction
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return row

    def delete(self, id: str) -> None:
        self._c().execute("DELETE FROM secrets WHERE id = ?", (id,))

    def purge_expired(self, now_ms: int) -> int:
        return self._c().execute("DELETE FROM secrets WHERE expires_at <= ?", (now_ms,)).rowcount

    def checkpoint(self) -> None:
        # Truncate the WAL so old page images don't linger; a no-op if readers block it.
        self._c().execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
