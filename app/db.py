import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  iv BLOB NOT NULL,
  auth_tag BLOB NOT NULL,
  max_views INTEGER NOT NULL DEFAULT 1,
  views_remaining INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_expiry ON secrets(expires_at);
"""

_local = threading.local()


def _open(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, timeout=5.0, check_same_thread=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA secure_delete = ON")  # storage hardening, not a forensic guarantee
    return conn


def get_conn(path: str) -> sqlite3.Connection:
    """One connection per thread (sqlite3 connections must not cross threads)."""
    conn = getattr(_local, "conn", None)
    if conn is None or getattr(_local, "path", None) != path:
        conn = _local.conn = _open(path)
        _local.path = path
    return conn


def init_db(path: str) -> None:
    if tuple(map(int, sqlite3.sqlite_version.split("."))) < (3, 35, 0):
        raise SystemExit(f"SQLite >= 3.35 required for RETURNING (found {sqlite3.sqlite_version})")
    conn = _open(path)
    try:
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]  # persisted in the DB file
        if mode.lower() != "wal":
            raise SystemExit(f"could not enable WAL (got {mode})")
        conn.executescript(SCHEMA)
    finally:
        conn.close()
