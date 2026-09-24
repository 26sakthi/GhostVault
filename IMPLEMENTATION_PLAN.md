# Implementation Plan — Ephemeral Secret Vault

**Stack:** Python 3.11 · FastAPI · Uvicorn · SQLite (WAL, stdlib `sqlite3`) · `cryptography` (AES-256-GCM) · Jinja2 · HTML/CSS/JS · pytest · httpx
**Time box:** 3 hours, with a **hard build freeze at 2:45**
**Read first:** [PRD.md](PRD.md) (what to build) · [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) (how it fits together; this plan follows it)
**Source of truth for scope:** `Ephemeral_Secret_Vault_IT HAPPENS @ RAALE #9.pdf` (the handout)

> Environment on the dev machine: Python 3.11.15, SQLite 3.53.1 (`RETURNING` supported), FastAPI 0.133 installed.

### Scope labels (same as SYSTEM_DESIGN.md)

| Label | Meaning |
|---|---|
| **[REQ]** | Required by the handout (Part 4 contract, Part 5 rules, Part 7.1 must-haves, Part 10 checklist, Part 12 FAQ). |
| **[HARD]** | Recommended hardening. Not required by the handout; it can be cut without failing a must-have. |
| **[STRETCH]** | Distinction feature from handout Part 7.2. Built **only after P6 is green**. |
| **[DECISION]** | A choice where the handout is silent or allows options. Stated in REPORT.md. |

---

## 0. Overview

### 0.1 Phases

| Phase | Clock | Goal | Marks at stake |
|---|---|---|---|
| P0 | Before the event | Tools, repo skeleton, scripts ready | — |
| P1 | 0:00–0:15 | App skeleton + lifecycle structure, config, DB, `/health` | — |
| P2 | 0:15–0:45 | Crypto core + unit tests | 20 (crypto) |
| P3 | 0:45–1:25 | Create + burn endpoints, error channels, CLI | 10 (API/CLI) + 10 (hostile) |
| P4 | 1:25–1:55 | Landing page, frontend, bot gate | 15 (scraper) |
| P5 | 1:55–2:25 | Concurrency verification, sweeper, final lifespan | 20 (concurrency) + 15 (GC) |
| P6 | 2:25–2:40 | Hostile testing + pre-freeze checklist | all |
| P7 | 2:40–2:45 | **BUILD FREEZE**: commit and push | — |
| P8 | 2:45–3:00 | REPORT.md | 10 (report) |
| S | Only after P6 is green | Stretch goals (fingerprint, password, E2E, performance) | distinction |

**Golden rule:** commit and push at the end of **every** phase. Pushed work counts; local work doesn't.

**Build the pipe before the logic** (handout §6.2): get dummy plaintext → SQLite → delete working first, then add AES-GCM.

### 0.2 Priority order

```text
Mandatory security requirements (AES-GCM, random IV, key from env)
        >
Core API functionality (create / burn / status codes / CLI)
        >
Required frontend / scraper defense (safe /view page, POST-only burn, bot gate)
        >
Concurrency + garbage collection
        >
Hostile tests
        >
Stretch features
        >
Cosmetic polish
```

**If you are behind schedule before 2:25**, cut in this order:
1. Frontend polish: CSS, dark mode, create page (`/`). The handout requires API/CLI creation, not a web form.
2. Fingerprinting (S1).
3. Password protection and E2E encryption (S2, S3).
4. Performance tuning (S4).
5. Hardening that isn't needed for a must-have: CSP/extra headers, extended bot list beyond the handout minimum, 413 limit.

**Never cut:** crypto, one-view concurrency, scraper defense (safe `GET /view` + POST-only burn + minimum bot list), TTL sweeper, tamper handling, CLI, REPORT.md. **The 2:45 freeze does not move.**

### 0.3 Deployment assumptions (from SYSTEM_DESIGN §13)

- **Single host or single container with a persistent local filesystem.**
- `vault.db`, `vault.db-wal` and `vault.db-shm` live together on persistent local storage, never on a network filesystem.
- **Not** meant for serverless/ephemeral functions: they have no persistent local file and no long-running sweeper.
- **Horizontal scaling is out of scope.** No PostgreSQL, Redis, or distributed lock.
- **One uvicorn worker** is the recommended demo configuration. Extra workers on the same host are still logically safe, because SQLite serializes writers at the storage level, but the demo doesn't need them.

### 0.4 What "zero trace" means in this build (from SYSTEM_DESIGN §5.4)

| Level | Claim | Scope |
|---|---|---|
| Core guarantee | Plaintext is **never persistently stored as application data**. SQLite rows hold only ciphertext, IV and auth tag. Logs, responses (other than the one successful burn), error messages and HTTP caches never store plaintext. Destroyed rows are removed with `DELETE`; there is no soft delete. | [REQ] |
| Storage hardening | `PRAGMA secure_delete = ON` and `PRAGMA wal_checkpoint(TRUNCATE)` after each sweep reduce leftover data **inside SQLite's files**. | [HARD] |
| Not claimed | Forensic erasure below SQLite: filesystem journals, SSD wear levelling, snapshots/backups, OS swap/crash dumps. Anything left there is ciphertext only. This limitation goes in REPORT.md. | out of scope |

---

## P0 — Before the Session (at home)

### Tasks
- [ ] Install the `sqlite3` CLI and check with `sqlite3 --version`. [REQ: handout §2.1]
- [ ] Create the repo and push an empty skeleton:
  ```bash
  git init ephemeral-vault && cd ephemeral-vault
  python -m venv .venv
  source .venv/Scripts/activate     # Git Bash on Windows; use .venv\Scripts\Activate.ps1 in PowerShell
  pip install fastapi "uvicorn[standard]" cryptography jinja2 python-dotenv pytest httpx
  pip freeze > requirements.txt
  ```
- [ ] Generate a dev key: `python -c "import secrets;print(secrets.token_hex(32))"` → put it in `.env` (git-ignored).
- [ ] Write `.gitignore`: `.venv/ .env *.db *.db-wal *.db-shm __pycache__/ .pytest_cache/`
- [ ] Write `.env.example` with `VAULT_MASTER_KEY=` left empty.
- [ ] Prepare `scripts/race.sh` and `scripts/inspect_db.sh` (content in P5 / P6).
- [ ] Check that `xargs -P 20` works in Git Bash, or have the pytest race test ready. [REQ: handout §2.2, "parallel requests"]
- [ ] Prepare the REPORT.md skeleton (P8 headings).
- [ ] Optional: `npm i -g autocannon` for the performance stretch goal. [STRETCH]

**Done when:** `python -c "import fastapi, cryptography, jinja2"` succeeds and the skeleton is pushed.

---

## P1 — Skeleton, Config, DB, Health (0:00–0:15)

### Files
`app/__init__.py`, `app/config.py`, `app/db.py`, `app/main.py`, `app/routes/__init__.py`, `app/routes/api.py`

### `app/config.py`
```python
import os, secrets, logging
from dataclasses import dataclass
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("vault")

@dataclass(frozen=True)
class Settings:
    master_key: bytes
    db_path: str
    base_url: str
    sweep_interval: int
    max_secret_bytes: int
    max_ttl: int
    max_views: int
    max_body_bytes: int
    enable_docs: bool

def _load_key() -> bytes:
    raw = os.getenv("VAULT_MASTER_KEY", "").strip()
    if not raw:                                   # [REQ] handout FAQ: env var OR generated at boot
        log.warning("VAULT_MASTER_KEY not set: using an ephemeral key; secrets will not survive restart")
        return secrets.token_bytes(32)
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit("VAULT_MASTER_KEY must be 64 hex chars")        # [HARD] fail fast
    if len(key) != 32:
        raise SystemExit("VAULT_MASTER_KEY must decode to exactly 32 bytes")
    return key

@lru_cache
def get_settings() -> Settings:
    return Settings(
        master_key=_load_key(),
        db_path=os.getenv("VAULT_DB_PATH", "vault.db"),
        base_url=os.getenv("VAULT_BASE_URL", "http://localhost:3000").rstrip("/"),
        sweep_interval=min(max(int(os.getenv("VAULT_SWEEP_INTERVAL", "10")), 5), 30),   # handout: 10–30 s
        max_secret_bytes=int(os.getenv("VAULT_MAX_SECRET_BYTES", "65536")),           # [HARD]
        max_ttl=int(os.getenv("VAULT_MAX_TTL", "604800")),                            # [HARD]
        max_views=int(os.getenv("VAULT_MAX_VIEWS", "100")),                           # [HARD]
        max_body_bytes=int(os.getenv("VAULT_MAX_BODY_BYTES", "131072")),              # [HARD]
        enable_docs=os.getenv("VAULT_ENABLE_DOCS", "0") == "1",                       # [HARD]
    )
```

### `app/db.py`
```python
import sqlite3, threading

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
    conn.execute("PRAGMA secure_delete = ON")          # [HARD] storage hardening, see §0.4
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
    mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]   # persisted in the DB file
    if mode.lower() != "wal":
        raise SystemExit(f"could not enable WAL (got {mode})")
    conn.executescript(SCHEMA)
    conn.close()
```

### `app/main.py`: **one** file that grows through the phases

P1 creates the app factory and the **lifecycle structure**. Later phases fill in the marked sections of the **same** `create_app()` and `lifespan()`. There is only one `main.py` design. The final version is shown in P5.

```python
import asyncio, logging
from contextlib import asynccontextmanager, suppress
from fastapi import FastAPI
from .config import get_settings
from .db import init_db
from .repository import SecretRepository
from .routes import api

@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()                          # config + key validation (fails fast)
    init_db(s.db_path)                          # schema + WAL
    app.state.repo = SecretRepository(s.db_path)
    # P3: app.state.service = VaultService(repo, CryptoEngine(s.master_key), s.base_url)
    # P5: startup purge + start sweeper task
    yield
    # P5: cancel sweeper task

def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(lifespan=lifespan,
                  docs_url="/docs" if s.enable_docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if s.enable_docs else None)
    # P3: errors.install(app)
    # P4: middleware, static files, pages router
    app.include_router(api.router)
    return app

app = create_app()
```
In P1, `repository.py` only needs the class with `_c()`. The full version comes in P3. `/health` in `routes/api.py` runs `SELECT 1` and returns `{"status":"ok"}`.

### Run
```bash
uvicorn app.main:app --port 3000 --no-access-log
curl -i localhost:3000/health
sqlite3 vault.db "PRAGMA journal_mode; .schema"
```

**Done when:** `/health` returns 200, `vault.db` exists with the schema, and `journal_mode` is `wal`. Commit: `feat: skeleton, config, sqlite schema, health`.

---

## P2 — Crypto Core (0:15–0:45)

### Files
`app/crypto.py`, `app/ids.py`, `tests/test_crypto.py`

### `app/crypto.py`: core only (encrypt / decrypt)
```python
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

IV_LEN, TAG_LEN = 12, 16

class TamperError(Exception):
    """Ciphertext, IV, tag or AAD failed authentication."""

@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes
    iv: bytes
    tag: bytes

class CryptoEngine:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: str, aad: bytes) -> Sealed:
        iv = os.urandom(IV_LEN)                      # [REQ] fresh random IV every call
        out = self._aead.encrypt(iv, plaintext.encode("utf-8"), aad)
        return Sealed(ciphertext=out[:-TAG_LEN], iv=iv, tag=out[-TAG_LEN:])

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes) -> str:
        if not isinstance(iv, bytes) or len(iv) != IV_LEN or not isinstance(tag, bytes) or len(tag) != TAG_LEN:
            raise TamperError()
        try:
            return self._aead.decrypt(iv, bytes(ciphertext) + tag, aad).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, TypeError, ValueError):
            raise TamperError() from None
```
`CryptoEngine` has no hashing or fingerprint code. Fingerprinting is stretch S1 and lives in a separate module.

`aad` = the secret ID **[HARD]**. It binds each ciphertext to its row.

### `app/ids.py`
```python
import re, secrets
_ID_RE = re.compile(r"^[0-9a-f]{16}$")
def new_id() -> str: return secrets.token_hex(8)          # [REQ] short, non-enumerable, URL-safe (64-bit)
def is_valid_id(s: str) -> bool: return bool(_ID_RE.fullmatch(s or ""))
```

### Tests (`tests/test_crypto.py`)
- [ ] Round trip: ASCII, Unicode (`"пароль🔑"`), multi-line PEM, 64 KB string.
- [ ] 1,000 encryptions of the same plaintext → **1,000 distinct IVs** and distinct ciphertexts. [REQ]
- [ ] `len(iv)==12`, `len(tag)==16`. [REQ]
- [ ] Flip one bit in the ciphertext → `TamperError`. [REQ]
- [ ] Flip one bit in the tag → `TamperError`. [REQ]
- [ ] Truncated ciphertext / empty tag / 11-byte IV → `TamperError`. [REQ]
- [ ] Wrong AAD (different ID) → `TamperError`. [HARD]
- [ ] Wrong key → `TamperError`.
- [ ] Ciphertext does not contain the plaintext bytes. [REQ]
- [ ] `is_valid_id`: accepts output of `new_id()`; rejects `""`, `"../etc"`, uppercase, 15/17 chars, `"' OR 1=1"`.

**Done when:** `pytest tests/test_crypto.py` passes. Commit: `feat: AES-256-GCM crypto engine + tests`.

---

## P3 — Core Endpoints, Error Channels, CLI (0:45–1:25)

### Files
`app/schemas.py`, `app/repository.py`, `app/service.py`, `app/errors.py`, `app/routes/api.py`, `cli/vault-cli`, `cli/vault-cli.cmd`, `tests/conftest.py` (in-process client), `tests/test_api.py`

### Step 3a: pipe first (~10 min)
Wire `POST /api/secret` → `INSERT` and `POST /burn` → `DELETE` with a dummy value. Confirm with `sqlite3` that the row appears and disappears. **Then** add crypto (3b).

### Step 3b: core create flow

```text
POST /api/secret → validate → generate ID → AES-256-GCM encrypt → store ciphertext/IV/tag → 201 {id, view_url, expires_at, views_remaining}
```

### `app/schemas.py`
```python
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .config import get_settings
_s = get_settings()

class CreateSecretIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)   # [HARD] strict: "3600" / true are rejected
    secret: str = Field(min_length=1)
    ttl_seconds: int = Field(default=3600, ge=1, le=_s.max_ttl)
    max_views: int = Field(default=1, ge=1, le=_s.max_views)

    @field_validator("secret")
    @classmethod
    def _size(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        if len(v.encode("utf-8")) > _s.max_secret_bytes:
            raise ValueError("too large")
        return v

class CreateSecretOut(BaseModel):      # [REQ] exactly the handout contract
    id: str
    view_url: str
    expires_at: str
    views_remaining: int

class BurnOut(BaseModel):              # [REQ]
    secret: str
    views_remaining: int
    burned: bool
```

### `app/repository.py`: all SQL lives here
```python
from .db import get_conn

BURN_SQL = """
UPDATE secrets
   SET views_remaining = views_remaining - 1
 WHERE id = ? AND views_remaining > 0 AND expires_at > ?
RETURNING ciphertext, iv, auth_tag, views_remaining
"""

class SecretRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _c(self):
        return get_conn(self.db_path)

    def insert(self, id, ct, iv, tag, max_views, expires_at, created_at) -> None:
        self._c().execute(
            "INSERT INTO secrets (id, ciphertext, iv, auth_tag, max_views, views_remaining, expires_at, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (id, ct, iv, tag, max_views, max_views, expires_at, created_at),
        )

    def get_meta(self, id: str, now_ms: int):
        # READ-ONLY: used by GET /view/{id}. Never mutates.  [REQ]
        return self._c().execute(
            "SELECT expires_at, views_remaining FROM secrets WHERE id = ? AND expires_at > ? AND views_remaining > 0",
            (id, now_ms),
        ).fetchone()

    def burn_atomic(self, id: str, now_ms: int):
        """Invariant: only one transaction can successfully consume the final available view."""
        conn = self._c()
        conn.execute("BEGIN IMMEDIATE")              # take SQLite's write lock up front
        try:
            rows = conn.execute(BURN_SQL, (id, now_ms)).fetchall()   # fully execute RETURNING before COMMIT
            row = rows[0] if rows else None
            if row is not None and row["views_remaining"] == 0:
                conn.execute("DELETE FROM secrets WHERE id = ?", (id,))   # same transaction
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
        # [HARD] truncate the WAL so old page images don't linger; harmless if readers block it
        self._c().execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
```

### Concurrency correctness [REQ: zero double-reads]

```text
BEGIN IMMEDIATE
→ UPDATE secrets SET views_remaining = views_remaining - 1
    WHERE id = ? AND views_remaining > 0 AND expires_at > ?
→ RETURNING ciphertext, iv, auth_tag, views_remaining
→ DELETE when views_remaining == 0      (same transaction)
→ COMMIT
→ decrypt (outside the transaction, only with the bytes this transaction received)
```

- **Invariant:** *only one transaction can successfully consume the final available view.*
- **The conditional atomic SQL mutation is what enforces it.** The check and the decrement are one statement, so no `SELECT → check → UPDATE` race is possible.
- **SQLite's transaction locking serializes competing writers.** `BEGIN IMMEDIATE` takes the write lock, which holds across threads *and* processes. Waiting requests then see the committed state, where `views_remaining = 0` or the row is gone. Their `UPDATE` matches nothing, so they get 404.
- **The final `DELETE` runs in the same transaction** as the last decrement.
- **No Python lock is used or relied on.** Do not add a `threading.Lock` "for safety"; it would hide bugs in tests and wouldn't cover multiple processes.

### `app/service.py`
```python
import sqlite3, time
from datetime import datetime, timezone
from .crypto import CryptoEngine, TamperError
from .ids import new_id, is_valid_id
from .errors import NotFound

def now_ms() -> int: return time.time_ns() // 1_000_000
def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

class VaultService:
    def __init__(self, repo, crypto: CryptoEngine, base_url: str):
        self.repo, self.crypto, self.base_url = repo, crypto, base_url

    def create(self, secret: str, ttl: int, views: int) -> dict:
        created = now_ms()
        expires = created + ttl * 1000
        for _ in range(3):
            sid = new_id()
            sealed = self.crypto.encrypt(secret, aad=sid.encode())
            try:
                self.repo.insert(sid, sealed.ciphertext, sealed.iv, sealed.tag, views, expires, created)
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise RuntimeError("id collision")
        return {"id": sid, "view_url": f"{self.base_url}/view/{sid}",
                "expires_at": iso(expires), "views_remaining": views}

    def burn(self, sid: str) -> dict:
        if not is_valid_id(sid):
            raise NotFound()
        row = self.repo.burn_atomic(sid, now_ms())
        if row is None:
            raise NotFound()
        try:
            pt = self.crypto.decrypt(row["ciphertext"], row["iv"], row["auth_tag"], aad=sid.encode())
        except TamperError:
            self.repo.delete(sid)              # destroy corrupted record  [DECISION: 404 + delete]
            raise NotFound()
        left = row["views_remaining"]
        return {"secret": pt, "views_remaining": left, "burned": left == 0}   # [DECISION] burned semantics

    def meta(self, sid: str):
        if not is_valid_id(sid):
            return None
        r = self.repo.get_meta(sid, now_ms())
        return None if r is None else {"expires_at": iso(r["expires_at"]), "views_remaining": r["views_remaining"]}
```

### `app/errors.py`: two error channels, no leaks

| Channel | Routes | Body |
|---|---|---|
| **JSON API** | paths starting with `/api/` | `{"error": "..."}` |
| **HTML pages** | everything else (`/`, `/view/*`, unknown paths) | `gone.html` (404) or `error.html` (other) |
| **Bots** | any | handled earlier by the bot gate (P4), never reaches these handlers |

No response contains a stack trace, exception text, request body, plaintext, or a hint about *why* a secret is unavailable.

```python
import logging
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("vault")
NOT_FOUND_MSG = "Secret not found, expired, or already destroyed."   # [REQ] identical for every miss

class NotFound(Exception): ...

def _is_api(request: Request) -> bool:
    return request.url.path.startswith("/api/")

def html_error(request: Request, status: int):
    from .routes.pages import templates          # added in P4; before P4 use JSON only
    name = "gone.html" if status == 404 else "error.html"
    return templates.TemplateResponse(request, name, status_code=status)

def generic_500(request: Request):
    if _is_api(request):
        return JSONResponse({"error": "Internal server error."}, status_code=500)
    return html_error(request, 500)

def install(app):
    @app.exception_handler(NotFound)             # raised only by /api routes
    async def _nf(request: Request, _: NotFound):
        return JSONResponse({"error": NOT_FOUND_MSG}, status_code=404)

    @app.exception_handler(RequestValidationError)   # [HARD] 400 instead of FastAPI's 422
    async def _val(request: Request, exc: RequestValidationError):
        e = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(p) for p in e.get("loc", []) if p != "body") or "body"
        # never echo e["input"]: it may contain the secret
        return JSONResponse({"error": f"Invalid request: {field}: {e.get('msg', 'invalid')}"}, status_code=400)

    @app.exception_handler(StarletteHTTPException)   # unknown routes, 405, etc.
    async def _http(request: Request, exc: StarletteHTTPException):
        if not _is_api(request):
            return html_error(request, exc.status_code)
        msg = NOT_FOUND_MSG if exc.status_code == 404 else {405: "Method not allowed."}.get(exc.status_code, "Error")
        return JSONResponse({"error": msg}, status_code=exc.status_code)
```

**Unhandled exceptions** are caught in the P4 HTTP middleware (`try/except Exception` around `call_next`), which logs only the exception **type** and returns `generic_500(request)`. Starlette's own `Exception` handler would re-raise the exception, and uvicorn would then log the full traceback, which breaks the logging policy in SYSTEM_DESIGN §14. Until P4 exists, a temporary `@app.exception_handler(Exception)` returning `generic_500` is fine.

### `app/routes/api.py`
```python
from fastapi import APIRouter, Request
from ..schemas import CreateSecretIn, CreateSecretOut, BurnOut

router = APIRouter()

@router.get("/health")
def health(request: Request):
    request.app.state.repo._c().execute("SELECT 1")
    return {"status": "ok"}

@router.post("/api/secret", status_code=201, response_model=CreateSecretOut)
def create_secret(body: CreateSecretIn, request: Request):
    return request.app.state.service.create(body.secret, body.ttl_seconds, body.max_views)

@router.post("/api/secret/{sid}/burn", response_model=BurnOut)
def burn_secret(sid: str, request: Request):
    return request.app.state.service.burn(sid)
```
Endpoints are **sync `def`**, so SQLite calls run in the threadpool (SYSTEM_DESIGN §13). `GET /api/secret/{id}/burn` → 405, which the handler turns into JSON.

**Wire-up in `main.py`:** fill in the P3 markers: `app.state.service = VaultService(...)` in `lifespan`, and `errors.install(app)` in `create_app`.

### `cli/vault-cli` [REQ] (stdlib only)
```python
#!/usr/bin/env python3
"""Push a secret from stdin:  cat secret.txt | ./vault-cli [--ttl 3600] [--views 1]"""
import argparse, json, os, sys, urllib.request, urllib.error

def main() -> int:
    p = argparse.ArgumentParser(prog="vault-cli")
    p.add_argument("--ttl", type=int, default=3600)
    p.add_argument("--views", type=int, default=1)
    p.add_argument("--server", default=os.getenv("VAULT_SERVER", "http://localhost:3000"))
    p.add_argument("--json", action="store_true", help="print full JSON response")
    a = p.parse_args()

    if sys.stdin.isatty():
        print("vault-cli: pipe a secret on stdin, e.g. `cat .env | vault-cli`", file=sys.stderr)
        return 1
    data = sys.stdin.buffer.read().decode("utf-8")
    if data.endswith("\n"):
        data = data[:-1]
        if data.endswith("\r"):
            data = data[:-1]
    if not data.strip():
        print("vault-cli: empty secret", file=sys.stderr)
        return 1

    body = json.dumps({"secret": data, "ttl_seconds": a.ttl, "max_views": a.views}).encode()
    req = urllib.request.Request(a.server.rstrip("/") + "/api/secret", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "vault-cli/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            out = json.load(r)
    except urllib.error.HTTPError as e:
        print(f"vault-cli: HTTP {e.code}: {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"vault-cli: cannot reach server: {e.reason}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2) if a.json else out["view_url"])
    return 0

if __name__ == "__main__":
    sys.exit(main())
```
`cli/vault-cli.cmd`: `@python "%~dp0vault-cli" %*`

### `tests/conftest.py` (in-process part)
- Set `VAULT_MASTER_KEY` (random), `VAULT_DB_PATH` (tmp file) and `VAULT_BASE_URL` in `os.environ` **before** importing `app.*`. Settings are cached at import.
- `client` fixture: `with TestClient(create_app()) as c: yield c`. Use the **context manager**, otherwise `lifespan` (DB init, state, sweeper) doesn't run.

### Tests (`tests/test_api.py`)
- [ ] Create (TTL 300, 1 view; handout Scenario A) → 201 with **exactly** `{id, view_url, expires_at, views_remaining}`; `view_url` ends with the ID; `expires_at` is ISO + `Z`. [REQ]
- [ ] Burn → 200 `{secret, views_remaining: 0, burned: true}`; second burn → 404 with the exact message. [REQ]
- [ ] After burn: `SELECT COUNT(*) FROM secrets WHERE id=?` == 0 (hard delete). [REQ]
- [ ] `max_views: 3` → 200 (2, false), 200 (1, false), 200 (0, true), 404. [DECISION: burned semantics]
- [ ] Validation → 400 JSON: missing secret, `""`, `"   "`, ttl 0/-1/"60"/true, views 0/101, extra field, malformed JSON, non-JSON body. [HARD]
- [ ] `GET /api/secret/{id}/burn` → 405 JSON. [HARD]
- [ ] Unknown ID, bad ID (`abc`, `../../x`, 1,000 chars) → 404 JSON with the identical message. [REQ]
- [ ] CLI: `subprocess.run([sys.executable, "cli/vault-cli"], input=b"s3cr3t\n")` against the live server (P5 fixture; or run manually now) → URL; burning it returns `s3cr3t`. [REQ]

**Done when:** create/burn work end to end, the DB holds only ciphertext, and `cat secret.txt | ./cli/vault-cli` prints a URL. Commit: `feat: create/burn API, error channels, CLI`.

---

## P4 — Landing Page, Frontend, Bot Gate (1:25–1:55)

### Files
`app/security.py`, `app/routes/pages.py`, `app/templates/*.html`, `app/static/css/app.css`, `app/static/js/create.js`, `app/static/js/reveal.js`, `tests/test_scraper.py`

### `app/security.py`
```python
import re
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse

# [REQ] handout minimum: bot, crawl, spider, Slackbot, facebookexternalhit
# [HARD] the rest: common link unfurlers
BOT_UA = re.compile(
    r"bot|crawl|spider|slurp|facebookexternalhit|facebookcatalog|embedly|"
    r"slack|discord|whatsapp|telegram|skypeuripreview|teams|linkedin|"
    r"twitter|pinterest|vkshare|quora|outbrain|bitly|"
    r"preview|unfurl|google-inspectiontool|mastodon", re.I)

def is_bot(ua: str | None) -> bool:
    return bool(ua) and bool(BOT_UA.search(ua))

SECURITY_HEADERS = {                               # [HARD]
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
}

class BodyLimitMiddleware:
    """[HARD] Pure ASGI. Buffers the request body (≤ limit) and returns 413 if it's larger.
    Buffering is used, rather than raising mid-read, because FastAPI turns exceptions
    raised while it reads the body into 400s."""
    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app, self.max = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        too_large = JSONResponse({"error": "Payload too large."}, status_code=413)
        cl = dict(scope["headers"]).get(b"content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > self.max):
            return await too_large(scope, receive, send)
        body, more = b"", True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body += msg.get("body", b"")
            if len(body) > self.max:
                return await too_large(scope, receive, send)
            more = msg.get("more_body", False)
        replayed = False
        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()
        await self.app(scope, replay, send)
```

### Bot gate + headers + catch-all (a module-level `gate` in `main.py`, registered in `create_app()`)

Middleware order (**outermost first**): *bot gate/headers/catch-all* → *body limit* → *routes*. Bots are rejected before their request body is read. In Starlette, the middleware registered **last** is the outermost, so register the body limit first. The final `main.py` in P5 shows this exact wiring.

```python
# in create_app():
#   app.add_middleware(BodyLimitMiddleware, max_bytes=s.max_body_bytes)
#   app.middleware("http")(gate)                 # registered last → outermost

async def gate(request: Request, call_next):
    if is_bot(request.headers.get("user-agent")):             # [REQ] no state change for bots
        path = request.url.path
        if path.startswith("/view/"):
            resp = templates.TemplateResponse(request, "bot.html", status_code=200)   # Scenario B: HTML shell
        elif path.startswith("/api/"):
            resp = JSONResponse({"error": "Automated clients are not permitted."}, status_code=403)
        else:
            resp = Response(status_code=403)                   # "/", "/static/*", "/health": empty
    else:
        try:
            resp = await call_next(request)
        except Exception as exc:                               # catch-all: no traceback in response or logs
            log.error("unhandled error: %s", type(exc).__name__)
            resp = generic_500(request)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp

app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
app.include_router(pages.router)
```

There is **no prefetch-header gate** (SYSTEM_DESIGN D12). Browser prefetch and prerender send `GET`s, and `GET /view` is already read-only.

### `app/routes/pages.py`
```python
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")
router = APIRouter()

@router.get("/")
def index(request: Request):                         # [HARD] web create form
    return templates.TemplateResponse(request, "index.html")

@router.get("/view/{sid}")
def view(sid: str, request: Request):                # [REQ] read-only landing page
    meta = request.app.state.service.meta(sid)       # SELECT only
    if meta is None:
        return templates.TemplateResponse(request, "gone.html", status_code=404)   # [DECISION]
    return templates.TemplateResponse(request, "view.html", {"sid": sid, **meta})
```

### Templates
- **`base.html`**: `<meta name="robots" content="noindex,nofollow">`, `<meta name="referrer" content="no-referrer">`, `<link rel="stylesheet" href="/static/css/app.css">`, `{% block content %}`. No inline `<script>` or `<style>`.
- **`view.html`** [REQ]:
  ```html
  <main class="card" data-secret-id="{{ sid }}">
    <h1>🔒 Secure secret</h1>
    <p class="notice">You have been sent a secure, self-destructing secret.</p>
    <dl class="meta">
      <dt>Expires</dt><dd><time id="expires" datetime="{{ expires_at }}">{{ expires_at }}</time></dd>
      <dt>Views remaining</dt><dd id="views">{{ views_remaining }}</dd>
    </dl>
    <button id="reveal" class="danger">Reveal and Destroy Secret</button>
    <section id="result" hidden aria-live="polite">
      <pre id="secret"></pre>
      <button id="copy">Copy</button>
      <p id="status"></p>
    </section>
  </main>
  <script src="/static/js/reveal.js" defer></script>
  ```
- **`gone.html`**: "This secret doesn't exist, has expired, or was already viewed." Links to `/`.
- **`error.html`**: "Something went wrong." No details.
- **`bot.html`** [REQ]: title "Secure secret", `og:title`="Secure, self-destructing secret", `og:description`="Open this link in a browser to view it." No ID, expiry or view count.
- **`index.html`** [HARD]: form with `<textarea id="secret">`, `<select id="ttl">` (300/3600/86400/604800), `<input id="views" type="number" min="1" max="10" value="1">`, and `<button>Create link</button>`. A hidden result panel shows the link (`<input readonly>`), a Copy button, expiry and views remaining. Loads `<script src="/static/js/create.js" defer>`.

### `app/static/js/reveal.js` [REQ: button POSTs to burn]
```js
(() => {
  const main = document.querySelector("[data-secret-id]");
  const id = main.dataset.secretId;
  const btn = document.getElementById("reveal");
  const out = document.getElementById("secret");
  const result = document.getElementById("result");
  const status = document.getElementById("status");
  const exp = document.getElementById("expires");
  exp.textContent = new Date(exp.dateTime).toLocaleString();

  btn.addEventListener("click", async () => {
    if (!confirm("This will reveal the secret and permanently destroy it. Continue?")) return;   // [HARD]
    btn.disabled = true; btn.textContent = "Revealing…";                                         // no double-POST
    try {
      const r = await fetch(`/api/secret/${encodeURIComponent(id)}/burn`,
        { method: "POST", cache: "no-store", credentials: "omit" });
      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        out.textContent = data.secret;                 // never innerHTML
        status.textContent = data.burned
          ? "This secret has been destroyed. It cannot be viewed again."
          : `${data.views_remaining} view(s) remaining.`;
        document.getElementById("views").textContent = data.views_remaining;
      } else {
        status.textContent = data.error || "Secret not found, expired, or already destroyed.";
      }
      result.hidden = false; btn.hidden = true;
    } catch {
      // The POST may have reached the server even though the response was lost.
      btn.disabled = false; btn.textContent = "Reveal and Destroy Secret";
      status.textContent = "Network error. The request may have succeeded, and the secret may already " +
                           "have been consumed. Check again before retrying.";
      result.hidden = false;
    }
  });

  document.getElementById("copy").addEventListener("click", () =>
    navigator.clipboard?.writeText(out.textContent));
  addEventListener("pagehide", () => { out.textContent = ""; });   // [HARD]
})();
```
The UI must **never** claim that a failed network request left the secret unconsumed.

### `app/static/js/create.js` [HARD]
Reads the form, POSTs JSON to `/api/secret`, and shows `view_url`, expiry and views remaining. Clears the textarea and shows `data.error` on a 400. It uses only the four contract fields and has no dependency on fingerprints.

### `app/static/css/app.css` [HARD]
CSS variables, `prefers-color-scheme: dark`, a centered `.card` (max-width 640px), red `.danger` button, monospace `pre` with `white-space: pre-wrap; word-break: break-all`, and visible `:focus-visible` outlines.

### Tests (`tests/test_scraper.py`)
Run each check with these UAs: `Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)`, `facebookexternalhit/1.1`, `Twitterbot/1.0`, `Discordbot/2.0`, `WhatsApp/2.23`, `TelegramBot`, `LinkedInBot/1.0`, `Googlebot/2.1`, `Mozilla/5.0 (compatible; bingbot/2.0)`.
- [ ] Bot `GET /view/{id}` → 200 HTML with **no** ID/expiry in the body; `views_remaining` in the DB unchanged. [REQ, Scenario B]
- [ ] Bot `POST /api/secret/{id}/burn` → 403 JSON; row unchanged. [REQ]
- [ ] Bot `POST /api/secret` → 403; no row inserted. [REQ]
- [ ] Bot `GET /`, `/health`, `/static/css/app.css` → 403 with an empty body. [REQ: "rejected or blank"]
- [ ] Human (Chrome UA) `GET /view/{id}` 10× → 200, contains "Reveal and Destroy Secret", `views_remaining` unchanged. [REQ]
- [ ] After all the bot traffic, a human burn → 200 with the secret. [REQ]
- [ ] `curl/8.5.0`, Chrome, Firefox and Safari UAs are **not** blocked.
- [ ] Every response has CSP, `no-store` and `no-referrer`. [HARD]

**Done when:** the full browser flow works (create at `/` → open link → Reveal → secret shown → refresh → gone page), and the scraper tests pass. Commit: `feat: landing page, frontend, bot gate, security headers`.

---

## P5 — Concurrency Verification, Sweeper, Final Lifespan (1:55–2:25)

### Files
`app/sweeper.py`, `app/main.py` (final lifespan), `tests/conftest.py` (live server), `tests/test_race.py`, `tests/test_sweeper.py`, `scripts/race.sh`

### `app/sweeper.py` [REQ]
```python
import asyncio, logging
from .service import now_ms

log = logging.getLogger("vault.sweeper")

def sweep_once(repo) -> int:
    n = repo.purge_expired(now_ms())
    try:
        repo.checkpoint()                              # [HARD] WAL truncate; failure is non-fatal
    except Exception:
        pass
    return n

async def sweeper_loop(repo, interval: int):
    while True:
        await asyncio.sleep(interval)
        try:
            n = await asyncio.to_thread(sweep_once, repo)
            if n:
                log.info("sweeper.purged n=%d", n)
        except Exception as e:                         # keep sweeping even if one run fails
            log.error("sweeper.error %s", type(e).__name__)
```
`asyncio.to_thread` may use different threads each time. That's fine, because `get_conn` gives each thread its own connection.

### Final `app/main.py`: completes the P1 structure

The final application lifecycle:

| Stage | What happens |
|---|---|
| Import / `create_app()` | Settings loaded and **key validated** (invalid key → exit); middleware, error handlers, static files and routers registered |
| `lifespan` startup | **DB init** (WAL + schema) → state (`repo`, `CryptoEngine`, `VaultService`) → **startup purge** → **sweeper task started** |
| Running | Requests + sweeper every `VAULT_SWEEP_INTERVAL` s |
| `lifespan` shutdown | **Sweeper task cancelled** and awaited |

```python
import asyncio, logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .crypto import CryptoEngine
from .db import init_db
from .repository import SecretRepository
from .service import VaultService
from .sweeper import sweep_once, sweeper_loop
from .security import BodyLimitMiddleware, SECURITY_HEADERS, is_bot
from .errors import install as install_errors, generic_500
from .routes import api, pages
from .routes.pages import templates

log = logging.getLogger("vault")
BASE = Path(__file__).parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    init_db(s.db_path)
    repo = SecretRepository(s.db_path)
    app.state.repo = repo
    app.state.service = VaultService(repo, CryptoEngine(s.master_key), s.base_url)
    await asyncio.to_thread(sweep_once, repo)                     # startup purge
    task = asyncio.create_task(sweeper_loop(repo, s.sweep_interval))
    try:
        yield
    finally:
        task.cancel()                                             # graceful shutdown
        with suppress(asyncio.CancelledError):
            await task

def create_app() -> FastAPI:
    s = get_settings()                                            # key validated here (fail fast)
    app = FastAPI(lifespan=lifespan,
                  docs_url="/docs" if s.enable_docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if s.enable_docs else None)
    install_errors(app)
    app.add_middleware(BodyLimitMiddleware, max_bytes=s.max_body_bytes)
    app.middleware("http")(gate)                                  # outermost (see P4)
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
    app.include_router(api.router)
    app.include_router(pages.router)
    return app

async def gate(request: Request, call_next):
    ...                                                           # body exactly as in P4

app = create_app()
```

### `tests/conftest.py`: live-server fixture (required for a real race test)
```python
import os, socket, subprocess, sys, time, secrets, httpx, pytest

def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    port = _free_port()
    db = tmp_path_factory.mktemp("db") / "race.db"
    env = {**os.environ, "VAULT_MASTER_KEY": secrets.token_hex(32), "VAULT_DB_PATH": str(db),
           "VAULT_BASE_URL": f"http://127.0.0.1:{port}", "VAULT_SWEEP_INTERVAL": "5"}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port),
                             "--no-access-log"], env=env)          # 1 worker = recommended config
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            if httpx.get(base + "/health").status_code == 200: break
        except httpx.HTTPError: pass
        time.sleep(0.1)
    yield {"base": base, "db": str(db)}
    proc.terminate(); proc.wait(5)
```

### `tests/test_race.py` [REQ: zero partial credit]

The race test must prove **three** things:
1. Exactly **one** request received the plaintext (HTTP 200).
2. Exactly **nineteen** requests received HTTP 404.
3. The secret row was **physically deleted**: `SELECT COUNT(*) FROM secrets WHERE id = ?` → `0`.

```python
import sqlite3, threading, httpx, pytest
from concurrent.futures import ThreadPoolExecutor

N = 20

def _row_count(db_path: str, sid: str) -> int:
    with sqlite3.connect(db_path) as c:                  # separate process view of committed state
        return c.execute("SELECT COUNT(*) FROM secrets WHERE id = ?", (sid,)).fetchone()[0]

@pytest.mark.parametrize("round_", range(10))          # repeat: races are probabilistic
def test_exactly_one_reader(live_server, round_):
    base, db = live_server["base"], live_server["db"]
    sid = httpx.post(base + "/api/secret", json={"secret": "race-me", "ttl_seconds": 60, "max_views": 1}).json()["id"]
    barrier = threading.Barrier(N)
    def hit(_):
        with httpx.Client() as c:
            barrier.wait()                              # release all 20 at once
            return c.post(f"{base}/api/secret/{sid}/burn")
    with ThreadPoolExecutor(N) as ex:
        rs = list(ex.map(hit, range(N)))
    codes = [r.status_code for r in rs]
    assert codes.count(200) == 1, codes                                          # (1)
    assert codes.count(404) == N - 1, codes                                      # (2)
    assert [r.json()["secret"] for r in rs if r.status_code == 200] == ["race-me"]
    assert _row_count(db, sid) == 0                                              # (3) physically deleted

def test_multi_view_never_over_delivers(live_server):
    base, db = live_server["base"], live_server["db"]
    sid = httpx.post(base + "/api/secret", json={"secret": "x", "ttl_seconds": 60, "max_views": 3}).json()["id"]
    with ThreadPoolExecutor(20) as ex:
        codes = list(ex.map(lambda _: httpx.post(f"{base}/api/secret/{sid}/burn").status_code, range(20)))
    assert codes.count(200) == 3 and codes.count(404) == 17
    assert _row_count(db, sid) == 0
```

### `scripts/race.sh` (demo for the judges)
```bash
#!/usr/bin/env bash
set -euo pipefail
BASE=${BASE:-http://localhost:3000}
DB=${DB:-vault.db}
ID=$(curl -s -X POST "$BASE/api/secret" -H 'Content-Type: application/json' \
      -d '{"secret":"race-me","ttl_seconds":60,"max_views":1}' | python -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "secret id: $ID"
seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE/api/secret/$ID/burn" | sort | uniq -c
# expected:   1 200
#            19 404
echo "rows left for $ID (expect 0):"
sqlite3 "$DB" "SELECT COUNT(*) FROM secrets WHERE id = '$ID';"
```

### `tests/test_sweeper.py` [REQ]
- [ ] Insert a row with `expires_at = now - 1` directly → `repo.purge_expired(now)` returns 1 → `COUNT(*) == 0`.
- [ ] A row with a future expiry is **not** purged.
- [ ] Burn on an expired-but-not-yet-swept row → 404, because the `WHERE` clause checks expiry.
- [ ] Live: create with `ttl_seconds: 1`, wait ≤ 2 × interval (5 s in the fixture), then query the DB file → row gone.
- [ ] `GET /view/{id}` on an expired row → 404 HTML page.
- [ ] Restart: an expired row inserted while the server is down is removed by the startup purge.

**Done when:** `pytest tests/test_race.py` passes all 10 rounds with the row-count check, `scripts/race.sh` prints `1 200 / 19 404 / 0`, and the sweeper tests pass. Commit: `feat: atomic burn verified under 20x concurrency, TTL sweeper, final lifespan`.

---

## P6 — Hostile Edge-Case Testing (2:25–2:40)

**Stop adding features.** Run everything, fix only what fails.

### `tests/test_tamper.py` [REQ]
- [ ] Flip a byte in `ciphertext` via raw `sqlite3.connect(db)` → burn → **404** with the exact message; body contains no `Traceback`/`File "`; row deleted.
- [ ] Same for `auth_tag`, `iv`, truncated ciphertext, empty `iv`, and a 3-byte `auth_tag`.
- [ ] Swap ciphertext/iv/tag between rows A and B → both burns → 404. [HARD: AAD binding]

### `tests/test_hostile.py`
- [ ] 200 KB body → 413; chunked body over the limit → 413. [HARD]
- [ ] `Content-Type: text/plain` body → 400. [HARD]
- [ ] Deeply nested JSON / huge JSON number / `null` values → 400. [HARD]
- [ ] Path-traversal and SQL-looking IDs → 404 (JSON on `/api`, HTML on `/view`). [REQ]
- [ ] Unicode, emoji and NUL (`"a\u0000b"`) secrets round-trip exactly.
- [ ] A secret containing `<script>alert(1)</script>` is never rendered by `view.html`; only `textContent` in JS displays it. [HARD]
- [ ] **Error channels:** every `/api/*` error is JSON `{"error": ...}`; every page error is HTML; no body contains `Traceback`, exception text, or the submitted secret. [REQ: no stack traces]
- [ ] `/docs` and `/openapi.json` → 404 when `VAULT_ENABLE_DOCS` is unset. [HARD]

### `scripts/inspect_db.sh`: proof that no plaintext is on disk
```bash
#!/usr/bin/env bash
DB=${1:-vault.db}; NEEDLE=${2:-my-database-password-xyz}
echo "rows / distinct IVs:"; sqlite3 "$DB" "SELECT COUNT(*), COUNT(DISTINCT iv) FROM secrets;"
echo "IV / tag lengths:";   sqlite3 "$DB" "SELECT DISTINCT length(iv), length(auth_tag) FROM secrets;"
echo "plaintext grep across DB + WAL (expect 0):"
cat "$DB" "$DB-wal" 2>/dev/null | grep -a -c "$NEEDLE" || echo "0 matches"
```
This grep is a valid test because plaintext is never written to SQLite at all (§0.4). It checks the core guarantee, not forensic erasure.

### Pre-freeze checklist (handout Part 10) [REQ]
- [ ] DB contains zero plaintext after ingestion (`inspect_db.sh`)
- [ ] Every record has a distinct IV
- [ ] `GET /view/:id` does not decrement or delete
- [ ] Slackbot / Twitterbot cannot consume the secret
- [ ] 20 parallel burns → 1×200 + 19×404, and the row is gone
- [ ] Sweeper deletes expired records automatically
- [ ] Corrupted ciphertext → clean 404, no stack trace
- [ ] `cat secret.txt | ./cli/vault-cli` works
- [ ] REPORT.md committed (P8)
- [ ] All code pushed

**Run all:** `pytest -q`. Commit: `test: hostile inputs, tamper, disk inspection`.

---

## P7 — BUILD FREEZE (2:40–2:45)

```bash
pytest -q
grep -rn "print(" app/                      # no debug prints that could leak secrets
git add -A
git status                                  # make sure no .env / *.db is staged
git commit -m "chore: build freeze"
git push
```
**No code changes after this point.**

---

## P8 — REPORT.md (2:45–3:00) [REQ: handout Part 9]

Prepare the skeleton in P0 so you only fill in results here.

1. **Architecture overview**: the diagram from SYSTEM_DESIGN §2, the schema, and the primitives (AES-256-GCM, 96-bit random IV, 128-bit tag, AAD = ID).
2. **Security & threat model**: key from env (never in the DB or git), IV per secret, tamper → 404 + delete, why not Base64/rot13/MD5/SHA/hardcoded IV (SYSTEM_DESIGN §6.3), threat table §12. **State the deletion guarantee precisely** (§0.4): no plaintext is ever stored; `secure_delete`/checkpoint are hardening only; no forensic guarantee below SQLite.
3. **The scraper problem**: read-only `GET /view` + POST-only burn (the real guarantee) + UA gate (defense in depth; can be bypassed by spoofing the user agent).
4. **Concurrency strategy**: the invariant "only one transaction can consume the final view"; `BEGIN IMMEDIATE` + conditional `UPDATE … RETURNING` + same-transaction `DELETE`; why a Python lock is neither needed nor sufficient.
5. **Results table** (paste real output):

   | Test | Command | Expected | Actual |
   |---|---|---|---|
   | Happy path (1-view burn) | `pytest tests/test_api.py -k happy` | 201 → 200 → 404, row gone | |
   | 20 parallel burns | `scripts/race.sh` / `pytest tests/test_race.py` | 1×200, 19×404, row count 0 (10/10 rounds) | |
   | TTL expiry cleanup | `pytest tests/test_sweeper.py` | row purged within 2 intervals | |
   | Tampered payload | `pytest tests/test_tamper.py` | 404, no stack trace, row deleted | |
   | Link crawler | `pytest tests/test_scraper.py` | bot gets shell/403, views unchanged | |
   | Plaintext on disk | `scripts/inspect_db.sh` | 0 matches, distinct IVs = rows | |
6. **Limitations & next steps**:
   - No rate limiting.
   - The UA gate can be bypassed by spoofing.
   - The server holds the key (E2E would fix this).
   - No key rotation.
   - No forensic erasure below SQLite.
   - Single host only; not horizontally scalable.
   - Burn throughput is limited to one writer at a time.
7. **Quickstart**:
   ```bash
   python -m venv .venv && source .venv/Scripts/activate
   pip install -r requirements.txt
   cp .env.example .env && python -c "import secrets;print(secrets.token_hex(32))"   # paste into .env
   uvicorn app.main:app --port 3000 --no-access-log
   curl -s -X POST localhost:3000/api/secret -H 'Content-Type: application/json' \
        -d '{"secret":"hello","ttl_seconds":300,"max_views":1}'
   curl -s -X POST localhost:3000/api/secret/<id>/burn
   echo "hello" | ./cli/vault-cli --ttl 300
   pytest -q
   ```

Commit & push: `docs: REPORT.md`.

---

## S — Stretch Goals [STRETCH] (only after P6 is fully green)

None of these are needed by P1–P8. Build them in this order; each can stop at any point without breaking the core.

| # | Stretch | Effort | Steps |
|---|---|---|---|
| S1 | **Audit fingerprint** | 15 min | Add `app/fingerprint.py`: `def fingerprint(pt: str) -> str: return "sha256:" + hashlib.sha256(pt.encode()).hexdigest()`. In `VaultService.create`, add `fingerprint` to the result **only if** `VAULT_FINGERPRINT=1`. Add `fingerprint: str \| None = None` to `CreateSecretOut` with `response_model_exclude_none=True`, so the core response keeps exactly 4 fields. Show it in `create.js` when present. In `reveal.js`, compute `crypto.subtle.digest("SHA-256")` and display it for comparison. **Never store the hash.** Do not put it in `CryptoEngine`. |
| S2 | **Password protection** | 30 min | Add nullable `pw_salt`, `pw_hash` columns. Create accepts `password` and stores `hashlib.scrypt(pw, salt=16B, n=2**14, r=8, p=1)`. Burn accepts JSON `{password}`, then does a read-only `SELECT` + `hmac.compare_digest` **before** `burn_atomic`. Wrong password → 401 with no view consumed. The landing page shows a password field when needed. |
| S3 | **Client-side E2E** | 45 min | In `create.js`: `crypto.subtle.generateKey(AES-GCM 256)` → encrypt → send `base64(iv‖ct)` with `e2e: true` → link `…/view/{id}#k=<b64url key>`. In `reveal.js`: after the burn, import the key from `location.hash`, decrypt locally, and use `history.replaceState` to remove the fragment. Server code doesn't change. |
| S4 | **Performance** | 20 min | Handout target: >1,500 reads/s, p99 < 15 ms. `pip install uvloop httptools orjson` (uvloop needs Linux/WSL), `--workers 4` **on the same host**, `default_response_class=ORJSONResponse`. Benchmark: `autocannon -c 50 -d 20 http://localhost:3000/view/<id>`. Report **measured** numbers only. |

---

## Risk Register (during the build)

| Risk | Signal | Response |
|---|---|---|
| `database is locked` under race | 500s in the race test | Confirm `busy_timeout=5000` is set on **every** connection and `BEGIN IMMEDIATE` (not `BEGIN`) is used |
| Race test passes too easily | Using TestClient | Use the `live_server` fixture + barrier + row-count check |
| `RETURNING` row missing | `fetchone()` returns None unexpectedly | Use `fetchall()` before `COMMIT`; check SQLite ≥ 3.35 |
| Tempted to add a Python lock | "Just to be safe" | Don't. The SQL invariant is the mechanism, and a lock would hide bugs |
| 422 instead of 400 | Validation tests fail | Confirm the `RequestValidationError` handler is installed |
| 400 instead of 413 for chunked bodies | Hostile test fails | Use the buffering `BodyLimitMiddleware` (P4), not one that raises mid-read |
| Tests fail with "no such table" / missing `app.state` | TestClient used without `with` | Use `with TestClient(app) as c:` so `lifespan` runs |
| Bot gate blocks curl/judges | Tests with curl get 403 | Remove any overly broad regex term; test `curl/8`, Chrome, Firefox and Safari UAs |
| CSP breaks the page | Buttons do nothing, console shows CSP errors | Keep all JS/CSS in `/static`, no inline handlers (`onclick=`) |
| Tracebacks in logs | uvicorn prints "Exception in ASGI application" | Make sure the catch-all `try/except` is in the outermost HTTP middleware |
| Running out of time | Past 2:25 with P5 unfinished | Apply the cut list in §0.2; concurrency + GC are worth 35 marks |
| Secrets in logs | `print(body)` left in code | `grep -rn "print(" app/` before the freeze |

---

## Definition of Done

- [ ] All 10 PDF must-have requirements pass, and all acceptance tests A–K (PRD §11) pass.
- [ ] `pytest -q` is fully green; the race test passes all 10 rounds, **including the row-count = 0 check**.
- [ ] `scripts/race.sh` prints `1 200`, `19 404`, and `0` rows left.
- [ ] `scripts/inspect_db.sh` finds 0 plaintext matches and distinct IVs = rows.
- [ ] Bots receive the shell/403 and never change state; humans can still reveal.
- [ ] API errors are JSON, page errors are HTML, and there are no stack traces anywhere.
- [ ] Browser flow works end to end with strict CSP and no console errors.
- [ ] `cat secret.txt | ./cli/vault-cli` prints a working link.
- [ ] The core build contains **no** stretch code paths (fingerprint, password, E2E) unless they were added after P6.
- [ ] No `.env` or `*.db` in git; `.env.example` present.
- [ ] REPORT.md is committed with **real** results and the precise deletion guarantee.
- [ ] Pushed before 2:45.
