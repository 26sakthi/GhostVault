# REPORT — Ephemeral Secret Vault

Python 3.11.15 · FastAPI 0.141 · SQLite 3.53.1 (WAL) · `cryptography` 50 (AES-256-GCM). All results below were measured on the dev machine (Windows 11) on 2026-09-24.

---

## 1. Architecture Overview

```
 CLI / curl / browser ─┐
 link-preview bots ────┤
                       ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ gate middleware: bot UA check · security headers · catch-all │
  │ body-limit middleware (128 KB)                               │
  ├─────────────────────────────────────────────────────────────┤
  │ routes   POST /api/secret · POST /api/secret/{id}/burn        │
  │          GET /view/{id} (read-only) · GET / · GET /health     │
  ├─────────────────────────────────────────────────────────────┤
  │ VaultService ─► CryptoEngine (AES-256-GCM)                    │
  │             └─► SecretRepository (all SQL) ─► SQLite WAL file │
  │ Sweeper task (every 10 s): DELETE expired + WAL checkpoint    │
  └─────────────────────────────────────────────────────────────┘
```

**Data flow**
- **Create:** validate → random 64-bit ID → encrypt → `INSERT` ciphertext, IV and tag → 201.
- **View:** read-only `SELECT` of expiry and views, then render HTML. The secret is not decrypted.
- **Burn:** one atomic transaction that decrements views and deletes the row on the last view, then decrypt → 200, or 404.
- **Sweeper:** deletes expired rows.

**Schema:** the handout's single `secrets` table, unchanged: `id, ciphertext, iv, auth_tag, max_views, views_remaining, expires_at, created_at` plus an index on `expires_at`. There is no plaintext column, no key column and no `is_deleted` flag.

**Crypto primitives:**
- AES-256-GCM.
- A 96-bit IV from `os.urandom(12)`, new for every secret.
- A 128-bit auth tag, stored in its own column.
- AAD = the secret's ID, so ciphertext cannot be moved to another row.
- A 32-byte master key from `VAULT_MASTER_KEY`.

## 2. Security & Threat Model

- **Key management:**
  - The key is loaded from the environment and validated at boot.
  - An invalid key stops the server from starting.
  - A missing key means a random key is generated, with a warning.
  - The key is never stored in the database or git. `.env` is git-ignored and only `.env.example` is committed.
- **IVs:** a fresh random 12-byte IV for every secret. Tests show 1,000 encryptions give 1,000 distinct IVs, and the DB check shows `COUNT(DISTINCT iv) = COUNT(*)`. A reused GCM nonce breaks both confidentiality and integrity, so there is no global or hardcoded IV.
- **Integrity:**
  - Any change to the ciphertext, IV or tag, a truncated value, or ciphertext moved from another row fails GCM authentication (`InvalidTag`).
  - The service then deletes the row and returns the standard 404.
  - No stack trace, exception text or plaintext appears in any response. This is covered by tests.
- **Why not Base64 or hashing:**
  - Base64 and rot13 are encodings that anyone can reverse without a key.
  - MD5 and SHA-256 are one-way, so the recipient could never get the secret back, and short secrets can be brute-forced.
  - Unauthenticated modes such as CBC or CTR can't detect tampering.
  - AES-GCM gives both confidentiality and integrity.
- **Deletion guarantee, stated precisely:**
  - Plaintext is **never persistently stored as application data**. The DB and WAL only ever contain ciphertext, IV and tag. A grep for a known secret across `vault.db` and `vault.db-wal` finds 0 matches.
  - Destroyed secrets are removed with `DELETE`, not soft-deleted.
  - `PRAGMA secure_delete = ON` and `wal_checkpoint(TRUNCATE)` after each sweep are **hardening** that reduces leftover data inside SQLite's files.
  - They are **not** a forensic-erasure guarantee below SQLite: filesystem journals, SSD wear levelling, backups and OS swap can still hold old bytes. Anything left there is ciphertext.
- **Other defenses:**
  - Bad input returns 400 without ever echoing the submitted value.
  - Request bodies are limited to 128 KB (413).
  - Strict CSP with no inline scripts; the secret is rendered with `textContent`.
  - `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `noindex`.
  - `/docs` is disabled.
  - Access logs are off, and application logs never contain secrets, bodies or full IDs.

## 3. The Scraper Problem

Chat apps request every pasted URL to build a preview card. Burning on `GET` would let that bot destroy the secret before the human sees it.

1. **The method split (the real guarantee):**
   - `GET /view/{id}` runs only a read-only `SELECT` and returns a landing page.
   - Decryption and deletion happen **only** on `POST /api/secret/{id}/burn`.
   - That POST is sent by the **Reveal and Destroy Secret** button, after a confirmation dialog.
   - Unfurlers, and browser prefetch and prerender, only send `GET`s.
2. **User-agent gate (defense in depth):** a case-insensitive match on `bot|crawl|spider|slack|facebookexternalhit|discord|whatsapp|telegram|twitter|linkedin|preview|unfurl…`, checked on **every** route before any database access:
   - `GET /view/*` → 200 generic HTML shell with no ID, expiry or view count (handout Scenario B);
   - `/api/*` → 403 JSON;
   - anything else → empty 403.

   `curl`, browsers, `python-httpx` and `vault-cli` are not matched.
3. **Honest limitation:** the UA gate can be bypassed by a bot that lies about its user agent. Layer 1 is what stops such a bot from burning a secret, unless it also sends a deliberate `POST`, which link unfurlers don't do.

## 4. Concurrency Strategy

**Invariant:** *only one transaction can successfully consume the final available view.*

```sql
BEGIN IMMEDIATE;                                   -- take SQLite's write lock
UPDATE secrets SET views_remaining = views_remaining - 1
 WHERE id = ? AND views_remaining > 0 AND expires_at > ?
RETURNING ciphertext, iv, auth_tag, views_remaining;
DELETE FROM secrets WHERE id = ?;                  -- only if views_remaining = 0, same transaction
COMMIT;
-- decrypt afterwards, using only the bytes this transaction received
```

- **Single statement:** the check and the decrement happen in one conditional statement, so there is no `SELECT → check → UPDATE` gap.
- **Serialized writers:** `BEGIN IMMEDIATE` makes SQLite serialize competing writers across threads **and processes**. When a waiting request gets the lock, it sees the committed state, its `WHERE` clause matches nothing, and it returns 404.
- **Same-transaction delete:** the last-view `DELETE` commits together with the decrement.
- **No Python lock:** none is used, and none is needed.
- **Verified by a mutation test:** I swapped in the handout's broken SELECT-then-UPDATE pattern and ran the same 20-request burst. It handed the secret to **4** and then **7** callers, so the test catches the bug.

## 5. Results & Benchmarks

Full suite: **`pytest` → 158 passed** (12.6 s). The race and sweeper tests run against a real uvicorn subprocess, not the in-process TestClient, which would serialize requests and hide races.

| Test | Command | Expected | Actual |
|---|---|---|---|
| Happy path (1-view burn, TTL 300 s) | `pytest tests/test_api.py -k happy` | 201 → 200 → 404, row gone | ✅ as expected; row count 0 |
| Multi-view (`max_views: 3`) | `pytest tests/test_api.py -k multi_view` | 200, 200, 200 (`burned: true`), 404 | ✅ |
| 20 parallel burns, 1 view | `pytest tests/test_race.py` | 1×200, 19×404, row count 0, 10 rounds | ✅ **10/10 rounds** |
| 20 parallel burns, 2/3/5 views | `pytest tests/test_race.py -k multi` | exactly N×200, each view handed out once, row gone | ✅ |
| Race demo (curl + xargs, 1 worker) | `scripts/race.sh` | `1 200`, `19 404`, `0` | ✅ `1 200 / 19 404 / 0` |
| Race demo, **4 uvicorn worker processes** | `uvicorn … --workers 4` + `scripts/race.sh` ×5 | same | ✅ **5/5 runs** `1 200 / 19 404 / 0` |
| TTL expiry cleanup (real sweeper, 5 s interval) | `pytest tests/test_sweeper.py -k live` | row physically deleted within 2 intervals | ✅ |
| Expired but not yet swept | `pytest tests/test_sweeper.py -k before_sweep` | burn 404, view 404 | ✅ |
| Startup purge | `pytest tests/test_sweeper.py -k startup` | expired row removed at boot | ✅ |
| Tampered payload (flip / truncate / empty ciphertext, IV or tag; swapped rows) | `pytest tests/test_tamper.py` | 404, no traceback, row deleted | ✅ 8/8 |
| Link crawler (12 bot UAs) | `pytest tests/test_scraper.py` | shell / 403, views unchanged, human still reveals | ✅ |
| Plaintext on disk | `scripts/inspect_db.sh` | 0 matches, distinct IVs = rows, 12/16 bytes, WAL | ✅ `1|1`, `12|16`, `wal`, `0` |
| Hostile input | `pytest tests/test_hostile.py` | 400/404/413, JSON vs HTML channels, generic 500s | ✅ |
| CLI pipeline | `echo x \| ./cli/vault-cli` | prints a working link | ✅ (Git Bash; also via `python cli/vault-cli`) |
| Browser flow | manual, in-app browser | create → view → reveal → gone, no console/CSP errors | ✅ |

**Performance (stretch):** not benchmarked. No throughput numbers are claimed.

## 6. Limitations & Next Steps

- **No rate limiting:** ID guessing is infeasible (64-bit IDs), but request flooding isn't throttled.
- **The server holds the key:** anyone with both the DB **and** `VAULT_MASTER_KEY` can decrypt unburned secrets. Next step: client-side E2E encryption with the key in the URL fragment (stretch S3).
- **The UA gate can be bypassed** by a bot that fakes its user agent (see §3). The method split remains the real protection.
- **No forensic erasure below SQLite** (see §2).
- **No key rotation:** a key-version column and re-encryption would add it.
- **Single host only:** SQLite allows one writer at a time and is not horizontally scalable. Multiple workers on one host are correct (measured above) but don't add write throughput.
- **A crash between `COMMIT` and the response** consumes that view without delivering it. The system fails closed.
- **Stretch goals not built:** audit fingerprint, password protection, E2E encryption, load benchmark.

## 7. Quickstart

```bash
python -m venv .venv && source .venv/Scripts/activate      # Linux/macOS: .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c "import secrets;print(secrets.token_hex(32))"      # paste into .env as VAULT_MASTER_KEY
uvicorn app.main:app --port 3000 --no-access-log

# create, then burn
curl -s -X POST localhost:3000/api/secret -H 'Content-Type: application/json' \
     -d '{"secret":"hello","ttl_seconds":300,"max_views":1}'
curl -s -X POST localhost:3000/api/secret/<id>/burn

# CLI
echo "hello" | ./cli/vault-cli --ttl 300

# tests and demos
pytest
scripts/race.sh
scripts/inspect_db.sh vault.db hello
```
