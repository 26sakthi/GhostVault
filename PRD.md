# PRD — Ephemeral Secret Vault

**Event:** It Happens @ RAALE #9 · **Format:** 3-hour build + 15-min report · **Total marks:** 100
**Source:** `Ephemeral_Secret_Vault_IT HAPPENS @ RAALE #9.pdf`

---

## 1. Summary

A small, standalone web service that lets an engineer share a sensitive value (password, API key, `.env`, private key) through a **one-time, self-destructing link** instead of pasting it into Slack/Teams/email where it lives forever.

The secret is **encrypted at rest with AES-256-GCM**, reachable via a short **non-guessable ID**, revealed **only on an explicit human action (POST)**, and **hard-deleted** from storage once its views are used up or its TTL expires.

The product is judged not on CRUD, but on four hard guarantees:

| Guarantee | One-line definition |
|---|---|
| Crypto at rest | DB dump yields only ciphertext + random IVs + auth tags. Never plaintext. |
| Scraper shield | Link-preview bots (Slackbot, Discordbot, facebookexternalhit…) can never burn a secret. |
| No double-read | 20 parallel burns of a 1-view secret → exactly **1×200**, **19×404**. |
| Guaranteed GC | Expired/unread secrets are physically `DELETE`d by a background sweeper. |

---

## 2. Problem Statement

- Secrets pasted into chat tools are indexed, backed up, and searchable forever; a later account compromise exposes them.
- Public pastebins log IPs, store plaintext, and are scraped.
- Naive "burn-after-reading" services break in two ways:
  1. **Burn-on-GET trap** — chat apps' link unfurlers `GET` the URL first and destroy the secret before the human opens it.
  2. **Double-read race** — `SELECT` → decrypt → `DELETE` as separate steps leaks the secret to multiple concurrent callers.

---

## 3. Goals & Non-Goals

### Goals
1. Accept a secret via HTTP API **and** a terminal CLI (stdin).
2. Encrypt with AES-256-GCM, unique 12-byte random IV per secret, 16-byte auth tag.
3. Serve a safe HTML landing page that never mutates state.
4. Reveal + burn only through `POST /api/secret/:id/burn`, atomically.
5. Purge expired rows automatically every 10–30 s.
6. Fail cleanly (no stack traces) on tampered data, bad IDs, bad input.
7. Ship `REPORT.md` with architecture, threat model, and test results.

### Non-Goals (for the 3-hour build)
- User accounts, auth, roles, multi-tenancy.
- External DBs (Postgres/Redis) — SQLite WAL is preferred.
- Horizontal scaling / multi-node deployment.
- Pretty UI beyond a clear, functional landing page.

---

## 4. Users & Use Cases

| Actor | Need |
|---|---|
| **Sender** (engineer) | `cat .env \| ./vault-cli` → get a link, paste it in chat. |
| **Recipient** (human) | Opens link → sees a notice + "Reveal and Destroy Secret" button → clicks → sees secret once. |
| **Link-preview bot** | Hits the link to build a preview card. Must get harmless HTML/blank; must not change state. |
| **Attacker** | Guesses IDs, fires parallel burns, tampers with DB rows, dumps the DB file. Must get nothing useful. |
| **Judge** | Runs curl with spoofed UAs, parallel requests, and inspects SQLite directly. |

---

## 5. System Architecture

```
            ┌──────────────────────────────────────────────┐
 CLI/curl → │ API GATEWAY                                  │ ← Browser
            │  POST /api/secret      GET /view/:id         │
            │  POST /api/secret/:id/burn   GET /health     │
            │  [Bot User-Agent gate on every route]        │
            └───────────────┬──────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────┐
            │ CRYPTO ENGINE  AES-256-GCM                   │
            │  key = VAULT_MASTER_KEY (env, 32 bytes)      │
            │  iv  = randomBytes(12) per secret            │
            │  tag = 16 bytes                              │
            └───────────────┬──────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────┐
            │ STORAGE ENGINE  SQLite (WAL)                 │
            │  atomic UPDATE … RETURNING + hard DELETE     │
            └───────────────▲──────────────────────────────┘
                            │ every 10s
            ┌───────────────┴──────────────────────────────┐
            │ TTL SWEEPER  DELETE WHERE expires_at <= now  │
            └──────────────────────────────────────────────┘
```

### Recommended stack
| Layer | Choice |
|---|---|
| Runtime | Node.js 20+ (Express/Fastify) — or Go 1.21+ / Python 3.11+ |
| Storage | SQLite with `PRAGMA journal_mode = WAL;` (`better-sqlite3`), single local file or in-memory |
| Crypto | Native `node:crypto`, `aes-256-gcm` |
| IDs | `crypto.randomBytes(8).toString('hex')` or `nanoid` (URL-safe, ≥64 bits entropy) |
| Sweeper | In-process `setInterval` / Go ticker (10–30 s; we use 10 s) |

Library equivalents if not using Node:
- **Python 3.11+:** `cryptography`, native `sqlite3`
- **Go 1.21+:** `crypto/cipher`, `crypto/aes`, `modernc.org/sqlite`

---

## 6. Data Model

```sql
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS secrets (
  id               TEXT    PRIMARY KEY,
  ciphertext       BLOB    NOT NULL,
  iv               BLOB    NOT NULL,       -- 12 bytes, unique per row
  auth_tag         BLOB    NOT NULL,       -- 16 bytes
  max_views        INTEGER NOT NULL DEFAULT 1,
  views_remaining  INTEGER NOT NULL DEFAULT 1,
  expires_at       INTEGER NOT NULL,       -- epoch ms
  created_at       INTEGER NOT NULL        -- epoch ms
);
CREATE INDEX IF NOT EXISTS idx_secrets_expiry ON secrets(expires_at);
```

Rules:
- **No plaintext column. No key column.** Ever.
- **No soft delete** (`is_deleted = true` scores **0** on destruction).

---

## 7. API Contract

### 7.1 `POST /api/secret` — create
Request:
```json
{ "secret": "my-database-password-xyz", "ttl_seconds": 3600, "max_views": 1 }
```
Response **201 Created**:
```json
{
  "id": "e8a1b4c7d2e9",
  "view_url": "http://localhost:3000/view/e8a1b4c7d2e9",
  "expires_at": "2026-09-24T12:00:00.000Z",
  "views_remaining": 1
}
```
Validation → **400** with `{ "error": "..." }`:
- `secret` missing, not a string, empty, or above size cap (e.g. 64 KB).
- `ttl_seconds` not a positive integer or above cap (e.g. 7 days).
- `max_views` not a positive integer or above cap (e.g. 100). Defaults: `max_views = 1`, `ttl_seconds = 3600`.
- Malformed JSON body.

### 7.2 `GET /view/:id` — safe landing page
- Returns **200 HTML**. **Never decrypts, never decrements, never deletes.**
- Shows: *"You have been sent a secure, self-destructing secret."*, expiry timestamp, views remaining.
- Button **"Reveal and Destroy Secret"** → client-side `fetch('POST /api/secret/:id/burn')` → renders secret (as text, not HTML) in the page.
- If the recipient closes the page without clicking Reveal, **nothing happens**: the secret stays encrypted and available until its TTL expires or someone clicks Reveal.
- Unknown/expired ID → friendly "not found / already destroyed" HTML (404; see §17).
- Add `<meta name="robots" content="noindex,nofollow">`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.

### 7.3 `POST /api/secret/:id/burn` — reveal & destroy
Response **200 OK**:
```json
{ "secret": "my-database-password-xyz", "views_remaining": 0, "burned": true }
```
(`burned` is `true` when this read consumed the last view and the row was deleted.)

Response **404 Not Found** (burned, expired, never existed, malformed ID, or tampered):
```json
{ "error": "Secret not found, expired, or already destroyed." }
```

### 7.4 `GET /health` — **200** `{ "status": "ok" }`

### 7.5 Global response rules
- All error bodies are JSON `{ "error": "..." }` — **no stack traces**, ever.
- `Cache-Control: no-store` on every secret-related response.

---

## 8. Functional Requirements

### FR-1 Crypto Engine
- `encrypt(plaintext) → { ciphertext, iv, tag }` using `aes-256-gcm`, fresh `randomBytes(12)` IV every call.
- `decrypt(ciphertext, iv, tag) → plaintext`; GCM auth failure throws → caught → mapped to 404/400.
- Master key from `VAULT_MASTER_KEY` (64 hex chars / 32 bytes). Validate length at boot; **fail fast** if invalid. If absent, generate a random key at boot and log a warning (secrets won't survive restart).
- Key never stored in DB, never committed to git (`.env` in `.gitignore`, provide `.env.example`).
- **Explicitly forbidden** (fake/decorative crypto): Base64 encoding, rot13, MD5/SHA-256 hashing used as "encryption", a hardcoded or global/reused IV, keys in version control.
- *Optional hardening:* bind `id` as GCM AAD so a ciphertext can't be swapped between rows.

### FR-2 Scraper Shield
- `GET /view/:id` is strictly read-only.
- **Bot UA gate** middleware on GET and POST: case-insensitive match against
  `bot, crawl, spider, slurp, slackbot, discordbot, twitterbot, facebookexternalhit, whatsapp, telegrambot, linkedinbot, embedly, preview, skypeuripreview, teams` → return a blank/generic 200 (or 403) with **no state change**.
- Only `POST` can burn. `GET /api/secret/:id/burn` → **405**.

### FR-3 Atomic Burn (no double-read)
Single statement check-and-decrement:
```sql
UPDATE secrets
   SET views_remaining = views_remaining - 1
 WHERE id = ? AND views_remaining > 0 AND expires_at > ?
RETURNING ciphertext, iv, auth_tag, views_remaining;
```
- No row → 404.
- `views_remaining == 0` → `DELETE FROM secrets WHERE id = ?` immediately (ideally in the same transaction).
- Then decrypt from the returned values and respond.
- Never do `SELECT` then `UPDATE`/`DELETE` as separate steps.

### FR-4 TTL Sweeper
- Runs every 10 s: `DELETE FROM secrets WHERE expires_at <= ?` (now, ms).
- Logs count of purged rows (never content).
- Reads also enforce `expires_at > now`, so an expired secret is unreadable even before the sweeper runs.
- Runs once at startup to clean anything expired while the server was down.

### FR-5 CLI helper
- `vault-cli` script: reads stdin, POSTs to the API, prints `view_url`.
- Flags: `--ttl <seconds>`, `--views <n>`, `--server <url>`.
- Must work as: `cat secret.txt | ./vault-cli` and `echo "pw" | ./vault-cli --ttl 300`.
- Also document a pure curl one-liner.

### FR-6 Hostile Input Resilience
- Bad/overlong/non-hex IDs → 404 (reject before hitting DB).
- Tampered/truncated ciphertext, IV or tag → clean 404/400 JSON, no stack trace; row deleted.
- Oversized body → 413; wrong content type / bad JSON → 400.
- Global error handler catches everything.

---

## 9. Non-Functional Requirements

| Area | Requirement |
|---|---|
| Security | Zero plaintext on disk (incl. logs). Keys only in env. Secret shown via `textContent`, not `innerHTML`. |
| Concurrency | 20 parallel burns → exactly 1×200, 19×404, every run. |
| Performance (stretch) | >1,500 reads/sec, p99 < 15 ms under autocannon/k6. |
| Reliability | SQLite WAL; `busy_timeout` set; graceful shutdown stops sweeper and closes DB. |
| Privacy | No logging of secrets, request bodies, or IPs. |

---

## 10. Stretch Goals (Distinction)

1. **Client-side E2E encryption** — encrypt in browser/CLI with WebCrypto; key lives in URL fragment `#key` (never sent to server).
2. **Password protection** — optional passphrase required at burn time (derive key via PBKDF2/scrypt).
3. **Audit fingerprint** — return SHA-256 of the plaintext to the sender at creation.
4. **High-load performance** — benchmark and publish numbers in REPORT.md.

---

## 11. Acceptance Tests

| # | Scenario | Steps | Expected |
|---|---|---|---|
| A | Happy path | Create (TTL 300, views 1) → burn → burn again | 201 → 200 with secret → 404; row absent in `sqlite3` |
| B | Link crawler | `GET /view/:id` and `POST …/burn` with `User-Agent: Slackbot-LinkExpanding 1.0` | HTML shell / blank; `views_remaining` unchanged; human burn still works |
| C | Race | 20 parallel `POST …/burn` on 1-view secret | Exactly 1×200, 19×404 |
| D | TTL cleanup | Create TTL 2 s → wait ~15 s → query DB | Burn returns 404; row physically gone |
| E | Tamper | Flip a byte in `ciphertext`/`auth_tag` via `sqlite3` → burn | Clean 404/400 JSON, no stack trace |
| F | Plaintext check | Create secret → `sqlite3 vault.db .dump \| grep <secret>` | No match |
| G | Unique IVs | Create 100 secrets → `SELECT COUNT(DISTINCT iv)` | = 100 |
| H | View page is safe | `GET /view/:id` 10× | `views_remaining` unchanged |
| I | Bad input | Missing secret, negative TTL, bad JSON, bad ID | 400 / 404, JSON errors |
| J | CLI | `cat secret.txt \| ./vault-cli` | Prints working `view_url` |
| K | Multi-view | Create `max_views: 3` → burn ×4 | 200, 200, 200 (`burned: true`), 404 |

Race test example:
```bash
seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3000/api/secret/$ID/burn | sort | uniq -c
```

---

## 12. Marking Criteria → Where It's Covered

| Component | Marks | PRD section |
|---|---|---|
| Cryptographic rigor | 20 | FR-1, Tests F/G |
| Concurrency defense | 20 | FR-3, Test C |
| Scraper shield | 15 | FR-2, §7.2, Tests B/H |
| Garbage collection | 15 | FR-4, Test D |
| API quality & CLI | 10 | §7, FR-5, Test J |
| Hostile input resilience | 10 | FR-6, Tests E/I |
| Report | 10 | §14 |
| **Total** | **100** | |

---

## 13. Build Plan (3 hours)

### Before the session (prep — no setup time is given during the build)
- [ ] Scratch repo created with the chosen runtime installed
- [ ] `sqlite3` CLI installed (to inspect table state)
- [ ] Docker installed **only** if using an external DB/cache (not recommended)
- [ ] Crypto + SQLite libraries installed and verified (§5)
- [ ] Parallel HTTP test runner ready (`curl` + `xargs`, `autocannon`, or a Python script)
- [ ] Scenarios A (happy path), B (link crawler), C (20-parallel race) scripted at home

### Build order rule — "build the pipe before the logic"
1. `POST /api/secret` writes a **dummy unencrypted** string to SQLite and returns an ID.
2. `POST /api/secret/:id/burn` deletes the row.
3. Only then swap in real AES-256-GCM encrypt/decrypt.
4. Client-side E2E encryption (stretch) only **after** server-side crypto passes the race and scraper tests.

| Time | Phase | Done when |
|---|---|---|
| 0:00–0:15 | Setup | Repo, SQLite schema (WAL), `/health` = 200 |
| 0:15–0:45 | Crypto core | `encrypt`/`decrypt` unit-tested incl. tamper failure |
| 0:45–1:25 | Core endpoints | Create stores encrypted rows; burn decrypts + wipes |
| 1:25–1:55 | Scraper defense | `/view/:id` HTML + Reveal button; bot UA gate |
| 1:55–2:25 | Concurrency + sweeper | 20-parallel test passes; sweeper purges |
| 2:25–2:40 | Hostile testing | Run all acceptance tests + checklist |
| **2:40–2:45** | **BUILD FREEZE** | Everything committed & pushed |
| 2:45–3:00 | Report | `REPORT.md` committed |

> **The 2:45 freeze is hard.** Work that is not pushed does not exist. From 2:25, stop adding features and run the §15 checklist.

---

## 14. Deliverables

1. Source code in the repo (server, crypto module, sweeper, landing HTML).
2. `vault-cli` script (stdin → link).
3. Test script(s) for scenarios A–K.
4. `.env.example` with `VAULT_MASTER_KEY=` (no real key committed).
5. **`REPORT.md`** containing:
   1. Architecture overview (data flow, schema, crypto primitives)
   2. Security & threat model (GCM usage, key/IV management, why not Base64/hashing)
   3. The scraper problem & solution
   4. Concurrency strategy
   5. Results table: happy path, 20-parallel race, TTL cleanup, tampered payload
   6. Limitations & next steps (E2E crypto, rate limiting, key rotation)
   7. Quickstart (install, run, test, curl example)

---

## 15. Pre-Freeze Checklist

- [ ] DB contains zero plaintext after ingestion
- [ ] Every record has a distinct IV
- [ ] `GET /view/:id` never decrements or deletes
- [ ] Slackbot/Twitterbot cannot consume a secret
- [ ] 20 parallel burns → 1×200 + 19×404
- [ ] Sweeper deletes expired records automatically
- [ ] Corrupted ciphertext → clean 404/400, no stack trace
- [ ] `cat secret.txt | ./vault-cli` works
- [ ] `REPORT.md` committed
- [ ] All code pushed

---

## 16. Risks & Notes

| Risk | Mitigation |
|---|---|
| Master key generated at boot → all secrets lost on restart | Use `VAULT_MASTER_KEY` env var; document in Quickstart |
| Row decremented but decryption fails (tampered) | Treat as destroyed: delete row, return 404 |
| UA gate is spoofable (a bot could pretend to be a browser) | Real defense is GET-never-burns + POST-only burn; UA gate is defense-in-depth |
| SQLite `SQLITE_BUSY` under load | WAL + `busy_timeout = 5000`; single process with synchronous driver |
| Secret leaked via logs/referrer/cache | No body logging; `no-store`, `no-referrer` headers |
| Deleted data still in WAL / free pages | Optional `PRAGMA secure_delete = ON`; mention in REPORT limitations |

---

## 17. Assumptions Beyond the PDF

These choices are **not** set by the PDF. They're ours, so state them in REPORT.md:

| Topic | PDF says | This PRD decides |
|---|---|---|
| `burned` field | Only shows the 1-view example (`views_remaining: 0, burned: true`) | `burned: true` only when the last view is used and the row is deleted; `false` on earlier views of a multi-view secret |
| `GET /view/:id` for unknown/expired ID | Only defines the 200 case | Return a 404 HTML page (still read-only) |
| Tampered ciphertext | "clean 404 or 400" | Return 404 and delete the row |
| 404 error text | Contract: "Secret not found, expired, or already destroyed."; sample code uses different text | Use the contract text |
| Bot action | "rejected **or** served a blank response" | Blank/generic response; list extended beyond the PDF's examples |
| Extra status codes | Lists 201 / 200 / 404 | Also 400 (bad input), 405 (GET on burn), 413 (too large) |
| Input limits, security headers, AAD binding, `secure_delete` | Not mentioned | Added as hardening |
