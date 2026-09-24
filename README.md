# Ephemeral Secret Vault

A self-destructing secret-sharing service (It Happens @ RAALE #9). Paste a password, API key or `.env` file and get a one-time link. The secret is encrypted with AES-256-GCM, revealed only when a human clicks **Reveal and Destroy Secret**, and then permanently deleted. Unread secrets are deleted when their TTL expires.

**Stack:** Python 3.11 · FastAPI · Uvicorn · SQLite (WAL) · `cryptography` · Jinja2 · HTML/CSS/JS

Docs: [PRD.md](PRD.md) · [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) · [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) · [REPORT.md](REPORT.md)

## Quickstart

```bash
python -m venv .venv
source .venv/Scripts/activate          # Windows Git Bash; Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c "import secrets;print(secrets.token_hex(32))"   # paste the output as VAULT_MASTER_KEY in .env
uvicorn app.main:app --port 3000 --no-access-log
```

Open http://localhost:3000 to create a secret in the browser.

## API

```bash
# create
curl -s -X POST localhost:3000/api/secret -H 'Content-Type: application/json' \
     -d '{"secret":"my-database-password-xyz","ttl_seconds":3600,"max_views":1}'
# -> 201 {"id":"…","view_url":"http://localhost:3000/view/…","expires_at":"…","views_remaining":1}

# landing page (safe for link previews; never consumes the secret)
curl -s localhost:3000/view/<id>

# reveal + destroy
curl -s -X POST localhost:3000/api/secret/<id>/burn
# -> 200 {"secret":"my-database-password-xyz","views_remaining":0,"burned":true}
# -> 404 {"error":"Secret not found, expired, or already destroyed."}
```

## CLI

```bash
cat secret.txt | ./cli/vault-cli                 # prints the one-time link
echo "hunter2" | ./cli/vault-cli --ttl 300 --views 1
./cli/vault-cli --json < .env                    # full JSON response
```
It reads stdin, needs no extra packages, and uses `--server` or `VAULT_SERVER` (default `http://localhost:3000`). On Windows cmd/PowerShell use `cli\vault-cli.cmd` or `python cli/vault-cli`.

## Tests & demos

```bash
pytest                                            # full suite (starts a real uvicorn for race/sweeper tests)
scripts/race.sh                                   # 20 parallel burns: expect 1x200, 19x404, 0 rows left
scripts/inspect_db.sh vault.db my-database-password-xyz   # distinct IVs, 12/16-byte IV/tag, 0 plaintext matches
```
Set `PY=.venv/Scripts/python` (or your interpreter) and `DB=<path>` if needed. The scripts look for the `sqlite3` CLI in `$SQLITE`, then on `PATH`, then at `tools/sqlite/sqlite3.exe`, and fall back to Python otherwise.

**Windows, portable sqlite3 (git-ignored):** download `sqlite-tools-win-x64-*.zip` from https://sqlite.org/download.html, check its SHA3-256 against the value on that page, and extract it to `tools/sqlite/`. Then inspect the DB directly with `tools/sqlite/sqlite3.exe vault.db ".schema secrets"`.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `VAULT_MASTER_KEY` | *(generated at boot)* | 64 hex chars. If unset, a random key is used and secrets are lost on restart. An invalid value stops the server from starting. |
| `VAULT_DB_PATH` | `vault.db` | Must be on persistent local disk (not a network share). |
| `VAULT_BASE_URL` | `http://localhost:3000` | Used to build `view_url`. |
| `VAULT_SWEEP_INTERVAL` | `10` | Seconds between expiry sweeps (5–30). |
| `VAULT_MAX_SECRET_BYTES` / `VAULT_MAX_TTL` / `VAULT_MAX_VIEWS` / `VAULT_MAX_BODY_BYTES` | 65536 / 604800 / 100 / 131072 | Input limits |
| `VAULT_ENABLE_DOCS` | `0` | Set `1` to expose `/docs` during development |

**Deployment:** a single host or container with a persistent local filesystem, and one uvicorn worker recommended. It is not designed for serverless platforms or multiple hosts.
