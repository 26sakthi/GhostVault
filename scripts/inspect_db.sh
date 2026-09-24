#!/usr/bin/env bash
# Proof of encryption at rest: row/IV counts, IV/tag lengths, and a plaintext grep over DB + WAL.
# Usage: scripts/inspect_db.sh [db-path] [plaintext-to-search-for]
DB=${1:-vault.db}; NEEDLE=${2:-my-database-password-xyz}; PY=${PY:-python}
# sqlite3 CLI: $SQLITE, else PATH, else the portable copy in tools/sqlite (Windows)
SQLITE=${SQLITE:-$(command -v sqlite3 || ls "$(dirname "$0")/../tools/sqlite/sqlite3.exe" 2>/dev/null || true)}
q() {
  if [ -n "$SQLITE" ]; then "$SQLITE" "$DB" "$1"
  else "$PY" -c "import sqlite3,sys;[print('|'.join(map(str,r))) for r in sqlite3.connect(sys.argv[1]).execute(sys.argv[2])]" "$DB" "$1"; fi
}
echo "rows | distinct IVs:"; q "SELECT COUNT(*), COUNT(DISTINCT iv) FROM secrets;"
echo "IV length | tag length:"; q "SELECT DISTINCT length(iv), length(auth_tag) FROM secrets;"
echo "journal mode:"; q "PRAGMA journal_mode;"
echo "plaintext matches across DB + WAL (expect 0):"
cat "$DB" "$DB-wal" 2>/dev/null | grep -a -c -- "$NEEDLE" || true
