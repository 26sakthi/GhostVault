#!/usr/bin/env bash
# Scenario C demo: 20 simultaneous burns of one 1-view secret.
# Expected: 1x 200, 19x 404, and 0 rows left for the id.
set -euo pipefail
BASE=${BASE:-http://localhost:3000}
DB=${DB:-vault.db}
PY=${PY:-python}
# sqlite3 CLI: $SQLITE, else PATH, else the portable copy in tools/sqlite (Windows)
SQLITE=${SQLITE:-$(command -v sqlite3 || ls "$(dirname "$0")/../tools/sqlite/sqlite3.exe" 2>/dev/null || true)}

ID=$(curl -s -X POST "$BASE/api/secret" -H 'Content-Type: application/json' \
      -d '{"secret":"race-me","ttl_seconds":60,"max_views":1}' | "$PY" -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "secret id: $ID"
seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE/api/secret/$ID/burn" | sort | uniq -c
echo "rows left for $ID (expect 0):"
if [ -n "$SQLITE" ]; then
  "$SQLITE" "$DB" "SELECT COUNT(*) FROM secrets WHERE id = '$ID';"
else
  "$PY" -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('SELECT COUNT(*) FROM secrets WHERE id=?',(sys.argv[2],)).fetchone()[0])" "$DB" "$ID"
fi
