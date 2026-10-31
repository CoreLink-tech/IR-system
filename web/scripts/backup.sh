#!/usr/bin/env bash
# Local SQLite backup. For Turso use: turso db shell / dump per provider docs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${DATABASE_URL:-file:$ROOT/data/ir.db}"
SRC="${SRC#file:}"
OUT_DIR="${1:-$ROOT/data/backups}"
mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$OUT_DIR/ir-$STAMP.db"
cp "$SRC" "$OUT"
echo "Backup written: $OUT"
echo "RPO: since last run of this script. RTO: restore file to DATABASE_URL path and restart."
