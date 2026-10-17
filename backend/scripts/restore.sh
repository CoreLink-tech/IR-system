#!/usr/bin/env bash
# Restores a backup made by backup.sh into an EMPTY database and checks it.
#
#   DB_NAME=shop_restored DB_USER=ir_admin ./scripts/restore.sh /var/backups/ir-system/ir-security-20261014-031700.sql.gz
#
# It never writes into a database that already has security_* tables: restore into a NEW, empty database,
# check it, then point the API at it. Steps: verify the checksum, check the target is empty, load, compare
# every table's row count with the backup's counts file.
# Same settings as backup.sh (DB_NAME, DB_USER, DB_HOST, DB_PORT, MYSQL_PWD, MYSQL_EXTRA_ARGS).
set -euo pipefail
FILE="${1:?Usage: restore.sh path/to/ir-security-....sql.gz}"
: "${DB_NAME:?Set DB_NAME to the EMPTY database to restore into}"
DB_HOST="${DB_HOST:-127.0.0.1}"; DB_PORT="${DB_PORT:-3306}"
EXTRA=(${MYSQL_EXTRA_ARGS:-})
AUTH=(-h "$DB_HOST" -P "$DB_PORT"); [ -n "${DB_USER:-}" ] && AUTH+=(-u "$DB_USER")
CLIENT=$(command -v mariadb || command -v mysql || true); [ -n "$CLIENT" ] || { echo "restore: mysql/mariadb client required" >&2; exit 2; }
COUNTS="${FILE%.sql.gz}.counts.txt"

[ -f "$FILE" ] || { echo "restore: $FILE not found" >&2; exit 2; }
[ -f "$FILE.sha256" ] || { echo "restore: $FILE.sha256 not found, refusing to restore an unchecked file" >&2; exit 2; }
( cd "$(dirname "$FILE")" && sha256sum -c "$(basename "$FILE").sha256" >/dev/null ) || { echo "restore: CHECKSUM MISMATCH, the backup is damaged or was changed" >&2; exit 3; }
gzip -t "$FILE"
existing=$("$CLIENT" "${AUTH[@]}" "${EXTRA[@]}" -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_NAME' AND (table_name LIKE 'security\\_%' OR table_name='_prisma_migrations')")
[ "$existing" = "0" ] || { echo "restore: $DB_NAME already has $existing security tables. Restore into an empty database." >&2; exit 4; }

gzip -dc "$FILE" | "$CLIENT" "${AUTH[@]}" "${EXTRA[@]}" "$DB_NAME"

bad=0
if [ -f "$COUNTS" ]; then
  while IFS=$'\t' read -r t lo hi; do
    got=$("$CLIENT" "${AUTH[@]}" "${EXTRA[@]}" -N -B -e "SELECT COUNT(*) FROM \`$DB_NAME\`.\`$t\`")
    if [ "$got" -ge "$lo" ] && [ "$got" -le "$hi" ]; then printf 'ok    %-32s %s rows (backup range %s to %s)\n' "$t" "$got" "$lo" "$hi"; else printf 'FAIL  %-32s restored %s, backup recorded %s to %s\n' "$t" "$got" "$lo" "$hi"; bad=1; fi
  done < "$COUNTS"
else
  echo "warning: no counts file next to the backup, row counts not compared" >&2
fi
[ "$bad" = "0" ] || { echo "restore: row counts do not match the backup" >&2; exit 5; }
echo "restore ok into $DB_NAME. Next: point a copy of the API at it, sign in, then switch over (docs/DATABASE.md)."
