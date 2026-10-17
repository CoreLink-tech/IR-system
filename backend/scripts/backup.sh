#!/usr/bin/env bash
# Backs up the security_* tables (and Prisma's migration record) of one database. Safe to run while the
# system is live: it takes a consistent snapshot without locking writers.
#
#   DB_NAME=shop DB_USER=ir_backup BACKUP_DIR=/var/backups/ir-system ./scripts/backup.sh
#
# Settings (environment):
#   DB_NAME (required)  DB_USER  DB_HOST (default 127.0.0.1)  DB_PORT (default 3306)
#   MYSQL_PWD           the password. Never put it on the command line.
#   BACKUP_DIR          where to write (default ./backups). Created with mode 700.
#   KEEP                how many backups to keep (default 14). Older ones are deleted.
#   MYSQL_EXTRA_ARGS    extra client arguments, for example --socket=/run/mysqld/mysqld.sock
#
# Writes three files, readable only by the owner:
#   ir-security-YYYYmmdd-HHMMSS.sql.gz         the backup
#   ir-security-YYYYmmdd-HHMMSS.sql.gz.sha256  its checksum
#   ir-security-YYYYmmdd-HHMMSS.counts.txt     for every table, the lowest and highest row count seen around the dump
#
# The backup contains password hashes, API key hashes and refresh token hashes. Treat it as a secret:
# keep it off shared storage and encrypt it before it leaves the server (see docs/DATABASE.md).
# Exit codes: 0 ok, 2 bad settings or missing tools, 3 no tables found, 4 the archive failed its own check.
set -euo pipefail
umask 077

: "${DB_NAME:?Set DB_NAME to the database that holds the security_* tables}"
DB_HOST="${DB_HOST:-127.0.0.1}"; DB_PORT="${DB_PORT:-3306}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"; KEEP="${KEEP:-14}"
EXTRA=(${MYSQL_EXTRA_ARGS:-})
AUTH=(-h "$DB_HOST" -P "$DB_PORT"); if [ -n "${DB_USER:-}" ]; then AUTH+=(-u "$DB_USER"); fi
CLIENT=$(command -v mariadb || command -v mysql || true)
DUMP=$(command -v mariadb-dump || command -v mysqldump || true)
if [ -z "$CLIENT" ] || [ -z "$DUMP" ]; then echo "backup: the mysql or mariadb client and dump tools are required" >&2; exit 2; fi
if ! [[ "$KEEP" =~ ^[0-9]+$ ]] || [ "$KEEP" -lt 1 ]; then echo "backup: KEEP must be a whole number of at least 1" >&2; exit 2; fi

mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
BASE="$BACKUP_DIR/ir-security-$(date +%Y%m%d-%H%M%S)"
sql() { "$CLIENT" "${AUTH[@]}" "${EXTRA[@]}" -N -B -e "$1"; }

# Only this system's tables: the database may be shared with the website.
mapfile -t TABLES < <(sql "SELECT table_name FROM information_schema.tables WHERE table_schema='$DB_NAME' AND (table_name LIKE 'security\\_%' OR table_name='_prisma_migrations') ORDER BY table_name")
if [ "${#TABLES[@]}" -eq 0 ]; then echo "backup: no security_* tables found in $DB_NAME" >&2; exit 3; fi

# Row counts just before and just after the dump. The dump is one consistent snapshot taken in between,
# so on a system that keeps receiving events each table's restored count must fall inside the recorded
# range. restore.sh checks exactly that.
count_all() { local t; for t in "${TABLES[@]}"; do printf '%s\t%s\n' "$t" "$(sql "SELECT COUNT(*) FROM \`$DB_NAME\`.\`$t\`")"; done; }
count_all > "$BASE.counts.before"

"$DUMP" "${AUTH[@]}" "${EXTRA[@]}" --single-transaction --quick --default-character-set=utf8mb4 --no-tablespaces --skip-lock-tables "$DB_NAME" "${TABLES[@]}" | gzip -9 > "$BASE.sql.gz"
# The archive must be readable end to end and contain every table, or it is thrown away.
if ! gzip -t "$BASE.sql.gz" || [ "$(gzip -dc "$BASE.sql.gz" | grep -c '^CREATE TABLE')" -ne "${#TABLES[@]}" ]; then
  echo "backup: the archive is damaged or incomplete, discarded" >&2; rm -f "$BASE.sql.gz" "$BASE.counts.before"; exit 4
fi

count_all > "$BASE.counts.after"
paste "$BASE.counts.before" "$BASE.counts.after" | awk -F'\t' '{lo=($2+0<$4+0)?$2:$4; hi=($2+0<$4+0)?$4:$2; printf "%s\t%s\t%s\n", $1, lo, hi}' > "$BASE.counts.txt"
rm -f "$BASE.counts.before" "$BASE.counts.after"
( cd "$BACKUP_DIR" && sha256sum "$(basename "$BASE").sql.gz" > "$(basename "$BASE").sql.gz.sha256" )

# Keep the newest KEEP backups.
ls -1 "$BACKUP_DIR"/ir-security-*.sql.gz 2>/dev/null | sort | head -n -"$KEEP" | while read -r old; do rm -f "$old" "$old.sha256" "${old%.sql.gz}.counts.txt"; done

echo "backup ok: $BASE.sql.gz ($(du -h "$BASE.sql.gz" | cut -f1), ${#TABLES[@]} tables)"
