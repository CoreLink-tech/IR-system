# Database and migrations

The schema is applied with versioned migrations in `backend/prisma/migrations`, never with
`prisma db push`. `db push` has no history, cannot backfill data, and can drop columns without a
record. Do not run it against a database you care about.

Requirements: MySQL 8.0 or newer, or MariaDB 10.2 or newer. The tables work on older versions, but
the Stage 8 migration backfills existing rows with window functions. Only `security_*` tables are
created or changed.

## New database

    cd backend
    npx prisma migrate deploy

This applies all nine migrations in order and records them in `_prisma_migrations`.

## Existing database (created earlier with `prisma db push`)

Take a backup first (see the backup runbook when it is added in a later Stage 10 step; until then
`mysqldump --single-transaction DATABASE > before-migrations.sql` is enough).

1. Find out which migrations the database already has. This only reads:

        mysql -u USER -p DATABASE < backend/prisma/baseline/detect-stage.sql

   The output has one row per migration with `present` and `partial`. A healthy database shows a run
   of `present = 1` followed by `present = 0`. If any row shows `partial = 1`, a previous upgrade was
   interrupted: see "If a migration fails" below before going on.

2. Tell Prisma about the ones that are already there, in order, one command each:

        npx prisma migrate resolve --applied 20260101000000_init
        npx prisma migrate resolve --applied 20260101000100_stage3_event_matched_rules
        ... (every row with present = 1)

3. Apply the rest, then check:

        npx prisma migrate deploy
        npx prisma migrate status

A database that has every migration is all `present = 1`: mark all nine as applied and there is nothing to deploy.
A Stage 9 database has the first five; deploy the rest (the index migration changes no data; the sessions migration adds columns and gives every existing sign-in its own session; the two-factor migration adds columns and a table with no effect on existing rows).

## Every schema change shipped so far

| Migration | Added in | Change | Effect on existing rows |
| --- | --- | --- | --- |
| `20260101000000_init` | Stage 1 | All 11 tables | None (the starting point) |
| `20260101000100_stage3_event_matched_rules` | Stage 3 | `security_events.matchedRules` (JSON, null) | Old events keep NULL, which reports describe as "recorded before this field existed" |
| `20260101000200_stage8_unique_slots` | Stage 8 | `security_incidents.openKey` and `security_ip_blocks.activeKey`, each with a unique index | Backfilled, see below |
| `20260101000300_stage8_event_external_id` | Stage 8 | `security_events.externalId` and a unique index on (`apiKeyId`, `externalId`) | Old events keep NULL; the pair is unique only when both parts are set |
| `20260101000400_stage9_must_change_password` | Stage 9 | `security_users.mustChangePassword` (boolean, default false) | Everyone starts as false |
| `20260101000500_stage10_indexes` | Stage 10 | Index review: five composite event indexes and one audit index added, seven single-column or duplicate indexes dropped | None. Indexes only, see "Index review" |
| `20260101000600_stage10_sessions_and_token_version` | Stage 10 | `security_users.tokenVersion` (default 0) and `passwordChangedAt`; `security_refresh_tokens.sessionId`, `sessionStartedAt`, `lastUsedAt`, `deviceLabel`, `revokedReason` and an index on `sessionId` | Each existing sign-in becomes its own session (started when it was created). Existing accounts start at version 0, so nobody is signed out |
| `20260101000700_stage10_login_throttle` | Stage 10 | New table `security_login_throttle` (failed sign-in counters per hashed email) | None. Starts empty. Old rows are removed by the cleanup job |
| `20260101000800_stage10_two_factor` | Stage 10 | `security_users.totpSecret`, `totpEnabledAt`, `totpLastStep`; new table `security_recovery_codes` (hashed codes only, cascade on user delete) | None. Existing accounts have two-step off. Retention does not touch recovery codes; they cascade with their user |

### How existing rows are backfilled (Stage 8)

The application keeps at most one open incident per slot (`ip:<address>`, `acct:<user>:<rule>` or
`glob:<rule>`) and at most one active block per address, and the unique indexes enforce it. A database
from before Stage 8 has neither key, so the migration fills them in:

- Open incidents (status OPEN or INVESTIGATING): the most recently updated incident for a slot takes it.
  If an old database already held several for one slot, the others stay open but do not take new
  events, which is the same state the application itself produces for a quiet incident. Nothing is
  closed, reopened or deleted.
- Active blocks: if several are active for one address, the strongest takes the slot (permanent, then
  the latest expiry, then the newest). The others stay active, so the address stays blocked exactly as
  before. Inactive blocks hold no slot.

To see which rows ended up without a slot after the migration:

    SELECT id, incidentId, sourceIp, status FROM security_incidents
      WHERE status IN ('OPEN','INVESTIGATING') AND openKey IS NULL;
    SELECT id, ipAddress, isPermanent, expiresAt FROM security_ip_blocks
      WHERE active = 1 AND activeKey IS NULL;

## If a migration fails

MySQL and MariaDB do not roll back schema changes, so a failed migration can leave part of its work in
place. Run `detect-stage.sql` again: a row with `partial = 1` names the migration. Either finish the
missing parts by hand (the SQL is in the migration file) or undo the parts that did apply, then run
`npx prisma migrate resolve --rolled-back <name>` and `npx prisma migrate deploy` again. If you
finished it by hand, run `npx prisma migrate resolve --applied <name>` instead.

## Writing a new migration

1. Edit `prisma/schema.prisma`.
2. With the Prisma schema engine available: `npx prisma migrate dev --create-only --name what_changed`,
   read the SQL it wrote, and add a backfill if existing rows need one.
3. Without it (some environments cannot download the engine): write the SQL by hand in a new directory
   named `YYYYMMDDHHMMSS_what_changed` that sorts after the last one, in the same style as the others.
   `node scripts/schema-to-ddl.mjs` prints the DDL the schema implies, to copy from.
4. Run the proof against a scratch server (it drops three databases named `ir_migtest_*`):

        MIGRATION_TEST_CONFIRM=yes MIGRATION_TEST_CLI="mysql -uroot -pSECRET -h127.0.0.1" \
          npm run verify:migrations

   It checks that all migrations together produce exactly the schema, that a Stage 1 database filled
   with awkward data upgrades without losing or closing anything, and that stage detection works.
5. `npm test` also runs `test/migrations-static.spec.ts`, which fails if a table, column or index in the
   schema appears in no migration. Migrations that drop tables or columns are refused by that test; a
   deliberate destructive change needs its own reviewed exception.

## What has and has not been verified

Verified, on MariaDB 10.11 with the SQL applied by the `mariadb` client: the five migrations build a
database identical to the schema (200 facts compared: tables, columns, types, defaults, collations,
indexes, foreign keys); a Stage 1 database with duplicate open incidents, duplicate active blocks and
existing events and users upgrades with nothing lost, closed or reopened; the unique indexes then hold;
stage detection is right at each of the five levels, for an interrupted upgrade and for an empty database.
The scripts fail when a migration is broken (checked by removing an index and by removing the backfill).

Not verified: `prisma migrate deploy` and `prisma migrate resolve` themselves (the Prisma schema engine
could not be downloaded where this was built, so the SQL was applied directly); MySQL 8 (only MariaDB was
available). To check both on your own server, with a scratch database as the shadow database:

    npx prisma migrate diff --from-migrations prisma/migrations \
      --to-schema-datamodel prisma/schema.prisma \
      --shadow-database-url "mysql://USER:PASS@HOST:3306/shadow_scratch" --exit-code

Exit code 0 means Prisma itself agrees the migrations equal the schema. Then run the "New database"
steps against another scratch database.

## Index review (Stage 10)

Method: `scripts/index-review.mjs` builds a deterministic dataset and runs 62 query shapes copied from the
application's services. The dataset has 660,000 events (60 days of ordinary traffic, one attacker address with
40,000 events over three days attached to one incident, and a distributed attack of 20,000 failed sign-ins from
4,000 addresses in the last 10 minutes), 30,000 incidents, 150,000 audit rows, 60,000 addresses and 30,000
blocks. Rows read and times come from `ANALYZE FORMAT=JSON` on MariaDB 10.11, best of three warm runs, on a
single-CPU sandbox. They are relative evidence about the plans, not a capacity claim (Workstream 7 measures
capacity).

What was wrong: the event table had only single-column indexes. For "this address (or account, incident, type)
within a time window", which runs on every incoming event, the optimizer picked the time index or the address
index and read tens of thousands of rows. The attacker address is the worst case and the one that matters: an
attacker who sends more events makes every later event of theirs more expensive to process (an amplification an
attacker could use against ingestion).

What changed (migration `20260101000500_stage10_indexes`): each single-column index that these lookups used is
replaced by a composite that starts with the same column and ends with the time the window or sort uses
(`ipAddress, occurredAt`; `eventType, occurredAt`; `userId, eventType, occurredAt`; `incidentId, occurredAt`;
`severity, occurredAt`), plus `security_audit_logs (targetId, createdAt)`. The unused `riskLevel` event index and
the duplicate `security_api_keys.keyPrefix` index (the column is already unique) are dropped. The events table
goes from nine indexes to eight.

Queries that changed by more than a factor of 1.6 (all others were within noise):

| Query | Index used before | Rows read | ms | Index used after | Rows read | ms |
|---|---|---:|---:|---|---:|---:|
| ingest: failed sign-ins from one address, last 10 min (attacker) | `occurredAt` | 20,174 | 24.0 | `ipAddress_occurredAt` | 99 | 0.2 |
| ingest: all events from one address, last 10 min (attacker) | `occurredAt` | 20,174 | 23.7 | `ipAddress_occurredAt` | 99 | 0.0 |
| ingest: distinct accounts failed from one address (attacker) | `occurredAt` | 20,174 | 24.8 | `ipAddress_occurredAt` | 99 | 0.2 |
| ingest: password resets from one address | `eventType` | 6,000 | 10.2 | `eventType_occurredAt` | 0 | 0.0 |
| ingest: highest risk from one address, last 24 h (attacker) | `ipAddress` | 40,000 | 46.3 | `ipAddress_occurredAt` | 14,071 | 18.1 |
| events list: filter severity=CRITICAL, newest first | `occurredAt` | 24,651 | 30.3 | `severity_occurredAt` | 20 | 0.1 |
| events list: filter address (attacker), newest first | `occurredAt` | 4,047 | 5.1 | `ipAddress_occurredAt` | 20 | 0.1 |
| incidents: events of the big incident, newest 200 | `occurredAt` | 20,353 | 23.6 | `incidentId_occurredAt` | 200 | 0.3 |
| reports: attacker incident: events in range (count, min, max) | `ipAddress` | 40,000 | 47.0 | `ipAddress_occurredAt` | 40,000 | 9.1 |
| reports: sign-ins that succeeded in the last 30 days | `eventType` | 64,000 | 93.9 | `eventType_occurredAt` | 36,400 | 7.8 |
| audit: one target (type + id), newest first | `createdAt` | 150,000 | 166.4 | `targetId_createdAt` | 8 | 0.0 |

Cost of the change, measured: inserting 300,000 events took 4.7 to 4.8 s with the old index set and 4.5 to 4.7 s with
the new one (one index fewer). The events indexes grow from 61 MB to 69 MB at this size (+13%). A covering variant
(`eventType, occurredAt, ipAddress`) cost about 8% more on writes, was not chosen by the optimizer for the grouping
query it was meant to help, and was not adopted.

Known limits found by the review, not fixed here (each has a Workstream that owns it):

- The distributed-attack rule reads every failed sign-in in its 10 minute window (about 20,000 rows, 35 ms) for each
  failed sign-in that arrives during such an attack. It is the same 34 to 38 ms before and after. At a high failed
  sign-in rate this is the first thing to saturate. Workstream 7 measures it; the likely fix is to evaluate that rule
  at most once every few seconds.
- The dashboard summary runs three grouped scans of the last 24 hours (about 65 to 80 ms each at 45,000 events a day).
  This grows with event volume. Workstream 7 decides between a short cache and hourly roll-up counts.
- Sorting the event list by risk score is a full scan and sort (120 ms at 660,000 events). The other sort columns use an
  index. The page can restrict the allowed sorts if this becomes a problem.
- The audit log filter "action contains" is a substring search and cannot use an index; it is fast only while the
  log is bounded. The retention job in this Workstream keeps it bounded.
- Total counts for the event list (`COUNT(*)`, 68 ms at 660,000 rows) grow with the table.

## Retention and cleanup

Left alone, the events and audit tables grow without limit. The cleanup command removes what is past its
limit, in small batches, without stopping live traffic.

    cd backend
    npm run build                 # once per release
    npm run cleanup:dry           # prints what WOULD be affected, changes nothing
    npm run cleanup               # does it; exit code 0 = finished, 1 = a job failed or settings invalid

Schedule it nightly, outside peak hours. With cron:

    17 3 * * *  cd /srv/ir-system/backend && /usr/bin/node dist/retention/cleanup.js >> /var/log/ir-cleanup.log 2>&1

Or as a systemd timer (`/etc/systemd/system/ir-cleanup.service` and `ir-cleanup.timer`):

    [Service]
    Type=oneshot
    WorkingDirectory=/srv/ir-system/backend
    EnvironmentFile=/etc/ir-system/backend.env
    ExecStart=/usr/bin/node dist/retention/cleanup.js
    User=irsystem

    [Timer]
    OnCalendar=*-*-* 03:17:00
    Persistent=true
    [Install]
    WantedBy=timers.target

Running it more than once, or from two servers at the same time, is safe: a database lock lets one run work
and the other reports "another cleanup run holds the lock" and changes nothing. Stopping it part-way is safe
too: every batch is committed on its own, and the next run carries on.

### What is removed, and what is never removed

| Job | Removes | Default | Setting |
| --- | --- | --- | --- |
| `events` | Events older than the limit. **Events that belong to an incident that is not resolved (open, investigating, contained) are kept**, however old, because they are the evidence | 90 days | `RETENTION_EVENT_DAYS` |
| `incidents` | Resolved and false-positive incidents older than the limit, with their timeline | 730 days | `RETENTION_INCIDENT_DAYS` |
| `audit_ingest` | The audit row written for each accepted event (`event.ingest`). The event is its own record | 30 days | `RETENTION_INGEST_AUDIT_DAYS` |
| `audit_log` | All other audit entries (and any ingestion entries left) | 365 days | `RETENTION_AUDIT_DAYS` |
| `login_throttle` | Failed sign-in counters whose last failure was more than two days ago (a lock lasts at most a day) | always | none |
| `refresh_tokens` | Refresh tokens that expired more than the grace period ago. A revoked token that has not expired yet is kept, so a stolen token being replayed is still detected | 7 days after expiry | `RETENTION_TOKEN_GRACE_DAYS` |
| `expire_blocks` | Not a deletion. Temporary blocks whose time has passed are switched off, which frees their address slot. The row stays as history. Permanent blocks are never touched | always | none |
| `block_history` | Inactive blocks older than the limit | 365 days | `RETENTION_BLOCK_HISTORY_DAYS` |
| `expired_allowlist` | Allowlist entries that expired more than the grace period ago. Entries with no expiry are never removed | 7 days | `RETENTION_EXPIRED_ENTRY_DAYS` |

A limit of `0` keeps that table forever (the job is skipped). Limits below a safe floor (events 7 days, audit
30, incidents 30, block history 30, ingestion audit 7) are refused and the API will not start, so a typing
mistake cannot erase recent evidence. Other settings: `RETENTION_BATCH_SIZE` (default 5000 rows per statement,
500 for incidents), `RETENTION_PAUSE_MS` (default 200 between batches), `RETENTION_MAX_SECONDS` (default 600; the
run stops starting new batches after that and the next run continues). Each run writes an audit entry
(`retention.run`, or `retention.dry_run`) with the counts.

### Growth: how big the tables get

Measured on MariaDB 10.11 with the current indexes: an event row costs about 400 bytes (data and indexes, with
no `metadata`; rows that carry metadata are larger) and an audit row about 550 bytes. Every accepted event also
writes one audit row (`event.ingest`), so each event costs about 950 bytes in total until its audit row is
removed. Steady state at the default limits (events 90 days, ingestion audit 30 days), events plus ingestion
audit only:

| Events per second | Events per day | Events table at 90 days | Ingestion audit at 30 days | Total |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 86,400 | 3.1 GB | 1.4 GB | 4.5 GB |
| 10 | 864,000 | 31 GB | 14 GB | 45 GB |
| 50 | 4.3 million | 156 GB | 71 GB | 227 GB |
| 200 | 17.3 million | 622 GB | 285 GB | 907 GB |

Choose the event limit from your disk, not the other way round. At a sustained 10 events per second, 30 days
of events is about 10 GB. Also see the finding below: the PHP library already sends only security-relevant
events, and the audit row per event can be switched off in a later Stage 10 step if capacity testing shows it is
worth it.

### What has and has not been verified

Verified on MariaDB 10.11 (test/retention-db.spec.ts, 7 tests, plus 25 unit tests in test/retention.spec.ts):
each rule above on seeded data, including unresolved-incident evidence, revoked-but-unexpired tokens and
permanent blocks; a dry run predicts the real run exactly and changes nothing; a second run finds nothing; a run
cut short and finished by the next run ends in the same state as one run; two runs at once (one skipped);
a cleanup of about 30,000 events while a writer kept inserting (261 to 274 inserts during the run, no failures,
slowest insert 45 ms, slowest windowed read 29 ms); an expired block's address can be blocked again. Breaking
the evidence rule, the token grace or the lock makes the tests fail. The built command was run for real:
dry run, real run, invalid setting (exit 1), audit trail.

Not verified: MySQL 8 (MariaDB only); behaviour with more than about 100,000 rows past their limit in a single
run on slow disks (measured rate on the sandbox: about 8,500 events per second deleted while serving live
inserts; with a 600 second limit a backlog larger than that is simply finished by the next night's run); the
`GET_LOCK` based lock across several API servers (verified for two concurrent runs on one server).
These tests need a real database, so in the repository they are skipped unless `RETENTION_TEST_CONFIRM=yes` and
`DATABASE_URL` point at a scratch database whose name starts with `ir_`.

## Backup and restore

What a backup covers: every `security_*` table and, when it exists, Prisma's `_prisma_migrations` table, from
one database (the database may be shared with the website; only these tables are touched).

**What a backup does NOT cover, and must be kept separately:** the secrets in the API's environment file,
`JWT_SECRET`, `JWT_REFRESH_SECRET` and `API_KEY_HASH_PEPPER` (and any other secret added later). Keep a copy in
your password manager or secret store, never next to the database backups. Measured on the restored drill
database with newly generated secrets: sign-in with the password still worked (HTTP 201), but **every existing
API key was rejected (401), which stops event reporting from the website, and every existing session ended
(401)**. Losing `API_KEY_HASH_PEPPER` means issuing and distributing new API keys.

### Taking a backup

    cd backend
    DB_NAME=shop DB_USER=ir_backup MYSQL_PWD=... BACKUP_DIR=/var/backups/ir-system ./scripts/backup.sh

It is safe while the system is live (one consistent snapshot, writers are not locked). It writes
`ir-security-<time>.sql.gz`, a `.sha256` checksum and a `.counts.txt` (the lowest and highest row count of each
table around the dump), all readable by the owner only, checks the archive before it finishes, and keeps the
newest `KEEP` (default 14). Exit codes: 0 ok, 2 bad settings or tools missing, 3 no tables found, 4 archive
failed its own check. Schedule it, and also run it before every upgrade:

    5 2 * * *  cd /srv/ir-system/backend && DB_NAME=shop DB_USER=ir_backup BACKUP_DIR=/var/backups/ir-system ./scripts/backup.sh >> /var/log/ir-backup.log 2>&1

Treat the files as secrets: they hold password hashes, API key hashes and refresh token hashes. Copy them off
the server (a backup on the same disk is not a backup), encrypted first, for example
`gpg --symmetric --cipher-algo AES256 file.sql.gz`, or `age -r <recipient>`. Check the copy by running a restore
drill, not by looking at the file size.

### Restoring

Restore into a NEW, empty database, check it, and only then point the API at it. The script refuses a database
that already has security tables, refuses a backup whose checksum does not match, and compares every table's row
count to the backup's recorded range.

1. Stop the API (or leave the damaged one stopped). Create an empty database:
   `CREATE DATABASE shop_restored DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
2. `DB_NAME=shop_restored DB_USER=ir_admin MYSQL_PWD=... ./scripts/restore.sh /var/backups/ir-system/ir-security-<time>.sql.gz`
   Every table must print `ok`, and the last line must be `restore ok`.
3. Put the saved secrets back in the API's environment file and set `DATABASE_URL` to the restored database.
4. If the backup is older than the last release, run `npx prisma migrate status` and then `npx prisma migrate deploy`
   (see "Existing database" above if the backup has no `_prisma_migrations` table).
5. Start the API and check `GET /api/v1/health`, sign in to the dashboard, open the incident list, and send one test
   event with the website's API key.
6. Switch the website's reporting to it (if the API address changed) and keep the old database until you are sure.

What is lost: everything recorded after the backup's snapshot. In the drill the live system had 114 events when it
was destroyed and the restore held 55, the state at the moment of the snapshot. Back up as often as you can
afford to lose data (the recovery point is the time since the last backup). Until the website's reporting is
switched over, its events are not recorded anywhere; the PHP library queues them on disk, but only up to about
500 KB and it drops the oldest first (integration/php/README.md), so a long outage loses events.

### Restore drill (performed)

Run on MariaDB 10.11 with the built API (Prisma 6 engine-free client). Steps and results:

1. A live system with an administrator, an API key, 54 events, an automatic block on an attacking address and an
   incident. A backup was taken while 60 more events were being sent. Recorded count ranges, for example
   events 54 to 55, addresses 41 to 42.
2. The source database was dropped.
3. Refusals: a backup with one byte appended was refused (checksum mismatch, exit 3); a backup without its checksum
   file was refused (exit 2); neither created any table. A second restore into the already restored database was
   refused (exit 4).
4. The restore into an empty database passed every table's count check.
5. A copy of the API on the restored database: sign-in with the same password worked (201); a refresh token issued
   before the disaster still worked (201); a wrong password was refused (401); the old API key still worked and the
   attacker's address was still on the blocklist; the dashboard's incident list showed the incident; a new event was
   accepted with the old key (201).
6. With newly generated secrets instead of the originals: sign-in worked, but the old API key and the old refresh
   token were rejected (401 and 401).

Timing, on a 320,000 event table (119 MB with indexes) in the same sandbox: backup 4.9 s, restore and check 8.7 s,
archive 4.7 MB. The test data is synthetic and repetitive, so real archives will be larger; real data on real disks
restores more slowly. Plan the recovery time from a restore drill on your own data, and repeat the drill every
quarter and after any major upgrade.

### Not verified

A backup user with limited rights (the commands above were run with the database administrator account; the
minimum grants have not been tested); MySQL 8 and the `mysqldump` tool (MariaDB's `mariadb-dump` was used); the
gpg and age encryption commands (not run); restoring a backup that contains `_prisma_migrations` and then running
`prisma migrate status` (the drill database was built from the migration files directly); backups of more than a
few hundred megabytes.
