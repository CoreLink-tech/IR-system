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

This applies all five migrations in order and records them in `_prisma_migrations`.

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

A database from the current stage (Stage 9) is all `present = 1`: mark all five as applied and
there is nothing to deploy.

## Every schema change shipped so far

| Migration | Added in | Change | Effect on existing rows |
| --- | --- | --- | --- |
| `20260101000000_init` | Stage 1 | All 11 tables | None (the starting point) |
| `20260101000100_stage3_event_matched_rules` | Stage 3 | `security_events.matchedRules` (JSON, null) | Old events keep NULL, which reports describe as "recorded before this field existed" |
| `20260101000200_stage8_unique_slots` | Stage 8 | `security_incidents.openKey` and `security_ip_blocks.activeKey`, each with a unique index | Backfilled, see below |
| `20260101000300_stage8_event_external_id` | Stage 8 | `security_events.externalId` and a unique index on (`apiKeyId`, `externalId`) | Old events keep NULL; the pair is unique only when both parts are set |
| `20260101000400_stage9_must_change_password` | Stage 9 | `security_users.mustChangePassword` (boolean, default false) | Everyone starts as false |

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
