#!/usr/bin/env node
/**
 * Proves the migrations in prisma/migrations against a real MySQL or MariaDB server.
 *
 *   MIGRATION_TEST_CONFIRM=yes MIGRATION_TEST_CLI="mysql -uroot -psecret -h127.0.0.1" \
 *     node scripts/verify-migrations.mjs
 *
 * It creates and DROPS three scratch databases named ir_migtest_fresh, ir_migtest_schema and
 * ir_migtest_upgrade. It never touches any other database. Checks:
 *
 *   1. Fresh: applying every migration in order gives the same tables, columns, indexes and foreign
 *      keys as the DDL derived from prisma/schema.prisma (column order is ignored, as Prisma does).
 *   2. Upgrade: a database built from the Stage 1 schema and filled with awkward data (duplicate open
 *      incidents, duplicate active blocks, existing events and users) is upgraded by the later
 *      migrations. No row is lost or closed, the backfill picks the documented winners, and the new
 *      unique indexes then hold.
 *
 * This script applies the SQL files directly with the database client. It does NOT run
 * "prisma migrate deploy" (that needs the Prisma schema engine). See docs/DATABASE.md.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { schemaToDdl } from './schema-to-ddl.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '../prisma/migrations');
const schemaPath = join(here, '../prisma/schema.prisma');
const DBS = { fresh: 'ir_migtest_fresh', schema: 'ir_migtest_schema', upgrade: 'ir_migtest_upgrade' };

if (process.env.MIGRATION_TEST_CONFIRM !== 'yes') {
  console.error('Refusing to run: this drops the databases ir_migtest_fresh, ir_migtest_schema and ir_migtest_upgrade.\nSet MIGRATION_TEST_CONFIRM=yes to continue.');
  process.exit(2);
}
const CLI = process.env.MIGRATION_TEST_CLI || 'mysql -uroot';

function sql(text, db) {
  const r = spawnSync(`${CLI} ${db ? db : ''} --batch --raw -N`, { input: text, shell: true, encoding: 'utf8', maxBuffer: 1 << 26 });
  if (r.status !== 0) throw new Error(`SQL failed${db ? ` on ${db}` : ''}: ${r.stderr.trim()}\n--- statement ---\n${text.slice(0, 600)}`);
  return r.stdout;
}
const rows = (text, db) => sql(text, db).split('\n').filter(Boolean).map((l) => l.split('\t'));
function reset(db) { sql(`DROP DATABASE IF EXISTS \`${db}\`; CREATE DATABASE \`${db}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`); }

const migrations = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
const apply = (db, names) => names.forEach((n) => sql(readFileSync(join(migrationsDir, n, 'migration.sql'), 'utf8'), db));

function describeDb(db) {
  const q = (s) => rows(s.replaceAll('@@DB', `'${db}'`));
  const out = [];
  q("SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA=@@DB AND TABLE_TYPE='BASE TABLE' ORDER BY 1").forEach((r) => out.push(`table ${r[0]} collation=${r[1]}`));
  q("SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, IFNULL(COLUMN_DEFAULT,'<none>'), IFNULL(COLLATION_NAME,'-'), EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@@DB ORDER BY 1,2")
    .forEach((r) => out.push(`column ${r[0]}.${r[1]} type=${r[2]} null=${r[3]} default=${r[4]} collation=${r[5]} extra=${r[6]}`));
  q("SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@@DB GROUP BY 1,2,3 ORDER BY 1,2")
    .forEach((r) => out.push(`index ${r[0]}.${r[1]} unique=${r[2] === '0'} columns=${r[3]}`));
  q("SELECT k.TABLE_NAME, k.CONSTRAINT_NAME, GROUP_CONCAT(k.COLUMN_NAME ORDER BY k.ORDINAL_POSITION), k.REFERENCED_TABLE_NAME, GROUP_CONCAT(k.REFERENCED_COLUMN_NAME ORDER BY k.ORDINAL_POSITION), c.DELETE_RULE, c.UPDATE_RULE FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=k.TABLE_SCHEMA AND c.CONSTRAINT_NAME=k.CONSTRAINT_NAME WHERE k.TABLE_SCHEMA=@@DB AND k.REFERENCED_TABLE_NAME IS NOT NULL GROUP BY 1,2,4,6,7 ORDER BY 1,2")
    .forEach((r) => out.push(`foreign_key ${r[0]}.${r[1]} (${r[2]}) -> ${r[3]}(${r[4]}) delete=${r[5]} update=${r[6]}`));
  return out;
}

let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${ok ? '' : ` ${detail}`}`); if (!ok) failures++; };

// ------------------------------------------------------------------ 1. fresh install equals the schema
console.log('1. Fresh install: all migrations vs schema.prisma');
reset(DBS.fresh); reset(DBS.schema);
apply(DBS.fresh, migrations);
sql(schemaToDdl(readFileSync(schemaPath, 'utf8')), DBS.schema);
const a = describeDb(DBS.fresh); const b = describeDb(DBS.schema);
const onlyA = a.filter((x) => !b.includes(x)); const onlyB = b.filter((x) => !a.includes(x));
check(`${a.length} schema facts compared (tables, columns, indexes, foreign keys)`, onlyA.length === 0 && onlyB.length === 0,
  `\n  only in migrations:\n    ${onlyA.join('\n    ')}\n  only in schema.prisma:\n    ${onlyB.join('\n    ')}`);

// ------------------------------------------------------------------ 2. upgrade from Stage 1 with awkward data
console.log('2. Upgrade: Stage 1 database with existing data');
reset(DBS.upgrade);
apply(DBS.upgrade, [migrations[0]]);
const inc = (id, ip, user, rule, status, updated) =>
  `INSERT INTO security_incidents (id, incidentId, title, description, severity, riskScore, status, sourceIp, userId, detectionRule, updatedAt) VALUES ('${id}','INC-${id}','t','d','HIGH',50,'${status}',${ip ? `'${ip}'` : 'NULL'},${user ? `'${user}'` : 'NULL'},${rule ? `'${rule}'` : 'NULL'},'${updated}');`;
const blk = (id, ip, active, perm, expires, created) =>
  `INSERT INTO security_ip_blocks (id, ipAddress, action, reason, isPermanent, expiresAt, active, createdAt, updatedAt) VALUES ('${id}','${ip}','BLOCK','r',${perm},${expires ? `'${expires}'` : 'NULL'},${active},'${created}','${created}');`;
sql([
  "INSERT INTO security_users (id, email, passwordHash, role, updatedAt) VALUES ('u1','a@pishon.ng','x','SECURITY_ADMIN',NOW(3));",
  // three open incidents for one address (the newest, i3, must win the slot), plus a resolved one
  inc('i1', '203.0.113.9', null, 'R_IP', 'OPEN', '2026-01-01 10:00:00'),
  inc('i2', '203.0.113.9', null, 'R_IP', 'INVESTIGATING', '2026-01-01 11:00:00'),
  inc('i3', '203.0.113.9', null, 'R_IP', 'OPEN', '2026-01-01 12:00:00'),
  inc('i4', '203.0.113.9', null, 'R_IP', 'RESOLVED', '2026-01-01 13:00:00'),
  inc('i5', null, 'u1', 'R_ACCT', 'OPEN', '2026-01-01 10:00:00'),
  inc('i6', null, null, 'R_GLOBAL', 'INVESTIGATING', '2026-01-01 10:00:00'),
  inc('i7', null, null, null, 'OPEN', '2026-01-01 10:00:00'),
  inc('i8', '203.0.113.20', null, 'R_IP', 'CONTAINED', '2026-01-01 10:00:00'),
  // blocks: a permanent one beats a temporary one; later expiry beats earlier; inactive holds nothing
  blk('b1', '198.51.100.1', 1, 0, '2030-01-01 00:00:00', '2026-01-01 10:00:00'),
  blk('b2', '198.51.100.1', 1, 1, null, '2025-01-01 10:00:00'),
  blk('b3', '198.51.100.1', 1, 0, '2027-01-01 00:00:00', '2026-02-01 10:00:00'),
  blk('b4', '198.51.100.2', 1, 0, '2026-06-01 00:00:00', '2026-01-01 10:00:00'),
  blk('b5', '198.51.100.2', 1, 0, '2026-09-01 00:00:00', '2026-01-02 10:00:00'),
  blk('b6', '198.51.100.3', 0, 0, '2026-09-01 00:00:00', '2026-01-02 10:00:00'),
  blk('b7', '198.51.100.4', 1, 0, '2026-09-01 00:00:00', '2026-01-02 10:00:00'),
  "INSERT INTO security_events (id, eventType, severity, ipAddress, occurredAt, apiKeyId) VALUES ('e1','LOGIN_FAILED','LOW','203.0.113.9',NOW(3),'k1'),('e2','LOGIN_FAILED','LOW','203.0.113.9',NOW(3),'k1');",
].join('\n'), DBS.upgrade);

const count = (t, w = '1=1') => Number(rows(`SELECT COUNT(*) FROM ${t} WHERE ${w}`, DBS.upgrade)[0][0]);
const before = { inc: count('security_incidents'), blk: count('security_ip_blocks'), act: count('security_ip_blocks', 'active=1'), ev: count('security_events'), us: count('security_users') };
const statusesBefore = rows('SELECT id, status FROM security_incidents ORDER BY id', DBS.upgrade).join('|');

apply(DBS.upgrade, migrations.slice(1));

check('no incident, block, event or user was lost', count('security_incidents') === before.inc && count('security_ip_blocks') === before.blk && count('security_events') === before.ev && count('security_users') === before.us);
check('no incident status changed (nothing closed or reopened)', rows('SELECT id, status FROM security_incidents ORDER BY id', DBS.upgrade).join('|') === statusesBefore);
check('no block was activated or deactivated', count('security_ip_blocks', 'active=1') === before.act);
const slots = Object.fromEntries(rows('SELECT id, IFNULL(openKey,"<null>") FROM security_incidents', DBS.upgrade));
check('newest open incident takes the address slot', slots.i3 === 'ip:203.0.113.9', JSON.stringify(slots));
check('older duplicates stay open without a slot', slots.i1 === '<null>' && slots.i2 === '<null>');
check('resolved and contained incidents hold no slot', slots.i4 === '<null>' && slots.i8 === '<null>');
check('account and platform-wide slots are named as the application names them', slots.i5 === 'acct:u1:R_ACCT' && slots.i6 === 'glob:R_GLOBAL' && slots.i7 === 'glob:');
const keys = Object.fromEntries(rows('SELECT id, IFNULL(activeKey,"<null>") FROM security_ip_blocks', DBS.upgrade));
check('a permanent block outranks temporary ones for the same address', keys.b2 === '198.51.100.1' && keys.b1 === '<null>' && keys.b3 === '<null>', JSON.stringify(keys));
check('the later expiry wins between two temporary blocks', keys.b5 === '198.51.100.2' && keys.b4 === '<null>');
check('an inactive block holds no slot; a single active block holds its address', keys.b6 === '<null>' && keys.b7 === '198.51.100.4');
check('existing events: matchedRules and externalId are NULL, repeats with no externalId are allowed', rows('SELECT COUNT(*) FROM security_events WHERE matchedRules IS NULL AND externalId IS NULL', DBS.upgrade)[0][0] === '2');
check('existing users do not have to change their password', rows("SELECT mustChangePassword FROM security_users WHERE id='u1'", DBS.upgrade)[0][0] === '0');

const refuses = (stmt) => { try { sql(stmt, DBS.upgrade); return false; } catch (e) { return /Duplicate entry/i.test(String(e)); } };
check('a second open incident for the same address is now refused by the database', refuses("INSERT INTO security_incidents (id, incidentId, title, description, severity, riskScore, status, sourceIp, detectionRule, openKey, updatedAt) VALUES ('i9','INC-i9','t','d','HIGH',50,'OPEN','203.0.113.9','R_IP','ip:203.0.113.9',NOW(3));"));
check('a second active block for the same address is now refused', refuses("INSERT INTO security_ip_blocks (id, ipAddress, action, reason, isPermanent, active, activeKey, updatedAt) VALUES ('b9','198.51.100.4','BLOCK','r',0,1,'198.51.100.4',NOW(3));"));
check('a repeated delivery (same key and externalId) is refused', refuses("INSERT INTO security_events (id, eventType, severity, occurredAt, apiKeyId, externalId) VALUES ('e3','X','LOW',NOW(3),'k1','dup'),('e4','X','LOW',NOW(3),'k1','dup');"));

// The upgraded database must also equal the schema.
const c = describeDb(DBS.upgrade);
const diffU = [...c.filter((x) => !b.includes(x)), ...b.filter((x) => !c.includes(x))];
check('the upgraded database equals the schema (tables, columns, indexes, foreign keys)', diffU.length === 0, `\n    ${diffU.join('\n    ')}`);

// ------------------------------------------------------------------ 3. stage detection for databases made with "db push"
console.log('3. Stage detection (prisma/baseline/detect-stage.sql)');
const detectSql = readFileSync(join(here, '../prisma/baseline/detect-stage.sql'), 'utf8');
const detect = (db) => rows(detectSql, db).map((r) => `${r[1]}${r[2]}`).join(',');
for (let k = 1; k <= migrations.length; k++) {
  reset(DBS.fresh);
  apply(DBS.fresh, migrations.slice(0, k));
  const expected = migrations.map((_, i) => (i < k ? '10' : '00')).join(',');
  check(`database at migration ${k} of ${migrations.length} is detected as such`, detect(DBS.fresh) === expected, `got ${detect(DBS.fresh)} expected ${expected}`);
}
reset(DBS.fresh);
apply(DBS.fresh, migrations.slice(0, 2));
sql('ALTER TABLE security_incidents ADD COLUMN openKey VARCHAR(191) NULL;', DBS.fresh);
check('an interrupted upgrade (one of four parts present) is reported as partial', detect(DBS.fresh).split(',')[2] === '01', detect(DBS.fresh));
reset(DBS.fresh);
apply(DBS.fresh, migrations.slice(0, 5));
sql('CREATE INDEX security_events_ipAddress_occurredAt_idx ON security_events(ipAddress, occurredAt);', DBS.fresh);
check('an interrupted index migration (new index made, old ones not yet dropped) is reported as partial', detect(DBS.fresh).split(',')[5] === '01', detect(DBS.fresh));
reset(DBS.fresh);
check('an empty database is reported as having nothing', detect(DBS.fresh) === migrations.map(() => '00').join(','));

Object.values(DBS).forEach((d) => sql(`DROP DATABASE IF EXISTS \`${d}\``));
console.log(failures === 0 ? '\nAll migration checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
