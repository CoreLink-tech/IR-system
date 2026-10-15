#!/usr/bin/env node
/**
 * Measures the application's real query shapes on a realistic dataset, so index changes are
 * decided by evidence (index used, rows read, time) and not by guesswork.
 *
 *   MIGRATION_TEST_CONFIRM=yes MIGRATION_TEST_CLI="mysql -uroot -pSECRET -h127.0.0.1" \
 *     node scripts/index-review.mjs [--scale 1]
 *
 * It creates and DROPS one scratch database, ir_idxtest. Steps:
 *   1. apply every migration EXCEPT those whose directory name ends in "_indexes" (the candidates);
 *   2. load a dataset (scale 1 = about 660,000 events, 30,000 incidents, 150,000 audit rows,
 *      60,000 addresses, 30,000 blocks), including one attacker address with 40,000 events and one
 *      distributed attack of 20,000 failed sign-ins in the last 10 minutes;
 *   3. run every query shape and record the index used, rows read and time ("before");
 *   4. apply the candidate "_indexes" migrations and run the same queries again ("after").
 *
 * Times come from ANALYZE FORMAT=JSON (MariaDB), best of 3 warm runs. They are relative evidence from
 * the machine this ran on, not a capacity claim.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '../prisma/migrations');
const DB = 'ir_idxtest';
if (process.env.MIGRATION_TEST_CONFIRM !== 'yes') { console.error('Set MIGRATION_TEST_CONFIRM=yes (this drops the database ir_idxtest).'); process.exit(2); }
const CLI = process.env.MIGRATION_TEST_CLI || 'mysql -uroot';
const SCALE = Number((process.argv.includes('--scale') ? process.argv[process.argv.indexOf('--scale') + 1] : 1)) || 1;

function sql(text, db) {
  const r = spawnSync(`${CLI} ${db || ''} --batch --raw -N`, { input: text, shell: true, encoding: 'utf8', maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error(`SQL failed: ${r.stderr.trim()}\n${text.slice(0, 400)}`);
  return r.stdout;
}
const names = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
const base = names.filter((n) => !n.endsWith('_indexes'));
const candidates = names.filter((n) => n.endsWith('_indexes'));
const apply = (list) => list.forEach((n) => sql(readFileSync(join(migrationsDir, n, 'migration.sql'), 'utf8'), DB));

// A deterministic address from a number, e.g. 203.0.1.44. No randomness: the dataset is the same every run.
const ip = (n) => `CONCAT('203.', (${n}) DIV 65536 MOD 256, '.', (${n}) DIV 256 MOD 256, '.', (${n}) MOD 256)`;
const N_EV = 600000 * SCALE, N_INC = 30000 * SCALE, N_AUD = 150000 * SCALE, N_IPS = 60000 * SCALE, N_BLK = 30000 * SCALE;
const ATTACKER = '198.51.100.77';

function load() {
  const t0 = Date.now();
  sql(`SET unique_checks=0, foreign_key_checks=0;
INSERT INTO security_users (id, email, passwordHash, role, updatedAt) VALUES ('u-admin','admin@pishon.ng','x','SECURITY_ADMIN',NOW(3));
INSERT INTO security_incidents (id, incidentId, title, description, severity, riskScore, status, sourceIp, detectionRule, openKey, createdAt, updatedAt)
SELECT CONCAT('inc', seq), CONCAT('INC-20260101-', LPAD(seq, 7, '0')), 'Repeated failed sign-ins', 'd',
  ELT(1 + seq MOD 4, 'LOW','MEDIUM','HIGH','CRITICAL'), (seq*7) MOD 100,
  CASE WHEN seq MOD 100 < 4 THEN 'OPEN' WHEN seq MOD 100 < 6 THEN 'INVESTIGATING' WHEN seq MOD 100 < 16 THEN 'FALSE_POSITIVE' ELSE 'RESOLVED' END,
  ${ip('(seq*2) MOD 60000')}, 'brute_force',
  CASE WHEN seq MOD 100 < 4 THEN CONCAT('ip:', ${ip('(seq*2) MOD 60000')}) ELSE NULL END,
  NOW(3) - INTERVAL (${N_INC} - seq) * 170 SECOND, NOW(3) - INTERVAL (${N_INC} - seq) * 170 SECOND
FROM seq_1_to_${N_INC};
INSERT INTO security_ips (id, ipAddress, firstSeenAt, lastSeenAt, requestCount, eventCount, riskScore, riskLevel, country)
SELECT CONCAT('ip', seq), ${ip('seq')}, NOW(3) - INTERVAL (seq MOD 5000) HOUR, NOW(3) - INTERVAL ((seq*7919) MOD 86400) MINUTE, seq MOD 900, seq MOD 90, (seq*13) MOD 100,
  CASE WHEN seq MOD 200 = 0 THEN 'CRITICAL' WHEN seq MOD 100 = 1 THEN 'HIGH' WHEN seq MOD 20 = 2 THEN 'ELEVATED' ELSE 'NORMAL' END,
  ELT(1 + seq MOD 40, 'NG','US','GB','GH','ZA','KE','IN','DE','FR','CN','BR','CA','AU','JP','RU','NL','ES','IT','SE','PL','TR','EG','MA','AE','SA','PK','ID','MX','AR','CO','CL','PE','VN','TH','PH','MY','SG','KR','UA','RO')
FROM seq_1_to_${N_IPS};
INSERT INTO security_ip_blocks (id, ipAddress, action, reason, isPermanent, expiresAt, active, automatic, activeKey, createdAt, updatedAt)
SELECT CONCAT('blk', seq), ${ip('(seq*2) MOD 60000')}, 'BLOCK', 'r', seq MOD 50 = 0,
  CASE WHEN seq MOD 50 = 0 THEN NULL ELSE NOW(3) + INTERVAL (CAST(seq MOD 7 AS SIGNED) - 3) HOUR END,
  seq MOD 20 = 0, seq MOD 3 = 0, CASE WHEN seq MOD 20 = 0 THEN ${ip('(seq*2) MOD 60000')} ELSE NULL END,
  NOW(3) - INTERVAL (${N_BLK} - seq) * 170 SECOND, NOW(3) - INTERVAL (${N_BLK} - seq) * 170 SECOND
FROM seq_1_to_${N_BLK};
INSERT INTO security_audit_logs (id, requestId, actorType, actorId, action, targetType, targetId, result, ipAddress, createdAt)
SELECT CONCAT('aud', seq), CONCAT('req-', seq), ELT(1 + seq MOD 3, 'USER','API_KEY','SYSTEM'), CONCAT('actor', seq MOD 200),
  ELT(1 + seq MOD 12, 'auth.login','auth.logout','auth.refresh','incident.status','ip.block','ip.unblock','event.ingest','api_key.create','rule.update','user.create','report.view','note.update'),
  ELT(1 + seq MOD 4, 'incident','ip','user','rule'), CONCAT('t', (seq*7) MOD 20000), CASE WHEN seq MOD 10 = 0 THEN 'FAILURE' ELSE 'SUCCESS' END,
  ${ip('(seq*31) MOD 60000')}, NOW(3) - INTERVAL (${N_AUD} - seq) * 34 SECOND
FROM seq_1_to_${N_AUD};
`, DB);
  // Events in chunks so no single transaction is huge. Ordinary traffic spread over 60 days.
  const chunk = 100000;
  for (let from = 1; from <= N_EV; from += chunk) {
    const to = Math.min(N_EV, from + chunk - 1);
    sql(`SET unique_checks=0, foreign_key_checks=0;
INSERT INTO security_events (id, eventType, severity, ipAddress, userId, requestMethod, requestPath, externalId, riskScore, riskLevel, occurredAt, apiKeyId, incidentId)
SELECT CONCAT('ev', seq),
  CASE WHEN (seq*37) MOD 100 < 8 THEN 'login_failed' WHEN (seq*37) MOD 100 < 18 THEN 'login_success' WHEN (seq*37) MOD 100 < 19 THEN 'password_reset'
       WHEN (seq*37) MOD 100 < 40 THEN 'checkout' WHEN (seq*37) MOD 100 < 70 THEN 'page_view' ELSE 'api_request' END,
  CASE WHEN (seq*11) MOD 100 < 70 THEN 'INFO' WHEN (seq*11) MOD 100 < 85 THEN 'LOW' WHEN (seq*11) MOD 100 < 94 THEN 'MEDIUM' WHEN (seq*11) MOD 100 < 99 THEN 'HIGH' ELSE 'CRITICAL' END,
  CASE WHEN (seq*13) MOD 10 < 7 THEN ${ip('(seq*31) MOD 500')} ELSE ${ip('(seq*7919) MOD 60000')} END,
  CASE WHEN seq MOD 10 < 3 THEN CONCAT('u', (seq*17) MOD 5000) ELSE NULL END,
  'GET', '/shop/page', CAST(seq AS CHAR), (seq*7) MOD 40, 'NORMAL',
  NOW(3) - INTERVAL (${N_EV} - seq) * 8 SECOND, 'key1',
  CASE WHEN seq MOD 20 = 0 THEN CONCAT('inc', 2 + (seq DIV 20) MOD ${N_INC - 2}) ELSE NULL END
FROM seq_1_to_${to} WHERE seq >= ${from};
`, DB);
  }
  // One attacker address: 40,000 events over three days, all attached to one incident (inc1).
  sql(`SET unique_checks=0, foreign_key_checks=0;
INSERT INTO security_events (id, eventType, severity, ipAddress, userId, requestMethod, requestPath, externalId, riskScore, riskLevel, occurredAt, apiKeyId, incidentId)
SELECT CONCAT('atk', seq), CASE WHEN seq MOD 10 < 9 THEN 'login_failed' ELSE 'login_success' END, 'HIGH', '${ATTACKER}', CONCAT('u', seq MOD 5000), 'POST', '/login',
  CONCAT('atk', seq), 80, 'HIGH', NOW(3) - INTERVAL (seq MOD 4320) MINUTE - INTERVAL (seq MOD 60) SECOND, 'key1', 'inc1'
FROM seq_1_to_${40000 * SCALE};
-- A distributed attack: 20,000 failed sign-ins from 4,000 addresses in the last 10 minutes.
INSERT INTO security_events (id, eventType, severity, ipAddress, userId, requestMethod, requestPath, externalId, riskScore, riskLevel, occurredAt, apiKeyId)
SELECT CONCAT('dst', seq), 'login_failed', 'MEDIUM', ${ip('100000 + seq MOD 4000')}, CONCAT('u', seq MOD 5000), 'POST', '/login',
  CONCAT('dst', seq), 40, 'ELEVATED', NOW(3) - INTERVAL (seq MOD 590) SECOND - INTERVAL 5 SECOND, 'key1'
FROM seq_1_to_${20000 * SCALE};
ANALYZE TABLE security_events, security_incidents, security_ips, security_ip_blocks, security_audit_logs;
`, DB);
  console.log(`loaded in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
}

const D = (m) => `NOW(3) - INTERVAL ${m}`;
const HOT = `203.0.0.17`;
const QUERIES = [
  // --- ingestion hot path: runs for every event that arrives (detection.service.ts)
  ['ingest', 'failed sign-ins from one address, last 10 min (attacker)', `SELECT COUNT(*) FROM security_events WHERE ipAddress='${ATTACKER}' AND eventType='login_failed' AND occurredAt >= ${D('10 MINUTE')}`],
  ['ingest', 'all events from one address, last 10 min (attacker)', `SELECT COUNT(*) FROM security_events WHERE ipAddress='${ATTACKER}' AND occurredAt >= ${D('10 MINUTE')}`],
  ['ingest', 'distinct accounts failed from one address (attacker)', `SELECT DISTINCT userId FROM security_events WHERE ipAddress='${ATTACKER}' AND eventType='login_failed' AND occurredAt >= ${D('10 MINUTE')} AND userId IS NOT NULL`],
  ['ingest', 'password resets from one address', `SELECT COUNT(*) FROM security_events WHERE ipAddress='${ATTACKER}' AND eventType='password_reset' AND occurredAt >= ${D('10 MINUTE')}`],
  ['ingest', 'highest risk from one address, last 24 h (attacker)', `SELECT MAX(riskScore) FROM security_events WHERE ipAddress='${ATTACKER}' AND occurredAt >= ${D('24 HOUR')}`],
  ['ingest', 'failed sign-ins for one account, last 60 min', `SELECT ipAddress FROM security_events WHERE userId='u17' AND eventType='login_failed' AND occurredAt >= ${D('60 MINUTE')} LIMIT 1000`],
  ['ingest', 'all failed sign-ins in the last 10 min grouped by address (distributed attack)', `SELECT ipAddress, COUNT(*) FROM security_events WHERE eventType='login_failed' AND occurredAt >= ${D('10 MINUTE')} AND ipAddress IS NOT NULL GROUP BY ipAddress`],
  ['ingest', 'previous login of the account from another address (impossible travel)', `SELECT ipAddress, occurredAt FROM security_events WHERE userId='u17' AND eventType='login_success' AND id <> 'x' AND ipAddress <> '${HOT}' AND occurredAt >= ${D('120 MINUTE')} ORDER BY occurredAt DESC LIMIT 1`],
  ['ingest', 'repeat delivery check (apiKeyId, externalId)', `SELECT id FROM security_events WHERE apiKeyId='key1' AND externalId='123456' LIMIT 1`],
  ['ingest', 'open incident for a slot', `SELECT id FROM security_incidents WHERE openKey='ip:${HOT}' AND status IN ('OPEN','INVESTIGATING') LIMIT 1`],
  ['ingest', 'is this address blocked (one address)', `SELECT id FROM security_ip_blocks WHERE ipAddress='203.0.0.20' AND action='BLOCK' AND active=1 AND (isPermanent=1 OR expiresAt > NOW(3)) ORDER BY createdAt DESC LIMIT 1`],
  // --- blocklist read (the PHP library refreshes this list)
  ['blocklist', 'all blocks in force', `SELECT * FROM security_ip_blocks WHERE action='BLOCK' AND active=1 AND (isPermanent=1 OR expiresAt > NOW(3)) ORDER BY createdAt DESC`],
  ['blocklist', 'history for one address', `SELECT * FROM security_ip_blocks WHERE ipAddress='203.0.0.20' ORDER BY createdAt DESC LIMIT 100`],
  ['blocklist', 'count in force (statistics)', `SELECT COUNT(*) FROM security_ip_blocks WHERE action='BLOCK' AND active=1 AND (isPermanent=1 OR expiresAt > NOW(3))`],
  // --- events list
  ['events list', 'newest first, page 1', `SELECT * FROM security_events ORDER BY occurredAt DESC LIMIT 20`],
  ['events list', 'total count, no filter', `SELECT COUNT(*) FROM security_events`],
  ['events list', 'filter type=login_failed, newest first', `SELECT * FROM security_events WHERE eventType='login_failed' ORDER BY occurredAt DESC LIMIT 20`],
  ['events list', 'filter type=login_failed, count', `SELECT COUNT(*) FROM security_events WHERE eventType='login_failed'`],
  ['events list', 'filter severity=CRITICAL, newest first', `SELECT * FROM security_events WHERE severity='CRITICAL' ORDER BY occurredAt DESC LIMIT 20`],
  ['events list', 'filter severity=CRITICAL, count', `SELECT COUNT(*) FROM security_events WHERE severity='CRITICAL'`],
  ['events list', 'filter address (attacker), newest first', `SELECT * FROM security_events WHERE ipAddress='${ATTACKER}' ORDER BY occurredAt DESC LIMIT 20`],
  ['events list', 'filter address (attacker), count', `SELECT COUNT(*) FROM security_events WHERE ipAddress='${ATTACKER}'`],
  ['events list', 'filter account, newest first', `SELECT * FROM security_events WHERE userId='u17' ORDER BY occurredAt DESC LIMIT 20`],
  ['events list', 'last 24 hours, newest first', `SELECT * FROM security_events WHERE occurredAt >= ${D('24 HOUR')} ORDER BY occurredAt DESC LIMIT 20`],
  ['events list', 'sort by risk score', `SELECT * FROM security_events ORDER BY riskScore DESC LIMIT 20`],
  ['events list', 'sort by event type', `SELECT * FROM security_events ORDER BY eventType DESC LIMIT 20`],
  // --- incidents
  ['incidents', 'newest first, page 1', `SELECT * FROM security_incidents ORDER BY createdAt DESC LIMIT 20`],
  ['incidents', 'status=OPEN, newest first', `SELECT * FROM security_incidents WHERE status='OPEN' ORDER BY createdAt DESC LIMIT 20`],
  ['incidents', 'severity=CRITICAL, newest first', `SELECT * FROM security_incidents WHERE severity='CRITICAL' ORDER BY createdAt DESC LIMIT 20`],
  ['incidents', 'sort by risk score', `SELECT * FROM security_incidents ORDER BY riskScore DESC LIMIT 20`],
  ['incidents', 'sort by last updated', `SELECT * FROM security_incidents ORDER BY updatedAt DESC LIMIT 20`],
  ['incidents', 'sort by severity', `SELECT * FROM security_incidents ORDER BY severity DESC LIMIT 20`],
  ['incidents', 'search by address or number prefix', `SELECT * FROM security_incidents WHERE sourceIp LIKE '203.0.1%' OR incidentId LIKE 'INC-2026%' ORDER BY createdAt DESC LIMIT 20`],
  ['incidents', 'events of the big incident, newest 200', `SELECT * FROM security_events WHERE incidentId='inc1' ORDER BY occurredAt DESC LIMIT 200`],
  // --- reports
  ['reports', 'attacker incident: events in range (count, min, max)', `SELECT COUNT(*), MIN(occurredAt), MAX(occurredAt) FROM security_events WHERE ipAddress='${ATTACKER}' AND occurredAt BETWEEN ${D('4 DAY')} AND NOW(3)`],
  ['reports', 'attacker incident: by event type', `SELECT eventType, COUNT(*) FROM security_events WHERE ipAddress='${ATTACKER}' AND occurredAt BETWEEN ${D('4 DAY')} AND NOW(3) GROUP BY eventType`],
  ['reports', 'attacker incident: newest 25 sample', `SELECT requestPath, matchedRules FROM security_events WHERE ipAddress='${ATTACKER}' AND occurredAt BETWEEN ${D('4 DAY')} AND NOW(3) ORDER BY occurredAt DESC LIMIT 25`],
  ['reports', 'attached events for an incident (count)', `SELECT COUNT(*) FROM security_events WHERE incidentId='inc1'`],
  ['reports', 'lifetime events from an address', `SELECT COUNT(*) FROM security_events WHERE ipAddress='${ATTACKER}'`],
  ['reports', 'sign-ins that succeeded in the last 30 days', `SELECT COUNT(*) FROM security_events WHERE eventType='login_success' AND occurredAt >= ${D('30 DAY')}`],
  ['reports', 'distributed attack: failed sign-ins by address in range', `SELECT ipAddress, COUNT(*) FROM security_events WHERE eventType='login_failed' AND occurredAt BETWEEN ${D('30 MINUTE')} AND NOW(3) AND ipAddress IS NOT NULL GROUP BY ipAddress`],
  // --- dashboard statistics
  ['statistics', 'events in 24 hours', `SELECT COUNT(*) FROM security_events WHERE occurredAt >= ${D('24 HOUR')}`],
  ['statistics', 'events in 30 days', `SELECT COUNT(*) FROM security_events WHERE occurredAt >= ${D('30 DAY')}`],
  ['statistics', 'open incidents', `SELECT COUNT(*) FROM security_incidents WHERE status='OPEN'`],
  ['statistics', 'critical incidents in 24 hours', `SELECT COUNT(*) FROM security_incidents WHERE createdAt >= ${D('24 HOUR')} AND severity='CRITICAL'`],
  ['statistics', 'top 10 addresses in 24 hours', `SELECT ipAddress, COUNT(ipAddress) c FROM security_events WHERE occurredAt >= ${D('24 HOUR')} AND ipAddress IS NOT NULL GROUP BY ipAddress ORDER BY c DESC LIMIT 10`],
  ['statistics', 'top event types in 24 hours', `SELECT eventType, COUNT(eventType) c FROM security_events WHERE occurredAt >= ${D('24 HOUR')} GROUP BY eventType ORDER BY c DESC LIMIT 10`],
  ['statistics', 'risk levels in 24 hours', `SELECT riskLevel, COUNT(*) FROM security_events WHERE occurredAt >= ${D('24 HOUR')} GROUP BY riskLevel`],
  // --- audit log
  ['audit', 'newest first, page 1', `SELECT * FROM security_audit_logs ORDER BY createdAt DESC LIMIT 20`],
  ['audit', 'filter actor type, newest first', `SELECT * FROM security_audit_logs WHERE actorType='USER' ORDER BY createdAt DESC LIMIT 20`],
  ['audit', 'filter result=FAILURE, newest first', `SELECT * FROM security_audit_logs WHERE result='FAILURE' ORDER BY createdAt DESC LIMIT 20`],
  ['audit', 'filter result=FAILURE, count', `SELECT COUNT(*) FROM security_audit_logs WHERE result='FAILURE'`],
  ['audit', 'action contains "block"', `SELECT * FROM security_audit_logs WHERE action LIKE '%block%' ORDER BY createdAt DESC LIMIT 20`],
  ['audit', 'one target (type + id), newest first', `SELECT * FROM security_audit_logs WHERE targetType='incident' AND targetId='t77' ORDER BY createdAt DESC LIMIT 20`],
  ['audit', 'sort by action', `SELECT * FROM security_audit_logs ORDER BY action DESC LIMIT 20`],
  // --- address list
  ['addresses', 'last seen first, page 1', `SELECT * FROM security_ips ORDER BY lastSeenAt DESC LIMIT 20`],
  ['addresses', 'risk level HIGH, last seen first', `SELECT * FROM security_ips WHERE riskLevel='HIGH' ORDER BY lastSeenAt DESC LIMIT 20`],
  ['addresses', 'risk level HIGH, count', `SELECT COUNT(*) FROM security_ips WHERE riskLevel='HIGH'`],
  ['addresses', 'country filter, last seen first', `SELECT * FROM security_ips WHERE country='NG' ORDER BY lastSeenAt DESC LIMIT 20`],
  ['addresses', 'sort by risk score', `SELECT * FROM security_ips ORDER BY riskScore DESC LIMIT 20`],
  ['addresses', 'search by address prefix', `SELECT * FROM security_ips WHERE ipAddress LIKE '203.0.1%' ORDER BY lastSeenAt DESC LIMIT 20`],
];

function analyze(query) {
  const runs = [];
  let plan;
  for (let i = 0; i < 3; i++) {
    const out = sql(`ANALYZE FORMAT=JSON ${query};`, DB).trim();
    plan = JSON.parse(out);
    runs.push(plan.query_block.r_total_time_ms ?? 0);
  }
  const tables = [];
  (function walk(o) {
    if (Array.isArray(o)) return o.forEach(walk);
    if (o && typeof o === 'object') {
      if (o.table && o.table.table_name) tables.push(o.table);
      Object.values(o).forEach(walk);
    }
  })(plan);
  const t = tables[0] || {};
  const filesort = JSON.stringify(plan).includes('"filesort"');
  return {
    ms: Math.min(...runs),
    key: t.key || t.access_type === 'ALL' ? (t.key || 'FULL SCAN') : (t.access_type || '?'),
    rows: Math.round(t.r_rows ?? t.rows ?? 0),
    filesort,
  };
}
function suite() { return QUERIES.map(([area, name, q]) => ({ area, name, ...analyze(q) })); }

sql(`DROP DATABASE IF EXISTS ${DB}; CREATE DATABASE ${DB} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
apply(base);
console.log(`migrations applied: ${base.length}; candidates: ${candidates.length ? candidates.join(', ') : 'none'}`);
load();
const counts = sql('SELECT (SELECT COUNT(*) FROM security_events),(SELECT COUNT(*) FROM security_incidents),(SELECT COUNT(*) FROM security_audit_logs),(SELECT COUNT(*) FROM security_ips),(SELECT COUNT(*) FROM security_ip_blocks)', DB).trim().split('\t');
console.log(`rows: events=${counts[0]} incidents=${counts[1]} audit=${counts[2]} addresses=${counts[3]} blocks=${counts[4]}`);
const expected = [N_EV + 60000 * SCALE, N_INC, N_AUD, N_IPS, N_BLK].map(String);
if (counts.join() !== expected.join()) { console.error(`Dataset is not what was asked for: got ${counts.join(',')}, expected ${expected.join(',')}. Not measuring.`); process.exit(1); }
const before = suite();
let after = null;
if (candidates.length) {
  apply(candidates);
  sql('ANALYZE TABLE security_events, security_incidents, security_ips, security_ip_blocks, security_audit_logs, security_api_keys;', DB);
  after = suite();
}
const fmt = (r) => r ? `${r.key}${r.filesort ? ' +sort' : ''} / ${r.rows} rows / ${r.ms.toFixed(1)} ms` : '';
console.log('\n| Area | Query | Before: index / rows read / time | After: index / rows read / time |\n|---|---|---|---|');
before.forEach((b, i) => console.log(`| ${b.area} | ${b.name} | ${fmt(b)} | ${after ? fmt(after[i]) : ''} |`));
console.log('\nindexes on security_events: ' + sql(`SELECT GROUP_CONCAT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='${DB}' AND TABLE_NAME='security_events'`, DB).trim());
if (!process.argv.includes('--keep')) sql(`DROP DATABASE IF EXISTS ${DB}`);
