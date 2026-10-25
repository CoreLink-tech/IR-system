/**
 * Static checks for migration files (no DB required).
 * Run: node scripts/migration-files.test.mjs
 */
import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import assert from 'assert';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const drizzle = join(root, 'drizzle');
const journal = JSON.parse(readFileSync(join(drizzle, 'meta', '_journal.json'), 'utf8'));
assert.ok(journal.entries?.length >= 1, 'journal must have entries');

const dirs = readdirSync(drizzle, { withFileTypes: true })
  .filter((d) => d.isDirectory() && /^\d{4}_/.test(d.name))
  .map((d) => d.name);
assert.ok(dirs.includes('0000_initial'), '0000_initial folder required');

const sql = readFileSync(join(drizzle, '0000_initial', 'migration.sql'), 'utf8');
for (const table of [
  'users', 'events', 'incidents', 'ip_blocks', 'api_keys',
  'audit_log', 'detection_rules', 'refresh_tokens', 'recovery_codes',
]) {
  assert.ok(sql.includes(table), `migration must create ${table}`);
}
console.log('migration-files.test.mjs: ok');
