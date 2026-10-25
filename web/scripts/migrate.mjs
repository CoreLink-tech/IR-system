/**
 * Apply SQL files under drizzle/*/migration.sql in order.
 * Records applied tags in __drizzle_migrations.
 *
 * Usage: node --env-file=.env scripts/migrate.mjs
 */
import { createClient } from '@libsql/client';
import { createHash } from 'crypto';
import { readdirSync, readFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const url = process.env.DATABASE_URL || 'file:./data/ir.db';
if (url.startsWith('file:')) {
  try {
    mkdirSync(dirname(url.replace('file:', '')), { recursive: true });
  } catch { /* */ }
}
const client = createClient({
  url,
  authToken: process.env.DATABASE_AUTH_TOKEN || undefined,
});

await client.execute(`
  CREATE TABLE IF NOT EXISTS __drizzle_migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    created_at INTEGER
  )
`);

const applied = await client.execute('SELECT hash FROM __drizzle_migrations');
const done = new Set(applied.rows.map((r) => String(r.hash)));

const drizzleDir = join(root, 'drizzle');
const dirs = readdirSync(drizzleDir, { withFileTypes: true })
  .filter((d) => d.isDirectory() && /^\d{4}_/.test(d.name))
  .map((d) => d.name)
  .sort();

for (const tag of dirs) {
  const sqlPath = join(drizzleDir, tag, 'migration.sql');
  const sql = readFileSync(sqlPath, 'utf8');
  const hash = createHash('sha256').update(sql).digest('hex');
  if (done.has(hash) || done.has(tag)) {
    console.log('skip', tag);
    continue;
  }
  console.log('apply', tag);
  await client.executeMultiple(sql);
  await client.execute({
    sql: 'INSERT INTO __drizzle_migrations (hash, created_at) VALUES (?, ?)',
    args: [hash, Date.now()],
  });
}
console.log('migrations complete');
