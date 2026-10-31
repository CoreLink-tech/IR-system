/**
 * Apply SQL files under drizzle/<tag>/migration.sql in order.
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
    mkdirSync(dirname(url.replace(/^file:/, '')), { recursive: true });
  } catch {
    /* ignore */
  }
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

for (const dir of dirs) {
  const sqlPath = join(drizzleDir, dir, 'migration.sql');
  let sql;
  try {
    sql = readFileSync(sqlPath, 'utf8');
  } catch {
    console.warn('skip missing', sqlPath);
    continue;
  }
  const hash = createHash('sha256').update(dir + '\n' + sql).digest('hex');
  if (done.has(hash) || done.has(dir)) {
    console.log('already applied', dir);
    continue;
  }
  console.log('applying', dir);
  try {
    await client.executeMultiple(sql);
  } catch (e) {
    // SQLite ALTER ADD COLUMN may fail if column exists on re-run of partial state
    console.warn('executeMultiple warning:', e instanceof Error ? e.message : e);
    // try statement-by-statement
    for (const stmt of sql.split(';').map((s) => s.trim()).filter(Boolean)) {
      try {
        await client.execute(stmt);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/duplicate column|already exists/i.test(msg)) continue;
        console.warn('stmt fail:', msg.slice(0, 120));
      }
    }
  }
  await client.execute({
    sql: 'INSERT INTO __drizzle_migrations (hash, created_at) VALUES (?, ?)',
    args: [hash, Date.now()],
  });
  console.log('applied', dir);
}

console.log('migrations complete');
client.close();
