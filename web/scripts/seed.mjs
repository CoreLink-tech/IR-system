/**
 * Seed first super admin and a sample API key.
 * Usage: node --env-file=.env scripts/seed.mjs
 */
import { createClient } from '@libsql/client';
import { createHash, randomBytes } from 'crypto';
import { hashSync } from 'bcryptjs';

const url = process.env.DATABASE_URL || 'file:./data/ir.db';
const authToken = process.env.DATABASE_AUTH_TOKEN;
const pepper = process.env.API_KEY_HASH_PEPPER || 'dev-pepper-change-me-16';
const prefix = process.env.API_KEY_PREFIX || 'IRS_';

const client = createClient({ url, authToken: authToken || undefined });

function id() {
  return randomBytes(16).toString('hex');
}

async function main() {
  // Ensure tables exist (simple bootstrap — prefer drizzle-kit push/migrate in real use)
  await client.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'VIEWER',
      is_active INTEGER NOT NULL DEFAULT 1,
      must_change_password INTEGER NOT NULL DEFAULT 0,
      token_version INTEGER NOT NULL DEFAULT 0,
      password_changed_at INTEGER,
      last_login_at INTEGER,
      totp_secret TEXT,
      totp_enabled_at INTEGER,
      totp_last_step INTEGER,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT 'events:write',
      is_active INTEGER NOT NULL DEFAULT 1,
      expires_at INTEGER,
      last_used_at INTEGER,
      revoked_at INTEGER,
      created_by TEXT,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
  `);

  const email = process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@example.com';
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || randomBytes(12).toString('base64url');
  const existing = await client.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
  if (existing.rows.length === 0) {
    await client.execute({
      sql: `INSERT INTO users (id, email, name, password_hash, role, must_change_password, created_at)
            VALUES (?, ?, ?, ?, 'SUPER_ADMIN', 1, ?)`,
      args: [id(), email, 'Initial Admin', hashSync(password, 12), Date.now()],
    });
    console.log('Admin created:', email);
    console.log('Password:', password);
  } else {
    console.log('Admin already exists:', email);
  }

  const lookup = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('base64url');
  const keyPrefix = `${prefix}${lookup}`;
  const raw = `${keyPrefix}${secret}`;
  const keyHash = createHash('sha256').update(raw + pepper).digest('hex');
  await client.execute({
    sql: `INSERT INTO api_keys (id, name, key_prefix, key_hash, scopes, created_at)
          VALUES (?, ?, ?, ?, ?, ?)`,
    args: [id(), 'Website', keyPrefix, keyHash, 'events:write,block:read', Date.now()],
  });
  console.log('API key (save once):', raw);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
