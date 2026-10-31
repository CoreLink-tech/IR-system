/**
 * Clear login/MFA throttle rows for a user email.
 * Usage: node --env-file=.env scripts/unlock-user.mjs user@example.com
 */
import { createClient } from '@libsql/client';
import { createHash } from 'crypto';

const email = (process.argv[2] || '').trim().toLowerCase();
if (!email) {
  console.error('Usage: node scripts/unlock-user.mjs <email>');
  process.exit(1);
}
const url = process.env.DATABASE_URL || 'file:./data/ir.db';
const client = createClient({ url, authToken: process.env.DATABASE_AUTH_TOKEN || undefined });
const key = createHash('sha256').update(email).digest('hex');
const users = await client.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
const userId = users.rows[0]?.id;
await client.execute({ sql: 'DELETE FROM login_throttle WHERE key_hash = ?', args: [key] });
if (userId) {
  await client.execute({ sql: 'DELETE FROM login_throttle WHERE key_hash = ?', args: [`mfa:${userId}`] });
}
await client.execute({
  sql: `INSERT INTO audit_log (id, actor_type, actor_label, action, result, metadata, created_at)
        VALUES (?, 'SYSTEM', 'unlock-user.mjs', 'auth.unlock', 'SUCCESS', ?, ?)`,
  args: [
    createHash('sha256').update(email + Date.now()).digest('hex').slice(0, 32),
    JSON.stringify({ email }),
    Date.now(),
  ],
});
console.log('Unlocked throttle for', email);
client.close();
