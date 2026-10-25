import { createClient } from '@libsql/client';
import { drizzle } from 'drizzle-orm/libsql';
import * as schema from './schema';

/**
 * Turso (libSQL) or local SQLite.
 *
 * Local dev:  DATABASE_URL=file:./data/ir.db
 * Turso:      DATABASE_URL=libsql://your-db.turso.io
 *             DATABASE_AUTH_TOKEN=...
 */
function createDb() {
  const url = process.env.DATABASE_URL || 'file:./data/ir.db';
  const authToken = process.env.DATABASE_AUTH_TOKEN;
  const client = createClient({
    url,
    authToken: authToken || undefined,
  });
  return drizzle(client, { schema });
}

export type Db = ReturnType<typeof createDb>;

const globalForDb = globalThis as unknown as { __irDb?: Db };

export const db: Db = globalForDb.__irDb ?? createDb();

if (process.env.NODE_ENV !== 'production') {
  globalForDb.__irDb = db;
}
