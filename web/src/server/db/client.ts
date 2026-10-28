import { createClient } from '@libsql/client';
import { drizzle } from 'drizzle-orm/libsql';
import * as schema from './schema';

/**
 * Turso (libSQL) or local SQLite.
 *
 * Local dev:  DATABASE_URL=file:./data/ir.db
 * Turso:      DATABASE_URL=libsql://your-db.turso.io
 *             DATABASE_AUTH_TOKEN=...
 *
 * Connection is created lazily on first use so `next build` can import
 * route modules without opening a local SQLite file that does not exist
 * on the build machine.
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

function getDb(): Db {
  if (!globalForDb.__irDb) {
    globalForDb.__irDb = createDb();
  }
  return globalForDb.__irDb;
}

/** Lazy Drizzle client — safe to import at module load during builds. */
export const db: Db = new Proxy({} as Db, {
  get(_target, prop, receiver) {
    const instance = getDb() as unknown as Record<string | symbol, unknown>;
    const value = Reflect.get(instance, prop, receiver);
    return typeof value === 'function' ? value.bind(instance) : value;
  },
});
