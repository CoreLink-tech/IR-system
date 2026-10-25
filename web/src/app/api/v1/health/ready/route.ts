import { json } from '@/server/api';
import { db } from '@/server/db/client';
import { sql } from 'drizzle-orm';

export const runtime = 'nodejs';

/** Readiness — database reachable. */
export async function GET() {
  let database: 'up' | 'down' = 'down';
  try {
    await db.run(sql`SELECT 1`);
    database = 'up';
  } catch {
    database = 'down';
  }
  const ready = database === 'up';
  return json(
    {
      status: ready ? 'ready' : 'not_ready',
      service: 'security-api',
      time: new Date().toISOString(),
      database,
    },
    { status: ready ? 200 : 503 },
  );
}
