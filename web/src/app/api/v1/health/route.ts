import { json } from '@/server/api';

export const runtime = 'nodejs';

/** Liveness — no DB. Safe for Vercel health checks. */
export async function GET() {
  return json({
    status: 'ok',
    service: 'security-api',
    version: process.env.npm_package_version || '2.0.0',
    time: new Date().toISOString(),
    platform: 'next-vercel',
  });
}
