/**
 * Rate limit helper.
 * - If UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN are set, uses Upstash REST
 *   for shared limits across Vercel isolates.
 * - Otherwise falls back to in-memory (per-isolate only).
 */
type Bucket = { count: number; resetAt: number };

const store = (globalThis as unknown as { __irRl?: Map<string, Bucket> }).__irRl
  ?? new Map<string, Bucket>();
(globalThis as unknown as { __irRl?: Map<string, Bucket> }).__irRl = store;

async function upstashLimit(
  key: string,
  limit: number,
  windowMs: number,
): Promise<{ ok: true } | { ok: false; retryAfterSeconds: number } | null> {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  const windowSec = Math.max(1, Math.ceil(windowMs / 1000));
  const redisKey = `rl:${key}`;
  try {
    const incr = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify([
        ['INCR', redisKey],
        ['EXPIRE', redisKey, String(windowSec), 'NX'],
        ['TTL', redisKey],
      ]),
    });
    if (!incr.ok) return null;
    const data = (await incr.json()) as Array<{ result: number }>;
    const count = Number(data?.[0]?.result ?? 0);
    const ttl = Number(data?.[2]?.result ?? windowSec);
    if (count > limit) {
      return { ok: false, retryAfterSeconds: Math.max(1, ttl > 0 ? ttl : windowSec) };
    }
    return { ok: true };
  } catch {
    return null;
  }
}

function memoryLimit(
  key: string,
  limit: number,
  windowMs: number,
): { ok: true } | { ok: false; retryAfterSeconds: number } {
  const now = Date.now();
  let b = store.get(key);
  if (!b || b.resetAt <= now) {
    b = { count: 0, resetAt: now + windowMs };
    store.set(key, b);
  }
  b.count += 1;
  if (b.count > limit) {
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((b.resetAt - now) / 1000)) };
  }
  return { ok: true };
}

/** Sync API kept for call sites; prefers Upstash when configured (fire-and-forget init on first call uses memory until async path is used). */
export function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): { ok: true } | { ok: false; retryAfterSeconds: number } {
  // Sync path: memory always available. Callers that need shared limits should use rateLimitAsync.
  return memoryLimit(key, limit, windowMs);
}

export async function rateLimitAsync(
  key: string,
  limit: number,
  windowMs: number,
): Promise<{ ok: true } | { ok: false; retryAfterSeconds: number }> {
  const remote = await upstashLimit(key, limit, windowMs);
  if (remote) return remote;
  return memoryLimit(key, limit, windowMs);
}
