/**
 * Simple sliding window rate limit. Uses globalThis so it survives warm serverless
 * invocations on the same isolate; not a cluster-wide store. For multi-region
 * production, replace with Redis/Upstash.
 */
type Bucket = { count: number; resetAt: number };

const store = (globalThis as unknown as { __irRl?: Map<string, Bucket> }).__irRl
  ?? new Map<string, Bucket>();
(globalThis as unknown as { __irRl?: Map<string, Bucket> }).__irRl = store;

export function rateLimit(
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
