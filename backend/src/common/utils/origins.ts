/**
 * The dashboard origins the API trusts, exactly as listed in CORS_ORIGINS. Used by the
 * CORS setup and by the cookie-session checks, so both always agree.
 */
export function allowedOrigins(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.CORS_ORIGINS || 'http://localhost:3000')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** True only for an exact match. No wildcards, no suffix or prefix matching. */
export function isAllowedOrigin(origin: unknown, env: NodeJS.ProcessEnv = process.env): boolean {
  return typeof origin === 'string' && origin.length > 0 && allowedOrigins(env).includes(origin);
}
