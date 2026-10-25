/**
 * JWT signing key ring with optional previous key for zero-downtime rotation.
 *
 * Settings:
 *   JWT_SECRET              current access-token signing secret (required)
 *   JWT_SECRET_PREVIOUS     previous secret during overlap (optional)
 *   JWT_KEY_ID              kid header written on new tokens (default "v1")
 *   JWT_KEY_ID_PREVIOUS     kid of the previous key (default "v0")
 *
 * Sign with the current key and put its kid in the header.
 * Verify by looking up the kid; if the kid is missing (old tokens) try current then previous.
 * After the overlap window, remove JWT_SECRET_PREVIOUS; tokens still carrying the old kid are refused.
 *
 * The same pattern is used for the refresh secret (JWT_REFRESH_SECRET / JWT_REFRESH_SECRET_PREVIOUS)
 * which also keys the CSRF HMAC.
 */
export interface JwtKeyRing {
  current: string;
  previous?: string;
  currentKid: string;
  previousKid: string;
}

export function loadAccessKeyRing(env: NodeJS.ProcessEnv = process.env): JwtKeyRing {
  return {
    current: (env.JWT_SECRET ?? '').trim(),
    previous: (env.JWT_SECRET_PREVIOUS ?? '').trim() || undefined,
    currentKid: (env.JWT_KEY_ID ?? 'v1').trim() || 'v1',
    previousKid: (env.JWT_KEY_ID_PREVIOUS ?? 'v0').trim() || 'v0',
  };
}

export function loadRefreshKeyRing(env: NodeJS.ProcessEnv = process.env): JwtKeyRing {
  return {
    current: (env.JWT_REFRESH_SECRET ?? '').trim(),
    previous: (env.JWT_REFRESH_SECRET_PREVIOUS ?? '').trim() || undefined,
    currentKid: (env.JWT_REFRESH_KEY_ID ?? 'v1').trim() || 'v1',
    previousKid: (env.JWT_REFRESH_KEY_ID_PREVIOUS ?? 'v0').trim() || 'v0',
  };
}

/** Resolve the secret for a token's kid. Missing kid (legacy) tries current then previous. */
export function secretForKid(ring: JwtKeyRing, kid?: string | null): string | null {
  if (kid === ring.currentKid) return ring.current;
  if (kid === ring.previousKid && ring.previous) return ring.previous;
  if (!kid) {
    // Tokens issued before kid existed: try current, then previous.
    return ring.current || ring.previous || null;
  }
  return null;
}

/** Problems with the rotation settings, as plain sentences. */
export function jwtKeyProblems(env: NodeJS.ProcessEnv = process.env): string[] {
  const out: string[] = [];
  if (env.JWT_SECRET_PREVIOUS && !env.JWT_SECRET) {
    out.push('JWT_SECRET_PREVIOUS is set but JWT_SECRET is not.');
  }
  if (env.JWT_REFRESH_SECRET_PREVIOUS && !env.JWT_REFRESH_SECRET) {
    out.push('JWT_REFRESH_SECRET_PREVIOUS is set but JWT_REFRESH_SECRET is not.');
  }
  if (env.JWT_SECRET && env.JWT_SECRET_PREVIOUS && env.JWT_SECRET === env.JWT_SECRET_PREVIOUS) {
    out.push('JWT_SECRET and JWT_SECRET_PREVIOUS must be different.');
  }
  if (env.JWT_REFRESH_SECRET && env.JWT_REFRESH_SECRET_PREVIOUS && env.JWT_REFRESH_SECRET === env.JWT_REFRESH_SECRET_PREVIOUS) {
    out.push('JWT_REFRESH_SECRET and JWT_REFRESH_SECRET_PREVIOUS must be different.');
  }
  const access = loadAccessKeyRing(env);
  if (access.currentKid === access.previousKid && access.previous) {
    out.push('JWT_KEY_ID and JWT_KEY_ID_PREVIOUS must be different when a previous secret is configured.');
  }
  return out;
}
