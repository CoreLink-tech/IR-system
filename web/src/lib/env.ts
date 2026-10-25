/**
 * Server env. Validated at first use. Never import this into client components.
 */
function required(name: string, min = 16): string {
  const v = process.env[name]?.trim();
  if (!v) throw new Error(`${name} is not set`);
  if (v.length < min) throw new Error(`${name} is too short (need >= ${min})`);
  if (/change[_-]?me|dev-insecure|replace[_-]?me/i.test(v)) {
    throw new Error(`${name} still looks like a placeholder`);
  }
  return v;
}

export function getEnv() {
  return {
    databaseUrl: process.env.DATABASE_URL || 'file:./data/ir.db',
    databaseAuthToken: process.env.DATABASE_AUTH_TOKEN || '',
    jwtSecret: required('JWT_SECRET', 32),
    jwtRefreshSecret: required('JWT_REFRESH_SECRET', 32),
    apiKeyPepper: required('API_KEY_HASH_PEPPER', 16),
    apiKeyPrefix: process.env.API_KEY_PREFIX || 'IRS_',
    totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY || '',
    require2fa: process.env.REQUIRE_2FA === 'true' || process.env.NODE_ENV === 'production',
    totpIssuer: process.env.TOTP_ISSUER || 'Security Dashboard',
    nodeEnv: process.env.NODE_ENV || 'development',
  };
}
