/**
 * Startup checks for settings that, if wrong, quietly break the security of the
 * whole system. The server refuses to start when any of them fail.
 *
 * The important one is the signing secret. The sample .env file ships with a public
 * placeholder, and anyone who knows the secret can forge a login token for any
 * administrator. Copying the sample file without editing it must therefore fail
 * loudly instead of producing a server that looks fine and is wide open.
 */
import { loadRetentionConfig } from '../retention/retention.config';
import { parseTrustedProxies, trustedProxyProblems } from '../common/utils/ip.util';
export interface ConfigReport {
  errors: string[];
  warnings: string[];
}

const PLACEHOLDER = /change[_-]?me|dev-insecure|replace[_-]?me|your[_-]?secret|example|password123/i;

function checkSecret(name: string, value: string | undefined, minLength: number, errors: string[]) {
  if (!value) {
    errors.push(`${name} is not set. Generate one with: npm run gen:secrets`);
    return;
  }
  if (PLACEHOLDER.test(value)) {
    errors.push(`${name} still contains the placeholder from .env.example. Generate a real one with: npm run gen:secrets`);
    return;
  }
  if (value.length < minLength) {
    errors.push(`${name} is too short (${value.length} characters, need at least ${minLength}). Generate one with: npm run gen:secrets`);
  }
}

export function validateConfig(env: NodeJS.ProcessEnv = process.env): ConfigReport {
  const errors: string[] = [];
  const warnings: string[] = [];

  checkSecret('JWT_SECRET', env.JWT_SECRET, 32, errors);
  checkSecret('JWT_REFRESH_SECRET', env.JWT_REFRESH_SECRET, 32, errors);
  if (env.JWT_SECRET && env.JWT_SECRET === env.JWT_REFRESH_SECRET) {
    errors.push('JWT_SECRET and JWT_REFRESH_SECRET must be different, or a refresh token could be used as an access token.');
  }
  checkSecret('API_KEY_HASH_PEPPER', env.API_KEY_HASH_PEPPER, 16, errors);

  if (!env.DATABASE_URL) {
    errors.push('DATABASE_URL is not set.');
  } else if (/:CHANGE_ME@/i.test(env.DATABASE_URL)) {
    errors.push('DATABASE_URL still contains the placeholder database password.');
  }

  if (!(env.API_KEY_PREFIX ?? 'IRS_').trim()) {
    errors.push('API_KEY_PREFIX must not be empty. Key detection relies on it.');
  }

  const origins = (env.CORS_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (origins.includes('*')) {
    errors.push('CORS_ORIGINS must not be "*" because the API uses credentials. List the dashboard origins explicitly.');
  }

  loadRetentionConfig(env).errors.forEach((m) => errors.push(m));

  const trusted = parseTrustedProxies(env.TRUSTED_PROXIES);
  trustedProxyProblems(trusted).forEach((m) => errors.push(m));
  if ((env.CLIENT_IP_HEADER ?? '').trim() && trusted.length === 0) {
    warnings.push('CLIENT_IP_HEADER is set but TRUSTED_PROXIES is empty, so the header is ignored.');
  }

  if (env.NODE_ENV === 'production') {
    if (trusted.length === 0) {
      warnings.push('TRUSTED_PROXIES is empty. If the API sits behind a reverse proxy, every caller will look like the proxy address and share one rate limit. List the proxy address, or "private".');
    }
    if (origins.some((o) => /localhost|127\.0\.0\.1/.test(o))) {
      warnings.push('CORS_ORIGINS includes a localhost address in production.');
    }
    if (String(env.AUTO_BLOCK_ENABLED ?? 'true') !== 'true') {
      warnings.push('AUTO_BLOCK_ENABLED is off, so critical activity will not be blocked automatically.');
    }
  }
  return { errors, warnings };
}

/** Throws one readable error that lists every problem. */
export function assertValidConfig(env: NodeJS.ProcessEnv = process.env): string[] {
  const { errors, warnings } = validateConfig(env);
  if (errors.length > 0) {
    throw new Error(`Refusing to start because of unsafe configuration:\n - ${errors.join('\n - ')}`);
  }
  return warnings;
}
