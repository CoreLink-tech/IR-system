import { ROLES } from '../common/constants';
import { KeyRing, keyProblems, loadKeyRing } from './two-factor.crypto';

/** Roles that must use two-step verification when REQUIRE_2FA is on. Others may switch it on themselves. */
export const MANDATORY_ROLES: string[] = [ROLES.SUPER_ADMIN, ROLES.SECURITY_ADMIN];

export interface TwoFactorConfig {
  /** REQUIRE_2FA. Defaults to on in production and off elsewhere. */
  required: boolean;
  /** Shown in the authenticator app next to the account. */
  issuer: string;
  /** Steps either side of the current one that are accepted (1 = 30 seconds of clock difference). */
  window: number;
  /** The encryption keys, or null when TOTP_ENCRYPTION_KEY is not set. */
  ring: KeyRing | null;
}

const truthy = (v: string) => ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
const falsy = (v: string) => ['0', 'false', 'no', 'off'].includes(v.trim().toLowerCase());

export function twoFactorConfig(env: NodeJS.ProcessEnv = process.env): TwoFactorConfig {
  const raw = env.REQUIRE_2FA;
  const required = raw !== undefined && raw.trim() !== '' ? truthy(raw) : env.NODE_ENV === 'production';
  const w = Number((env.TOTP_WINDOW ?? '1').trim());
  return {
    required,
    issuer: (env.TOTP_ISSUER ?? '').trim() || 'Security Dashboard',
    window: Number.isInteger(w) && w >= 0 && w <= 2 ? w : 1,
    ring: loadKeyRing(env),
  };
}

export const isMandatoryRole = (role: string) => MANDATORY_ROLES.includes(role);

/** Startup problems, as plain sentences. The API refuses to start when this is not empty. */
export function twoFactorProblems(env: NodeJS.ProcessEnv = process.env): string[] {
  const out = keyProblems(env);
  const raw = env.REQUIRE_2FA;
  if (raw !== undefined && raw.trim() !== '' && !truthy(raw) && !falsy(raw)) out.push(`REQUIRE_2FA must be true or false, got "${raw}".`);
  if (env.TOTP_WINDOW !== undefined && env.TOTP_WINDOW.trim() !== '' && !/^[0-2]$/.test(env.TOTP_WINDOW.trim())) out.push('TOTP_WINDOW must be 0, 1 or 2.');
  const cfg = twoFactorConfig(env);
  if (cfg.required && !cfg.ring && !out.length) {
    out.push('Two-step verification is required (REQUIRE_2FA is on, which is the default in production) but TOTP_ENCRYPTION_KEY is not set, so administrators could not enrol. Generate a key with: openssl rand -hex 32. To run without two-step verification, set REQUIRE_2FA=false.');
  }
  return out;
}
