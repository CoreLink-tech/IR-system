import { SignJWT, jwtVerify } from 'jose';
import { getEnv } from '@/lib/env';
import { createHash, createHmac, randomBytes } from 'crypto';

export type AccessClaims = {
  sub: string;
  email: string;
  role: string;
  tv: number; // token version
  typ: 'access';
};

export type ChallengeClaims = {
  sub: string;
  email: string;
  role: string;
  typ: 'mfa' | 'enroll';
};

function accessKey() {
  return new TextEncoder().encode(getEnv().jwtSecret);
}
export async function signAccess(claims: Omit<AccessClaims, 'typ'>, expiresIn = '15m') {
  return new SignJWT({ ...claims, typ: 'access' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(accessKey());
}

export async function verifyAccess(token: string): Promise<AccessClaims | null> {
  try {
    const { payload } = await jwtVerify(token, accessKey());
    if (payload.typ !== 'access') return null;
    return payload as unknown as AccessClaims;
  } catch {
    return null;
  }
}

export async function signChallenge(
  claims: Omit<ChallengeClaims, 'typ'> & { typ: 'mfa' | 'enroll' },
  expiresIn = '5m',
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(accessKey());
}

export async function verifyChallenge(token: string): Promise<ChallengeClaims | null> {
  try {
    const { payload } = await jwtVerify(token, accessKey());
    if (payload.typ !== 'mfa' && payload.typ !== 'enroll') return null;
    return payload as unknown as ChallengeClaims;
  } catch {
    return null;
  }
}

export function newRefreshToken(): string {
  return randomBytes(48).toString('base64url');
}

export function csrfFor(refreshToken: string): string {
  const bound = createHash('sha256').update(refreshToken).digest('hex');
  return createHmac('sha256', getEnv().jwtRefreshSecret).update(`csrf:${bound}`).digest('base64url');
}
