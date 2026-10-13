import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const API = process.env.E2E_API ?? 'http://localhost:4000';
export const DASH = process.env.E2E_DASHBOARD_URL ?? 'http://localhost:5173';
const FILE = join(__dirname, '.accounts.json');

export type RoleName = 'SUPER_ADMIN' | 'SECURITY_ADMIN' | 'ANALYST' | 'VIEWER';
export interface Account { email: string; password: string; id: string }

export async function apiCall(method: string, path: string, token?: string, body?: unknown) {
  const res = await fetch(`${API}/api/v1${path}`, {
    method, headers: { 'content-type': 'application/json', origin: DASH, ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => undefined) as any };
}

export const saveAccounts = (a: Record<RoleName, Account>) => writeFileSync(FILE, JSON.stringify(a));
export const loadAccounts = (): Record<RoleName, Account> => {
  if (!existsSync(FILE)) throw new Error('Accounts were not created. Set E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD (a super admin on a TEST server).');
  return JSON.parse(readFileSync(FILE, 'utf8'));
};
export const accountsFile = FILE;
