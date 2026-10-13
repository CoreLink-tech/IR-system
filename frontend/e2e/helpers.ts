import { expect, type Page } from '@playwright/test';
import { loadAccounts, type RoleName } from './accounts';

export async function signInAs(page: Page, role: RoleName) {
  const a = loadAccounts()[role];
  await page.goto('/sign-in');
  await page.getByLabel('Email').fill(a.email);
  await page.getByLabel('Password').fill(a.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
}

/** Collects anything the browser reports as a console error or a blocked-by-CSP resource. */
export function watchProblems(page: Page) {
  const problems: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => { (window as any).__csp = ((window as any).__csp ?? []).concat(`${e.violatedDirective} ${e.blockedURI}`); });
  });
  return { problems, csp: async () => (await page.evaluate(() => (window as any).__csp ?? [])) as string[] };
}

export const NAV: Record<RoleName, string[]> = {
  SUPER_ADMIN: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports', 'Users', 'API keys', 'Detection rules', 'Audit log', 'Settings'],
  SECURITY_ADMIN: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports', 'API keys', 'Detection rules', 'Audit log', 'Settings'],
  ANALYST: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports', 'Audit log'],
  VIEWER: ['Overview', 'Incidents', 'Addresses', 'Blocking', 'Reports'],
};

export const ALL_PAGES: Record<RoleName, string[]> = {
  SUPER_ADMIN: ['/', '/incidents', '/ips', '/blocking', '/reports', '/admin/users', '/admin/api-keys', '/admin/rules', '/admin/audit', '/admin/settings', '/account/password'],
  SECURITY_ADMIN: ['/', '/incidents', '/ips', '/blocking', '/reports', '/admin/api-keys', '/admin/rules', '/admin/audit', '/admin/settings'],
  ANALYST: ['/', '/incidents', '/ips', '/blocking', '/reports', '/admin/audit'],
  VIEWER: ['/', '/incidents', '/ips', '/blocking', '/reports'],
};
