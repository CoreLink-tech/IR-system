import { existsSync, unlinkSync } from 'node:fs';
import { accountsFile, apiCall, loadAccounts } from './accounts';

/** Switches the test accounts off again (accounts cannot be deleted through the API). */
export default async function teardown() {
  if (!existsSync(accountsFile)) return;
  const a = loadAccounts();
  const login = await apiCall('POST', '/auth/login', undefined, { email: a.SUPER_ADMIN.email, password: a.SUPER_ADMIN.password });
  if (login.status === 201) for (const r of ['SECURITY_ADMIN', 'ANALYST', 'VIEWER'] as const) await apiCall('PATCH', `/auth/users/${a[r].id}`, login.body.accessToken, { isActive: false });
  unlinkSync(accountsFile);
}
