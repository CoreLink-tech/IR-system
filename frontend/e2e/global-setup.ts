import { API, apiCall, saveAccounts, type Account, type RoleName } from './accounts';

/** Creates one account per role on the TEST server, so the tests sign in as real people of each role. */
export default async function setup() {
  const email = process.env.E2E_ADMIN_EMAIL, password = process.env.E2E_ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Set E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD (a super admin on a TEST server, never production).');
  const login = await apiCall('POST', '/auth/login', undefined, { email, password });
  if (login.status !== 201) throw new Error(`Cannot sign in to ${API}: ${login.status}`);
  const token = login.body.accessToken as string;
  const run = Date.now().toString(36);
  const out = {} as Record<RoleName, Account>;
  out.SUPER_ADMIN = { email, password, id: login.body.user.id };
  for (const role of ['SECURITY_ADMIN', 'ANALYST', 'VIEWER'] as const) {
    const a = { email: `pw-${run}-${role.toLowerCase()}@example.test`, password: `Pw-${run}-${role}-Pass1!` };
    const r = await apiCall('POST', '/auth/users', token, { email: a.email, password: a.password, role, name: `${role} Test` });
    if (r.status !== 201) throw new Error(`Cannot create ${role}: ${r.status}`);
    out[role] = { ...a, id: r.body.id };
  }
  saveAccounts(out);
}
