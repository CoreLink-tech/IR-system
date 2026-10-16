import { expect, test } from '@playwright/test';
import { API, apiCall, loadAccounts } from './accounts';
import { signInAs, watchProblems } from './helpers';

test.describe('what the browser enforces', () => {
  test('the page cannot be framed, and sends the security headers', async ({ page }) => {
    const res = await page.goto('/');
    const h = res!.headers();
    expect(h['content-security-policy']).toContain("script-src 'self'");
    expect(h['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(h['content-security-policy']).not.toMatch(/unsafe-inline|unsafe-eval/);
    expect(h['x-frame-options']).toBe('DENY');
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['referrer-policy']).toBe('no-referrer');
  });

  test('inline script injection is blocked by the CSP', async ({ page }) => {
    const w = watchProblems(page);
    await page.goto('/sign-in');
    await page.evaluate(() => { const s = document.createElement('script'); s.textContent = 'window.__ran = true'; document.head.appendChild(s); });
    expect(await page.evaluate(() => (window as any).__ran)).toBeUndefined();
    expect((await w.csp()).join()).toMatch(/script-src/);
  });

  test('text from the server that looks like markup or script is shown as text on every place it appears', async ({ page }) => {
    const a = loadAccounts();
    const login = await apiCall('POST', '/auth/login', undefined, { email: a.SUPER_ADMIN.email, password: a.SUPER_ADMIN.password });
    const token = login.body.accessToken as string;
    const inc = (await apiCall('GET', '/incidents?pageSize=1', token)).body.data[0];
    test.skip(!inc, 'needs at least one incident on the test server');
    const payload = '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script>';
    await apiCall('POST', `/incidents/${inc.id}/notes`, token, { note: payload });
    const w = watchProblems(page);
    await signInAs(page, 'ANALYST');
    await page.goto(`/incidents/${inc.incidentId}?tab=timeline`);
    await expect(page.getByText(payload).first()).toBeVisible();
    await page.goto('/admin/audit');
    await page.waitForTimeout(500);
    expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
    expect(await page.locator('img[src="x"]').count()).toBe(0);
    expect(await w.csp()).toEqual([]);
  });

  test('a redirect target after sign-in can never leave the site', async ({ page }) => {
    await page.goto('/sign-in');
    await page.evaluate(() => sessionStorage.setItem('ir-return-to', '//evil.example/steal'));
    const a = loadAccounts().VIEWER;
    await page.getByLabel('Email').fill(a.email); await page.getByLabel('Password').fill(a.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(new RegExp(`^${(process.env.E2E_DASHBOARD_URL ?? 'http://localhost:5173').replace(/\./g, '\\.')}/?$`));
  });

  test('a cross-site page cannot use the refresh cookie (SameSite) and the API refuses a foreign origin', async ({ page, request }) => {
    await signInAs(page, 'VIEWER');
    const res = await request.post(`${API}/api/v1/auth/refresh`, { headers: { origin: 'https://evil.example' }, data: {} });
    expect(res.status()).toBe(401);                                     // the request context has no cookie: Strict cookies are not sent cross-site
    const withToken = await page.evaluate(async (api) => {
      const r = await fetch(`${api}/api/v1/auth/refresh`, { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: '{}' });
      return r.status;
    }, API);
    expect([401, 403]).toContain(withToken);                            // from the page: no CSRF header, so refused
  });
});
