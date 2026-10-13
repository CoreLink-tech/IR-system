import { expect, test } from '@playwright/test';
import { loadAccounts } from './accounts';
import { signInAs, watchProblems } from './helpers';

test.describe('sign in and the session, in a real browser', () => {
  test('signs in, keeps no token in any storage, and holds the refresh token only in an httpOnly cookie', async ({ page, context }) => {
    const w = watchProblems(page);
    await signInAs(page, 'ANALYST');
    const storage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
    expect(storage).not.toMatch(/eyJ/);
    expect(await page.evaluate(() => document.cookie)).not.toMatch(/pishon_rt/);        // JavaScript cannot see it
    const cookie = (await context.cookies()).find((c) => c.name === 'pishon_rt');
    expect(cookie).toBeTruthy();
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.sameSite).toBe('Strict');
    expect(cookie!.path).toBe('/api/v1/auth');
    expect(w.problems).toEqual([]);
  });

  test('a wrong password and a wrong email give the same message', async ({ page }) => {
    await page.goto('/sign-in');
    await page.getByLabel('Email').fill('nobody@example.test');
    await page.getByLabel('Password').fill('not-the-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    const msg = await page.getByRole('alert').first().innerText();
    await page.getByLabel('Email').fill(loadAccounts().VIEWER.email);
    await page.getByLabel('Password').fill('also-not-the-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert').first()).toHaveText(msg);
  });

  test('a reload resumes the session from the cookie, and a deep link returns after signing in', async ({ page }) => {
    await page.goto('/incidents?status=OPEN');
    await expect(page).toHaveURL(/sign-in/);
    const a = loadAccounts().ANALYST;
    await page.getByLabel('Email').fill(a.email); await page.getByLabel('Password').fill(a.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/\/incidents\?status=OPEN/);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Incidents' })).toBeVisible();
  });

  test('signing out in one tab signs out the other tab', async ({ page, context }) => {
    await signInAs(page, 'VIEWER');
    const second = await context.newPage();
    await second.goto('/incidents');
    await expect(second.getByRole('heading', { name: 'Incidents' })).toBeVisible();
    await page.getByRole('button', { name: /VIEWER Test/ }).click();
    await page.getByRole('menuitem', { name: 'Sign out' }).click();
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(second.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 10_000 });
  });

  test('two tabs refreshing at the same moment never trigger theft detection', async ({ page, context }) => {
    await signInAs(page, 'ANALYST');
    const second = await context.newPage();
    await second.goto('/');
    await expect(second.getByRole('heading', { name: 'Overview' })).toBeVisible();
    // Reload both together several times: each load resumes from the same cookie at once.
    for (let i = 0; i < 5; i++) await Promise.all([page.reload(), second.reload()]);
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(second.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.getByText('All your sessions were ended for safety')).toHaveCount(0);
  });
});
