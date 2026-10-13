import { expect, test } from '@playwright/test';
import { ALL_PAGES, NAV, signInAs, watchProblems } from './helpers';
import type { RoleName } from './accounts';

const roles: RoleName[] = ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'];

for (const role of roles) {
  test.describe(role, () => {
    test('sees exactly its navigation, and every page it may use loads without errors', async ({ page }) => {
      const w = watchProblems(page);
      await signInAs(page, role);
      const links = await page.getByRole('navigation', { name: 'Main' }).getByRole('link').allInnerTexts();
      expect(links).toEqual(NAV[role]);
      for (const path of ALL_PAGES[role]) {
        await page.goto(path);
        await expect(page.locator('main')).toBeVisible();
        await expect(page.getByText('You do not have access to this page')).toHaveCount(0);
        await expect(page.locator('[aria-label="Loading"]')).toHaveCount(0, { timeout: 15_000 });
      }
      expect(await w.csp()).toEqual([]);
      expect(w.problems.filter((p) => !/Failed to load resource.*(40[34])/.test(p))).toEqual([]);
    });

    test('is told plainly when it opens a page it may not use', async ({ page }) => {
      await signInAs(page, role);
      const forbidden = ['/admin/users', '/admin/rules', '/admin/api-keys', '/admin/settings', '/admin/audit'].filter((p) => !ALL_PAGES[role].includes(p));
      for (const path of forbidden) {
        await page.goto(path);
        await expect(page.getByRole('heading', { name: 'You do not have access to this page' })).toBeVisible();
      }
    });
  });
}
