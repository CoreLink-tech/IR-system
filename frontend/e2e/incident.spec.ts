import { expect, test } from '@playwright/test';
import { apiCall, loadAccounts } from './accounts';
import { signInAs } from './helpers';

test.describe('investigating an incident', () => {
  test('report first, then timeline, technical and actions by role; a private address cannot be blocked', async ({ page }) => {
    const a = loadAccounts();
    const token = (await apiCall('POST', '/auth/login', undefined, { email: a.SUPER_ADMIN.email, password: a.SUPER_ADMIN.password })).body.accessToken as string;
    const inc = (await apiCall('GET', '/incidents?pageSize=1', token)).body.data[0];
    test.skip(!inc, 'needs at least one incident on the test server');

    await signInAs(page, 'VIEWER');
    await page.goto(`/incidents/${inc.incidentId}`);
    await expect(page.getByRole('heading', { name: 'What happened' })).toBeVisible();
    await expect(page.getByText('What this report cannot confirm')).toBeVisible();
    await expect(page.getByRole('tab')).toHaveCount(2);
    await page.getByRole('button', { name: 'Print or save as PDF' }).waitFor();
    await page.emulateMedia({ media: 'print' });
    await expect(page.locator('.topbar')).toBeHidden();
    await expect(page.getByRole('heading', { name: 'What happened' })).toBeVisible();
    await page.emulateMedia({ media: 'screen' });
    await page.getByRole('button', { name: /VIEWER Test/ }).click();
    await page.getByRole('menuitem', { name: 'Sign out' }).click();

    await signInAs(page, 'SECURITY_ADMIN');
    await page.goto('/blocking');
    await page.getByRole('button', { name: 'Block an address' }).click();
    const dlg = page.getByRole('dialog', { name: 'Block an address' });
    await dlg.getByLabel('Address').fill('10.0.0.5');
    await dlg.getByLabel('Reason').fill('browser test');
    await dlg.getByRole('button', { name: 'Block address' }).click();
    await expect(dlg.getByText(/private or internal address/)).toBeVisible();
  });
});
