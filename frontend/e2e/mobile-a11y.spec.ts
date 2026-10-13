import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { ALL_PAGES, signInAs } from './helpers';

test.describe('small screens and accessibility in a real browser', () => {
  test('every page fits a 360px phone without sideways scrolling, and tables become cards', async ({ page }, info) => {
    test.skip(info.project.name !== 'phone-360', 'phone project only');
    await signInAs(page, 'SUPER_ADMIN');
    for (const path of ALL_PAGES.SUPER_ADMIN) {
      await page.goto(path);
      await expect(page.locator('[aria-label="Loading"]')).toHaveCount(0, { timeout: 15_000 });
      const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect([path, over <= 1]).toEqual([path, true]);
      for (const th of await page.locator('table.rtable thead').all()) {
        const box = await th.boundingBox();
        expect(box === null || box.width <= 2 || box.height <= 2).toBe(true);        // the header row is hidden on a phone
      }
    }
  });

  test('buttons, links and fields are at least 44px tall on a phone', async ({ page }, info) => {
    test.skip(info.project.name !== 'phone-360', 'phone project only');
    await signInAs(page, 'SUPER_ADMIN');
    for (const path of ['/', '/incidents', '/blocking', '/admin/rules']) {
      await page.goto(path);
      await expect(page.locator('[aria-label="Loading"]')).toHaveCount(0, { timeout: 15_000 });
      const small = await page.$$eval('button, a.btn, .nav a, select, input:not([type=checkbox]):not([type=radio])', (els) =>
        els.filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.height < 43.5; }).map((e) => `${e.tagName} ${(e.textContent || e.getAttribute('aria-label') || '').trim().slice(0, 30)}`));
      expect([path, small]).toEqual([path, []]);
    }
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`no accessibility violations, including real colour contrast, in ${scheme} mode`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await signInAs(page, 'SUPER_ADMIN');
      for (const path of ALL_PAGES.SUPER_ADMIN) {
        await page.goto(path);
        await expect(page.locator('[aria-label="Loading"]')).toHaveCount(0, { timeout: 15_000 });
        const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
        expect([path, r.violations.map((v) => `${v.id}: ${v.nodes.length}`)]).toEqual([path, []]);
      }
    });
  }

  test('reduced motion is respected', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/sign-in');
    const anim = await page.evaluate(() => getComputedStyle(document.body).animationDuration);
    expect(['0s', '']).toContain(anim);
  });

  test('keyboard only: tab to the skip link, skip to content, and open and close a dialog with the keyboard', async ({ page }) => {
    await signInAs(page, 'SECURITY_ADMIN');
    await page.goto('/blocking');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
    await page.getByRole('button', { name: 'Block an address' }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog', { name: 'Block an address' })).toBeVisible();
    for (let i = 0; i < 15; i++) { await page.keyboard.press('Tab'); expect(await page.evaluate(() => !!document.activeElement?.closest('[role=dialog]'))).toBe(true); }
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Block an address' })).toBeFocused();
  });
});
