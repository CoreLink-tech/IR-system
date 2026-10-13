import { defineConfig, devices } from '@playwright/test';

/**
 * Browser tests. They need a real browser (`npx playwright install chromium`), a running Security API and a
 * dashboard to point at. See e2e/README.md. Nothing here was run in the sandbox that wrote it
 * (no browser could be installed there); that is stated in docs/FRONTEND.md.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: { baseURL: process.env.E2E_DASHBOARD_URL ?? 'http://localhost:5173', trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'phone-360', use: { ...devices['Pixel 5'], viewport: { width: 360, height: 740 } } },
  ],
  webServer: process.env.E2E_NO_SERVER ? undefined : { command: 'npm run build && npm run preview -- --port 5173', url: 'http://localhost:5173', reuseExistingServer: true, timeout: 180_000 },
});
