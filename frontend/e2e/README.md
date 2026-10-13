# Browser tests (Playwright)

These need a real browser, which the environment that wrote them could not install, so
**they have not been run**. They are complete and typechecked; run them on a machine with a browser.

```bash
cd frontend
npx playwright install chromium            # once
# a TEST Security API (never production), with CORS_ORIGINS including http://localhost:5173
export E2E_API=http://localhost:4000
export E2E_ADMIN_EMAIL=...  E2E_ADMIN_PASSWORD=...      # a super admin on that server
npm run e2e                                # builds, serves on :5173, runs desktop and phone-360 projects
```

Set `E2E_DASHBOARD_URL` and `E2E_NO_SERVER=1` to test an already deployed dashboard (for example the one behind your nginx config, which also checks the real CSP).
Sign-in is limited to 20 per minute per address on the API, so if you run the suite repeatedly raise `THROTTLE_LOGIN_LIMIT` on the test server.
Setup creates one account per role and switches them off afterwards.

What they cover that jsdom cannot: real cookie flags, CSP enforcement, framing, two tabs sharing a session, real colour contrast (axe), 360px layout and 44px touch targets, keyboard focus, and print.
