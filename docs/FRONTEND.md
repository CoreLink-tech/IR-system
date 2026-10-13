# The dashboard (frontend/)

A React 18 + TypeScript + Vite single-page app that is built to static files and served by any web
server. It **displays what the Security API returns and nothing more**. It never decides that a
score is critical, that an address is blocked, what a report says or what to recommend: those come
from the API, and a test fails if the source compares a score with a number to pick a level.

## Architecture

    src/
      api/        client.ts (one fetch wrapper), session.ts (tokens, refresh, tabs, idle), hooks.ts (reads),
                  actions.ts (every change), errors.ts (plain-English errors), types.ts (API shapes)
      auth/       useSession.ts
      components/ Layout, guards (sign-in and role gates, error boundary), Dialog, table, Tabs, badges, ...
      pages/      one file per page (lazy loaded)
      lib/        permissions.ts + route-matrix.json, format.ts (labels), time.tsx, config.ts, useUrlState.ts
      styles/     global.css (tokens, light and dark, small screens, print)
    deploy/       nginx.conf.example, security-headers.conf

Choices: TanStack Query for reads and caching (nothing is cached across sign-outs), React Router,
plain CSS variables, no UI framework, no chart library (the chart is plain SVG with a table
alternative), no third-party fonts or scripts. Four runtime dependencies. Report types are imported
straight from `backend/src/reports/report.types.ts`, so a change there breaks the frontend build.

## Roles and what the interface offers

The role lists are not written in the frontend. `backend/scripts/export-route-matrix.ts` writes
`src/lib/route-matrix.json` from the API's own route decorators (`npm run export:routes` in
`backend/`), and a backend test fails if the file is stale. `lib/permissions.ts` names each thing the
interface offers (`blocks.block`, `rules.manage`, ...) and points it at a route; components only ask
`can(user, 'blocks.block')`. A test fails if any source file compares role names itself.

| | Viewer | Analyst | Security admin | Super admin |
|---|---|---|---|---|
| Overview (executive summary), incidents list, incident report and timeline, addresses (lookup, detail without events), blocked list and allowlist | yes | yes | yes | yes |
| Raw events, technical report, security summary and chart, address list, block history, audit log, refresh intelligence, change incident status, add notes | | yes | yes | yes |
| Block, unblock, allowlist add and remove, assign incidents, API keys, detection rules, settings | | | yes | yes |
| Users (create, change role, deactivate, reset password) | | | | yes |

A page the role cannot use shows "You do not have access to this page", never a blank screen.
Navigation shows only what the role may use.

## Pages

Sign in; Overview; Incidents (filters, sort, paging, all in the URL); Incident (report, timeline, technical,
actions); Addresses (lookup, list, detail); Blocking (blocked now, allowlist, history); Reports; Users;
API keys; Detection rules; Audit log; Settings; Change password. Every page has loading skeletons, empty
states, and a separate error state per panel, so one failed panel does not blank a page.

Plain English first: codes (rule codes, event types) appear only in the Technical tab and the audit
log's details. Vocabulary is fixed: address, block, incident, posture.

## Session and token handling (the decision)

| Secret | Where it lives | Why |
|---|---|---|
| Access token (15 min) | A variable in the tab's memory | Never in storage, a cookie or a URL, so reading the page's storage yields nothing |
| Refresh token (7 days) | An `httpOnly`, `Secure`, `SameSite=Strict` cookie set by the API, path `/api/v1/auth` | JavaScript cannot read it, and it is not sent with ordinary API calls |
| CSRF token | Memory; fetched from `GET auth/csrf` after a reload | Ties refresh and logout to a page that could read the API's answer |

The trade-off against keeping the refresh token in memory or storage: a cookie survives reloads and is
unreadable by script, but the browser sends it by itself, so refresh and logout need the CSRF protections
(SameSite, exact Origin check, bound token). What the design does not prevent: a script injected into the
open page can still call the API as the user; the strict CSP is what guards against that.

- Silent refresh runs a minute before expiry. On failure the person is signed out and returns to where they were.
- Refresh tokens rotate and a reused one ends all sessions. Two tabs refreshing together would look like reuse,
  so refreshes take a Web Lock and share the result by BroadcastChannel. A server outage during refresh is
  not treated as a sign-out.
- A 401 on a token that has not expired still triggers a refresh (the server may have revoked it).
- A wrong current password on the change-password page is shown as that, not as an ended session.
- Theft detection shows a clear message: all sessions were ended, sign in again, change your password if unexpected.
- Signing out, or an ended session, in one tab ends all tabs. Sign-out also empties the query cache.
- Idle timeout: 30 minutes by default (`idleTimeoutMinutes` in `config.json`), counted across tabs.
- Nothing logs tokens: a test fails on any `console.*` call or a token in a URL.

## Security of the page itself

Strict CSP and the other headers are in `deploy/security-headers.conf`. The page uses no inline script, no
`eval`, no `dangerouslySetInnerHTML`, no `target=_blank` links, and loads nothing from another origin (tests check
all of these). Report text and all other server text are rendered as text. Downloads, copying and printing happen
only when clicked. `CORS_ORIGINS` on the API must list the dashboard origin exactly.

## Configuration and deployment

`public/config.json` is read when the page starts, so one build serves any environment:

    { "apiBaseUrl": "https://api.example.com", "idleTimeoutMinutes": 30 }

Build (`npm run build`) typechecks, builds, and fails if the bundle exceeds its budget: initial JavaScript
110 KB gzipped (currently 81), any page chunk 25 KB (largest 4), CSS 12 KB (3.4). See `frontend/README.md` and
`deploy/nginx.conf.example`. The dashboard and API must be on the same site (for example `dashboard.example.com`
and `api.example.com`) because of `SameSite=Strict`.

## Adding a page

1. Add the API call to `api/hooks.ts` (a read) or `api/actions.ts` (a change). Reads and changes wait for the server; no optimistic updates for security actions.
2. If it is a new API route, add it to the matrix (`npm run export:routes` in `backend/`), and add a capability in `lib/permissions.ts`.
3. Write `pages/YourPage.tsx` using `QueryState` (loading, error, retry) and `ResponsiveTable`; gate it in `App.tsx` with `RequireCap`, and add a nav entry in `components/Layout.tsx`.
4. Use `describeError` for failures, `Time` for times, and the badges for severity and status (an icon and a word, never colour alone).
5. Add the page to `pages/a11y-and-states.test.tsx` and write role tests as the others do.

## What was and was not verified

See `docs/TESTING.md`. In short: verified with 301 jsdom tests, 10 tests and 403 contract checks against a live API on
MariaDB, and the production build behind a real nginx. **Never run in a real browser** (none could be installed): layout at
360 px, real colour contrast (checked by computing the ratios from the style sheet instead), print output,
CSP enforcement and real multi-tab behaviour are covered by `frontend/e2e/` (Playwright, written and typechecked, not run).

## Known limits

- The related-events table on an incident shows the 200 most recent events the API returns, paged in the browser.
- Incident lists sort by risk score, not by severity (the API sorts severity alphabetically).
- Assignee names are shown for incidents but analysts cannot see the user list; assignment is for security admins and above.
- The detection windows are fixed at 10 minutes in the detector, so that setting is shown read-only.
- Access tokens are not revoked individually; see `docs/SECURITY.md`.
