# Testing

## Running the tests

    cd backend
    npm test            # 837 unit and HTTP-level tests (plus 7 real-database cleanup tests that run only against a scratch database)
    npm run test:cov    # same, plus coverage; fails if coverage drops below the floors
    npm run test:php    # the PHP library tests, three files (needs php with the curl extension)
    npm run test:all    # both

## What is covered

| Area | What the tests check |
|------|----------------------|
| Route policy | Every route is protected; no duplicate paths; the role matrix; viewers cannot change anything or read raw data; API keys can reach only three routes |
| Authentication | Login, token rotation, theft detection, logout, password change, user creation, timing equalization, audit entries |
| API keys | Create, verify, revoke, rotate, expiry, scope validation, the three guards |
| Event ingestion | Order of the pipeline, address normalization, timestamps, redaction of metadata and URLs, failure tolerance, DTO limits |
| Detection | All 16 rules, scoring, incident opening and escalation, grouping by address, account and platform, auto-block rules, address risk |
| Blocking | Block, unblock, allowlist, internal-address protection, automatic blocking never overriding an administrator |
| Reports | All wording, honesty rules, posture, scoped incidents, the HTTP endpoints |
| IP intelligence | Each provider, merging, caching, failure handling |
| Configuration | Startup refusal of placeholder and weak secrets |
| PHP library | Visitor address and trusted proxies, blocklist cache, circuit breaker, event queue and replay, redaction, guard modes, configuration, PHP 7.4 syntax check, end-to-end through a fake API (211 checks) |
| Sessions and token revocation | `test/sessions-http.spec.ts`: the real JWT strategy, guards, auth and sessions services over HTTP: list, end one, sign out everywhere, password change and administrator reset end access tokens at once, tokens from before the feature keep working, other accounts' sessions are out of reach. See docs/SECURITY.md |
| Password policy | `test/password-policy.spec.ts` (accepted and refused examples, look-alikes, patterns, the person's own details, the optional blocklist file) and the HTTP checks in `test/sessions-http.spec.ts` (create, change and administrator reset all enforce it, a refused change signs nobody out and leaks nothing). See docs/SECURITY.md |
| Retention | `test/retention.spec.ts` (settings and floors, lock, batching, evidence rules, retries, time limit, dry run) and `test/retention-db.spec.ts` against a real MySQL or MariaDB, including cleanup during live inserts. See `docs/DATABASE.md` |
| Build layout | `test/build-layout.spec.ts` (build must put main.js at dist/main.js) |
| Migrations | `test/migrations-static.spec.ts` (every schema table, column and index is in a migration; nothing destructive) and, against a real MySQL or MariaDB, `npm run verify:migrations` (migrations equal the schema, a Stage 1 database upgrades with data intact, stage detection). See `docs/DATABASE.md` |
| Client addresses | `test/client-ip.spec.ts`: 47 shared forwarding cases, spoofing from untrusted and trusted peers, multi-hop, duplicate headers, and HTTP-level proof that a forged X-Forwarded-For does not change the rate limit bucket, the audit record or the login record |
| Address parsing | One shared file of 95 cases, run by both the server tests and the PHP tests, so both sides agree on what an address means |

| Dashboard backend (Stage 9) | Cookie session flow over HTTP with the real auth service, CSRF and origin checks, user administration safeguards (self-change, last super admin, forced password change), rule limits and audit, address list filters, incident notes, health and settings (no secrets), the exported role matrix staying in sync with the route decorators |

## Dashboard tests (frontend/)

    cd frontend
    npm test               # 301 tests: components and pages for every role, API client, session, accessibility
    npm run test:coverage  # same, with floors: 95% statements and lines, 88% functions, 82% branches (about 99.5 / 85)
    npm run build          # typecheck, production build, and the bundle size budget
    LIVE_API=http://localhost:4000 LIVE_EMAIL=... LIVE_PASSWORD=... npm run test:live   # 10 tests, the real dashboard code against a live API
    SMOKE_API=... SMOKE_EMAIL=... SMOKE_PASSWORD=... npm run smoke                      # 403 contract checks against a live API
    npm run e2e            # Playwright browser tests (need a browser; not run where they were written)

What the 301 tests check: what each page shows, hides and disables for each of the four roles; that
no navigation entry or action is offered that the API's route matrix would refuse (the matrix is
generated from the route decorators and a backend test fails when it is stale); that the interface
shows the level the API returned and never derives one from a number; that no markup from the server
is interpreted; the refresh flow (one refresh shared by concurrent requests, theft detection, 401, 403,
429 with Retry-After, 5xx with the request id, network failure); that tokens are never stored or put
in a URL; sign-out and theft detection across tabs; the idle timeout; the safe return path after
sign-in; every error state on a real page; keyboard behaviour of tabs and dialogs; axe accessibility
checks on every page and on open dialogs; and WCAG AA contrast of every colour pair in both themes,
computed from the style sheet.

## Coverage floors

Wiring that needs a live database or the full framework (`main.ts`, `*.module.ts`,
the Prisma connection, the seed script) is excluded from the percentage and is
exercised by the live end-to-end run instead. Current coverage is about 91% of
statements and 92% of lines. The floors in `jest.config.js` are 88% statements,
75% branches, 82% functions and 89% lines overall, and 90 to 95% on the
security-critical files (authentication, API keys, guards, event ingestion,
blocking, address parsing, configuration check).

## Conventions

- Services are tested with small in-memory stand-ins for the database, so the tests
  run in seconds and need no setup.
- HTTP-level tests use the real guards, validation and error filter, with only the
  login check and the services replaced.
- A test that found a bug keeps a regression case named after the bug.

## What is verified, and what is not

Verified by running it: everything above; the dashboard's own code and pages against a live API on
MariaDB 10.11 (10 tests, 403 contract checks); the production build served by a real nginx with the
example configuration (history fallback, caching, 404 for missing files, headers); the parallel
demotion of the last two super admins on a live database (one succeeded, one was refused).

Not verified (state this to anyone relying on it): behaviour in a real browser (no browser could be
installed where this was built), so layout at 360 px, touch target sizes, print output, real colour
contrast, CSP enforcement and two real tabs are covered by jsdom stand-ins and by Playwright tests
that are written and typechecked but were never run; `prisma migrate deploy` (the schema engine could not be
downloaded, so the tables for the live runs were created by applying the migration SQL directly or from the schema by a script, with Prisma 6's
engine-free client and the MariaDB adapter, not the repository's Prisma 5); real MySQL; PHP 7.4 (PHP 8.3.6 was used).

## End-to-end suite

`e2e/run.mjs` starts nothing itself. It talks to a running API, database and the real PHP
library, with nothing mocked, and takes about two minutes. It is the check that the
pieces work together: attack to incident to block to the website refusing the visitor,
reports that quote the stored numbers, parallel traffic, rate limits, and recovery after
the API or database goes down. See `e2e/README.md`.

    E2E_CONFIRM=yes node e2e/run.mjs       # writes test data: use a test database

Stage 9 added scenario 14 (the dashboard): browser cookie sign-in, CSRF and foreign-origin refusals,
rotation and theft detection, the original body-token flow still working, forced password change,
user administration safeguards, rules (refused values, stored in full, audited, reset), the address
list, incident notes and lookup by public number, operational settings without secrets, a revoked key
returning no hash, and CORS. The whole suite then ran 154 checks (scenario 14 is 32 of them) with every check passing on
MariaDB 10.11; one scenario, the API outage, needs stop and start hooks and was skipped. It deliberately does not demote the last two super admins in parallel,
because on a shared database that could lock out the real administrator. Do that on a scratch
database: create two super admins, switch every other one off, and send both demotions at once.
Expect one success and one refusal with `last_super_admin`.

Sign-in is limited to 20 per minute per address, so running the suite twice within a minute makes
the second run's sign-ins fail. That is the limit working, not a bug.

## Not covered by unit tests

Behavior with the real Prisma 5 engine and MySQL (the end-to-end runs were made on
MariaDB with Prisma 6's driver adapter, because the sandbox could not download Prisma's
engine), and performance under sustained load. Load testing is Stage 10.
