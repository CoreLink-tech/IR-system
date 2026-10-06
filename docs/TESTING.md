# Testing

## Running the tests

    cd backend
    npm test            # 420 unit and HTTP-level tests
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
| PHP library | Visitor address and trusted proxies, blocklist cache, circuit breaker, event queue and replay, redaction, guard modes, configuration, PHP 7.4 syntax check, end-to-end through a fake API (198 checks) |
| Address parsing | One shared file of 95 cases, run by both the server tests and the PHP tests, so both sides agree on what an address means |

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

## End-to-end suite

`e2e/run.mjs` starts nothing itself. It talks to a running API, database and the real PHP
library, with nothing mocked, and takes about two minutes. It is the check that the
pieces work together: attack to incident to block to the website refusing the visitor,
reports that quote the stored numbers, parallel traffic, rate limits, and recovery after
the API or database goes down. See `e2e/README.md`.

    E2E_CONFIRM=yes node e2e/run.mjs       # writes test data: use a test database

## Not covered by unit tests

Behavior with the real Prisma 5 engine and MySQL (the end-to-end runs were made on
MariaDB with Prisma 6's driver adapter, because the sandbox could not download Prisma's
engine), and performance under sustained load. Load testing is Stage 10.
