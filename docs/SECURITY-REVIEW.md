# Security Review (Stage 10)

This file is built up workstream by workstream. Every finding lists its fix and the regression test
that fails without it. Items marked "not verified" say how the owner can check them.

## Findings

### F-01 Spoofable client address (open item 1)
- Where: `extractIp` took the first `X-Forwarded-For` entry from anyone, then `X-Real-IP`.
- Impact: an attacker chose the address used for rate limiting (fresh allowance per request by
  changing the header), the audit log and the login record (an attacker could frame another address
  or hide their own).
- Fix: `TRUSTED_PROXIES`; headers are used only from a listed proxy, read from the right.
- Regression tests: `test/client-ip.spec.ts` ("rate limit: an untrusted caller cannot get a fresh
  allowance by changing the header", "audit record: carries the connection address, not a forged
  one", "failed and successful sign-ins record the connection address when the header is forged"),
  plus 47 shared vectors also run by the PHP library.
- Check on the fix: with the protection removed (every peer trusted) the vector and spoofing tests fail.

### F-02 X-Real-IP trusted from anyone (new, not in the open list)
- Same impact as F-01. The old unit test asserted this behaviour, so it was never noticed.
- Fix: `X-Real-IP` is never read. Test: "never reads X-Real-IP, trusted proxy or not".

### F-03 Guard failures had no request id (open item 3)
- Fix: `requestIdMiddleware` runs before guards. 401, 403 and 429 carry `requestId` in body and header.
- Tests: "a 401 from a guard carries a request id", "a 403 ...", "a 429 carries a request id too".

### F-04 Caller-supplied request id was unvalidated (new)
- `X-Request-Id` was copied into logs and the response as sent. A caller could forge log lines or
  inject odd characters. Fix: kept only if 8 to 64 characters of `A-Za-z0-9._:-`.
- Test: "request ids: keeps a plain id and replaces anything that could forge a log line".

### F-05 Old tests encoded the vulnerability
- `controllers.spec.ts` asserted that a forged `X-Forwarded-For` became the recorded login address.
  Rewritten to assert the connection address.

### F-06 Over-long and over-deep forwarding chains (PHP and API)
- A very long header could be parsed at length. Both sides now treat more than 32 entries or more than
  2048 characters as unreliable. Vectors: "33 entries", "over-long header".

### F-07 Upgrading an older database left the one-per-slot protections unenforced (Workstream 3)
- Where: the Stage 8 fix for parallel incidents and blocks added `openKey` and `activeKey`, but nothing
  filled them for rows that already existed, and the documented upgrade was `prisma db push`.
- Impact: on an upgraded database, an existing open incident or active block held no slot, so the
  application could open a second open incident, or a second active block, beside it. The guarantee
  the Stage 8 tests proved applied only to new rows. Had an old database held duplicates, adding the
  unique index would also have failed.
- Fix: migration `20260101000200_stage8_unique_slots` backfills the slots with documented tie-breaks
  (nothing closed, no block deactivated), then adds the unique indexes.
- Regression proof: `npm run verify:migrations` section 2 (duplicate open incidents and active blocks,
  winners, nothing lost or reopened, second open incident and second active block refused afterwards).
  Removing the backfill makes it fail.

### F-08 Ingestion cost grew with an attacker's own traffic (Workstream 3)
- Where: detection looks up "events from this address in the last 10 minutes" for every event. With only a
  single-column address index, and the optimizer choosing between that and the time index, an address with 40,000
  stored events made each new event from it read about 20,000 to 40,000 rows (24 to 46 ms).
- Impact: the more an attacker sent, the more each of their events cost to process, which can be used to slow
  ingestion for everyone (a denial of service by amplification).
- Fix: composite indexes (address, time) and others, migration `20260101000500_stage10_indexes`. The same lookups
  read about 100 rows (0.0 to 0.2 ms). Details and measurements: docs/DATABASE.md, "Index review".
- Regression proof: `scripts/index-review.mjs` (the attacker queries must show the composite index and a small
  row count); `test/migrations-static.spec.ts` fails if the indexes disappear from the schema without a migration.

### F-09 The audit table grew with traffic and doubled the write work per event (Workstream 3)
- Where: every accepted event writes one `event.ingest` audit row in addition to the event itself
  (`events.service.ts`). With audit kept for a year and events for 90 days, the audit table would hold about
  four times as many rows as the events table, at about 550 bytes each.
- Impact: unbounded disk growth in the audit log; one extra insert, with six indexes, in the ingestion path of
  every event (this matters for the load tests in Workstream 7).
- Fix applied now: a separate, shorter limit for these rows (`RETENTION_INGEST_AUDIT_DAYS`, default 30) so the
  general audit log keeps its year.
- Open decision for the owner (to be settled with the Workstream 7 measurements): stop writing the per-event
  audit row, because the event row already records the key that sent it and when.
- Regression proof: `test/retention-db.spec.ts` (ingestion rows past 30 days removed, other audit rows
  untouched).

### F-10 The production start command did not work after a build (Workstream 3)
- Where: `npm run build` produced `dist/src/main.js`, but `npm run start:prod` runs `node dist/main.js`. A
  TypeScript file added under `scripts/` made TypeScript treat the backend folder, not `src/`, as the source
  root. Confirmed by building the repository and listing `dist/`.
- Impact: a deployment that followed the README (`npm run build`, then `npm run start:prod`) would fail to start.
- Fix: `tsconfig.build.json` now compiles `src/` only.
- Regression test: `test/build-layout.spec.ts`. A build-and-start check belongs in the CI workstream.

### F-11 A password change did not end the account's other access tokens (open item 2)
- Where: changing your own password revoked refresh tokens only. An access token already issued kept working
  for up to 15 minutes, on every device, including one in the hands of whoever the password change was meant
  to lock out.
- Fix: a per-account token version carried in every token and checked on every request (the account is read
  anyway, so there is no extra query). A password change, "sign out everywhere", an administrator password
  reset or sign-out raise it, and every token of the account is refused at once (`401 session_ended`).
  Alternative considered: shorter access tokens (for example 5 minutes), which only narrow the window and
  multiply refreshes. Remaining limit: ending a single session leaves its access token valid until it expires.
- Regression tests: `test/sessions-http.spec.ts` ("changing your own password ends the access tokens of your
  other devices at once", "sign out everywhere ...", "an administrator resetting a password ...", tokens from
  before the feature keep working). Removing the check, or the version bump on password change, makes them fail.

### F-12 Deliberately ended sessions were treated as theft (found while building the sessions page)
- Where: any revoked refresh token that was presented again ended every session of the account. With a
  sessions page that lets an owner (or an administrator) end one device, that device's next refresh would have
  signed the owner out everywhere.
- Fix: each token records why it ended. Only a token that was already replaced still triggers the theft
  response; a session ended on purpose only fails (`session_ended`).
- Regression tests: "ending one session ... does NOT end every session" and "a token that was already replaced
  and is presented again still ends every session (theft response kept)". Older rows with no recorded reason are
  treated as replaced, as before.

### F-13 No per-account protection against credential stuffing (open item 7, first part)
- Where: sign-in was limited per client address only (20 a minute). An attacker using many addresses (a botnet
  or rotating proxies) could guess at one administrator's password without any per-account limit.
- Fix: per-email lockout with growing, capped, self-expiring delays, counted before the password is checked
  (so simultaneous attempts cannot get around it), identical for real and invented addresses, audited, with
  super admin unlock and optional trusted networks. Details in docs/SECURITY.md.
- Tests that show it: 60 addresses guessing at one admin: exactly 5 password checks and 55 refusals, and the
  real admin signs in right after the delay; a 60-request simultaneous burst: still exactly 5 checks; one
  address against 40 accounts: no account locked, the address is stopped by the per-address limit, and the real
  admin signs in; real and invented addresses return identical responses. Breaking the lock check, or letting
  refused attempts extend the lock, makes them fail.
- Residual risk: an attacker who knows an administrator's email can slow that administrator's sign-in (see
  docs/SECURITY.md). Owner: the deployment owner, via `LOCKOUT_EXEMPT_NETWORKS`.

### F-14 Simultaneous sign-in attempts for one account deadlocked the counter (found while building F-13)
- Found only on a real database: with 40 simultaneous attempts for one account, InnoDB reported deadlocks
  (error 1213) and the first version of the counter, using INSERT IGNORE followed by SELECT ... FOR UPDATE,
  gave up. The cause is a lock upgrade (shared then exclusive) in that pattern. It would have turned a burst of
  attempts into server errors.
- Fix: take the exclusive lock directly (INSERT ... ON DUPLICATE KEY UPDATE), and retry deadlocks up to 6 times
  with jitter as a backstop. Verified: 40 simultaneous attempts on one account and 300 across five, three runs in a
  row, no errors (`test/login-throttle-db.spec.ts`). The in-memory tests could not have found it.

### F-15 In-memory tests could not prove atomic single use of a TOTP code or recovery code
- Where: recovery-code consumption and TOTP step claiming both use a conditional UPDATE so that two
  simultaneous successful checks cannot both succeed. An in-memory stand-in cannot prove database
  atomicity or isolation.
- Fix / evidence: real-database tests in `test/two-factor-db.spec.ts` (gated, run with
  `RETENTION_TEST_CONFIRM=yes` against a scratch `ir_*` database). Mutation check: removing the
  conditional clause makes the concurrent-use test fail; restoring it makes the test pass.
- Residual: the real-database suite must be run before go-live on the same engine the production
  deployment will use.

## Verification notes for workstream 1
- Backend: 715 tests passing, run against the repository's Prisma 5 package set (the Prisma engine is
  not needed by these tests, which use in-memory stand-ins).
- PHP: 211 checks passing on PHP 8.3.6. PHP 7.4 is not available in this environment: not verified.
- Not verified: behaviour behind a real nginx or CDN. Owner check: deploy with `TRUSTED_PROXIES` set to
  the proxy address, send a request with a forged `X-Forwarded-For`, and confirm the audit log shows the
  true address.
