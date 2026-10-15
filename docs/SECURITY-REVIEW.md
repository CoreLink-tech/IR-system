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

## Verification notes for workstream 1
- Backend: 715 tests passing, run against the repository's Prisma 5 package set (the Prisma engine is
  not needed by these tests, which use in-memory stand-ins).
- PHP: 211 checks passing on PHP 8.3.6. PHP 7.4 is not available in this environment: not verified.
- Not verified: behaviour behind a real nginx or CDN. Owner check: deploy with `TRUSTED_PROXIES` set to
  the proxy address, send a request with a forged `X-Forwarded-For`, and confirm the audit log shows the
  true address.
