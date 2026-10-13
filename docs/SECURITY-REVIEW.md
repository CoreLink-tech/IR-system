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

## Verification notes for workstream 1
- Backend: 715 tests passing, run against the repository's Prisma 5 package set (the Prisma engine is
  not needed by these tests, which use in-memory stand-ins).
- PHP: 211 checks passing on PHP 8.3.6. PHP 7.4 is not available in this environment: not verified.
- Not verified: behaviour behind a real nginx or CDN. Owner check: deploy with `TRUSTED_PROXIES` set to
  the proxy address, send a request with a forged `X-Forwarded-For`, and confirm the audit log shows the
  true address.
