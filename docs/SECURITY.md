# Security Model

## Threat Model
- Pishon server is trusted to send events with valid API key.
- Attackers may control X-Forwarded-For. Put a reverse proxy in front in production.
  (Trusting only a known proxy is tracked for Stage 10.)
- Addresses are parsed strictly: shorthand, hexadecimal and octal forms such as
  `127.1` or `010.0.0.1` are rejected rather than read as a different address.
- Loopback, private and link-local addresses can never be blocked, so the website
  cannot lock itself out. Automatic blocking never overrides an administrator.
- DB may be accessed by untrusted admins. All credentials hashed.

## Secrets

    Secret              Storage                              Algorithm
    Admin password      security_users.passwordHash          bcrypt cost 12
    API key             security_api_keys.keyHash            SHA-256(key + pepper)
    Refresh token       security_refresh_tokens.tokenHash    SHA-256
    JWT signing         env JWT_SECRET                       HS256
    DB password         .env                                 -

Never commit .env. Rotate JWT_SECRET and API_KEY_HASH_PEPPER if leaked.

### Startup check
The server refuses to start if a secret is missing, shorter than 32 characters
(16 for the pepper), still a placeholder from `.env.example`, or if the access and
refresh secrets are equal. The sample file ships a public placeholder; without this
check, copying it unchanged would let anyone forge an administrator login. Generate
real values with `npm run gen:secrets`. `CORS_ORIGINS` may not be `*`. Seeding
production requires an explicit `BOOTSTRAP_ADMIN_PASSWORD`.

## Rate limiting
Counted per route. Administrators and anonymous callers per address, sign-in and token
refresh much tighter (20 a minute), and the website per API key with a large allowance, so
a busy shop is not refused during an attack and a leaked key is still bounded. Refusals
carry `Retry-After`.

## Concurrency
Parallel requests from one attacker are safe: the database itself allows one open incident
per address, account or attack and one active block per address, counters are incremented
in the database, and an event sent twice with the same `event_id` is stored once.

## Authentication
- Login compares the password even for an unknown email or a disabled account, so
  response time does not reveal which emails exist.
- Refresh tokens rotate on every use. Presenting an already-used token is treated as
  theft: every session for that user is ended and the event is audited.
- Changing a password revokes all sessions, requires the current password and a
  different new one, and is audited, as are failed attempts and user creation.
- Roles are read from the database on every request, so a role change or a disabled
  account takes effect immediately, not when the token expires.

## Browser sessions (the dashboard)
- The short-lived access token lives only in the dashboard's memory. It is never written to
  storage, a cookie or a URL.
- The refresh token never reaches JavaScript. It is an `httpOnly`, `Secure` (in production),
  `SameSite=Strict` cookie scoped to `/api/v1/auth`, so ordinary API calls do not carry it and an
  injected script cannot read it. The cost: a script running in the page can still *use* the
  session while the page is open (call the API as the user), which is why the CSP below matters.
- Refresh and logout from the cookie are protected against cross-site requests three ways
  (SameSite, an exact `Origin` check, and an `X-CSRF-Token` bound to the refresh token).
- Rotating refresh tokens plus theft detection make two tabs refreshing at once look like theft,
  so the dashboard serialises refreshes across tabs with a Web Lock and shares the new token
  through a BroadcastChannel. Signing out, or a detected reuse, in one tab ends all tabs.
- The dashboard signs out after a period of inactivity (default 30 minutes, `idleTimeoutMinutes`
  in its `config.json`), and returns the person to the page they were on, accepting only a
  same-site path (no open redirect).
- The cookie must be same-site with the API (for example `dashboard.example.com` and
  `api.example.com`), because `SameSite=Strict` cookies are not sent for a different site.
- Known limit: access tokens are not revoked one by one. The server re-reads the account on every
  request, so deactivating an account or changing its role takes effect at once, and an admin
  password reset leaves old access tokens able to do nothing but change the password (the
  `mustChangePassword` check). But a password change by the person themselves revokes refresh tokens
  only: an access token already issued keeps working until it expires (15 minutes by default).

## Dashboard hosting
`frontend/deploy/nginx.conf.example` and `security-headers.conf` set a strict Content-Security-Policy
(`default-src 'none'`; scripts, styles, images and fonts only from the site; `connect-src` only the
API; no inline script, no eval; `frame-ancestors 'none'`), `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
`Cross-Origin-Resource-Policy` and HSTS. Nothing loads from another site: fonts and icons are local.
All server text is rendered as text (no `dangerouslySetInnerHTML`, enforced by a test). A test also
fails if the dashboard compares role names itself instead of using the generated route matrix.

## Access control
Every route's protection is checked by `test/route-policy.spec.ts`, which reads the
decorators and fails if a route becomes unprotected or a sensitive route opens to a
wider role. Viewers can read the plain-English reports, incident summaries and the
blocklist, but not raw events, audit logs, API keys, technical reports or block
history, and they cannot change anything.

## Data stored from events
Metadata fields with sensitive names (password, token, secret, cookie, card number,
pin, otp, key and similar) are replaced with `[REDACTED]` at any depth. Short words
such as `pin` match only as whole words, so `shipping_address` is kept. Sensitive
query parameters in a request path (for example a reset token) are redacted too,
while the rest of the path is kept so injection attempts remain detectable. Events
dated more than 5 minutes in the future are rejected.

## Input Validation
Every endpoint uses a DTO with class-validator.
ValidationPipe runs with whitelist, forbidNonWhitelisted, transform.
Extra fields rejected.

## SQL Injection
All queries go through Prisma. Two report aggregations use `$queryRaw` with tagged
template parameters (never string concatenation), so values are always bound.
Sort columns on list endpoints are checked against an allowed list.

## Logging
AuditService writes: requestId, actorType, actorId, action, targetType,
targetId, result, ipAddress, userAgent, metadata.
Passwords, tokens, API keys never logged. Event metadata scrubbed.

## Response Hygiene
- AllExceptionsFilter returns uniform error shape.
- Stack traces server-side only.
- JWT secrets, DB URLs, hashes never serialized.

## Headers
Helmet applied globally. CORS strict from CORS_ORIGINS.

## Rate Limiting
ThrottlerModule global bucket. Tune with THROTTLE_TTL and THROTTLE_LIMIT.

## Blocking Safety
- Automatic blocks temporary by default.
- Skipped for allowlisted IPs.
- Recorded in audit with actorType SYSTEM.
- Permanent only manual via POST /security/block with permanent: true.

## Endpoint Permissions

    Endpoint                           Who
    POST /api/v1/security/block        SUPER_ADMIN, SECURITY_ADMIN
    POST /api/v1/security/unblock      SUPER_ADMIN, SECURITY_ADMIN
    POST /api/v1/security/allow        SUPER_ADMIN, SECURITY_ADMIN
    API key management                 SUPER_ADMIN, SECURITY_ADMIN
    User management                    SUPER_ADMIN
    Detection rules (read, change)     SUPER_ADMIN, SECURITY_ADMIN
    Operational settings (read)        SUPER_ADMIN, SECURITY_ADMIN
    Address list, incident notes       SUPER_ADMIN, SECURITY_ADMIN, ANALYST
    Read events/incidents              all 4 roles
    Update incidents                   SUPER_ADMIN, SECURITY_ADMIN, ANALYST

## Deployment Checklist
- Reverse proxy (nginx/Caddy) terminating HTTPS
- NODE_ENV=production
- Strong JWT_SECRET, JWT_REFRESH_SECRET, API_KEY_HASH_PEPPER (64+ bytes)
- CORS_ORIGINS restricted to the dashboard's exact origin(s)
- COOKIE_SECURE left at its default (on in production); the dashboard served over HTTPS and
  same-site with the API
- Dashboard served with the headers in frontend/deploy/security-headers.conf
- DB user privileges on pishon_market.security_* tables
- Logs shipped off-host
- Backups of security_* scheduled
- Pishon PHP middleware enabled with blocklist cache
