# Security Model

## Threat Model
- The website server is trusted to send events with valid API key.
- Attackers may control X-Forwarded-For and X-Real-IP. The API ignores both unless the
  connection comes from a proxy listed in `TRUSTED_PROXIES` (see "Client addresses" below).
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

## Client addresses
One function (`extractIp` in `backend/src/common/utils/ip.util.ts`) decides who a caller is. The
rate limit tracker, audit records, login records and event ingestion all use it, and Express's
`trust proxy` setting is derived from the same rule (`configureApp`).

- `TRUSTED_PROXIES` lists the reverse proxies whose headers are believed: addresses, CIDR blocks, or
  the word `private`. The default is empty, which means forwarding headers are ignored and the
  connection address is used. An invalid entry stops the server from starting.
- Behind a trusted proxy, `X-Forwarded-For` is read from the right, skipping trusted hops. The first
  address that is not a trusted proxy is the caller. Entries on the left are whatever the caller
  claimed and are never reached.
- A malformed or empty entry, a header longer than 2048 characters or one with more than 32 entries
  means the header cannot be relied on, and the connection address is used.
- `CLIENT_IP_HEADER` (for example `CF-Connecting-IP`) may name a header the proxy sets. It is used only
  behind a trusted proxy and falls back to the forwarding chain if it is malformed.
- `X-Real-IP` is never read.
- The PHP library follows the same rules. Both sides run `integration/shared/forwarding-vectors.json`
  (47 cases), so they cannot drift apart.
- If the API runs behind a proxy and `TRUSTED_PROXIES` is empty, every caller looks like the proxy and
  shares one rate limit. Startup prints a warning in production for this case.

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

## Sign-in lockout

In addition to the per-address limit (20 sign-ins a minute), each **email address** has its own counter, so
an attacker spread over thousands of addresses still hits one wall per account.

- The first 5 wrong attempts are free. The 5th (still checked) starts a 30 second lock. When it ends, one more
  attempt is allowed; if that is wrong, the lock is twice as long (30, 60, 120, 240, 480, then 900 seconds, the
  cap). A lock always ends by itself, and failures are forgotten after an hour without a new one.
- Attempts are counted, and the lock set, **before** the password is checked. So even a burst of simultaneous
  attempts gets no more than 5 password checks per lock window (tested with 60 requests at once, and with 40
  over 10 real database connections). While locked the password is not checked at all, and attempts made during a
  lock never make it longer.
- Counted per email address whether or not an account exists, so a real and an invented address behave
  identically (same statuses, messages and shape). The address is stored only as a SHA-256 hash.
- The 5th wrong attempt answers 401 with `retryAfterSeconds`; further attempts answer 429 `account_locked` with
  `retryAfterSeconds` and a `Retry-After` header.
- Every lock is written to the audit log (`auth.lockout`: who, from where, failures, delay), never the password.
- **Unlock.** A super admin can unlock an account at once (`POST /auth/users/:id/unlock`, audited), and the user
  list shows who is locked. An administrator password reset also clears the lock.
- **Trusted networks.** `LOCKOUT_EXEMPT_NETWORKS` (addresses, CIDR blocks, `private`) are never locked out, so
  administrators on the office or VPN network cannot be held up. The address used is the one the server
  determines (see "Client addresses"), never a header an outsider sets. List only networks you trust: sign-ins
  from them are limited only by the per-address limit.
- Settings: `LOCKOUT_THRESHOLD` (5), `LOCKOUT_BASE_SECONDS` (30), `LOCKOUT_MAX_SECONDS` (900),
  `LOCKOUT_RESET_MINUTES` (60). Invalid values stop the API from starting.
- If the only super admin is locked and cannot wait: the lock ends by itself in at most 15 minutes, or on the
  database server run `DELETE FROM security_login_throttle;` (this forgets every account's failures).

**Residual risk, stated plainly.** Any lockout lets someone who knows an administrator's email address slow
that administrator's sign-in. The delays are capped at 15 minutes and expire, attempts during a lock do not
extend it, and the cheapest attacker move (one attempt just as each lock ends) costs them a request every few
minutes. They cannot get in, and they cannot lock the account permanently, but they can make signing in
slower for as long as they keep at it. Mitigations in place: the exempt networks above, super admin unlock,
audit of every lock, the per-address limit (which stops one address from locking many accounts). Not
done: a "known device" exemption. Owner: whoever runs the deployment, to set `LOCKOUT_EXEMPT_NETWORKS`.

## Password policy

Applies when an account is created, when an administrator sets a temporary password, and when someone
changes their own (which still needs the current password). The server checks, and tells the person in plain
sentences, every problem it finds at once (`400`, `code: weak_password`, `message` is a list):

- 12 to 128 characters.
- Not only numbers.
- Not a very common password, and not a common password with a few characters added (`Password123456!`,
  `Qwerty123456`). Look-alike characters count as the same (`P@ssw0rd` is `password`). A long passphrase that
  merely contains a common word is fine.
- Not the same character or short pattern repeated, not a run in order (`abcdefghijkl`, `123456789012`),
  not a keyboard walk (`asdfghjklzxc`).
- Not containing the person's email name or their own name (for an administrator's temporary password, checked
  against the person it is for).

Limits you should know: the built-in list is about 400 entries, the passwords and words attackers try first. It is
not a breached-password database. To block more, set `PASSWORD_BLOCKLIST_FILE` to a text file with one password
or word per line (`#` comments allowed, up to 50 MB). It is read again when the file changes, no restart
needed, and the API refuses to start if the file is set but missing. Checking passwords against an online
breach service was left out on purpose (it would make sign-up depend on another company's server).

## Sessions and ending them

A sign-in is a session. The refresh token is replaced on every use, so each token row carries a
`sessionId` that stays the same, which is what the sessions page lists (device label, address, started,
last used). Every access and refresh token carries the account's **token version** (`tv`) and its session
(`sid`).

- **Ending everything at once.** Changing your own password, "sign out everywhere", an administrator
  resetting a password or signing an account out, all raise the account's token version. The server reads
  the account on every request already, so a token with an old version is refused immediately with
  `401 session_ended`. There is no waiting for the 15 minute access token to expire. Tokens issued before
  this feature existed carry no version and count as version 0, so deploying it signs nobody out.
- **Ending one session.** Its refresh token stops working at once. Its current access token (at most 15
  minutes old) keeps working until it expires, because checking the session on every request would add a
  second database lookup to every request. If that delay matters for a lost device, use "sign out
  everywhere" instead, which has no delay.
- **Why two different responses to a revoked token.** A token that was already replaced and is presented
  again means two parties hold the same token chain (the owner and possibly a thief), so every session of
  that account is ended (`refresh_token_reuse`). A session that was ended on purpose (signed out, ended from
  the sessions page, password changed) only fails with `session_ended`; it does not sign the owner out of
  their other devices. Each refresh token records why it was ended (`revokedReason`).
- A super admin can list and end another account's sessions, or sign the account out everywhere. Every one
  of these is in the audit log (`auth.session_revoke`, `auth.sessions_revoke_all`).
- Expired and revoked tokens are removed by the cleanup job (see docs/DATABASE.md). A revoked token that has
  not expired yet is kept, so replay of a stolen one is still recognised.

## Two-step verification

Authenticator-app codes (TOTP, RFC 6238) plus recovery codes. The backend is complete; the dashboard
screens and the break-glass CLI are part of the remaining Stage 10 work.

### When it is required
`REQUIRE_2FA` defaults to on when `NODE_ENV=production` and off otherwise. When it is on, every
`SUPER_ADMIN` and `SECURITY_ADMIN` must enrol before they can finish signing in. Other roles may
turn it on themselves from the settings page. The API refuses to start in production (or whenever
`REQUIRE_2FA` is true) if `TOTP_ENCRYPTION_KEY` is missing.

### Sign-in flow
1. Password is accepted. If the account has two-step verification, the response is
   `{ twoFactorRequired: true, challengeToken, expiresInSeconds: 300 }` and **no session is created**.
2. The client posts the challenge token plus a 6-digit code (or a recovery code) to
   `POST /auth/2fa/verify`. On success a normal session is started.
3. If two-step is required for the role and the account has not enrolled yet, the response is
   `{ twoFactorEnrollmentRequired: true, challengeToken }` instead. The client then calls
   `POST /auth/2fa/enroll/start` (returns the secret and otpauth URI) and
   `POST /auth/2fa/enroll/confirm` with the first code. Confirm returns the ten recovery codes
   once and starts the session.

The challenge token is a short-lived JWT (`typ: 'mfa'` or `'enroll'`, 5 minutes, bound to the
account's token version). It cannot be used as an access token.

### Enrolment and recovery codes
- The secret is generated server-side, encrypted at rest with AES-256-GCM under
  `TOTP_ENCRYPTION_KEY` (64 hex characters or base64). The ciphertext carries a key fingerprint so
  a previous key (`TOTP_ENCRYPTION_KEY_PREVIOUS`) still decrypts older secrets during a key change.
- Ten recovery codes (80 bits each, shown as `XXXX-XXXX-XXXX-XXXX`) are issued once. Only HMAC
  hashes are stored. Each code is consumed by a single conditional `UPDATE`, so two simultaneous
  uses cannot both succeed.
- Clock window: `TOTP_WINDOW` (0, 1 or 2; default 1). Replay protection: the time step of a
  successful code is claimed with a conditional update, so the same code cannot be reused even
  inside the window.
- Code attempts are rate-limited per account with the same growing delays used for passwords
  (key `mfa:<userId>`). A locked second step answers `429 two_factor_locked`.

### Administrator actions
- `GET /auth/2fa` returns status (enabled, recovery codes remaining, required or not).
- Regenerate recovery codes or turn two-step off: both require the current password **and** a
  current code. Disable is refused for roles that must use it.
- Super admin only: `POST /auth/users/:id/2fa/reset` clears the secret and codes, ends every
  session of that account, and is audited. You cannot reset your own account this way
  (`self_reset_forbidden`). After a reset the person must enrol again at next sign-in if the role
  requires it.
- Break-glass and key-change CLI (run from the backend directory after `npm run build`):
  - `npm run admin:reset-2fa -- <email>` clears two-step verification, ends all sessions of that
    account, and is audited as SYSTEM / "cli". The person must enrol again at next sign-in if the
    role requires it.
  - `npm run admin:unlock -- <email>` clears the sign-in lockout so the next five attempts are free
    again. Also audited as SYSTEM / "cli".
  - `npm run admin:reencrypt-2fa` (optional `--dry-run`) re-encrypts every stored TOTP secret with
    the current `TOTP_ENCRYPTION_KEY`. Use after setting the old key as
    `TOTP_ENCRYPTION_KEY_PREVIOUS`. Skips secrets already on the current key (resumable).
    Recovery-code hashes already verify under both keys. After every secret uses the current key
    you may remove the previous key; any recovery codes that were never re-hashed under the new
    key will then stop working until the user regenerates them.
  Commands exit 0 on success and 1 on failure (unknown email, missing secrets, etc.).

### Residual risks (honest)
- A borrowed unlocked phone or laptop that already has an active session can be used until the
  session is ended.
- Recovery codes are only as safe as the place the user stores them. They are shown once; the
  server never has the plain text again.
- TOTP is phishable by a live relay (the attacker prompts the victim for the current code). This is
  a property of the protocol, not of this implementation. Hardware keys or passkeys would be a
  later improvement.
- The encryption key protects secrets at rest. If an attacker obtains both the database and the
  key they can forge codes for any enrolled account. Protect the key the same way you protect
  `JWT_SECRET`.

Settings: `REQUIRE_2FA`, `TOTP_ENCRYPTION_KEY`, `TOTP_ENCRYPTION_KEY_PREVIOUS`, `TOTP_ISSUER`
(default "Security Dashboard"), `TOTP_WINDOW` (default 1). Generate the encryption key with
`openssl rand -hex 32` or `npm run gen:secrets`.

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
- DB user privileges on shop.security_* tables
- Logs shipped off-host
- Backups of security_* scheduled
- PHP middleware enabled with blocklist cache
