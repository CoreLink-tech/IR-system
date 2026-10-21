# API Reference

Base URL: http://host:4000
All requests JSON. All responses include X-Request-Id.

## Authentication

Admin (JWT): Authorization: Bearer <accessToken> from POST /api/v1/auth/login.
API Key (website): Authorization: Bearer IRS_xxx. Scopes enforced per endpoint.

Two ways to hold the long-lived refresh token:

- **Non-browser clients** (scripts, the PHP library): the token is in the response body and
  is sent back in the body of refresh and logout. Unchanged since Stage 1.
- **Browsers** (the dashboard): send `"useCookie": true` on login. The refresh token is then
  set in an `httpOnly`, `SameSite=Strict` cookie named `ir_rt`, scoped to `/api/v1/auth`
  (`Secure` in production), and is left out of the response body. Refresh and logout then
  read the cookie, and must carry `Origin` (exactly one of `CORS_ORIGINS`) and an
  `X-CSRF-Token` header. See "Cookie sessions" below.

## Endpoints

### POST /api/v1/auth/login
Body: { "email": "...", "password": "...", "useCookie": true? }
Returns { user, accessToken, refreshToken } (body mode), or { user, accessToken, csrfToken }
and a `Set-Cookie` (cookie mode). `user` is { id, email, name, role, isActive, mustChangePassword }.

### POST /api/v1/auth/refresh
Body: { "refreshToken": "..." } for body mode. With no body token the cookie is used (cookie
mode: needs `Origin` and `X-CSRF-Token`). Refresh tokens rotate; the answer carries the new
token (body or cookie) and, in cookie mode, a new `csrfToken`. Re-using an old token ends
all of that user's sessions and answers 401 with `code: "refresh_token_reuse"`. A session that was ended
on purpose (signed out, ended from the sessions page, password changed) answers 401 with
`code: "session_ended"` and does not affect the account's other sessions.

### Sign-in lockout
After repeated wrong passwords for one email address (5 by default), `POST /auth/login` answers
`429` with `code: "account_locked"`, `retryAfterSeconds` and a `Retry-After` header, without checking the
password. The attempt that triggers the lock answers `401` with `code: "invalid_credentials"` and
`retryAfterSeconds`. A real and an invented address behave identically. `POST /auth/users/:id/unlock`
(super admin) lets the account sign in at once. `GET /auth/users` includes `lockedUntil` (null when not
locked). See docs/SECURITY.md.

### Sessions
    GET    /api/v1/auth/sessions                          any role: my active sessions, newest use first
    DELETE /api/v1/auth/sessions/:id                      any role: end one of MY sessions
    POST   /api/v1/auth/sessions/revoke-all               any role: sign me out everywhere, at once
    GET    /api/v1/auth/users/:id/sessions                super admin: another account's sessions
    DELETE /api/v1/auth/users/:id/sessions/:sessionId     super admin: end one of its sessions
    POST   /api/v1/auth/users/:id/sessions/revoke-all     super admin: sign that account out everywhere

A session is { id, device, ipAddress, createdAt, lastUsedAt, expiresAt, current }. `device` is a label such
as "Chrome on Windows", made from the browser's user agent for the owner to recognise. Tokens are never
returned. The routes for "my" sessions take the account from the access token, never from the URL: an id that
belongs to someone else answers 404. Ending one session stops its refresh token at once; its access token (at
most 15 minutes old) works until it expires. "Sign out everywhere" and a password change end access tokens
immediately (`401 session_ended`).

### POST /api/v1/auth/logout
Body: { "refreshToken": "..." } or the cookie (same checks as refresh). Clears the cookie.

### GET /api/v1/auth/csrf — public, needs the cookie
Returns { csrfToken } for the cookie's refresh token. Another website cannot read this answer
(CORS), so it cannot forge a refresh. A page that has just reloaded holds only the cookie, so
it asks here first. 401 `no_session` if there is no valid cookie.

### Cookie sessions: the checks
1. `SameSite=Strict`: the browser does not send the cookie from another site.
2. `Origin` must match an entry of `CORS_ORIGINS` exactly (no wildcard, prefix or suffix match).
3. `X-CSRF-Token` must equal the token derived from the refresh token (HMAC with
   `JWT_REFRESH_SECRET`). It changes whenever the refresh token rotates.
Failures answer 403 with `code: "origin_not_allowed"` or `"csrf_invalid"` and consume nothing.

### GET /api/v1/auth/me — JWT (any role)
The signed-in account: { id, email, name, role, isActive, mustChangePassword }.

### GET /api/v1/health — public
{ status: "ok", service, version, time }. No database call and no secrets. A readiness check that
tests the database is Stage 10.

### GET /api/v1/settings/operational — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Read-only operational facts: version, intelligence providers, auto-block settings, rate limits,
risk-level thresholds, token lifetimes and whether the cookie is `Secure`. Never a secret, key,
connection string or origin.

### POST /api/v1/events — API key, scope events:write
Body fields: event_type, severity, ip_address, user_id, session_id,
user_agent, request_method, request_path, request_id, metadata, timestamp.
Returns { id, riskScore, riskLevel, incidentId }.

Valid event_type values:
login_failed, login_success, password_reset, account_change, admin_access,
suspicious_request, rate_limit_exceeded, payment_security_event,
application_error, server_error, logout, session_anomaly.

### GET /api/v1/events — JWT
Query: page, pageSize, sortBy, sortOrder, eventType, severity, ipAddress, userId, from, to.

### GET /api/v1/events/:id — JWT

### GET /api/v1/incidents — JWT
Query: page, pageSize, sortBy, sortOrder, status, severity, sourceIp, assignedTo, search.
`search` matches the start of an address or of the public number (INC-...); only characters that
can occur in either are used. Sortable: createdAt, updatedAt, riskScore and the other plain columns.
Note `severity` sorts alphabetically, not by seriousness; sort by `riskScore` for that.
Each row carries `assignee`: { id, email, name } or null.

### GET /api/v1/incidents/:id — JWT
`:id` is the internal id or the public number (INC-...), as the report routes already accepted.
Returns incident + `assignee` + timeline + related events (the 200 most recent; omitted for viewers).

### POST /api/v1/incidents/:id/notes — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)
Body: { "note": "1 to 2000 characters" }. Adds a `note.added` entry to the timeline and changes
nothing else (not the status, assignee or last-updated time). Audited; the audit entry records the
length of the note, not its text.

### POST /api/v1/incidents/:id/status — JWT (SECURITY_ADMIN, ANALYST)
Body: { "status": "INVESTIGATING", "notes": "..." }

### POST /api/v1/incidents/:id/assign — JWT (SECURITY_ADMIN)
Body: { "assignedTo": "<userId>" }

### GET /api/v1/ips — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)
Query: page, pageSize, sortBy (lastSeenAt, firstSeenAt, riskScore, eventCount, failedLogins,
ipAddress), sortOrder, riskLevel, blocked (true or false), country, search. `search` matches the
start of an address and strips anything that cannot be part of one. Each row is the address record
plus `blocked`: true while an active block is in force (the same test the website uses).

### GET /api/v1/ips/:ip — JWT

### POST /api/v1/ips/:ip/refresh-intelligence — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)
Forces a fresh provider lookup, bypassing the 24 hour cache. Returns the merged
intelligence and the list of active providers. Returns 404 for an invalid address.

### GET /api/v1/security/blocked-ips — JWT or API key with block:read
Returns only active blocks. Used by the website middleware. The same route serves
administrators (any role) and the website's key (scope `block:read`).

### GET /api/v1/security/blocks/history — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST) or API key with block:read
Optional `ip` and `limit` (1 to 500, default 100).

### POST /api/v1/security/block — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Body: { ipAddress, reason, permanent, ttlMinutes, relatedIncidentId }

### POST /api/v1/security/unblock — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Body: { ipAddress, reason }

### POST /api/v1/security/allow — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Body: { ipAddress, reason, ttlMinutes }

### DELETE /api/v1/security/allow/:ip — JWT (SUPER_ADMIN, SECURITY_ADMIN)

### GET /api/v1/statistics — JWT

### GET /api/v1/audit-logs — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)

### API Keys — JWT (SUPER_ADMIN, SECURITY_ADMIN)
GET    /api/v1/api-keys
POST   /api/v1/api-keys           returns raw key ONCE
POST   /api/v1/api-keys/:id/rotate
DELETE /api/v1/api-keys/:id       revoke

A revoke (DELETE) answers { id, name, isActive, revokedAt } only. The stored hash never leaves the server.

### Users — JWT (SUPER_ADMIN)
POST   /api/v1/auth/users                       body: email, password (12+), name?, role, requirePasswordChange?
GET    /api/v1/auth/users                       { data: [ { id, email, name, role, isActive, mustChangePassword, lastLoginAt, createdAt } ] }
PATCH  /api/v1/auth/users/:id                   body: { role?, isActive? }
POST   /api/v1/auth/users/:id/reset-password    body: { newPassword } (12 to 128). Returns { ok: true }.
GET    /api/v1/auth/assignees                   (SUPER_ADMIN, SECURITY_ADMIN) { data: [ { id, email, name, role } ] }, active accounts, for assigning incidents

Safeguards, enforced by the server (not only the dashboard):
- Nobody changes their own role or deactivates themselves (400, `self_change_forbidden`), and
  cannot reset their own password this way (400, `self_reset_forbidden`; use change-password).
- The last active super admin cannot be demoted or deactivated (409, `last_super_admin`). The
  check and the change run in one serializable transaction, so two super admins demoting each
  other at the same moment cannot both succeed.
- Deactivating an account, or resetting its password, revokes all of its refresh tokens. A role
  change or deactivation applies to the very next request, because roles are read from the database.
- A reset sets `mustChangePassword`. Until the person changes it, the server answers 403
  `password_change_required` to every route except `GET auth/me` and `POST auth/change-password`.
  Accounts created with `requirePasswordChange: true` are treated the same way.
- Every change is audited (`user.update` with old and new values, `user.password_reset`), including refusals.

### Detection rules — JWT (SUPER_ADMIN, SECURITY_ADMIN)
GET    /api/v1/rules                  { data: [ { code, title, name, description, whyItMatters, isEnabled, priority, config, defaultConfig, isDefault, limits, updatedAt } ] }
PATCH  /api/v1/rules/:code            body: { isEnabled?, config? (only the settings to change), reason? }
POST   /api/v1/rules/:code/reset      body: { reason? } puts every setting back to its default; on or off is untouched

- Every setting has a range (`limits`, whole numbers) and some pairs must stay in order (for example
  the risk added per attempt cannot exceed the maximum risk). Out-of-range, fractional, unknown
  settings and anything with a prototype-style name are refused with a list of problems (400).
- `windowMinutes` is shown but cannot be changed: the detector always counts the last 10 minutes,
  so editing it would change only the wording of reasons.
- The full set of settings is always stored, so a partial change never leaves a setting undefined.
- Changes apply to the next event. Each change is audited with the old and new values and the
  optional reason (`rule.update`, `rule.reset`); nothing is written or audited if nothing changed.

## Error format

    {
      "statusCode": 400,
      "message": "...",
      "path": "/api/v1/events",
      "method": "POST",
      "requestId": "...",
      "timestamp": "2025-01-01T12:00:00.000Z",
      "code": "..."            (only when there is a specific reason)
    }

`message` is a string, or an array of strings for validation errors. `code` values:
`refresh_token_reuse` (a used refresh token was presented: all sessions ended), `session_ended` (this
session was ended on purpose or by a password change; sign in again), `no_session`,
`csrf_invalid`, `origin_not_allowed`, `password_change_required`, `self_change_forbidden`,
`self_reset_forbidden`, `last_super_admin`, `weak_password` (the new password failed the password policy; `message`
lists every reason in plain sentences, see docs/SECURITY.md).

Every response, including errors raised by a guard (401, 403) and rate limit refusals (429), carries
a `requestId` in the body and in the `X-Request-Id` response header. A caller may supply its own
`X-Request-Id`; it is kept only if it is 8 to 64 characters of letters, digits and `. _ : -`, and is
replaced by a generated id otherwise, so it cannot forge or break a log line.

## CORS
`CORS_ORIGINS` is the exact list of dashboard origins. Credentials are allowed. The browser may
read the response headers `Retry-After` and `X-Request-Id` (they are exposed, so a dashboard on
another origin can show how long to wait after a 429), and may send `Authorization`,
`Content-Type`, `X-CSRF-Token` and `X-Request-Id`.

## Rate limits

Limits are counted per route. Administrators and anonymous callers are counted per
client address (default 120 requests a minute); signing in and refreshing are limited
more tightly (20 a minute). The website is counted per API key, with a much larger
allowance (default 6000 a minute), because every visitor's events arrive from one
server address. A refused request gets `429` and a `Retry-After` header in seconds.
Settings: `THROTTLE_LIMIT`, `THROTTLE_KEY_LIMIT`, `THROTTLE_LOGIN_LIMIT`, `THROTTLE_TTL`.

## Sending the same event twice

`POST /events` accepts an optional `event_id` (up to 64 characters of letters, digits,
dot, colon, underscore or hyphen). If the same API key sends the same `event_id` again,
for example after a timeout, the original event's result is returned with
`"duplicate": true` and nothing is stored a second time. Ids are scoped to the key.

## Reports

All report endpoints are read-only, require an administrator login (JWT), send
`Cache-Control: no-store`, and write each successful read to the audit log.
Add `?format=text` to get a plain-text version ready for email or printing.
Period endpoints accept `from` and `to` (ISO 8601) or `days` (1 to 366, default 7).
The period cannot exceed 366 days. Unknown query parameters are rejected with 400.

### GET /api/v1/reports/incidents/:id — JWT (any role)
Plain-English incident report for a non-technical reader. `:id` can be the
internal id or the public number (for example `INC-20261002-00001ABC`).
Sections: whatHappened, whyItMatters, riskLevel, evidence, actionTaken,
currentStatus, recommendedActions, plus a `limitations` list of things the report
cannot confirm. Returns 404 for an unknown incident.

### GET /api/v1/reports/technical/:id — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)
Technical detail for the same incident: raw rule codes and reasons, event counts by
type, top request paths (query strings removed), IP intelligence, block history,
timeline. JSON only.

### GET /api/v1/reports/executive-summary — JWT (any role)
Summary for the owner or CEO: posture (URGENT, ACTION_NEEDED, MONITORING,
ALL_CLEAR), headline, key numbers, items needing attention, notable incidents,
trend against the previous period of equal length, and limitations.

### GET /api/v1/reports/security-summary — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)
Aggregate view for the security team and dashboard charts: events by type and risk
level, incidents by severity, status and rule, top source addresses, response
metrics (unassigned open incidents, mean time to resolve), blocking totals, and a
daily series (UTC days) of events and incidents.
