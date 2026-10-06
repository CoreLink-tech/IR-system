# PHP Integration

The website talks to the Security API through the library in `integration/php/`.
Setup, configuration, the event calls and the rollout plan are in
[`integration/php/README.md`](../integration/php/README.md). This page explains how
the pieces fit and why they work the way they do.

## Flow

    Visitor -> [proxy / CDN] -> PHP page
                                  |  bootstrap.php: find the visitor, check the blocklist
                                  |  page runs; Security::loginFailed(...) etc. collect events
                                  |  response is sent to the visitor
                                  v  after the response: events are delivered
                          Security API  <-- events (API key, scope events:write)
                          Security API  --> blocklist (API key, scope block:read), cached by the website

The visitor never waits for the Security API. The only network call on the page path
is the blocklist refresh, which one request at a time makes every 30 seconds, with a
short timeout, while the others carry on with the previous copy.

## Decisions that matter

- **Blocking is enforced on the website.** The platform keeps the authoritative list;
  the website enforces it. The platform cannot see whether a block was applied.
- **Fail open.** A security outage must not take the shop offline. With no blocklist
  available, visitors are let in. "Could not ask" is never treated as "nothing is blocked":
  a failed refresh keeps the previous list.
- **The visitor address is only taken from forwarding headers when the connection is
  from a trusted proxy.** Otherwise anyone could forge a header to hide, or to get an
  innocent address blocked. The rightmost address that is not a trusted proxy is used,
  never the leftmost, which the visitor controls.
- **Addresses mean the same on both sides.** Shorthand, octal and hexadecimal forms
  are rejected, IPv4-mapped IPv6 becomes IPv4, and IPv6 is written one canonical way.
  `integration/shared/ip-vectors.json` holds 95 cases that both the server tests
  (Jest) and the PHP tests must pass.
- **Private and loopback addresses are never blocked.** The website cannot lock
  itself or its proxy out, even if the blocklist contains such an address.
- **Secrets stay home.** Passwords, tokens and similar are redacted before sending,
  and the session id is replaced by a one-way token.
- **Events are never stored twice.** Every event gets its own id when it happens. If a
  delivery times out after the server had already stored the event, the retry carries the
  same id and the server keeps one copy. Queued events are also sent on any later page view,
  not only when something new is reported.
- **Events survive outages.** Undelivered events are queued on disk, bounded in size,
  and sent later with their original timestamps (the server accepts old events and
  rejects ones from the future). An event the server rejects with a 4xx is dropped,
  not retried forever.
- **The API key has two scopes only.** `events:write` and `block:read`. A leaked key
  cannot read incidents, change blocks or see reports.

## Event types the server understands

| Helper | Event type | Default severity |
|--------|-----------|------------------|
| `loginFailed` | `login_failed` | MEDIUM |
| `loginSuccess` | `login_success` | INFO |
| `logout` | `logout` | INFO |
| `passwordReset` | `password_reset` | LOW |
| `adminAccess` | `admin_access` | INFO |
| `accountChange` | `account_change` | MEDIUM |
| `paymentIssue` | `payment_security_event` | MEDIUM |
| `sessionAnomaly` | `session_anomaly` | MEDIUM |
| `suspiciousRequest` | `suspicious_request` | HIGH |
| `rateLimited` | `rate_limit_exceeded` | LOW |

The detection rules read `login_failed`, `login_success`, `password_reset`,
`admin_access`, `payment_security_event` and `session_anomaly`, and always send the
`user_id` when you give one. The account-based rules (distributed attacks on one
account, takeover, impossible travel) need `user_id` on both failed and successful
logins.

## Operations

- `php bin/doctor.php` checks configuration, the state folder, address detection and
  API access. Run it after any change.
- State lives in `SECURITY_STATE_DIR`: the blocklist cache, breaker state and event
  queue. It is safe to delete; the library rebuilds it.
- `SECURITY_ENABLED=false` is the kill switch.
- Watch the error log for `[pishon-security]` lines. The ones to alert on:
  `security_api_key_rejected`, `security_blocklist_refresh_failed` repeating,
  `security_spool_full` and `security_state_dir_unusable`.
