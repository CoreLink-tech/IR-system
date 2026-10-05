# PishonMarket PHP integration

A small library that connects the PishonMarket website to the Security API. It does
two jobs:

1. **Reports security events** (failed logins, password resets, payment problems and
   so on) so the Security API can detect attacks.
2. **Blocks visitors** that the Security API has put on its blocklist.

It is plain PHP with no framework and no Composer: copy the folder, set a few
environment variables, add two lines. It needs **PHP 7.4 or newer** and the **curl**
extension.

The library can never take the website down. If the Security API is slow or offline,
visitors are let in, events are kept on disk and sent later, and the page is not
delayed. Every call is safe to make at any time and never throws.

## 1. Install

Copy this folder to the web server, for example `/var/www/pishon/security/`.

Create an API key in the Security dashboard (or with `POST /api/v1/api-keys`) with
exactly two scopes, `events:write` and `block:read`, and nothing else.

Set the environment variables (in your web server, PHP-FPM pool, or `.env` loader):

| Variable | Meaning | Default |
|----------|---------|---------|
| `SECURITY_API_BASE` | Address of the Security API, `https://...` | required |
| `SECURITY_API_KEY` | The key created above | required |
| `SECURITY_MODE` | `monitor` logs who would be blocked, `enforce` blocks them | `monitor` |
| `SECURITY_TRUSTED_PROXIES` | Your proxy or CDN addresses, see section 2 | none |
| `SECURITY_CLIENT_IP_HEADER` | For example `CF-Connecting-IP`, only used behind a trusted proxy | none |
| `SECURITY_ENABLED` | `false` or `0` turns the whole library off | `true` |
| `SECURITY_STATE_DIR` | Private folder for the blocklist cache and event queue | system temp folder |
| `SECURITY_BLOCKLIST_TTL` | Seconds between blocklist refreshes | `30` |
| `SECURITY_API_TIMEOUT` | Seconds to wait for the API on each call | `1.0` |
| `SECURITY_FLUSH_BUDGET` | Seconds allowed for sending events after the page is sent | `1.5` |

Then run the checker on the web server, as the same user PHP runs as:

    php bin/doctor.php

It tells you in plain words what is wrong, if anything.

## 2. Tell it about your proxy (important)

Behind a reverse proxy, load balancer or CDN (Cloudflare, nginx in front of PHP-FPM,
and so on) the address PHP sees is the proxy's, not the visitor's. If the library
used it, every customer would look like one machine: failed logins from hundreds of
people would add up against one address, and blocking that address would lock out
everyone.

Anyone can send a fake `X-Forwarded-For` header, so the library believes forwarding
headers **only** when the connection comes from a proxy you list:

    SECURITY_TRUSTED_PROXIES=private                       # nginx or Docker on the same host or network
    SECURITY_TRUSTED_PROXIES=10.0.0.1,10.0.0.2             # specific proxies
    SECURITY_TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22   # address blocks, for example Cloudflare's
    SECURITY_CLIENT_IP_HEADER=CF-Connecting-IP             # optional, for Cloudflare

With nothing listed, headers are ignored and the connection address is used. That is
correct when PHP is directly on the internet, and cannot be spoofed. The library
also notices the opposite mistake: if forwarding headers arrive from an address it
does not trust, it writes one warning an hour to the error log, and `doctor.php` fails.

## 3. Add two lines

At the very top of your front controller (`index.php`), or for every page by setting
`auto_prepend_file` in `php.ini` or `.user.ini`:

```php
require '/var/www/pishon/security/bootstrap.php';
```

This works out the visitor's address, checks the blocklist and, in `enforce` mode,
answers a blocked visitor with `403 Access denied`. The blocklist is cached in a
shared file and refreshed every 30 seconds by one request at a time, so it does not
add a network call to your pages.

## 4. Report what happens

Call these where the events occur. All take an optional user id (use your own
internal id, not an email address if you can avoid it).

```php
use App\Security\Security;

// login handler
if ($passwordIsWrong) { Security::loginFailed($userId); }
else                  { Security::loginSuccess($userId); }

// password reset: when requested and when completed
Security::passwordReset($userId);

// admin area: at the top of every admin page
Security::adminAccess($adminId);

// profile: email, password, phone or address changed
Security::accountChange($userId, 'email');

// checkout: failures that look like card testing or fraud
Security::paymentIssue($userId, ['reason' => 'card_declined', 'amount' => 12500]);

// your own input filter caught something
Security::suspiciousRequest('sql keywords in search box', $userId);

// a session looks wrong, for example it appeared on a new device
Security::sessionAnomaly($userId, 'new device');
```

`loginSuccess` matters: it lets the platform tell an attack that failed from one
that got in (a successful login right after many failures raises a takeover alert).

What the library does for you:

- **Passwords and secrets never leave the website.** Fields named like password,
  token, secret, cookie, card number, pin or otp are replaced with `[REDACTED]` before
  sending. Never pass card numbers or passwords anyway.
- **The session id is never sent**, only a one-way token, so events from one session
  can be linked without being able to use it.
- The request path, user agent, method and a request id are attached automatically.
- A typo in an event name (`Security::event('login-failed')`) is logged and dropped
  rather than sent as an event no rule would ever read.

## 5. Roll out safely

1. Deploy with `SECURITY_MODE=monitor` (the default) and the right proxy settings.
2. Run `php bin/doctor.php`. Confirm the visitor address it prints is a real visitor.
3. Watch the PHP error log for `security_would_block` lines for a few days. Each line
   is a visitor who would have been blocked. If they are all attackers, continue.
4. Set `SECURITY_MODE=enforce`.

To switch it all off instantly, set `SECURITY_ENABLED=false`. Nothing else changes.

## When things go wrong

| Situation | What happens |
|-----------|--------------|
| Security API down or slow | Visitors are let in. Events are queued on disk (up to about 500 KB, oldest dropped first) and sent when it returns, with their original times. |
| API down for a while | After 3 failures in a row, no more attempts for 30 seconds, so the website stops waiting. |
| Blocklist cannot be refreshed | The previous list stays in force. If there never was a list, visitors are let in. |
| A temporary block expires | It ends on time at the website, even before the next refresh. |
| API key wrong or missing a scope | Logged loudly as `security_api_key_rejected`; the breaker backs off. |
| State folder not private or not writable | Not used, an error is logged, and the library carries on without shared state. |
| Private or loopback visitor | Never blocked, even if the blocklist contains it. |

Log lines go to PHP's `error_log` and start with `[pishon-security]`. Pass your own
logger to `Security::boot($config, null, $logger)` to send them elsewhere.

## Files

| File | Purpose |
|------|---------|
| `bootstrap.php` | The two-line setup |
| `src/Security.php` | The facade you call |
| `src/ClientIp.php`, `src/IpAddress.php` | Visitor address, proxies, parsing identical to the server |
| `src/BlocklistCache.php` | Cached, lock-protected blocklist |
| `src/SecurityReporter.php`, `EventSpool.php`, `CircuitBreaker.php` | Event delivery that cannot hurt the site |
| `src/SecurityClient.php` | The HTTP client |
| `bin/doctor.php` | Setup checker |
| `tests/` | `run.php` (client), `unit.php` (library), `facade.php` (end to end) |

## Tests

    php tests/all.php

The tests need only PHP. They start PHP's built-in server as a pretend Security API.
`tests/unit.php` also checks that no file uses syntax newer than PHP 7.4, and runs
the shared address vectors (`../shared/ip-vectors.json`) that the server's own tests
run too, so both sides always agree on what an address means.
