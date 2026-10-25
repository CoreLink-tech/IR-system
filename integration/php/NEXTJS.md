# Pointing the PHP agent at the Next.js IR-System

The Next.js app (`web/`) exposes the same client-facing paths under `/api/v1`.

```php
// config example
$baseUrl = 'https://your-app.vercel.app/api/v1';
$apiKey  = 'IRS_...'; // from dashboard → API keys
```

## Endpoints used by the website

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/events` | Send security events (`Authorization: Bearer IRS_…`) |
| GET | `/security/blocked-ips` | Poll active blocks |

## Event body (JSON)

```json
{
  "event_type": "login_failed",
  "severity": "MEDIUM",
  "ip_address": "203.0.113.10",
  "event_id": "unique-per-event-for-idempotency",
  "user_agent": "...",
  "request_path": "/login"
}
```

Rate limit: about 120 events per API key per client IP per minute (429 + `Retry-After`).

Database is **Turso/SQLite on the IR-System side** — not your shop MySQL.
