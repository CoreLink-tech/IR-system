# Phase 1 progress (Watcher)

## Shipped in this pass

| Area | What |
|------|------|
| **Tenancy foundation** | `tenants`, `tenant_members`, `stores`; `tenant_id` on keys/events/incidents/blocks |
| **Default workspace** | `ensureDefaultTenant()` — existing single-tenant data maps to slug `default` |
| **Webhooks** | `POST/GET /api/v1/webhooks`; HMAC `X-Watcher-Signature`; fires `incident.created`, `block.created` |
| **Incident notes** | `GET/POST /api/v1/incidents/:id/notes` |
| **Log ingest MVP** | `POST /api/v1/logs` (JSON/NDJSON, API key); `GET /api/v1/logs` for dashboard |
| **Per-key rate limit** | `api_keys.rate_limit_per_minute` (default 120) |
| **Migration** | `drizzle/0001_phase1/migration.sql` |

## Compatibility

- `/api/v1/events` and `/api/v1/security/blocked-ips` unchanged for PHP clients.
- Keys without `tenant_id` resolve to the default tenant at ingest time.

## Not done yet (still Phase 1)

- Full workspace UI / invite members / multi-tenant dashboard switcher
- Webhook retry queue (QStash) and delivery UI
- Incident assign / merge / SLA
- Shared Redis rate limits
- Log viewer UI page, NGINX-specific parser, 7-day log purge in cron
- Separate log warehouse (ClickHouse etc.) — Turso is pilot-only

## Apply migration

```bash
cd web && npm run db:migrate
```
