# Phase 1 — complete (MVP scope)

Watcher Phase 1 is **closed for pilot**. Remaining gaps are Phase 2+ or production hardening.

## Delivered

| Capability | Status |
|------------|--------|
| Multi-tenancy foundation (`tenants`, members, stores, `tenant_id`) | Done |
| Default workspace (compat for single-tenant / PHP) | Done |
| Webhooks API + HMAC + dashboard UI | Done |
| Incident notes + assign + status history | Done |
| Log ingest (`POST /api/v1/logs`) + Logs UI | Done |
| Log retention 7 days (cron) | Done |
| Per-key rate limit + optional Upstash shared limits | Done |
| Rules admin (thresholds) | Done |
| Audit log | Done |

## Migrations

```bash
cd web && npm run db:migrate
```

- `0001_phase1` — tenancy, webhooks, notes, logs  
- `0002_phase1_status_history` — incident status history  

## Optional env

```
UPSTASH_REDIS_REST_URL=
UPSTASH_REDIS_REST_TOKEN=
```

Without Upstash, rate limits remain per serverless isolate.

## Deferred (not Phase 1)

- Multi-workspace switcher / member invites UI  
- Webhook retry queue (QStash)  
- Incident merge + SLA timers  
- ClickHouse / Axiom log warehouse  
- Full detection DSL / velocity windows (Phase 2)  
- `/v1/decide` (Phase 3)  
