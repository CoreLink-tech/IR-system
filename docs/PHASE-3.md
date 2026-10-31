# Phase 3 — real-time response (pilot complete)

## Endpoints

### `POST /api/v1/decide`

Auth: API key (`decide`, `events:write`, or `*`).

```json
{
  "ip_address": "203.0.113.10",
  "user_id": "optional",
  "session_id": "optional",
  "user_agent": "optional",
  "action": "browse|login|checkout|admin|password_reset",
  "severity": "INFO|MEDIUM|HIGH|CRITICAL",
  "idempotency_key": "optional-unique"
}
```

Response:

```json
{
  "decision_id": "...",
  "outcome": "allow|review|challenge|block",
  "score": 0,
  "reasons": ["..."],
  "rule_hits": ["..."],
  "ttl_seconds": 60,
  "meta": { "latency_ms": 12, "request_id": "..." }
}
```

**Order of evaluation:** allowlist → active block → detection score → action-aware outcome mapping.

On internal error the API returns **degraded allow** (`decide_error_fail_open`) so storefronts stay up. Clients should still fail-closed on **admin** if the request times out (no response).

### `POST /api/v1/decisions/:id/outcome`

```json
{ "feedback": "confirmed_fraud|false_positive|chargeback|legitimate" }
```

Auth: API key or dashboard session.

## Client policy (recommended)

| Action | Timeout | Suggested client behaviour |
|--------|---------|----------------------------|
| browse | 150–300ms | fail-open |
| login / checkout | 300–500ms | fail-open or soft challenge |
| admin | 300–500ms | fail-closed or force challenge |

Cache decisions by IP/session for `ttl_seconds`.

## Migration

`0005_phase3_decide` → `decisions` table.

```bash
cd web && python3 scripts/migrate_local.py
# Turso: npm run db:migrate
```

## Not in pilot Phase 3

Edge Workers dual-deploy · Shopify Functions · full anti-bypass fingerprint SDK · PoW challenges
