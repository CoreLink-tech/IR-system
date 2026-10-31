# Phase 2 — detection intelligence

## Shipped

| Feature | Implementation |
|---------|----------------|
| Velocity windows | DB counts over `windowMinutes` |
| `brute_force` | login_failed burst → bonus |
| `credential_stuffing` | Distinct users failing from one IP |
| `password_spray` | High fails for one user_id |
| `checkout_abuse` | payment_security_event burst |
| `wp_probe` | Log path hits wp-login / xmlrpc |
| Entity IP score | `entity_scores` + decay |
| Auto-block cooldown | `rule_cooldowns` |
| Simulate UI | Admin → Rules → Run simulation |
| Config edits | Inline threshold/window fields |
| Migrations | `0003_phase2_detection` |

## Apply migrations

Local SQLite:

```bash
cd web
python3 scripts/migrate_local.py
# or after npm install:
npm run db:migrate
```

Turso / production: set `DATABASE_URL` + `DATABASE_AUTH_TOKEN`, then `npm run db:migrate`.

## Not yet

Full sequence/absence DSL · ASN/device · precision tracking · ML  
