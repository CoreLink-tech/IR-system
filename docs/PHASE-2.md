# Phase 2 — detection intelligence

## Shipped

| Rule / feature | Type |
|----------------|------|
| `brute_force` | Velocity |
| `credential_stuffing` | Velocity (distinct users) |
| `password_spray` | Velocity (per user) |
| `checkout_abuse` | Velocity (payments) |
| `admin_after_fails` | Sequence |
| `reset_after_fails` | Sequence (ATO-style) |
| `session_risk` | Session entity / velocity |
| `off_hours_admin` | Time-of-day (default off) |
| `wp_probe` | Log-derived |
| Entity scores | IP + session with decay |
| Cooldown | Post auto-block suppression |
| Simulate | Multi-rule backtest API + Rules UI |

## Apply migrations

```bash
cd web
python3 scripts/migrate_local.py   # local SQLite
# or: npm run db:migrate           # Turso with env set
```

Requires `0003_phase2_detection` for `entity_scores` / `rule_cooldowns`.

## Still out of scope (later)

Full DSL · ASN/geo feeds · ML · precision auto-demotion UI  
