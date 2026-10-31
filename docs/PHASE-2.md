# Phase 2 — complete (pilot scope)

Detection intelligence for Watcher pilot is **closed**. Not a full SIEM DSL.

## Rules shipped

| Code | Type |
|------|------|
| login_failed, suspicious_request, rate_limit, payment, admin_access | Base score |
| brute_force, credential_stuffing, password_spray, checkout_abuse | Velocity |
| admin_after_fails, reset_after_fails | Sequence |
| session_risk | Session velocity |
| off_hours_admin | Time-of-day (default off) |
| wp_probe, path_scan | Log-derived |
| auto_block + cooldown | Response |
| entity_ip / session / device scores | Entity risk |

## Controls

- **monitor | enforce** mode per rule (monitor does not drive auto-block)
- **rule_hits** recorded on ingest
- **rule_verdicts** when incidents marked FALSE_POSITIVE / RESOLVED
- Multi-rule **simulate** API + Rules UI
- Config thresholds editable in Admin → Rules

## Migrations

`0003_phase2_detection`, `0004_phase2_finish`

```bash
cd web && python3 scripts/migrate_local.py
# production: npm run db:migrate with Turso env
```

## Explicitly not built (by design)

Full sequence DSL · ASN/geo vendors · ML models · automatic noisy-rule demotion engines

Next product phase: **Phase 3 — `/v1/decide` and real-time response**.
