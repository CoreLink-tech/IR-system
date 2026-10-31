# Phase 4 — trust & sellable (pilot complete)

| Item | Delivery |
|------|----------|
| Tamper-evident audit | `prev_hash` / `entry_hash` chain; `GET /api/v1/admin/audit-verify` |
| DSAR export | `POST /api/v1/privacy/export` |
| DSAR erase | `POST /api/v1/privacy/delete` (anonymize or hard) |
| Trust page | `/trust` |
| Status page | `/status` |
| Backup script | `web/scripts/backup.sh` |
| Security checklist | `docs/SECURITY-CHECKLIST.md` |
| Migration | `0006_phase4_trust` |

## Apply

```bash
cd web && python3 scripts/migrate_local.py
```

## Residual risk (honest)

- Single-region Vercel + Turso unless you multi-home
- In-memory rate limits without Upstash
- Hash chain is best-effort integrity, not a WORM legal archive
- Tenant isolation is foundation-level; not formally proven multi-tenant SaaS
