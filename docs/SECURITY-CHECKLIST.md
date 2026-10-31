# Watcher pre-sale security self-assessment (pilot)

| Control | Status |
|---------|--------|
| TLS on all public endpoints (Vercel) | Operator ensures custom domain HTTPS |
| API keys hashed + peppered | Yes |
| Short-lived access JWT + refresh rotation | Yes |
| Optional TOTP 2FA | Yes |
| RBAC roles | SUPER_ADMIN, SECURITY_ADMIN, ANALYST, VIEWER |
| Audit log with hash chain | Yes (Phase 4) |
| Privacy export / erase API | Yes |
| Secrets not in git | Operator responsibility |
| Dependency updates | CI build on main |
| Backups | `web/scripts/backup.sh` (SQLite); Turso provider backups |
| Status page | `/status` |
| Trust page | `/trust` |
| PCI: no CHD by design | Redaction on ingest; do not send PAN/CVV |

Operator must still: rotate leaked keys, enable 2FA for admins, set strong env secrets, run migrations, configure Turso backups.
