# Production launch runbook — IR-System (Next.js + Turso)

Use this for a **limited production / pilot** deploy (one client site, supervised).  
Do not treat multi-tenant unattended SaaS as “done” until the post-launch hardening section is complete.

**Deploy target:** Vercel project root = `web/`  
**Database:** Turso (libSQL), not the shop MySQL  
**Branch:** `main`

---

## 0. Before you start (security hygiene)

- [ ] **Revoke any GitHub token that appeared in chat or tickets.** Create a new fine-scoped token or use GitHub Apps / OIDC for CI.
- [ ] Confirm you control the Vercel team and Turso org (not shared personal accounts for production).
- [ ] Decide the production hostname (e.g. `ir.yourdomain.com`) and DNS owner.
- [ ] Have a break-glass admin email that is not the only account.

Generate secrets **once**, store them in a password manager, never commit them:

```bash
# Run locally; paste into Vercel / Turso only
openssl rand -base64 48   # JWT_SECRET
openssl rand -base64 48   # JWT_REFRESH_SECRET
openssl rand -base64 32   # API_KEY_HASH_PEPPER
openssl rand -base64 32   # CRON_SECRET
openssl rand -base64 24   # initial admin password (or use seed output)
```

---

## 1. Turso database

1. Create a database in the Turso dashboard (or CLI):

   ```bash
   turso db create ir-system-prod
   turso db show ir-system-prod --url
   turso db tokens create ir-system-prod
   ```

2. Note:
   - `DATABASE_URL` → `libsql://….turso.io`
   - `DATABASE_AUTH_TOKEN` → the token just created

3. Apply schema (from a trusted machine with the token set):

   ```bash
   cd web
   export DATABASE_URL='libsql://…'
   export DATABASE_AUTH_TOKEN='…'
   export JWT_SECRET='…'              # required by app modules if imported
   export JWT_REFRESH_SECRET='…'
   export API_KEY_HASH_PEPPER='…'
   npm install
   npm run db:migrate
   npm run seed
   ```

4. **Save seed output immediately** (shown once):
   - Bootstrap admin email / password
   - First website API key (`IRS_…`)

5. Prefer **Turso daily backups** / point-in-time if your plan includes them. Document who can restore.

---

## 2. Vercel project settings

| Setting | Value |
|--------|--------|
| **Root Directory** | `web` |
| **Framework** | Next.js (auto) |
| **Node** | 20.x |
| **Production branch** | `main` |
| **Build command** | `npm run build` (default) |
| **Install command** | `npm install` |

### Environment variables (Production + Preview as needed)

| Variable | Required | Notes |
|----------|----------|--------|
| `DATABASE_URL` | Yes | Turso `libsql://…` |
| `DATABASE_AUTH_TOKEN` | Yes | Turso token |
| `JWT_SECRET` | Yes | ≥ 32 chars, unique |
| `JWT_REFRESH_SECRET` | Yes | ≥ 32 chars, **different** from JWT_SECRET |
| `API_KEY_HASH_PEPPER` | Yes | ≥ 16 chars; **never rotate without rehashing all keys** |
| `API_KEY_PREFIX` | No | Default `IRS_` |
| `REQUIRE_2FA` | Recommended `true` | Forces admin 2FA enrolment |
| `TOTP_ISSUER` | No | Label in authenticator apps |
| `CRON_SECRET` | Yes if cron enabled | Bearer secret for `/api/v1/cron/cleanup` |
| `BOOTSTRAP_*` | Seed only | Do **not** rely on these in production after first seed |

`vercel.json` already schedules cleanup daily at 03:15 UTC:

```json
"path": "/api/v1/cron/cleanup",
"schedule": "15 3 * * *"
```

Vercel Cron should send the request; your handler expects:

```http
Authorization: Bearer $CRON_SECRET
```

Confirm in Vercel → Settings → Cron Jobs that the job is registered after the first production deploy.

### Domain

- [ ] Attach custom domain
- [ ] HTTPS only (Vercel default)
- [ ] Optional: restrict deployment protection for Preview

---

## 3. First deploy

1. Push `main` (or promote a clean commit).
2. Wait for Vercel build green (`web-ci` + Vercel build).
3. Open `https://<host>/api/v1/health` and `/api/v1/health/ready`.
4. Expect ready status and database reachable.
5. Open `https://<host>/sign-in` — sign in with bootstrap admin.
6. **Change password** (Account → Password).
7. **Enable 2FA** (Account → Security) if not forced at login; store recovery codes offline.
8. Create a **named API key** for the pilot site (Admin → API keys). Revoke the seed key if it was only for bootstrap.

---

## 4. Point the client website (PHP)

See [integration/php/NEXTJS.md](../integration/php/NEXTJS.md).

```php
$baseUrl = 'https://<your-ir-host>/api/v1';
$apiKey  = 'IRS_…'; // production key from dashboard
```

- [ ] `POST /events` with a test `login_failed` from a **non-production** path first
- [ ] `GET /security/blocked-ips` returns JSON `{ data: [...] }`
- [ ] Client enforces blocks (403/deny) for listed IPs
- [ ] Do **not** point production checkout at IR until the 24h checklist passes

---

## 5. First 24 hours — verification checklist

### Hour 0–1 (smoke)

| Check | How | Pass |
|-------|-----|------|
| Health | `GET /api/v1/health/ready` | `status: ready` |
| Sign-in | Dashboard login | Session issued |
| 2FA | Enrol or verify | Works |
| API key | Create + copy once | Stored in client secret store |
| Event | `POST /events` sample | 200, risk fields present |
| Blocklist | `GET /security/blocked-ips` | 200 |
| Manual block | Dashboard → Blocking | Appears in poll |
| Unblock | Dashboard | Removed from poll |
| Audit | Admin → Audit | Block/login actions visible |

### Hours 1–8 (pilot traffic)

| Check | Pass criteria |
|-------|----------------|
| Error rate | No sustained 5xx on Vercel |
| Rate limit | Burst of events returns 429 with retry, then recovers |
| Auto-block | High-risk test IP (public) gets blocked when threshold met |
| Private IP | `10.x` / `192.168.x` never blocked |
| Sessions | Sign out / revoke session works |
| Refresh | Stay signed in across soft navigations (cookie refresh + CSRF) |

### Hours 8–24 (stability)

| Check | Pass criteria |
|-------|----------------|
| Cron | Cleanup ran or manual `GET /api/v1/cron/cleanup` with Bearer secret succeeds |
| Reports | Executive report loads for 7 days |
| Disk/Turso | Metrics normal; no auth token errors |
| Access | Only needed admins; VIEWER accounts for read-only if required |

**Rollback:** Vercel → Deployments → Promote previous production deployment. Turso restore only if schema/data corruption (rare on app-only rollback).

---

## 6. Operational defaults (pilot)

- `REQUIRE_2FA=true` for production
- One API key **per** client environment (staging vs prod)
- Prefer temporary blocks; use allowlist for office/NAT exits that must never block
- Review **Audit** after any manual block or 2FA reset
- Rotate admin passwords on a schedule; never share recovery codes in chat

---

## 7. Explicitly not “done” yet (post-pilot hardening)

Track these before broad production:

1. Shared rate limit (e.g. Upstash Redis) across serverless isolates  
2. Playwright e2e: sign-in, 2FA, block, event ingest  
3. Backup restore **drill** documented with RTO/RPO  
4. Structured logs + alert on 5xx and auth lockouts  
5. Remove or archive legacy `backend/` and `frontend/` to avoid wrong root deploy  
6. Detection rule tuning with real traffic baselines  

---

## 8. Quick command reference

```bash
# Health
curl -sS https://<host>/api/v1/health/ready

# Ingest (client)
curl -sS -X POST https://<host>/api/v1/events \
  -H "Authorization: Bearer IRS_…" \
  -H "Content-Type: application/json" \
  -d '{"event_type":"login_failed","ip_address":"203.0.113.10","event_id":"test-1"}'

# Blocklist (client)
curl -sS https://<host>/api/v1/security/blocked-ips \
  -H "Authorization: Bearer IRS_…"

# Cron (manual)
curl -sS https://<host>/api/v1/cron/cleanup \
  -H "Authorization: Bearer $CRON_SECRET"
```

---

## 9. Go / no-go

**GO (limited production)** if sections 0–5 pass and one pilot site is supervised.

**NO-GO** if: health not ready, secrets still placeholders, 2FA skipped for admins, seed password still in use, or client cannot enforce the blocklist.

Document the go decision (date, hostname, pilot site, owner) in your internal ops channel.
