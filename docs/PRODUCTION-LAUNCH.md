# Production launch runbook — IR-System (Next.js + Turso)

Use this for a **limited production / pilot** deploy (one client site, supervised).
Broad multi-tenant production still needs shared rate limits, e2e coverage, and a load burn-in.

**Deploy root:** `web/` only. Do not deploy `backend/` or `frontend/`.

---

## 0. Before you start (security)

1. **Revoke any GitHub (or other) tokens that appeared in chat or tickets.** Create a new fine-scoped token if you still need git automation.
2. Use a dedicated Turso database for production (not the local `file:` DB).
3. Plan a **break-glass** admin account recovery path (password manager + recovery codes offline).

---

## 1. Create the database (Turso)

```bash
# Install Turso CLI if needed, then:
turso db create ir-system-prod
turso db show ir-system-prod --url
turso db tokens create ir-system-prod
```

Save:

- `DATABASE_URL` → `libsql://….turso.io`
- `DATABASE_AUTH_TOKEN` → the token just created

Optional: enable Turso backups / point-in-time recovery per your plan.

---

## 2. Generate secrets

Generate **unique** values (do not reuse across environments):

```bash
openssl rand -base64 48   # JWT_SECRET
openssl rand -base64 48   # JWT_REFRESH_SECRET
openssl rand -base64 32   # API_KEY_HASH_PEPPER
openssl rand -base64 32   # CRON_SECRET
```

Rules:

| Variable | Minimum | Notes |
|----------|---------|--------|
| `JWT_SECRET` | 32+ chars | Access tokens |
| `JWT_REFRESH_SECRET` | 32+ chars | Refresh + CSRF binding |
| `API_KEY_HASH_PEPPER` | 16+ chars | Never change lightly (invalidates all API keys) |
| `CRON_SECRET` | 16+ chars | Must match Vercel Cron `Authorization: Bearer …` |
| `API_KEY_PREFIX` | — | Default `IRS_` |
| `REQUIRE_2FA` | — | Set `true` for production admins |
| `TOTP_ISSUER` | — | e.g. `YourCo Security` |

Do **not** ship placeholder strings (`CHANGE_ME`, `dev-insecure`, etc.). The app rejects many of them at startup.

---

## 3. Vercel project settings

1. Import **https://github.com/CoreLink-tech/IR-system**
2. **Root Directory:** `web`
3. Framework: Next.js (auto)
4. Region: match `vercel.json` (default `iad1`) or change both deliberately
5. Environment variables (Production + Preview as needed):

```
DATABASE_URL=
DATABASE_AUTH_TOKEN=
JWT_SECRET=
JWT_REFRESH_SECRET=
API_KEY_HASH_PEPPER=
API_KEY_PREFIX=IRS_
REQUIRE_2FA=true
TOTP_ISSUER=Security Dashboard
CRON_SECRET=
BOOTSTRAP_ADMIN_EMAIL=you@yourcompany.com
# Prefer unset BOOTSTRAP_ADMIN_PASSWORD in prod; generate at seed time
```

6. Deploy once so the project URL exists (e.g. `https://ir-system-xxx.vercel.app`).

Cron (already in `web/vercel.json`):

- Path: `/api/v1/cron/cleanup`
- Schedule: `15 3 * * *` (03:15 UTC daily)
- Caller must send `Authorization: Bearer $CRON_SECRET`

Confirm in Vercel → Settings → Cron Jobs that the job is registered after deploy.

---

## 4. Migrate and seed

Run **once** against production Turso (from a trusted machine, not a shared CI log):

```bash
cd web
export DATABASE_URL='libsql://…'
export DATABASE_AUTH_TOKEN='…'
export JWT_SECRET='…'
export JWT_REFRESH_SECRET='…'
export API_KEY_HASH_PEPPER='…'
export BOOTSTRAP_ADMIN_EMAIL='you@yourcompany.com'
# optional: BOOTSTRAP_ADMIN_PASSWORD='…'  (else printed once by seed)

npm install
npm run db:migrate
npm run seed
```

**Save immediately (shown once):**

- Admin password (if generated)
- Website API key (`IRS_…`)

Then:

1. Sign in at `https://<your-app>/sign-in`
2. **Change password** (Account → Password)
3. **Enable 2FA** (Account → Security) and store recovery codes offline
4. Create a dedicated API key for the client site (Admin → API keys); revoke the seed key if it was only for bootstrap

---

## 5. Wire the client website

PHP agent notes: `integration/php/NEXTJS.md`

```
Base URL:  https://<your-app>/api/v1
API key:   IRS_…   (Authorization: Bearer IRS_…)
```

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/events` | Send security events |
| `GET` | `/security/blocked-ips` | Poll active blocks |

Smoke from the server or laptop:

```bash
# Health
curl -sS https://<your-app>/api/v1/health/ready

# Ingest (expect 200 JSON)
curl -sS -X POST https://<your-app>/api/v1/events \
  -H "Authorization: Bearer IRS_…" \
  -H "Content-Type: application/json" \
  -d '{"event_type":"login_failed","ip_address":"203.0.113.10","event_id":"launch-smoke-1"}'

# Blocklist
curl -sS https://<your-app>/api/v1/security/blocked-ips \
  -H "Authorization: Bearer IRS_…"
```

Confirm the event appears under **Incidents / Addresses** in the dashboard.

---

## 6. First 24 hours — verification checklist

Copy and tick:

- [ ] `/api/v1/health/ready` returns ready + database ok  
- [ ] Admin login works; password changed; 2FA on  
- [ ] Recovery codes stored offline  
- [ ] Client posts a real event; incident or event visible in UI  
- [ ] Manual block / unblock works; client poll reflects the change within your poll interval  
- [ ] Allowlist prevents blocking a known good IP (test in staging first if possible)  
- [ ] Cron: either wait for schedule or call cleanup with `Authorization: Bearer $CRON_SECRET` and confirm 200  
- [ ] Audit log shows admin actions (block, unlock, rule change)  
- [ ] Reports page loads (executive summary)  
- [ ] No secrets in Vercel build logs or Git history  

### If something fails

| Symptom | Check |
|---------|--------|
| 500 on all API | Env vars set on **Production**; redeploy after adding secrets |
| DB errors | Turso URL/token; migrate applied |
| 401 on events | API key active; prefix `IRS_`; pepper matches the env used at key creation |
| 429 on events | Ingest rate limit (120/min per key+IP); reduce client retries |
| Logged out on every refresh | Access token is memory-only; refresh cookie + CSRF path `/api/v1/auth` |
| Cron 401 | `CRON_SECRET` mismatch |

---

## 7. Ongoing operations

- **API keys:** one per site/environment; rotate by creating new then revoking old  
- **Users:** Super admin unlock / 2FA reset only; never reset your own 2FA from the admin UI  
- **Rules:** change scoring only when you understand impact on auto-block  
- **Backups:** Turso snapshot schedule + periodic export of incident counts for your records  
- **GitHub:** protect `main`; only deploy from CI/Vercel production branch  

---

## 8. Explicit non-goals of this pilot

- Multi-region shared rate limiting (current limit is per isolate)  
- Full Nest-era detection parity  
- Formal penetration test sign-off  
- Unattended multi-tenant SaaS  

Promote from pilot → general production only after a supervised week and the items above stay green.

---

## Quick command card

```bash
# Deploy source of truth
git checkout main && git pull

# Local parity (optional)
cd web && npm install && npm test && npm run build

# Prod data (trusted machine)
npm run db:migrate && npm run seed
```

Dashboard: `https://<your-app>/sign-in`  
Client API base: `https://<your-app>/api/v1`
