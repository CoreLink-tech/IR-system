# IR-System — Next.js + Turso

Incident response and security monitoring for e-commerce sites.

- **App:** `web/` — Next.js 15 (API + dashboard)
- **Database:** SQLite (local) or **Turso** (production) — **your** DB, not the client shop
- **Clients:** send events with API key; poll blocklist and enforce locally
- **Host:** Vercel (or any Node host)

## Quick start (local)

```bash
cd web
cp .env.example .env
# Set JWT_SECRET, JWT_REFRESH_SECRET, API_KEY_HASH_PEPPER (long random strings)
mkdir -p data
npm install
npx drizzle-kit push
npm run seed          # prints admin password + API key once
npm run dev
```

Open http://localhost:3000 → sign in → Overview, Incidents, Blocking, Users.

## Client API

```http
POST /api/v1/events
Authorization: Bearer IRS_...
Content-Type: application/json

{ "event_type": "login_failed", "ip_address": "203.0.113.10", "event_id": "optional-id" }
```

```http
GET /api/v1/security/blocked-ips
Authorization: Bearer IRS_...
```

```http
POST /api/v1/auth/login
{ "email": "...", "password": "...", "useCookie": true }
```

## Deploy to Vercel (fresh)

1. Go to [vercel.com/new](https://vercel.com/new) and import this repository.
2. **Root Directory** → set to `web`
3. Add these Environment Variables:

| Variable | Required | Notes |
|----------|----------|-------|
| `DATABASE_URL` | Yes | Turso `libsql://...` URL |
| `DATABASE_AUTH_TOKEN` | Yes | Turso token |
| `JWT_SECRET` | Yes | Long random string (64+ chars) |
| `JWT_REFRESH_SECRET` | Yes | Another long random string |
| `API_KEY_HASH_PEPPER` | Yes | Random string (32+ chars) |
| `CRON_SECRET` | Recommended | Random string for cron jobs |
| `BOOTSTRAP_ADMIN_EMAIL` | Recommended | Your email for the first admin |

Generate secrets:
```bash
openssl rand -base64 48
```

4. Click **Deploy**.

After the first deploy, run the migration + seed (see [docs/PRODUCTION-LAUNCH.md](./docs/PRODUCTION-LAUNCH.md)).

## PHP agent

`integration/php/` — set base URL to your Vercel/Next origin.

## Legacy Nest + Vite

`backend/` and `frontend/` are the previous stack (reference only). All new work is in `web/`.

## Production launch

Full step-by-step (Turso, secrets, seed, first-24h checks):

→ [docs/PRODUCTION-LAUNCH.md](./docs/PRODUCTION-LAUNCH.md)
