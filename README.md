# IR-System — Next.js + Turso

Incident response and security monitoring for e-commerce sites.

- **App:** `web/` — Next.js 15 (API + dashboard)
- **Database:** SQLite (local) or **Turso** (production) — **your** DB, not the client shop
- **Clients:** send events with API key; poll blocklist and enforce locally
- **Host:** Vercel (or any Node host)

## Quick start

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

## Vercel

1. Project root directory: **`web`**
2. Env: `DATABASE_URL`, `DATABASE_AUTH_TOKEN` (Turso), JWT secrets, `API_KEY_HASH_PEPPER`
3. Deploy

## PHP agent

`integration/php/` — set base URL to your Vercel/Next origin.

## Legacy Nest + Vite

`backend/` and `frontend/` are the previous stack (reference only). All new work is in `web/`.

## Production launch

Step-by-step env vars, Vercel, Turso, and first-24h checks:

→ [docs/PRODUCTION-LAUNCH.md](./docs/PRODUCTION-LAUNCH.md)

