# IR-System (Next.js + Turso)

Security monitoring and incident response platform.

- **Runtime:** Next.js 15 (App Router) on Vercel
- **Database:** SQLite locally, [Turso](https://turso.tech) (libSQL) in production — **our** database, not the client shop DB
- **Client sites:** send events with an API key to `POST /api/v1/events`; poll `GET /api/v1/security/blocked-ips` to enforce blocks

The legacy Nest (`backend/`) and Vite (`frontend/`) trees remain in the repo as reference during the port.

## Quick start (local)

```bash
cd web
cp .env.example .env
# Generate secrets:
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
# Paste into JWT_SECRET, JWT_REFRESH_SECRET, API_KEY_HASH_PEPPER

mkdir -p data
npm install
npm run db:migrate   # or: npx drizzle-kit push
npm run seed
npm run dev
```

Open http://localhost:3000 — health at `/api/v1/health`.

## Turso

```bash
# Create DB on Turso, then:
# DATABASE_URL=libsql://...
# DATABASE_AUTH_TOKEN=...
npm run db:migrate   # or: npx drizzle-kit push
npm run seed
```

On Vercel, set the same env vars (no `file:` URL in production).

## Client integration

```http
POST /api/v1/events
Authorization: Bearer IRS_...
Content-Type: application/json

{
  "event_type": "login_failed",
  "severity": "MEDIUM",
  "ip_address": "203.0.113.10",
  "event_id": "optional-idempotency-key",
  "user_agent": "..."
}
```

```http
GET /api/v1/security/blocked-ips
Authorization: Bearer IRS_...
```

PHP library under `integration/php/` can be pointed at this base URL (update config).

## Deploy (Vercel)

1. Root directory: `web`
2. Env: `DATABASE_URL`, `DATABASE_AUTH_TOKEN`, secrets above
3. Build: `npm run build`
4. Optional cron: see `vercel.json` → `/api/v1/cron/cleanup` (to implement)

## Status of the port

| Area | Status |
|------|--------|
| Schema (SQLite/Turso) | Done |
| Event ingest + scoring + auto-block | Done (baseline rules) |
| Blocklist API | Done |
| Health / ready | Done |
| Admin JWT auth + 2FA UI | Next |
| Full detection rule engine | Next (port from backend/) |
| Dashboard pages | Next (port from frontend/) |
