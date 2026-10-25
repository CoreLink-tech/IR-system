# Incident Response & Security Monitoring Platform

**Current target:** Next.js 15 + SQLite/Turso, deployable on **Vercel**.  
Client websites send security events via API key; this system uses **its own database** (not the shop DB).

## Active app: `web/`

```bash
cd web
cp .env.example .env   # set secrets + DATABASE_URL
npm install
npx drizzle-kit push
npm run seed
npm run dev
```

See [web/README.md](./web/README.md) for Turso, Vercel, and API examples.

### API (client → IR-System)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/events` | API key `IRS_…` | Ingest security event |
| GET | `/api/v1/security/blocked-ips` | API key | Blocklist for the website to enforce |
| GET | `/api/v1/health` | public | Liveness |
| GET | `/api/v1/health/ready` | public | Database readiness |

## Legacy reference (Nest + Vite)

- `backend/` — NestJS + Prisma + MySQL (Stage 1–10 hardening reference)
- `frontend/` — React + Vite dashboard (UI reference for the Next port)
- `integration/php/` — PHP client library (point `baseUrl` at the Next deployment)

These remain in the repo while the Next.js port is completed. New work happens under `web/`.

## License

See [LICENSE](./LICENSE). Proprietary terms apply.
