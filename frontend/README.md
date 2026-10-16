# Security dashboard

The web dashboard for the Security API. Plain English first, technical detail one click deeper.
Architecture, the session design and the role matrix are in `../docs/FRONTEND.md`.

## Run it (development)

    cd frontend
    npm ci
    cp .env.example .env            # VITE_API_BASE_URL, only a fallback for /config.json
    npm run dev                     # http://localhost:5173

The API must list the dashboard's exact origin in `CORS_ORIGINS` (for example `http://localhost:5173`).

## Build and deploy

    npm run build                   # typecheck + build + bundle size budget  ->  dist/

Copy `dist/` to the web server. Edit `dist/config.json`:

    { "apiBaseUrl": "https://api.example.com", "idleTimeoutMinutes": 30 }

`deploy/nginx.conf.example` and `deploy/security-headers.conf` show the server block (TLS, history fallback so
deep links work, caching, the strict Content-Security-Policy). Put the dashboard and the API on the same site
(`dashboard.example.com` and `api.example.com`): the refresh cookie is `SameSite=Strict`.
In the API's `.env`, set `CORS_ORIGINS` to the dashboard's exact origin.

## Scripts

| Command | Does |
|---|---|
| `npm test` | 301 component, page, API-client and accessibility tests |
| `npm run test:coverage` | the same with coverage floors |
| `npm run typecheck` | TypeScript only |
| `npm run test:live` | the real dashboard code against a live API (set `LIVE_API`, `LIVE_EMAIL`, `LIVE_PASSWORD`) |
| `npm run smoke` | contract checks against a live API (set `SMOKE_API`, `SMOKE_ORIGIN`, `SMOKE_EMAIL`, `SMOKE_PASSWORD`; test server only) |
| `npm run e2e` | Playwright browser tests; see `e2e/README.md` |

When the API's routes or roles change, run `npm run export:routes` in `backend/` and commit the updated
`src/lib/route-matrix.json`. A backend test fails when it is out of date.
