# Pishon Incident Response & Security Monitoring Platform

Production-oriented incident response backend for Pishon Market.

- Backend: Node.js + TypeScript + NestJS + Prisma
- Database: Reuses Pishon's existing MySQL/MariaDB. Creates only security_* tables.
- Auth: JWT for admins, hashed API keys for Pishon -> Security API.
- Detection: Configurable rule engine with 0-100 risk scoring.
- Blocking: State in DB, exposed via /api/v1/security/blocked-ips for Pishon to enforce.

## Quick Start (Termux)

    pkg update && pkg upgrade -y
    pkg install -y git nodejs-lts python make clang openssl libffi
    termux-setup-storage
    cd backend
    cp .env.example .env
    npm run gen:secrets      # prints fresh secrets; paste them into .env
                             # the server refuses to start with the sample placeholders
    npm install
    npx prisma generate
    npx prisma db push
    npm run seed
    npm run start:dev

## Environment Variables

Copy backend/.env.example to backend/.env and fill in:

- DATABASE_URL          Pishon MySQL/MariaDB connection string
- JWT_SECRET            Long random string, 64+ chars
- JWT_REFRESH_SECRET    Long random string, 64+ chars
- API_KEY_HASH_PEPPER   Random pepper for API key hashing
- BOOTSTRAP_ADMIN_*     Used once by npm run seed

Generate secrets:

    node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

## API Overview

    POST /api/v1/auth/login          Admin login (JWT)
    POST /api/v1/events              Ingest event (API key)
    GET  /api/v1/events              List events (JWT)
    GET  /api/v1/incidents           List incidents (JWT)
    GET  /api/v1/incidents/:id       Incident detail
    POST /api/v1/incidents/:id/status
    POST /api/v1/incidents/:id/assign
    GET  /api/v1/ips/:ip             IP intelligence
    GET  /api/v1/reports/incidents/:id        plain-English incident report
    GET  /api/v1/reports/technical/:id        technical incident report
    GET  /api/v1/reports/executive-summary    owner/CEO summary
    GET  /api/v1/reports/security-summary     aggregate security summary
    GET  /api/v1/security/blocked-ips
    POST /api/v1/security/block
    POST /api/v1/security/unblock
    POST /api/v1/security/allow
    DELETE /api/v1/security/allow/:ip
    GET  /api/v1/statistics
    GET  /api/v1/audit-logs

## Testing

    cd backend
    npm test

## Security

- bcrypt cost 12 for passwords
- API keys SHA-256 + pepper, raw returned once
- JWT HS256 with rotating refresh tokens
- Helmet, strict CORS, class-validator DTOs
- Prisma parameterized queries only
- Event metadata scrubbed of secrets before storage

## IP Blocking

This platform records block state. It does NOT enforce network blocks.
Pishon's PHP library (`integration/php/`, see its README) is responsible for rejecting traffic based on
GET /api/v1/security/blocked-ips. Automatic blocks are always temporary.

## License

MIT
