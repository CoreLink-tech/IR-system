# Security Model

## Threat Model
- Pishon server is trusted to send events with valid API key.
- Attackers may control X-Forwarded-For. Put a reverse proxy in front in production.
- DB may be accessed by untrusted admins. All credentials hashed.

## Secrets

    Secret              Storage                              Algorithm
    Admin password      security_users.passwordHash          bcrypt cost 12
    API key             security_api_keys.keyHash            SHA-256(key + pepper)
    Refresh token       security_refresh_tokens.tokenHash    SHA-256
    JWT signing         env JWT_SECRET                       HS256
    DB password         .env                                 -

Never commit .env. Rotate JWT_SECRET and API_KEY_HASH_PEPPER if leaked.

## Input Validation
Every endpoint uses a DTO with class-validator.
ValidationPipe runs with whitelist, forbidNonWhitelisted, transform.
Extra fields rejected.

## SQL Injection
All queries via Prisma. No raw SQL.

## Logging
AuditService writes: requestId, actorType, actorId, action, targetType,
targetId, result, ipAddress, userAgent, metadata.
Passwords, tokens, API keys never logged. Event metadata scrubbed.

## Response Hygiene
- AllExceptionsFilter returns uniform error shape.
- Stack traces server-side only.
- JWT secrets, DB URLs, hashes never serialized.

## Headers
Helmet applied globally. CORS strict from CORS_ORIGINS.

## Rate Limiting
ThrottlerModule global bucket. Tune with THROTTLE_TTL and THROTTLE_LIMIT.

## Blocking Safety
- Automatic blocks temporary by default.
- Skipped for allowlisted IPs.
- Recorded in audit with actorType SYSTEM.
- Permanent only manual via POST /security/block with permanent: true.

## Endpoint Permissions

    Endpoint                           Who
    POST /api/v1/security/block        SUPER_ADMIN, SECURITY_ADMIN
    POST /api/v1/security/unblock      SUPER_ADMIN, SECURITY_ADMIN
    POST /api/v1/security/allow        SUPER_ADMIN, SECURITY_ADMIN
    API key management                 SUPER_ADMIN, SECURITY_ADMIN
    User management                    SUPER_ADMIN
    Read events/incidents              all 4 roles
    Update incidents                   SUPER_ADMIN, SECURITY_ADMIN, ANALYST

## Deployment Checklist
- Reverse proxy (nginx/Caddy) terminating HTTPS
- NODE_ENV=production
- Strong JWT_SECRET, JWT_REFRESH_SECRET, API_KEY_HASH_PEPPER (64+ bytes)
- CORS_ORIGINS restricted
- DB user privileges on pishon_market.security_* tables
- Logs shipped off-host
- Backups of security_* scheduled
- Pishon PHP middleware enabled with blocklist cache
