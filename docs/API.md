# API Reference

Base URL: http://host:4000
All requests JSON. All responses include X-Request-Id.

## Authentication

Admin (JWT): Authorization: Bearer <accessToken> from POST /api/v1/auth/login.
API Key (Pishon): Authorization: Bearer PMS_xxx. Scopes enforced per endpoint.

## Endpoints

### POST /api/v1/auth/login
Body: { "email": "...", "password": "..." }
Returns { user, accessToken, refreshToken }.

### POST /api/v1/auth/refresh
Body: { "refreshToken": "..." }

### POST /api/v1/auth/logout
Body: { "refreshToken": "..." }

### POST /api/v1/events — API key, scope events:write
Body fields: event_type, severity, ip_address, user_id, session_id,
user_agent, request_method, request_path, request_id, metadata, timestamp.
Returns { id, riskScore, riskLevel, incidentId }.

Valid event_type values:
login_failed, login_success, password_reset, account_change, admin_access,
suspicious_request, rate_limit_exceeded, payment_security_event,
application_error, server_error, logout, session_anomaly.

### GET /api/v1/events — JWT
Query: page, pageSize, sortBy, sortOrder, eventType, severity, ipAddress, userId, from, to.

### GET /api/v1/events/:id — JWT

### GET /api/v1/incidents — JWT
Query: page, pageSize, sortBy, sortOrder, status, severity, sourceIp, assignedTo.

### GET /api/v1/incidents/:id — JWT
Returns incident + timeline + related events.

### POST /api/v1/incidents/:id/status — JWT (SECURITY_ADMIN, ANALYST)
Body: { "status": "INVESTIGATING", "notes": "..." }

### POST /api/v1/incidents/:id/assign — JWT (SECURITY_ADMIN)
Body: { "assignedTo": "<userId>" }

### GET /api/v1/ips/:ip — JWT

### POST /api/v1/ips/:ip/refresh-intelligence — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)
Forces a fresh provider lookup, bypassing the 24 hour cache. Returns the merged
intelligence and the list of active providers. Returns 404 for an invalid address.

### GET /api/v1/security/blocked-ips — JWT or API key with block:read
Returns only active blocks. Used by Pishon middleware.

### POST /api/v1/security/block — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Body: { ipAddress, reason, permanent, ttlMinutes, relatedIncidentId }

### POST /api/v1/security/unblock — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Body: { ipAddress, reason }

### POST /api/v1/security/allow — JWT (SUPER_ADMIN, SECURITY_ADMIN)
Body: { ipAddress, reason, ttlMinutes }

### DELETE /api/v1/security/allow/:ip — JWT (SUPER_ADMIN, SECURITY_ADMIN)

### GET /api/v1/statistics — JWT

### GET /api/v1/audit-logs — JWT (SUPER_ADMIN, SECURITY_ADMIN, ANALYST)

### API Keys — JWT (SUPER_ADMIN, SECURITY_ADMIN)
GET    /api/v1/api-keys
POST   /api/v1/api-keys           returns raw key ONCE
POST   /api/v1/api-keys/:id/rotate
DELETE /api/v1/api-keys/:id       revoke

### Users — JWT (SUPER_ADMIN)
POST /api/v1/auth/users

## Error format

    {
      "statusCode": 400,
      "message": "...",
      "path": "/api/v1/events",
      "method": "POST",
      "requestId": "...",
      "timestamp": "2025-01-01T12:00:00.000Z"
    }
