# Architecture

## Overview

    Pishon Market (PHP) --> Security API (NestJS) --> Pishon DB
                                                         (security_* tables)
    Web Dashboard --JWT--> Security API

## Layers

### Ingestion
POST /api/v1/events accepts structured events from Pishon.
1. Validates DTO (class-validator).
2. Authenticates API key, checks scope events:write.
3. Normalizes IP, sanitizes metadata (recursive redaction).
4. Writes to security_events.
5. Passes event to DetectionService.
6. Writes audit record.

Ingestion returns 200/201 if the event is valid. Detection failures are logged but not surfaced.

### Detection
DetectionService runs enabled rules from security_rules (seeded on first boot).
Each rule returns { riskDelta, matched, reason }. Total aggregated into riskScore.

riskScore mapped to riskLevel using env-configurable thresholds:
- below RISK_LEVEL_SUSPICIOUS -> NORMAL
- below RISK_LEVEL_HIGH -> SUSPICIOUS
- below RISK_LEVEL_CRITICAL -> HIGH
- at or above RISK_LEVEL_CRITICAL -> CRITICAL

### Incident Engine
If riskScore crosses a rule's incident threshold, an incident is created
(or attached to an existing open incident for the same IP + rule within 30 min).
State changes write timeline entries.

### IP Intelligence
IpIntelligenceService merges answers from pluggable providers (see docs/IP-INTELLIGENCE.md).
Providers: tor (Tor Project exit list), ipapi, ipinfo, abuseipdb. Configure with IP_INTEL_PROVIDERS.
Detection never depends on enrichment: if every provider is down the event is still processed.

### Blocking & Enforcement
Platform stores blocks in security_ip_blocks. DOES NOT enforce.
Pishon's middleware calls GET /api/v1/security/blocked-ips and enforces.
Allowlist takes precedence. Temporary blocks expire lazily at read time.

### Audit
AuditInterceptor writes to security_audit_logs on every security-sensitive write.
Direct service calls (DetectionService, BlockingService) also log directly.

## Database Strategy
Only security_* tables are created. No FK to Pishon business tables.

## Data Flow Example — Brute Force
1. Pishon sends POST /api/v1/events (login_failed).
2. Event stored; DetectionService runs.
3. brute_force_login matches (>= 5 fails in 10 min).
4. Risk crosses AUTO_BLOCK_MIN_RISK.
5. Incident + timeline entry created.
6. BlockingService creates temporary block.
7. Pishon's next poll of /blocked-ips includes this IP.
8. Pishon middleware rejects subsequent requests.
