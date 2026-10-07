export const ROLES = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  SECURITY_ADMIN: 'SECURITY_ADMIN',
  ANALYST: 'ANALYST',
  VIEWER: 'VIEWER',
} as const;

export type Role = keyof typeof ROLES;

export const SCOPES = {
  EVENTS_WRITE: 'events:write',
  EVENTS_READ: 'events:read',
  INCIDENTS_READ: 'incidents:read',
  INCIDENTS_WRITE: 'incidents:write',
  IPS_READ: 'ips:read',
  BLOCK_READ: 'block:read',
  BLOCK_WRITE: 'block:write',
  RULES_READ: 'rules:read',
  RULES_WRITE: 'rules:write',
  AUDIT_READ: 'audit:read',
  STATS_READ: 'stats:read',
  INTELLIGENCE_READ: 'intelligence:read',
} as const;

export type Scope = (typeof SCOPES)[keyof typeof SCOPES];

export const INCIDENT_STATUS = {
  OPEN: 'OPEN',
  INVESTIGATING: 'INVESTIGATING',
  CONTAINED: 'CONTAINED',
  RESOLVED: 'RESOLVED',
  FALSE_POSITIVE: 'FALSE_POSITIVE',
} as const;

export const SEVERITY = {
  INFO: 'INFO', LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL',
} as const;

export const EVENT_TYPES = [
  'login_failed','login_success','password_reset','account_change','admin_access',
  'suspicious_request','rate_limit_exceeded','payment_security_event',
  'application_error','server_error','logout','session_anomaly',
] as const;

export const RISK_LEVEL = {
  NORMAL: 'NORMAL', SUSPICIOUS: 'SUSPICIOUS', HIGH: 'HIGH', CRITICAL: 'CRITICAL',
} as const;

export const AUDIT_ACTIONS = {
  LOGIN: 'auth.login', LOGOUT: 'auth.logout', REFRESH: 'auth.refresh',
  PASSWORD_CHANGE: 'auth.password_change', USER_CREATE: 'user.create',
  API_KEY_CREATE: 'api_key.create', API_KEY_REVOKE: 'api_key.revoke', API_KEY_ROTATE: 'api_key.rotate',
  EVENT_INGEST: 'event.ingest',
  INCIDENT_CREATE: 'incident.create', INCIDENT_UPDATE: 'incident.update', INCIDENT_ASSIGN: 'incident.assign',
  IP_BLOCK: 'ip.block', IP_UNBLOCK: 'ip.unblock', IP_ALLOW: 'ip.allow', IP_UNALLOW: 'ip.unallow',
  RULE_UPDATE: 'rule.update', RULE_RESET: 'rule.reset', AUTO_BLOCK: 'ip.autoblock',
  USER_UPDATE: 'user.update', USER_PASSWORD_RESET: 'user.password_reset',
  INCIDENT_NOTE: 'incident.note',
} as const;

export const ROLES_KEY = 'roles';
export const SCOPES_KEY = 'scopes';
