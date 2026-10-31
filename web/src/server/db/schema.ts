/**
 * IR-System schema for SQLite / Turso (libSQL).
 * Own database — not shared with the client website.
 * Client sites push events via API key to /api/v1/events.
 */
import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

const id = () => text('id').primaryKey();
const ts = (name: string) => integer(name, { mode: 'timestamp_ms' }).notNull();
const tsNull = (name: string) => integer(name, { mode: 'timestamp_ms' });

export const users = sqliteTable('users', {
  id: id(),
  email: text('email').notNull().unique(),
  name: text('name'),
  passwordHash: text('password_hash').notNull(),
  role: text('role').notNull().default('VIEWER'), // SUPER_ADMIN | SECURITY_ADMIN | ANALYST | VIEWER
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  mustChangePassword: integer('must_change_password', { mode: 'boolean' }).notNull().default(false),
  tokenVersion: integer('token_version').notNull().default(0),
  passwordChangedAt: tsNull('password_changed_at'),
  lastLoginAt: tsNull('last_login_at'),
  totpSecret: text('totp_secret'),
  totpEnabledAt: tsNull('totp_enabled_at'),
  totpLastStep: integer('totp_last_step'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
});

export const recoveryCodes = sqliteTable('recovery_codes', {
  id: id(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  codeHash: text('code_hash').notNull().unique(),
  usedAt: tsNull('used_at'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('recovery_codes_user_idx').on(t.userId)]);

export const refreshTokens = sqliteTable('refresh_tokens', {
  id: id(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull().unique(),
  sessionId: text('session_id').notNull(),
  sessionStartedAt: ts('session_started_at'),
  lastUsedAt: tsNull('last_used_at'),
  deviceLabel: text('device_label'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  expiresAt: ts('expires_at'),
  revokedAt: tsNull('revoked_at'),
  revokedReason: text('revoked_reason'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('refresh_tokens_user_idx').on(t.userId), index('refresh_tokens_session_idx').on(t.sessionId)]);

export const apiKeys = sqliteTable('api_keys', {
  id: id(),
  name: text('name').notNull(),
  keyPrefix: text('key_prefix').notNull(),
  keyHash: text('key_hash').notNull(),
  scopes: text('scopes').notNull().default('events:write'), // comma-separated
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  expiresAt: tsNull('expires_at'),
  lastUsedAt: tsNull('last_used_at'),
  revokedAt: tsNull('revoked_at'),
  createdBy: text('created_by'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('api_keys_prefix_idx').on(t.keyPrefix)]);

export const events = sqliteTable('events', {
  id: id(),
  tenantId: text('tenant_id'),
  apiKeyId: text('api_key_id').references(() => apiKeys.id),
  externalId: text('external_id'),
  eventType: text('event_type').notNull(),
  severity: text('severity').notNull().default('INFO'),
  ipAddress: text('ip_address'),
  userId: text('user_id'),
  sessionId: text('session_id'),
  userAgent: text('user_agent'),
  requestMethod: text('request_method'),
  requestPath: text('request_path'),
  requestId: text('request_id'),
  metadata: text('metadata'), // JSON string
  riskScore: integer('risk_score').notNull().default(0),
  riskLevel: text('risk_level').notNull().default('NORMAL'),
  matchedRules: text('matched_rules'), // JSON array
  incidentId: text('incident_id'),
  occurredAt: ts('occurred_at'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [
  index('events_ip_created_idx').on(t.ipAddress, t.createdAt),
  index('events_type_created_idx').on(t.eventType, t.createdAt),
  index('events_incident_idx').on(t.incidentId),
  uniqueIndex('events_api_external_uidx').on(t.apiKeyId, t.externalId),
]);

export const incidents = sqliteTable('incidents', {
  id: id(),
  tenantId: text('tenant_id'),
  publicNumber: integer('public_number').notNull(),
  title: text('title').notNull(),
  status: text('status').notNull().default('OPEN'), // OPEN | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE
  severity: text('severity').notNull().default('MEDIUM'),
  sourceIp: text('source_ip'),
  userId: text('user_id'),
  openKey: text('open_key'),
  riskScore: integer('risk_score').notNull().default(0),
  assignedTo: text('assigned_to'),
  summary: text('summary'),
  eventCount: integer('event_count').notNull().default(0),
  resolvedAt: tsNull('resolved_at'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
  updatedAt: ts('updated_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [
  uniqueIndex('incidents_public_number_uidx').on(t.publicNumber),
  uniqueIndex('incidents_open_key_uidx').on(t.openKey),
  index('incidents_status_idx').on(t.status),
]);

export const ipBlocks = sqliteTable('ip_blocks', {
  id: id(),
  tenantId: text('tenant_id'),
  ipAddress: text('ip_address').notNull(),
  action: text('action').notNull().default('BLOCK'), // BLOCK | UNBLOCK
  reason: text('reason').notNull(),
  administratorId: text('administrator_id'),
  relatedIncidentId: text('related_incident_id'),
  isPermanent: integer('is_permanent', { mode: 'boolean' }).notNull().default(false),
  expiresAt: tsNull('expires_at'),
  active: integer('active', { mode: 'boolean' }).notNull().default(true),
  automatic: integer('automatic', { mode: 'boolean' }).notNull().default(false),
  activeKey: text('active_key'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [
  uniqueIndex('ip_blocks_active_key_uidx').on(t.activeKey),
  index('ip_blocks_ip_idx').on(t.ipAddress),
]);

export const allowlist = sqliteTable('allowlist', {
  id: id(),
  tenantId: text('tenant_id'),
  ipAddress: text('ip_address').notNull().unique(),
  reason: text('reason').notNull(),
  addedBy: text('added_by'),
  expiresAt: tsNull('expires_at'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
});

export const ipIntelligence = sqliteTable('ip_intelligence', {
  id: id(),
  ipAddress: text('ip_address').notNull().unique(),
  firstSeenAt: ts('first_seen_at'),
  lastSeenAt: ts('last_seen_at'),
  requestCount: integer('request_count').notNull().default(0),
  eventCount: integer('event_count').notNull().default(0),
  failedLogins: integer('failed_logins').notNull().default(0),
  riskScore: integer('risk_score').notNull().default(0),
  riskLevel: text('risk_level').notNull().default('NORMAL'),
  country: text('country'),
  region: text('region'),
  city: text('city'),
  isVpn: integer('is_vpn', { mode: 'boolean' }).notNull().default(false),
  isProxy: integer('is_proxy', { mode: 'boolean' }).notNull().default(false),
  isTor: integer('is_tor', { mode: 'boolean' }).notNull().default(false),
  isDatacenter: integer('is_datacenter', { mode: 'boolean' }).notNull().default(false),
  isMalicious: integer('is_malicious', { mode: 'boolean' }).notNull().default(false),
  reputationScore: integer('reputation_score').notNull().default(0),
  lastIntelUpdate: tsNull('last_intel_update'),
});

export const auditLog = sqliteTable('audit_log', {
  id: id(),
  requestId: text('request_id'),
  actorType: text('actor_type').notNull(), // USER | API_KEY | SYSTEM
  actorId: text('actor_id'),
  actorLabel: text('actor_label'),
  action: text('action').notNull(),
  targetType: text('target_type'),
  targetId: text('target_id'),
  result: text('result').notNull().default('SUCCESS'),
  metadata: text('metadata'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('audit_log_created_idx').on(t.createdAt), index('audit_log_action_idx').on(t.action)]);

export const loginThrottle = sqliteTable('login_throttle', {
  keyHash: text('key_hash').primaryKey(),
  failures: integer('failures').notNull().default(0),
  lockedUntil: tsNull('locked_until'),
  updatedAt: ts('updated_at').default(sql`(unixepoch() * 1000)`),
});

export const detectionRules = sqliteTable('detection_rules', {
  code: text('code').primaryKey(),
  isEnabled: integer('is_enabled', { mode: 'boolean' }).notNull().default(true),
  priority: integer('priority').notNull().default(100),
  config: text('config').notNull().default('{}'), // JSON
  updatedAt: tsNull('updated_at'),
});


export const tenants = sqliteTable('tenants', {
  id: id(),
  name: text('name').notNull(),
  slug: text('slug').notNull().unique(),
  plan: text('plan').notNull().default('pilot'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
});

export const tenantMembers = sqliteTable('tenant_members', {
  id: id(),
  tenantId: text('tenant_id').notNull(),
  userId: text('user_id').notNull(),
  role: text('role').notNull().default('VIEWER'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('tenant_members_user_idx').on(t.userId), index('tenant_members_tenant_idx').on(t.tenantId)]);

export const stores = sqliteTable('stores', {
  id: id(),
  tenantId: text('tenant_id').notNull(),
  name: text('name').notNull(),
  platform: text('platform'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('stores_tenant_idx').on(t.tenantId)]);

export const webhooks = sqliteTable('webhooks', {
  id: id(),
  tenantId: text('tenant_id').notNull(),
  url: text('url').notNull(),
  secret: text('secret').notNull(),
  events: text('events').notNull().default('incident.created,block.created'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('webhooks_tenant_idx').on(t.tenantId)]);

export const webhookDeliveries = sqliteTable('webhook_deliveries', {
  id: id(),
  webhookId: text('webhook_id').notNull(),
  eventType: text('event_type').notNull(),
  payload: text('payload').notNull(),
  statusCode: integer('status_code'),
  success: integer('success', { mode: 'boolean' }).notNull().default(false),
  attempts: integer('attempts').notNull().default(0),
  lastError: text('last_error'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('webhook_deliveries_webhook_idx').on(t.webhookId)]);

export const incidentNotes = sqliteTable('incident_notes', {
  id: id(),
  incidentId: text('incident_id').notNull(),
  authorId: text('author_id'),
  body: text('body').notNull(),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('incident_notes_incident_idx').on(t.incidentId)]);

export const logEntries = sqliteTable('log_entries', {
  id: id(),
  tenantId: text('tenant_id').notNull(),
  source: text('source').notNull().default('https'),
  severity: text('severity'),
  message: text('message').notNull(),
  ipAddress: text('ip_address'),
  path: text('path'),
  method: text('method'),
  statusCode: integer('status_code'),
  userAgent: text('user_agent'),
  raw: text('raw'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [
  index('log_entries_tenant_created_idx').on(t.tenantId, t.createdAt),
  index('log_entries_ip_idx').on(t.ipAddress),
]);

export const incidentStatusHistory = sqliteTable('incident_status_history', {
  id: id(),
  incidentId: text('incident_id').notNull(),
  fromStatus: text('from_status'),
  toStatus: text('to_status').notNull(),
  actorId: text('actor_id'),
  createdAt: ts('created_at').default(sql`(unixepoch() * 1000)`),
}, (t) => [index('incident_status_history_incident_idx').on(t.incidentId)]);
