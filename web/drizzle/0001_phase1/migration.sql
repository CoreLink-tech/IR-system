-- Phase 1: multi-tenancy foundation, webhooks, incident notes, log ingest MVP
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  plan TEXT NOT NULL DEFAULT 'pilot',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE TABLE IF NOT EXISTS tenant_members (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'VIEWER',
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  UNIQUE (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS tenant_members_user_idx ON tenant_members(user_id);
CREATE INDEX IF NOT EXISTS tenant_members_tenant_idx ON tenant_members(tenant_id);

CREATE TABLE IF NOT EXISTS stores (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  platform TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS stores_tenant_idx ON stores(tenant_id);

CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT 'incident.created,block.created',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS webhooks_tenant_idx ON webhooks(tenant_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY NOT NULL,
  webhook_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  status_code INTEGER,
  success INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_webhook_idx ON webhook_deliveries(webhook_id);

CREATE TABLE IF NOT EXISTS incident_notes (
  id TEXT PRIMARY KEY NOT NULL,
  incident_id TEXT NOT NULL,
  author_id TEXT,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS incident_notes_incident_idx ON incident_notes(incident_id);

CREATE TABLE IF NOT EXISTS log_entries (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'https',
  severity TEXT,
  message TEXT NOT NULL,
  ip_address TEXT,
  path TEXT,
  method TEXT,
  status_code INTEGER,
  user_agent TEXT,
  raw TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS log_entries_tenant_created_idx ON log_entries(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS log_entries_ip_idx ON log_entries(ip_address);

-- Soft tenancy on existing tables (nullable → backfilled to default tenant)
ALTER TABLE api_keys ADD COLUMN tenant_id TEXT;
ALTER TABLE api_keys ADD COLUMN rate_limit_per_minute INTEGER DEFAULT 120;
ALTER TABLE events ADD COLUMN tenant_id TEXT;
ALTER TABLE incidents ADD COLUMN tenant_id TEXT;
ALTER TABLE ip_blocks ADD COLUMN tenant_id TEXT;
ALTER TABLE allowlist ADD COLUMN tenant_id TEXT;
ALTER TABLE audit_log ADD COLUMN tenant_id TEXT;
ALTER TABLE detection_rules ADD COLUMN tenant_id TEXT;
ALTER TABLE ip_intelligence ADD COLUMN tenant_id TEXT;
