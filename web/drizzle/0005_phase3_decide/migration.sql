CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT,
  api_key_id TEXT,
  idempotency_key TEXT,
  outcome TEXT NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  reasons TEXT,
  rule_hits TEXT,
  ip_address TEXT,
  user_id TEXT,
  session_id TEXT,
  action_context TEXT,
  ttl_seconds INTEGER NOT NULL DEFAULT 60,
  feedback TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE UNIQUE INDEX IF NOT EXISTS decisions_idem_idx ON decisions(api_key_id, idempotency_key);
CREATE INDEX IF NOT EXISTS decisions_created_idx ON decisions(created_at);
CREATE INDEX IF NOT EXISTS decisions_ip_idx ON decisions(ip_address);
