CREATE TABLE IF NOT EXISTS rule_hits (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT,
  rule_code TEXT NOT NULL,
  entity_key TEXT,
  event_id TEXT,
  incident_id TEXT,
  mode TEXT NOT NULL DEFAULT 'enforce',
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS rule_hits_code_idx ON rule_hits(rule_code, created_at);

CREATE TABLE IF NOT EXISTS rule_verdicts (
  id TEXT PRIMARY KEY NOT NULL,
  rule_code TEXT NOT NULL,
  verdict TEXT NOT NULL,
  incident_id TEXT,
  actor_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS rule_verdicts_code_idx ON rule_verdicts(rule_code);

ALTER TABLE detection_rules ADD COLUMN mode TEXT DEFAULT 'enforce';
