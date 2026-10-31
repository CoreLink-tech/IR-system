CREATE TABLE IF NOT EXISTS entity_scores (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT,
  entity_type TEXT NOT NULL,
  entity_key TEXT NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  last_event_at INTEGER,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  UNIQUE (tenant_id, entity_type, entity_key)
);
CREATE INDEX IF NOT EXISTS entity_scores_key_idx ON entity_scores(entity_type, entity_key);

CREATE TABLE IF NOT EXISTS rule_cooldowns (
  id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT,
  rule_code TEXT NOT NULL,
  entity_key TEXT NOT NULL,
  until_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS rule_cooldowns_lookup_idx ON rule_cooldowns(rule_code, entity_key, until_at);
