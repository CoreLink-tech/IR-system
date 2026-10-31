CREATE TABLE IF NOT EXISTS incident_status_history (
  id TEXT PRIMARY KEY NOT NULL,
  incident_id TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  actor_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS incident_status_history_incident_idx ON incident_status_history(incident_id);
