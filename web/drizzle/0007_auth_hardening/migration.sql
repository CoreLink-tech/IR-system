CREATE TABLE IF NOT EXISTS used_challenges (
  jti TEXT PRIMARY KEY NOT NULL,
  user_id TEXT,
  failures INTEGER NOT NULL DEFAULT 0,
  burned_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE INDEX IF NOT EXISTS used_challenges_user_idx ON used_challenges(user_id);
