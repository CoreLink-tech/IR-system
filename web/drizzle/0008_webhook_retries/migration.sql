ALTER TABLE webhook_deliveries ADD COLUMN next_attempt_at INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN dead INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhook_deliveries ADD COLUMN event_id TEXT;
CREATE INDEX IF NOT EXISTS webhook_deliveries_next_idx ON webhook_deliveries(next_attempt_at);
