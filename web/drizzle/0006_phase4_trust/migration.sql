ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;
CREATE INDEX IF NOT EXISTS audit_log_entry_hash_idx ON audit_log(entry_hash);
