-- Stage 10: index review. Evidence (query plans, rows read and times before and after, on 660,000
-- events) is in docs/DATABASE.md and was produced by scripts/index-review.mjs.
--
-- The single-column event indexes made the optimizer read tens of thousands of rows for lookups that
-- ask for "this address (or account, incident, type) within a time window". Each is replaced by a
-- composite whose first column is the old one, so no lookup loses an index. The new indexes are created
-- before the old ones are dropped. No data changes. security_events keeps fewer indexes than before
-- (riskLevel was used by no query), so ingestion does not get slower.

-- security_events: create the composites
CREATE INDEX `security_events_ipAddress_occurredAt_idx` ON `security_events`(`ipAddress`, `occurredAt`);
CREATE INDEX `security_events_eventType_occurredAt_idx` ON `security_events`(`eventType`, `occurredAt`);
CREATE INDEX `security_events_userId_eventType_occurredAt_idx` ON `security_events`(`userId`, `eventType`, `occurredAt`);
CREATE INDEX `security_events_incidentId_occurredAt_idx` ON `security_events`(`incidentId`, `occurredAt`);
CREATE INDEX `security_events_severity_occurredAt_idx` ON `security_events`(`severity`, `occurredAt`);

-- security_events: drop what they replace, and the unused riskLevel index
DROP INDEX `security_events_ipAddress_idx` ON `security_events`;
DROP INDEX `security_events_eventType_idx` ON `security_events`;
DROP INDEX `security_events_userId_idx` ON `security_events`;
DROP INDEX `security_events_incidentId_idx` ON `security_events`;
DROP INDEX `security_events_severity_idx` ON `security_events`;
DROP INDEX `security_events_riskLevel_idx` ON `security_events`;

-- security_audit_logs: "everything that happened to this target", newest first
CREATE INDEX `security_audit_logs_targetId_createdAt_idx` ON `security_audit_logs`(`targetId`, `createdAt`);

-- security_api_keys: keyPrefix is already unique, so the second index on it was a pure duplicate
DROP INDEX `security_api_keys_keyPrefix_idx` ON `security_api_keys`;
