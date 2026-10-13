-- Stage 3: detection rules that fired for an event are stored with it, so reports can cite them.
ALTER TABLE `security_events` ADD COLUMN `matchedRules` JSON NULL;
