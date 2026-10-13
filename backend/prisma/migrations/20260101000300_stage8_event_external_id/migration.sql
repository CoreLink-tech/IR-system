-- Stage 8: a sender-chosen id per event, so a repeated delivery is recognised and stored once.
-- Existing events keep a NULL externalId; the pair is unique only when both parts are set.

-- AlterTable
ALTER TABLE `security_events` ADD COLUMN `externalId` VARCHAR(191) NULL;

-- CreateIndex
CREATE UNIQUE INDEX `security_events_apiKeyId_externalId_key` ON `security_events`(`apiKeyId`, `externalId`);
