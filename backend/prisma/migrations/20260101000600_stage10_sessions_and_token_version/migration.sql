-- Stage 10, authentication hardening (part 1): sessions and access-token revocation.
--
-- users.tokenVersion: every access and refresh token carries the version it was issued under. Changing a
-- password, signing out everywhere or an administrator reset raises it, which ends every token of that
-- account at once. Existing tokens carry no version and count as version 0, so nobody is signed out by this
-- migration.
-- users.passwordChangedAt: when the password was last set (shown to the owner, null for older accounts).
--
-- refresh_tokens.sessionId / sessionStartedAt: a refresh token is replaced on every use; these stay the same
-- across replacements so one device is one session. Existing tokens each become their own session.
-- refresh_tokens.lastUsedAt / deviceLabel: shown on the sessions page.
-- refresh_tokens.revokedReason: why a token was ended. Only a token that was already replaced ("rotated", or
-- empty on older rows) triggers the "possible theft, end all sessions" response when it is presented again.
-- A session ended on purpose does not.

-- AlterTable
ALTER TABLE `security_users` ADD COLUMN `tokenVersion` INTEGER NOT NULL DEFAULT 0;
ALTER TABLE `security_users` ADD COLUMN `passwordChangedAt` DATETIME(3) NULL;

-- AlterTable
ALTER TABLE `security_refresh_tokens` ADD COLUMN `sessionId` VARCHAR(191) NULL;
ALTER TABLE `security_refresh_tokens` ADD COLUMN `sessionStartedAt` DATETIME(3) NULL;
ALTER TABLE `security_refresh_tokens` ADD COLUMN `lastUsedAt` DATETIME(3) NULL;
ALTER TABLE `security_refresh_tokens` ADD COLUMN `deviceLabel` VARCHAR(191) NULL;
ALTER TABLE `security_refresh_tokens` ADD COLUMN `revokedReason` VARCHAR(191) NULL;

-- Backfill: every existing token is its own session.
UPDATE `security_refresh_tokens` SET `sessionId` = `id`, `sessionStartedAt` = `createdAt`, `lastUsedAt` = `createdAt` WHERE `sessionId` IS NULL;

ALTER TABLE `security_refresh_tokens` MODIFY `sessionId` VARCHAR(191) NOT NULL;
ALTER TABLE `security_refresh_tokens` MODIFY `sessionStartedAt` DATETIME(3) NOT NULL;

-- CreateIndex
CREATE INDEX `security_refresh_tokens_sessionId_idx` ON `security_refresh_tokens`(`sessionId`);
