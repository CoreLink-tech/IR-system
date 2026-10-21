-- Stage 10, authentication hardening (part 3): per-account sign-in lockout with growing delays.
--
-- One row per (hashed) email address that has had failed sign-in attempts, whether or not an account with that
-- email exists, so a lock looks the same for real and invented addresses. `key` is "login:" plus the SHA-256
-- of the lower-cased email (the email itself is never stored here). The row is deleted when the person signs
-- in successfully, when a super admin unlocks the account, and by the cleanup job a day after the last failure.

-- CreateTable
CREATE TABLE `security_login_throttle` (
    `key` VARCHAR(191) NOT NULL,
    `failures` INTEGER NOT NULL DEFAULT 0,
    `lockedUntil` DATETIME(3) NULL,
    `lastFailureAt` DATETIME(3) NOT NULL,
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `security_login_throttle_lastFailureAt_idx`(`lastFailureAt`),
    PRIMARY KEY (`key`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
