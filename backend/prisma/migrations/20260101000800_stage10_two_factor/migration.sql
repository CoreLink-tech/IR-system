-- Stage 10, authentication hardening (part 4): optional two-step verification (TOTP) with recovery codes.
--
-- users.totpSecret: the authenticator secret, ENCRYPTED with a key from the environment (AES-256-GCM). While
-- totpEnabledAt is empty it is a pending enrolment that the person has not confirmed yet.
-- users.totpEnabledAt: when two-step verification was switched on (confirmed with a first valid code).
-- users.totpLastStep: the time step of the last code accepted, so a code cannot be used twice.
--
-- recovery_codes: one row per recovery code. Only a keyed hash is stored, never the code. A code is used once
-- (usedAt), consumed with a single conditional UPDATE so two simultaneous uses cannot both succeed.

-- AlterTable
ALTER TABLE `security_users` ADD COLUMN `totpSecret` VARCHAR(191) NULL;
ALTER TABLE `security_users` ADD COLUMN `totpEnabledAt` DATETIME(3) NULL;
ALTER TABLE `security_users` ADD COLUMN `totpLastStep` INTEGER NULL;

-- CreateTable
CREATE TABLE `security_recovery_codes` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `codeHash` VARCHAR(191) NOT NULL,
    `usedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `security_recovery_codes_codeHash_key`(`codeHash`),
    INDEX `security_recovery_codes_userId_idx`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `security_recovery_codes` ADD CONSTRAINT `security_recovery_codes_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `security_users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
