-- Stage 9: an administrator can force a password change. Existing accounts are not affected.

-- AlterTable
ALTER TABLE `security_users` ADD COLUMN `mustChangePassword` BOOLEAN NOT NULL DEFAULT false;
