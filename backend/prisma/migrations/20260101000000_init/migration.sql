-- Stage 1 schema: the first database this project shipped. Later schema changes are the migrations after this one.

-- CreateTable
CREATE TABLE `security_users` (
    `id` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `passwordHash` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NULL,
    `role` VARCHAR(191) NOT NULL,
    `isActive` BOOLEAN NOT NULL DEFAULT true,
    `lastLoginAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `security_users_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_refresh_tokens` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `tokenHash` VARCHAR(191) NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `revokedAt` DATETIME(3) NULL,
    `userAgent` VARCHAR(191) NULL,
    `ipAddress` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `security_refresh_tokens_tokenHash_key`(`tokenHash`),
    INDEX `security_refresh_tokens_userId_idx`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_api_keys` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `keyPrefix` VARCHAR(191) NOT NULL,
    `keyHash` VARCHAR(191) NOT NULL,
    `scopes` VARCHAR(191) NOT NULL,
    `isActive` BOOLEAN NOT NULL DEFAULT true,
    `expiresAt` DATETIME(3) NULL,
    `lastUsedAt` DATETIME(3) NULL,
    `revokedAt` DATETIME(3) NULL,
    `createdBy` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `security_api_keys_keyPrefix_key`(`keyPrefix`),
    INDEX `security_api_keys_keyPrefix_idx`(`keyPrefix`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_events` (
    `id` VARCHAR(191) NOT NULL,
    `eventType` VARCHAR(191) NOT NULL,
    `severity` VARCHAR(191) NOT NULL,
    `ipAddress` VARCHAR(191) NULL,
    `userId` VARCHAR(191) NULL,
    `sessionId` VARCHAR(191) NULL,
    `userAgent` VARCHAR(191) NULL,
    `requestMethod` VARCHAR(191) NULL,
    `requestPath` VARCHAR(191) NULL,
    `requestId` VARCHAR(191) NULL,
    `metadata` JSON NULL,
    `riskScore` INTEGER NOT NULL DEFAULT 0,
    `riskLevel` VARCHAR(191) NOT NULL DEFAULT 'NORMAL',
    `occurredAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `apiKeyId` VARCHAR(191) NULL,
    `incidentId` VARCHAR(191) NULL,

    INDEX `security_events_ipAddress_idx`(`ipAddress`),
    INDEX `security_events_occurredAt_idx`(`occurredAt`),
    INDEX `security_events_eventType_idx`(`eventType`),
    INDEX `security_events_severity_idx`(`severity`),
    INDEX `security_events_userId_idx`(`userId`),
    INDEX `security_events_incidentId_idx`(`incidentId`),
    INDEX `security_events_riskLevel_idx`(`riskLevel`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_incidents` (
    `id` VARCHAR(191) NOT NULL,
    `incidentId` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `description` TEXT NOT NULL,
    `severity` VARCHAR(191) NOT NULL,
    `riskScore` INTEGER NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'OPEN',
    `sourceIp` VARCHAR(191) NULL,
    `userId` VARCHAR(191) NULL,
    `sessionId` VARCHAR(191) NULL,
    `detectionRule` VARCHAR(191) NULL,
    `assignedTo` VARCHAR(191) NULL,
    `resolutionNotes` TEXT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,
    `resolvedAt` DATETIME(3) NULL,

    UNIQUE INDEX `security_incidents_incidentId_key`(`incidentId`),
    INDEX `security_incidents_status_idx`(`status`),
    INDEX `security_incidents_severity_idx`(`severity`),
    INDEX `security_incidents_riskScore_idx`(`riskScore`),
    INDEX `security_incidents_sourceIp_idx`(`sourceIp`),
    INDEX `security_incidents_createdAt_idx`(`createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_incident_timeline` (
    `id` VARCHAR(191) NOT NULL,
    `incidentId` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `actor` VARCHAR(191) NULL,
    `details` TEXT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `security_incident_timeline_incidentId_idx`(`incidentId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_ips` (
    `id` VARCHAR(191) NOT NULL,
    `ipAddress` VARCHAR(191) NOT NULL,
    `firstSeenAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `lastSeenAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `requestCount` INTEGER NOT NULL DEFAULT 0,
    `eventCount` INTEGER NOT NULL DEFAULT 0,
    `failedLogins` INTEGER NOT NULL DEFAULT 0,
    `riskScore` INTEGER NOT NULL DEFAULT 0,
    `riskLevel` VARCHAR(191) NOT NULL DEFAULT 'NORMAL',
    `country` VARCHAR(191) NULL,
    `region` VARCHAR(191) NULL,
    `city` VARCHAR(191) NULL,
    `isVpn` BOOLEAN NOT NULL DEFAULT false,
    `isProxy` BOOLEAN NOT NULL DEFAULT false,
    `isTor` BOOLEAN NOT NULL DEFAULT false,
    `isDatacenter` BOOLEAN NOT NULL DEFAULT false,
    `isMalicious` BOOLEAN NOT NULL DEFAULT false,
    `reputationScore` INTEGER NOT NULL DEFAULT 0,
    `lastIntelUpdate` DATETIME(3) NULL,
    `notes` TEXT NULL,

    UNIQUE INDEX `security_ips_ipAddress_key`(`ipAddress`),
    INDEX `security_ips_riskScore_idx`(`riskScore`),
    INDEX `security_ips_lastSeenAt_idx`(`lastSeenAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_rules` (
    `id` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `description` TEXT NOT NULL,
    `isEnabled` BOOLEAN NOT NULL DEFAULT true,
    `priority` INTEGER NOT NULL DEFAULT 100,
    `config` JSON NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `security_rules_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_ip_blocks` (
    `id` VARCHAR(191) NOT NULL,
    `ipAddress` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `reason` TEXT NOT NULL,
    `administratorId` VARCHAR(191) NULL,
    `relatedIncidentId` VARCHAR(191) NULL,
    `isPermanent` BOOLEAN NOT NULL DEFAULT false,
    `expiresAt` DATETIME(3) NULL,
    `active` BOOLEAN NOT NULL DEFAULT true,
    `automatic` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `security_ip_blocks_ipAddress_idx`(`ipAddress`),
    INDEX `security_ip_blocks_active_idx`(`active`),
    INDEX `security_ip_blocks_expiresAt_idx`(`expiresAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_ip_allowlist` (
    `id` VARCHAR(191) NOT NULL,
    `ipAddress` VARCHAR(191) NOT NULL,
    `reason` TEXT NOT NULL,
    `addedBy` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `expiresAt` DATETIME(3) NULL,

    UNIQUE INDEX `security_ip_allowlist_ipAddress_key`(`ipAddress`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `security_audit_logs` (
    `id` VARCHAR(191) NOT NULL,
    `requestId` VARCHAR(191) NULL,
    `actorType` VARCHAR(191) NOT NULL,
    `actorId` VARCHAR(191) NULL,
    `actorLabel` VARCHAR(191) NULL,
    `action` VARCHAR(191) NOT NULL,
    `targetType` VARCHAR(191) NULL,
    `targetId` VARCHAR(191) NULL,
    `result` VARCHAR(191) NOT NULL,
    `metadata` JSON NULL,
    `ipAddress` VARCHAR(191) NULL,
    `userAgent` VARCHAR(191) NULL,
    `userId` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `security_audit_logs_actorId_idx`(`actorId`),
    INDEX `security_audit_logs_action_idx`(`action`),
    INDEX `security_audit_logs_createdAt_idx`(`createdAt`),
    INDEX `security_audit_logs_userId_idx`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `security_refresh_tokens` ADD CONSTRAINT `security_refresh_tokens_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `security_users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `security_events` ADD CONSTRAINT `security_events_incidentId_fkey` FOREIGN KEY (`incidentId`) REFERENCES `security_incidents`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `security_incidents` ADD CONSTRAINT `security_incidents_assignedTo_fkey` FOREIGN KEY (`assignedTo`) REFERENCES `security_users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `security_incident_timeline` ADD CONSTRAINT `security_incident_timeline_incidentId_fkey` FOREIGN KEY (`incidentId`) REFERENCES `security_incidents`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `security_ip_blocks` ADD CONSTRAINT `security_ip_blocks_administratorId_fkey` FOREIGN KEY (`administratorId`) REFERENCES `security_users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `security_ip_blocks` ADD CONSTRAINT `security_ip_blocks_relatedIncidentId_fkey` FOREIGN KEY (`relatedIncidentId`) REFERENCES `security_incidents`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `security_audit_logs` ADD CONSTRAINT `security_audit_logs_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `security_users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
