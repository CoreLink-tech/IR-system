-- Stage 8: the database itself guarantees one open incident per slot and one active block per address.
-- Needs MySQL 8.0 or MariaDB 10.2 or newer for the backfill below (window functions).

-- AlterTable
ALTER TABLE `security_incidents` ADD COLUMN `openKey` VARCHAR(191) NULL;
ALTER TABLE `security_ip_blocks` ADD COLUMN `activeKey` VARCHAR(191) NULL;

-- Backfill for rows that already exist, using the same slot names the application uses
-- (ip:<address>, acct:<user>:<rule>, glob:<rule>). Each slot can be held by one row only, so if an
-- older database already holds several open incidents for one slot, the most recently updated one
-- takes the slot and the others stay open but do not take new events (the same state the
-- application itself produces for a quiet incident). Nothing is closed or deleted.
UPDATE `security_incidents` AS i
JOIN (
    SELECT r.id, r.k FROM (
        SELECT s.id, s.k, ROW_NUMBER() OVER (PARTITION BY s.k ORDER BY s.updatedAt DESC, s.id DESC) AS rn
        FROM (
            SELECT id, updatedAt,
                CASE
                    WHEN sourceIp IS NOT NULL THEN CONCAT('ip:', sourceIp)
                    WHEN userId IS NOT NULL THEN CONCAT('acct:', userId, ':', COALESCE(detectionRule, ''))
                    ELSE CONCAT('glob:', COALESCE(detectionRule, ''))
                END AS k
            FROM `security_incidents`
            WHERE status IN ('OPEN', 'INVESTIGATING')
        ) AS s
    ) AS r
    WHERE r.rn = 1
) AS w ON w.id = i.id
SET i.openKey = w.k;

-- If several active blocks already exist for one address, the strongest one takes the slot
-- (permanent first, then the latest expiry, then the newest). The others stay active, so the address
-- stays blocked exactly as before; they simply do not hold the slot.
UPDATE `security_ip_blocks` AS b
JOIN (
    SELECT r.id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY ipAddress
            ORDER BY isPermanent DESC, (expiresAt IS NULL) DESC, expiresAt DESC, createdAt DESC, id DESC
        ) AS rn
        FROM `security_ip_blocks`
        WHERE active = true
    ) AS r
    WHERE r.rn = 1
) AS w ON w.id = b.id
SET b.activeKey = b.ipAddress;

-- CreateIndex
CREATE UNIQUE INDEX `security_incidents_openKey_key` ON `security_incidents`(`openKey`);
CREATE UNIQUE INDEX `security_ip_blocks_activeKey_key` ON `security_ip_blocks`(`activeKey`);
