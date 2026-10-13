-- Which migrations is this database already at? Run it against a database that was created with
-- "prisma db push" (or any other way) BEFORE the first "prisma migrate deploy":
--
--   mysql -u USER -p DATABASE < prisma/baseline/detect-stage.sql
--
-- One row per migration. present = 1 when everything that migration adds is already in the database.
-- partial = 1 when only some of it is (an interrupted upgrade): fix that by hand first, see docs/DATABASE.md.
-- For a healthy database the present column is a run of 1s followed by 0s. Mark every present = 1
-- migration as applied, then deploy the rest. This script only reads; it changes nothing.

SELECT migration, (found = total) AS present, (found > 0 AND found < total) AS partial
FROM (
    SELECT '20260101000000_init' AS migration, 1 AS ord, 11 AS total,
        (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN
            ('security_users','security_refresh_tokens','security_api_keys','security_events','security_incidents',
             'security_incident_timeline','security_ips','security_rules','security_ip_blocks','security_ip_allowlist',
             'security_audit_logs')) AS found
    UNION ALL
    SELECT '20260101000100_stage3_event_matched_rules', 2, 1,
        (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'security_events' AND column_name = 'matchedRules')
    UNION ALL
    SELECT '20260101000200_stage8_unique_slots', 3, 4,
        (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'security_incidents' AND column_name = 'openKey')
      + (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'security_ip_blocks' AND column_name = 'activeKey')
      + (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'security_incidents' AND index_name = 'security_incidents_openKey_key')
      + (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'security_ip_blocks' AND index_name = 'security_ip_blocks_activeKey_key')
    UNION ALL
    SELECT '20260101000300_stage8_event_external_id', 4, 2,
        (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'security_events' AND column_name = 'externalId')
      + (SELECT COUNT(*) FROM (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'security_events' AND index_name = 'security_events_apiKeyId_externalId_key' LIMIT 1) x)
    UNION ALL
    SELECT '20260101000400_stage9_must_change_password', 5, 1,
        (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'security_users' AND column_name = 'mustChangePassword')
) t
ORDER BY ord;
