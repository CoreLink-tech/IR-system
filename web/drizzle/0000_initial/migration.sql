CREATE TABLE IF NOT EXISTS `users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`name` text,
	`password_hash` text NOT NULL,
	`role` text DEFAULT 'VIEWER' NOT NULL,
	`is_active` integer DEFAULT true NOT NULL,
	`must_change_password` integer DEFAULT false NOT NULL,
	`token_version` integer DEFAULT 0 NOT NULL,
	`password_changed_at` integer,
	`last_login_at` integer,
	`totp_secret` text,
	`totp_enabled_at` integer,
	`totp_last_step` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS `users_email_unique` ON `users` (`email`);

CREATE TABLE IF NOT EXISTS `recovery_codes` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`code_hash` text NOT NULL,
	`used_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade
);
CREATE UNIQUE INDEX IF NOT EXISTS `recovery_codes_code_hash_unique` ON `recovery_codes` (`code_hash`);
CREATE INDEX IF NOT EXISTS `recovery_codes_user_idx` ON `recovery_codes` (`user_id`);

CREATE TABLE IF NOT EXISTS `refresh_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`session_id` text NOT NULL,
	`session_started_at` integer NOT NULL,
	`last_used_at` integer,
	`device_label` text,
	`ip_address` text,
	`user_agent` text,
	`expires_at` integer NOT NULL,
	`revoked_at` integer,
	`revoked_reason` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade
);
CREATE UNIQUE INDEX IF NOT EXISTS `refresh_tokens_token_hash_unique` ON `refresh_tokens` (`token_hash`);
CREATE INDEX IF NOT EXISTS `refresh_tokens_user_idx` ON `refresh_tokens` (`user_id`);
CREATE INDEX IF NOT EXISTS `refresh_tokens_session_idx` ON `refresh_tokens` (`session_id`);

CREATE TABLE IF NOT EXISTS `api_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`key_prefix` text NOT NULL,
	`key_hash` text NOT NULL,
	`scopes` text DEFAULT 'events:write' NOT NULL,
	`is_active` integer DEFAULT true NOT NULL,
	`expires_at` integer,
	`last_used_at` integer,
	`revoked_at` integer,
	`created_by` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
CREATE INDEX IF NOT EXISTS `api_keys_prefix_idx` ON `api_keys` (`key_prefix`);

CREATE TABLE IF NOT EXISTS `events` (
	`id` text PRIMARY KEY NOT NULL,
	`api_key_id` text,
	`external_id` text,
	`event_type` text NOT NULL,
	`severity` text DEFAULT 'INFO' NOT NULL,
	`ip_address` text,
	`user_id` text,
	`session_id` text,
	`user_agent` text,
	`request_method` text,
	`request_path` text,
	`request_id` text,
	`metadata` text,
	`risk_score` integer DEFAULT 0 NOT NULL,
	`risk_level` text DEFAULT 'NORMAL' NOT NULL,
	`matched_rules` text,
	`incident_id` text,
	`occurred_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`api_key_id`) REFERENCES `api_keys`(`id`)
);
CREATE INDEX IF NOT EXISTS `events_ip_created_idx` ON `events` (`ip_address`,`created_at`);
CREATE INDEX IF NOT EXISTS `events_type_created_idx` ON `events` (`event_type`,`created_at`);
CREATE INDEX IF NOT EXISTS `events_incident_idx` ON `events` (`incident_id`);
CREATE UNIQUE INDEX IF NOT EXISTS `events_api_external_uidx` ON `events` (`api_key_id`,`external_id`);

CREATE TABLE IF NOT EXISTS `incidents` (
	`id` text PRIMARY KEY NOT NULL,
	`public_number` integer NOT NULL,
	`title` text NOT NULL,
	`status` text DEFAULT 'OPEN' NOT NULL,
	`severity` text DEFAULT 'MEDIUM' NOT NULL,
	`source_ip` text,
	`user_id` text,
	`open_key` text,
	`risk_score` integer DEFAULT 0 NOT NULL,
	`assigned_to` text,
	`summary` text,
	`event_count` integer DEFAULT 0 NOT NULL,
	`resolved_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS `incidents_public_number_uidx` ON `incidents` (`public_number`);
CREATE UNIQUE INDEX IF NOT EXISTS `incidents_open_key_uidx` ON `incidents` (`open_key`);
CREATE INDEX IF NOT EXISTS `incidents_status_idx` ON `incidents` (`status`);

CREATE TABLE IF NOT EXISTS `ip_blocks` (
	`id` text PRIMARY KEY NOT NULL,
	`ip_address` text NOT NULL,
	`action` text DEFAULT 'BLOCK' NOT NULL,
	`reason` text NOT NULL,
	`administrator_id` text,
	`related_incident_id` text,
	`is_permanent` integer DEFAULT false NOT NULL,
	`expires_at` integer,
	`active` integer DEFAULT true NOT NULL,
	`automatic` integer DEFAULT false NOT NULL,
	`active_key` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS `ip_blocks_active_key_uidx` ON `ip_blocks` (`active_key`);
CREATE INDEX IF NOT EXISTS `ip_blocks_ip_idx` ON `ip_blocks` (`ip_address`);

CREATE TABLE IF NOT EXISTS `allowlist` (
	`id` text PRIMARY KEY NOT NULL,
	`ip_address` text NOT NULL,
	`reason` text NOT NULL,
	`added_by` text,
	`expires_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS `allowlist_ip_address_unique` ON `allowlist` (`ip_address`);

CREATE TABLE IF NOT EXISTS `ip_intelligence` (
	`id` text PRIMARY KEY NOT NULL,
	`ip_address` text NOT NULL,
	`first_seen_at` integer,
	`last_seen_at` integer,
	`request_count` integer DEFAULT 0 NOT NULL,
	`event_count` integer DEFAULT 0 NOT NULL,
	`failed_logins` integer DEFAULT 0 NOT NULL,
	`risk_score` integer DEFAULT 0 NOT NULL,
	`risk_level` text DEFAULT 'NORMAL' NOT NULL,
	`country` text,
	`region` text,
	`city` text,
	`is_vpn` integer DEFAULT false NOT NULL,
	`is_proxy` integer DEFAULT false NOT NULL,
	`is_tor` integer DEFAULT false NOT NULL,
	`is_datacenter` integer DEFAULT false NOT NULL,
	`is_malicious` integer DEFAULT false NOT NULL,
	`reputation_score` integer DEFAULT 0 NOT NULL,
	`last_intel_update` integer
);
CREATE UNIQUE INDEX IF NOT EXISTS `ip_intelligence_ip_address_unique` ON `ip_intelligence` (`ip_address`);

CREATE TABLE IF NOT EXISTS `audit_log` (
	`id` text PRIMARY KEY NOT NULL,
	`request_id` text,
	`actor_type` text NOT NULL,
	`actor_id` text,
	`actor_label` text,
	`action` text NOT NULL,
	`target_type` text,
	`target_id` text,
	`result` text DEFAULT 'SUCCESS' NOT NULL,
	`metadata` text,
	`ip_address` text,
	`user_agent` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
CREATE INDEX IF NOT EXISTS `audit_log_created_idx` ON `audit_log` (`created_at`);
CREATE INDEX IF NOT EXISTS `audit_log_action_idx` ON `audit_log` (`action`);

CREATE TABLE IF NOT EXISTS `login_throttle` (
	`key_hash` text PRIMARY KEY NOT NULL,
	`failures` integer DEFAULT 0 NOT NULL,
	`locked_until` integer,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);

CREATE TABLE IF NOT EXISTS `detection_rules` (
	`code` text PRIMARY KEY NOT NULL,
	`is_enabled` integer DEFAULT true NOT NULL,
	`priority` integer DEFAULT 100 NOT NULL,
	`config` text DEFAULT '{}' NOT NULL,
	`updated_at` integer
);

CREATE TABLE IF NOT EXISTS `__drizzle_migrations` (
	`id` integer PRIMARY KEY AUTOINCREMENT,
	`hash` text NOT NULL,
	`created_at` integer
);
