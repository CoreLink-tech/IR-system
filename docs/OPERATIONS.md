# Operations runbook

Daily checks, alerts, backups, secret rotation, upgrades, and break-glass procedures.
Expand this file as Stage 10 workstreams complete.

## Break-glass commands

From the backend directory after `npm run build`:

    npm run admin:reset-2fa -- user@example.com
    npm run admin:unlock -- user@example.com
    npm run admin:reencrypt-2fa          # or --dry-run

Both unlock and reset-2fa write an audit row with actorType SYSTEM and label "cli".

## Secret rotation (access JWT, refresh JWT, TOTP encryption key)

### Access token secret (JWT_SECRET)

1. Generate a new secret: `openssl rand -hex 48`
2. Set `JWT_SECRET_PREVIOUS` to the **current** value of `JWT_SECRET`.
3. Set `JWT_SECRET` to the new value.
4. Optionally bump `JWT_KEY_ID` (e.g. from `v1` to `v2`) and set `JWT_KEY_ID_PREVIOUS` to the old id.
5. Restart the API. Existing tokens keep working (verified under the previous key). New tokens are signed with the new key and carry the new kid.
6. After all access tokens issued under the old key have expired (15 minutes by default), remove `JWT_SECRET_PREVIOUS` and `JWT_KEY_ID_PREVIOUS`. Restart again. Old tokens are then refused.

### Refresh token secret (JWT_REFRESH_SECRET)

Same pattern with `JWT_REFRESH_SECRET` / `JWT_REFRESH_SECRET_PREVIOUS` and optional
`JWT_REFRESH_KEY_ID` / `JWT_REFRESH_KEY_ID_PREVIOUS`. The CSRF token HMAC uses the refresh
secret; during the overlap a CSRF token computed with either key is accepted. After the
overlap window (refresh tokens last 7 days by default), remove the previous settings.

### Two-step encryption key (TOTP_ENCRYPTION_KEY)

1. Set `TOTP_ENCRYPTION_KEY_PREVIOUS` to the current key.
2. Set `TOTP_ENCRYPTION_KEY` to a new key (`openssl rand -hex 32`).
3. Restart.
4. Run `npm run admin:reencrypt-2fa` (or `--dry-run` first). This rewrites every stored
   secret with the current key and is resumable.
5. After the report shows zero secrets still on the previous key, remove
   `TOTP_ENCRYPTION_KEY_PREVIOUS` and restart.
6. Recovery codes hashed only under the previous key will stop working once that key is
   removed. Ask users to regenerate recovery codes if any remain on the old key.

### API key pepper (API_KEY_HASH_PEPPER)

1. Generate a new pepper: `openssl rand -hex 24`
2. Set `API_KEY_HASH_PEPPER_PREVIOUS` to the **current** value of `API_KEY_HASH_PEPPER`.
3. Set `API_KEY_HASH_PEPPER` to the new value.
4. Restart the API. Existing keys still authenticate (verified under the previous pepper).
   On each successful use the key is rehashed under the current pepper and stored.
5. After traffic has exercised every active key (or after you have rotated any idle keys
   from the dashboard), remove `API_KEY_HASH_PEPPER_PREVIOUS` and restart. Any key that
   was never presented during the overlap will then fail verification and must be
   re-issued.

## First-install notes (two-step)

In production `REQUIRE_2FA` defaults to on. The first super admin created by `npm run seed`
must enrol at the first sign-in. The server will not start without `TOTP_ENCRYPTION_KEY`
when two-step is required. Generate secrets with `npm run gen:secrets`.

## Not yet covered here

- Daily checklists and alert suggestions (R2 metrics)
- Backup / restore drill schedule (see docs/DATABASE.md for the scripts)
- Full deployment steps (docs/DEPLOYMENT.md, still to be written)
- Upgrade and rollback notes beyond "migrations are forward only"


## Hand-applied Turso migrations (Phase 1–4)

Production Turso was updated in the SQL console with migrations `0001_phase1` through `0006_phase4_trust` without recording rows in `__drizzle_migrations`. Future `npm run db:migrate` may try to re-apply them. The migrator already treats a **directory name** as a valid applied marker (not only content hashes).

Run **once** in the Turso console so migrate skips those folders:

```sql
INSERT INTO __drizzle_migrations (hash, created_at) VALUES
  ('0001_phase1', unixepoch()*1000),
  ('0002_phase1_status_history', unixepoch()*1000),
  ('0003_phase2_detection', unixepoch()*1000),
  ('0004_phase2_finish', unixepoch()*1000),
  ('0005_phase3_decide', unixepoch()*1000),
  ('0006_phase4_trust', unixepoch()*1000);
```

Verify key columns exist:

```sql
PRAGMA table_info(api_keys);
PRAGMA table_info(events);
PRAGMA table_info(detection_rules);
```

You should see `tenant_id` and `rate_limit_per_minute` on `api_keys`, `tenant_id` on `events`, and `mode` on `detection_rules`.

## Branch protection (GitHub)

Require the **Web CI** check to pass before merging to `main`:

1. Repo **Settings → Branches → Add rule** (or edit rule for `main`).
2. Enable **Require status checks to pass before merging**.
3. Select **Web CI** (the workflow defined under `.github/workflows`).
4. Do not allow bypass for admins on production-critical merges if your org policy allows locking that down.


## Emergency unlock (web)

From `web/` with production env:

```bash
node --env-file=.env scripts/unlock-user.mjs user@example.com
```

Clears password-login and MFA throttle rows for that email and writes a SYSTEM audit row.


## Webhook retries migration (0008)

Run once in Turso if not already applied:

```sql
ALTER TABLE webhook_deliveries ADD COLUMN next_attempt_at INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN dead INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhook_deliveries ADD COLUMN event_id TEXT;
CREATE INDEX IF NOT EXISTS webhook_deliveries_next_idx ON webhook_deliveries(next_attempt_at);

INSERT INTO __drizzle_migrations (hash, created_at)
VALUES ('0008_webhook_retries', unixepoch()*1000);
```

## Tenancy note

This deployment remains **single-tenant** until every query filters by `tenant_id`. Do not onboard a second customer on the same database without that work.
