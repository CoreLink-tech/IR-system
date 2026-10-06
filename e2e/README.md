# End-to-end tests

These tests run the **whole system together**: the real API, the real database and the
real PHP library, talking over HTTP. Nothing is mocked. They answer one question:
*does the thing a shop owner actually relies on work?*

    E2E_CONFIRM=yes E2E_BASE=http://localhost:4000 node e2e/run.mjs

**They write test data** (accounts, API keys, events, incidents, blocks), so run them
against a test database, never production. The suite refuses to start without
`E2E_CONFIRM=yes`. It cleans up the blocks, allowlist entries and API keys it makes.
Events, incidents and the three test accounts stay behind, named `e2e-<run id>-...`.
All addresses come from ranges reserved for documentation and testing, so no real
visitor is ever involved.

Needs Node 18+. The PHP scenarios also need PHP 7.4+ with the curl extension and are
skipped, with a note, if PHP is not found.

## Settings

| Variable | Meaning | Default |
|----------|---------|---------|
| `E2E_CONFIRM` | must be `yes` | none |
| `E2E_BASE` | address of the API | `http://localhost:4000` |
| `E2E_ADMIN_EMAIL`, `E2E_ADMIN_PASSWORD` | a super administrator | the seed account |
| `E2E_PHP` | the PHP binary | `php` |
| `E2E_ONLY` | run only some scenarios, e.g. `05,08` | all |
| `E2E_API_STOP`, `E2E_API_START` | shell commands that stop and start the API | outage tests skipped |
| `E2E_DB_STOP`, `E2E_DB_START` | shell commands that stop and start the database | database outage test skipped |

The outage commands are yours because only you know how the API and database are run
(systemd, Docker, pm2...). For example with Docker:

    E2E_API_STOP='docker stop ir-api' E2E_API_START='docker start ir-api' \
    E2E_DB_STOP='docker stop ir-db'   E2E_DB_START='docker start ir-db'

Run the PHP scenarios with the same environment the shop will use, in particular the
blocklist refresh time. The suite sets its own short refresh (1 second) so it does not
have to wait.

## What it checks

| # | Scenario |
|---|----------|
| 00 | The system is up |
| 01 | Creating accounts for every role and API keys with different scopes |
| 02 | Wrong password and unknown email look the same; refresh tokens rotate; reusing one is treated as theft |
| 03 | About 40 combinations of role and route, plus what each kind of API key may do |
| 04 | What is stored: secrets redacted in data and URLs, addresses normalized, bad input refused |
| 05 | One address attacking logins: incident opens, escalates to CRITICAL, address is blocked, counts are exact |
| 06 | Injection attempts and reset abuse add risk without opening incidents |
| 07 | Account takeover, one account attacked from many addresses, a platform-wide spray |
| 08 | 60 simultaneous events from one attacker: one incident, one block, no lost counts |
| 09 | Reports quote the real numbers, hide the raw evidence from viewers, and are audited |
| 10 | Blocking: private addresses refused, an administrator's block survives an attack, the allowlist protects |
| 11 | API key rotation and revocation take effect at once |
| 12 | The PHP library: visitor behind a proxy is attributed correctly, blocked in enforce mode, never in monitor mode, spoofed headers ignored, unblock and manual block take effect |
| 13 | The API goes down and comes back; the database goes down and comes back. Blocks stay in force, pages stay fast, events queue and are delivered once each |
| 98 | A burst of 300 events is accepted; repeated sign-ins are cut off with a retry time |
| 99 | Clean up |

## Reading the results

Each line is `ok`, `FAIL` or `skip`. The run ends with a count and exits non-zero if
anything failed. A failure shows what was expected and what was seen.

## Findings so far

Running this suite found, and these were then fixed:

- 11 duplicate incidents, 10 block records and lost counts under parallel attack
  traffic (race conditions).
- The shop's whole event stream shared one small per-address rate limit, so events
  would have been refused during busy periods and attacks.
- Events delayed by a slow API could be stored twice.
- Queued events were only sent when something new happened to be reported.
- Releasing an old incident's slot made it look freshly updated.
