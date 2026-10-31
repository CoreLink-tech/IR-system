# Detection — what Watcher (`web/`) actually does today

This document is the **source of truth** for production detection. Legacy Nest docs that describe 16 rules, velocity windows, or external IP intel **do not apply** to `web/`.

## Scoring (synchronous, per event)

Base scores (defaults, configurable in Admin → Rules):

| Rule code | Event type | Default base |
|-----------|------------|--------------|
| `login_failed` | `login_failed` | 30 |
| `suspicious_request` | `suspicious_request` | 40 |
| `rate_limit` | `rate_limit_exceeded` | 30 |
| `payment` | `payment_security_event` | 50 |
| `admin_access` | `admin_access` | 45 |

Severity bumps: MEDIUM +10, HIGH +20, CRITICAL +30. Cap 100.

- **Incident open/attach:** score ≥ **35** and an IP is present.
- **Auto-block:** score ≥ **`auto_block.threshold`** (default **70**). Private and allowlisted IPs are never blocked.

## What is not implemented

- Time windows / velocity counters
- Sequence or absence rules
- Cross-IP or cross-account correlation
- External IP/ASN/geo reputation feeds
- Server log ingestion as a detection source
- Webhooks / email / Slack alerts

## Incident attachment

Incidents are keyed by `open_key = ip:<address>`. New events attach to the existing row while `open_key` is set (status OPEN, INVESTIGATING, or CONTAINED). `open_key` is cleared when status becomes RESOLVED or FALSE_POSITIVE.

## Event durability

Events are written **before** incident create and auto-block. Failures in those steps no longer drop the event or force endless SDK retries for a 500 on unique `open_key`.
