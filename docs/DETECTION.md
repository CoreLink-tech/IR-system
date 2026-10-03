# Detection

Detection is rule based and deterministic. Every event is scored by the enabled
rules; the scores are added (capped at 100) and rated NORMAL, SUSPICIOUS, HIGH or
CRITICAL (defaults: 30, 60 and 80, set by `RISK_LEVEL_*`). Rules that create
incidents are marked below. Rule thresholds are stored in `security_rules.config`
and can be changed without a deploy.

## Rules

| Rule | Fires when | Incident |
|------|------------|----------|
| `brute_force_login` | 5 or more failed logins from one address in 10 minutes | yes, by address |
| `credential_stuffing` | failed logins against 4 or more accounts from one address | yes, by address |
| `high_request_rate` | 60 or more events from one address in 5 minutes | no |
| `user_enumeration` | login or reset activity across 6 or more accounts from one address | no |
| `password_reset_abuse` | 4 or more password resets from one address | no |
| `suspicious_admin_access` | admin access from a Tor or known-malicious address | no |
| `known_malicious_ip` | the address is flagged malicious by the intelligence provider | no |
| `tor_or_proxy` | the address is Tor, proxy or VPN (a signal, not proof) | no |
| `suspicious_payload` | the request looks like script injection, SQL injection or path traversal | no |
| `order_id_enumeration` | many requests stepping through order or product numbers | no |
| `payment_abuse_signal` | 3 or more payment security events from one address | yes, by address |
| `session_anomaly` | repeated session anomaly events from one address | no |
| `possible_account_takeover` | a successful login on an account that had 3 or more failed logins in the last 15 minutes, from any address | yes, by address |
| `distributed_account_attack` | failed logins on one account from 4 or more different addresses | yes, by account |
| `distributed_login_attack` | 40 or more failed logins from 15 or more different addresses in 10 minutes, platform wide | yes, platform wide |
| `impossible_travel` | the same account logged in from two different countries within 2 hours | yes, by address |

Notes:
- Takeover is HIGH by default. It is CRITICAL only when the failures came from 3 or
  more addresses, so a customer who mistyped their own password is never critical.
- Impossible travel only fires when both countries are known and comparable. Providers
  report countries as codes ("NG") or names ("Nigeria"); values in different formats
  are never compared, and unknown is never treated as different.
- The cross-address rules only query extra data for login events, so ordinary
  traffic costs nothing extra. They need the website to send `login_failed` and
  `login_success` events with a `user_id`.
- Distributed rules do not auto-block, because each participating address made only a
  few attempts. The report lists the most active addresses so an administrator can act.

## Incident grouping and escalation

An incident is open to new events while it is OPEN or INVESTIGATING and has had
activity in the last 30 minutes. A long attack therefore stays one incident.

| Scope | One open incident per | Source address on incident |
|-------|-----------------------|----------------------------|
| address (default) | source address, whatever rule fired | set |
| account | targeted account, per rule | empty |
| platform wide | rule | empty |

When a later event is more severe or riskier, the incident is escalated (severity,
risk score and primary rule) and a timeline entry records exactly what changed.
An incident is never downgraded.

## Address risk

`security_ips.riskScore` and `riskLevel` hold the highest event risk seen from the
address in the last 24 hours. It rises during an attack and returns to zero after a
quiet day.

## Automatic blocking

An address is blocked automatically when an event reaches CRITICAL and at least
`AUTO_BLOCK_MIN_RISK` (default 85). Automatic blocking never overrides an
administrator: an existing manual or permanent block is left unchanged, and an
existing automatic block is renewed only when under half of its time remains.
The platform records blocks; the PishonMarket website must enforce them.

## Not yet covered

Device fingerprinting, bot behavior analysis, request sequence analysis, and
temporal anomaly detection need data the website does not send today. They are
deferred until the PHP integration reports it.
