# IP Intelligence

The platform enriches every public IP address it sees with geography, anonymizer
signals (proxy, VPN, Tor, datacenter) and an abuse reputation. Enrichment feeds
the detection rules; it never replaces them.

## Providers

| Name        | Key needed              | Supplies                                         |
|-------------|-------------------------|--------------------------------------------------|
| `tor`       | none                    | Tor exit node detection (Tor Project bulk list)  |
| `ipapi`     | none (free tier)        | geography, proxy flag, hosting (datacenter) flag |
| `ipinfo`    | `IPINFO_TOKEN`          | geography; vpn/proxy/tor/hosting on paid plans   |
| `abuseipdb` | `ABUSEIPDB_API_KEY`     | abuse reputation 0-100, malicious flag, Tor, usage type |

Recommended starting point, at no cost: `IP_INTEL_PROVIDERS=tor,ipapi`.
Add `abuseipdb` for malicious-IP reputation (free tier: 1000 checks per day).

Notes on accuracy:
- ip-api reports one combined `proxy` flag for proxies, VPNs and Tor. It is stored
  as `isProxy`, not `isVpn`. Only IPinfo (paid privacy plan) separates VPN.
- The free ip-api tier is HTTP only and licensed for non-commercial use. For
  production, set `IP_API_KEY` (HTTPS, paid) or use another provider.
- An address is marked malicious only at or above `ABUSEIPDB_MALICIOUS_THRESHOLD`
  (default 75), so a few stray reports do not label an address malicious.

## Configuration

```
IP_INTEL_PROVIDERS=tor,ipapi      # comma separated, priority order, "none" disables
IP_INTEL_TIMEOUT_MS=3000          # per-provider request timeout
IP_INTEL_CACHE_HOURS=24           # how long a result is reused
```

The older single-value `IP_INTEL_PROVIDER` is still honoured when
`IP_INTEL_PROVIDERS` is not set. A provider with missing credentials is skipped
with a warning; the application still starts.

## Behaviour

- Results are cached in `security_ips` and reused for `IP_INTEL_CACHE_HOURS`.
- Private and reserved addresses (10.x, 192.168.x, 127.x, ::1 and so on) are never
  sent to an external provider.
- Providers run in parallel. Merge rules: geography from the first provider that
  has it, boolean flags combined with OR, reputation takes the highest value.
- If every provider fails, nothing is cached and the address is not retried for
  5 minutes. An outage never stores a false "clean" result.
- A provider that fails 5 times in a row is skipped for 60 seconds (circuit breaker).
- Concurrent lookups of the same address share a single provider request.

## Adding a provider

Implement `IpIntelProvider` (`src/ips/providers/provider.types.ts`): a `name` and
a `lookup(ip)` that returns the fields it knows, or throws on error. Register it
in `provider.factory.ts`. No other code changes are needed.

## Operations

`POST /api/v1/ips/:ip/refresh-intelligence` forces a fresh lookup for one address.
