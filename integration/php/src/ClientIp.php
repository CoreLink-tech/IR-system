<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Works out the visitor's real address.
 *
 * Behind a reverse proxy or CDN, REMOTE_ADDR is the proxy, not the visitor. Reporting
 * the proxy address would make every customer look like one machine: failed logins
 * from many people would add up against a single address, and blocking that address
 * would lock everyone out.
 *
 * Forwarding headers can be forged by anyone, so they are trusted ONLY when the
 * connection really comes from a proxy you listed. With no trusted proxies listed,
 * headers are ignored completely and REMOTE_ADDR is used, which cannot be spoofed.
 *
 * Reading X-Forwarded-For goes from the right: each trusted proxy adds the address
 * it saw on the right, so the first address from the right that is not a trusted
 * proxy is the visitor. The left side is whatever the visitor chose to claim.
 */
final class ClientIp
{
    /** @var string[] */
    private $trusted;
    /** @var string|null Header holding the client address, for example "CF-Connecting-IP". */
    private $header;

    /**
     * @param string[] $trustedProxies Addresses or CIDR blocks. The word "private" means
     *                                 loopback and private network ranges.
     */
    public function __construct(array $trustedProxies = [], ?string $clientIpHeader = null)
    {
        $this->trusted = array_values(array_filter(array_map('trim', $trustedProxies), 'strlen'));
        $h = $clientIpHeader !== null ? trim($clientIpHeader) : '';
        $this->header = $h !== '' ? $h : null;
    }

    /** @param array<string,mixed> $server Usually $_SERVER. */
    public function resolve(array $server): ?string
    {
        $remote = IpAddress::normalize($server['REMOTE_ADDR'] ?? null);
        if ($remote === null || !$this->isTrusted($remote)) {
            return $remote;
        }

        if ($this->header !== null) {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $this->header));
            $fromHeader = self::parseOne($server[$key] ?? null);
            if ($fromHeader !== null) {
                return $fromHeader;
            }
        }

        $chain = self::parseList($server['HTTP_X_FORWARDED_FOR'] ?? null);
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if ($chain[$i] === null) {
                // A malformed entry means the header cannot be relied on.
                return $remote;
            }
            if (!$this->isTrusted($chain[$i])) {
                return $chain[$i];
            }
        }
        return $remote;
    }

    /** True when forwarding headers are present although the connection is not from a trusted proxy. */
    public function looksMisconfigured(array $server): bool
    {
        $remote = IpAddress::normalize($server['REMOTE_ADDR'] ?? null);
        if ($remote === null || $this->isTrusted($remote)) {
            return false;
        }
        return !empty($server['HTTP_X_FORWARDED_FOR']) || ($this->header !== null && !empty($server['HTTP_' . strtoupper(str_replace('-', '_', $this->header))]));
    }

    public function isTrusted(string $ip): bool
    {
        foreach ($this->trusted as $entry) {
            if (strtolower($entry) === 'private') {
                if (IpAddress::isInternal($ip)) {
                    return true;
                }
                continue;
            }
            if (IpAddress::inCidr($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    /** @return array<int,string|null> Normalized addresses in header order; null marks a malformed entry. */
    private static function parseList($header): array
    {
        if (!is_string($header) || trim($header) === '') {
            return [];
        }
        return array_map([self::class, 'parseOne'], explode(',', $header));
    }

    /** Accepts "1.2.3.4", "1.2.3.4:5678", "2001:db8::1" and "[2001:db8::1]:443". */
    private static function parseOne($value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $v = trim($value);
        if ($v !== '' && $v[0] === '[') {
            $end = strpos($v, ']');
            return $end === false ? null : IpAddress::normalize(substr($v, 1, $end - 1));
        }
        if (substr_count($v, ':') === 1) {
            $v = substr($v, 0, (int) strpos($v, ':'));
        }
        return IpAddress::normalize($v);
    }
}
