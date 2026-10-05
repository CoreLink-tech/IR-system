<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Parses and classifies IP addresses with exactly the same rules as the server, so
 * an address means the same thing on both sides. The shared test file
 * integration/shared/ip-vectors.json is run against both implementations.
 *
 * Parsing is deliberately strict. Shorthand ("127.1"), hexadecimal, octal and
 * leading-zero forms are rejected, because other software reads them as a different
 * address than the one that was meant.
 */
final class IpAddress
{
    /** Ranges that must never be blocked: the site could lock itself out. [network, prefix length] */
    private const INTERNAL_V4 = [
        ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
        ['172.16.0.0', 12], ['192.168.0.0', 16], ['224.0.0.0', 4], ['255.255.255.255', 32],
    ];
    private const INTERNAL_V6 = [
        ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
    ];

    /** Returns the canonical text of a valid address, or null. IPv4-mapped IPv6 becomes plain IPv4. */
    public static function normalize($input): ?string
    {
        if (!is_string($input)) {
            return null;
        }
        $v = trim($input);
        if ($v === '' || strpos($v, '%') !== false) {
            return null;
        }
        if (strpos($v, ':') === false) {
            return self::ipv4($v);
        }
        if (strpos($v, '.') !== false) {
            // Only the IPv4-mapped form may carry a dotted quad.
            if (!preg_match('/^(?:::|(?:0{1,4}:){5})ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/Di', $v, $m)) {
                return null;
            }
            return self::ipv4($m[1]);
        }
        $bin = @inet_pton($v);
        if ($bin === false || strlen($bin) !== 16) {
            return null;
        }
        if (substr($bin, 0, 10) === str_repeat("\0", 10) && substr($bin, 10, 2) === "\xff\xff") {
            return implode('.', array_map('ord', str_split(substr($bin, 12, 4))));
        }
        return self::formatV6($bin);
    }

    /** True for loopback, private, link-local, carrier-grade NAT, multicast and similar. Expects a normalized address. */
    public static function isInternal(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        $table = strlen($bin) === 4 ? self::INTERNAL_V4 : self::INTERNAL_V6;
        foreach ($table as $range) {
            if (self::matches($bin, (string) inet_pton($range[0]), $range[1])) {
                return true;
            }
        }
        return false;
    }

    /** Is the address inside a CIDR block ("10.0.0.0/8") or equal to a single address? Families never mix. */
    public static function inCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', trim($cidr), 2);
        $net = self::normalize($parts[0]);
        $addr = self::normalize($ip);
        if ($net === null || $addr === null) {
            return false;
        }
        $a = (string) inet_pton($addr);
        $n = (string) inet_pton($net);
        if (strlen($a) !== strlen($n)) {
            return false;
        }
        $max = strlen($n) * 8;
        if (count($parts) === 1) {
            $bits = $max;
        } elseif (preg_match('/^\d{1,3}$/D', $parts[1]) && (int) $parts[1] <= $max) {
            $bits = (int) $parts[1];
        } else {
            return false;
        }
        return self::matches($a, $n, $bits);
    }

    private static function ipv4(string $v): ?string
    {
        if (!preg_match('/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/D', $v)) {
            return null;
        }
        foreach (explode('.', $v) as $octet) {
            if ((int) $octet > 255) {
                return null;
            }
        }
        return $v;
    }

    /** RFC 5952: lowercase, the longest run of two or more zero groups becomes "::" (leftmost wins a tie). */
    private static function formatV6(string $bin): string
    {
        $g = array_values((array) unpack('n8', $bin));
        $bestStart = -1;
        $bestLen = 0;
        for ($i = 0; $i < 8; ) {
            if ($g[$i] !== 0) {
                $i++;
                continue;
            }
            $j = $i;
            while ($j < 8 && $g[$j] === 0) {
                $j++;
            }
            if ($j - $i > $bestLen) {
                $bestStart = $i;
                $bestLen = $j - $i;
            }
            $i = $j;
        }
        if ($bestLen < 2) {
            return implode(':', array_map('dechex', $g));
        }
        $head = implode(':', array_map('dechex', array_slice($g, 0, $bestStart)));
        $tail = implode(':', array_map('dechex', array_slice($g, $bestStart + $bestLen)));
        return $head . '::' . $tail;
    }

    private static function matches(string $a, string $n, int $bits): bool
    {
        $full = intdiv($bits, 8);
        if ($full > 0 && substr($a, 0, $full) !== substr($n, 0, $full)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;
        return (ord($a[$full]) & $mask) === (ord($n[$full]) & $mask);
    }
}
