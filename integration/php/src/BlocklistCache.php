<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Answers "is this address blocked?" without calling the Security API on every page.
 *
 *  - The list is kept in a shared file and refreshed when it is older than $ttl seconds.
 *  - Only ONE request refreshes at a time (a lock); the others keep using the previous
 *    copy, so a slow API never stacks up waiting requests.
 *  - If a refresh fails, the old list stays in use and no new attempt is made for
 *    $backoff seconds. Failing to ask is never read as "nothing is blocked".
 *  - If there is no list at all and the API is down, requests are allowed (fail open):
 *    a security outage must not take the shop offline.
 *  - Each entry's own expiry time is honoured locally, so a temporary block ends on
 *    time even if the cache is stale.
 */
final class BlocklistCache
{
    private const DATA = 'blocklist.json';
    private const STATE = 'blocklist.state.json';
    private const LOCK = 'blocklist.lock';

    /** @var FileStore */
    private $store;
    /** @var callable */
    private $fetch;
    /** @var int */
    private $ttl;
    /** @var int */
    private $backoff;
    /** @var callable */
    private $clock;
    /** @var callable|null */
    private $logger;

    /**
     * @param callable $fetch Returns the server's rows, or null when it could not be fetched.
     */
    public function __construct(
        FileStore $store,
        callable $fetch,
        int $ttl = 30,
        int $backoff = 15,
        ?callable $clock = null,
        ?callable $logger = null
    ) {
        $this->store = $store;
        $this->fetch = $fetch;
        $this->ttl = max(1, $ttl);
        $this->backoff = max(1, $backoff);
        $this->clock = $clock ?? 'time';
        $this->logger = $logger;
    }

    public function isBlocked(string $ip): bool
    {
        $ip = (string) IpAddress::normalize($ip);
        if ($ip === '') {
            return false;
        }
        $now = (int) ($this->clock)();
        $data = $this->store->readJson(self::DATA);
        if ($data === null || ($now - (int) ($data['fetchedAt'] ?? 0)) >= $this->ttl) {
            $this->refresh($now);
            $data = $this->store->readJson(self::DATA) ?? $data;
        }
        // array_key_exists, not isset: a permanent block is stored with a null expiry,
        // and isset() treats null as "not there", which would let blocked visitors in.
        if ($data === null || !isset($data['entries']) || !array_key_exists($ip, $data['entries'])) {
            return false;
        }
        $expires = $data['entries'][$ip];
        return $expires === null || (int) $expires > $now;
    }

    /** Seconds since the list was last refreshed, or null if there is none. Useful for alerting. */
    public function ageSeconds(): ?int
    {
        $data = $this->store->readJson(self::DATA);
        return $data === null ? null : max(0, (int) ($this->clock)() - (int) ($data['fetchedAt'] ?? 0));
    }

    private function refresh(int $now): void
    {
        $lock = $this->store->tryLock(self::LOCK);
        if ($lock === null) {
            return; // another request is refreshing, or the folder is unusable
        }
        try {
            // Someone may have refreshed while we waited for the lock.
            $data = $this->store->readJson(self::DATA);
            if ($data !== null && ($now - (int) ($data['fetchedAt'] ?? 0)) < $this->ttl) {
                return;
            }
            $state = $this->store->readJson(self::STATE);
            if ($state !== null && $now < (int) ($state['nextTry'] ?? 0)) {
                return;
            }

            $rows = ($this->fetch)();
            if ($rows === null) {
                $this->store->writeJson(self::STATE, ['nextTry' => $now + $this->backoff]);
                $this->log('warn', 'security_blocklist_refresh_failed', [
                    'using' => $data === null ? 'nothing (allowing all)' : 'previous list',
                    'retry_in' => $this->backoff,
                ]);
                return;
            }
            $this->store->writeJson(self::DATA, ['fetchedAt' => $now, 'entries' => self::entries($rows)]);
            $this->store->writeJson(self::STATE, ['nextTry' => 0]);
        } finally {
            $this->store->release($lock);
        }
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @return array<string,int|null> address => expiry timestamp, or null for no expiry
     */
    private static function entries(array $rows): array
    {
        $out = [];
        foreach ($rows as $row) {
            $ip = IpAddress::normalize($row['ipAddress'] ?? null);
            if ($ip === null || IpAddress::isInternal($ip)) {
                continue; // never block the site's own addresses, even if the server says so
            }
            $expires = null;
            if (empty($row['permanent']) && !empty($row['expiresAt']) && is_string($row['expiresAt'])) {
                $t = strtotime($row['expiresAt']);
                if ($t === false) {
                    continue; // an expiry we cannot read is not safe to guess
                }
                $expires = $t;
            }
            // If an address appears twice, the later expiry (or no expiry) wins.
            if (!array_key_exists($ip, $out) || $expires === null || ($out[$ip] !== null && $expires > $out[$ip])) {
                $out[$ip] = $expires;
            }
        }
        return $out;
    }

    private function log(string $level, string $message, array $context): void
    {
        if ($this->logger !== null) {
            ($this->logger)($level, $message, $context);
        }
    }
}
