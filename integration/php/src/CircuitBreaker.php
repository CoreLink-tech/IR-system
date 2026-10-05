<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Stops the website from waiting on a security API that is down. After several
 * failures in a row it "opens" for a short time, during which nothing is sent and
 * events are kept locally instead. When the time is up, the next attempt goes
 * through; if it succeeds the breaker closes again.
 */
final class CircuitBreaker
{
    /** @var FileStore */
    private $store;
    /** @var string */
    private $file;
    /** @var int */
    private $threshold;
    /** @var int */
    private $openSeconds;
    /** @var callable */
    private $clock;

    public function __construct(FileStore $store, string $name, int $threshold = 3, int $openSeconds = 30, ?callable $clock = null)
    {
        $this->store = $store;
        $this->file = 'breaker-' . preg_replace('/[^a-z0-9_-]/i', '', $name) . '.json';
        $this->threshold = max(1, $threshold);
        $this->openSeconds = max(1, $openSeconds);
        $this->clock = $clock ?? 'time';
    }

    /** May a request be attempted right now? */
    public function allow(): bool
    {
        $s = $this->store->readJson($this->file);
        return $s === null || (int) ($s['openUntil'] ?? 0) <= (int) ($this->clock)();
    }

    public function success(): void
    {
        if ($this->store->readJson($this->file) !== null) {
            $this->store->writeJson($this->file, ['failures' => 0, 'openUntil' => 0]);
        }
    }

    public function failure(): void
    {
        $s = $this->store->readJson($this->file) ?? ['failures' => 0, 'openUntil' => 0];
        $failures = (int) ($s['failures'] ?? 0) + 1;
        $openUntil = 0;
        if ($failures >= $this->threshold) {
            $openUntil = (int) ($this->clock)() + $this->openSeconds;
            $failures = 0;
        }
        $this->store->writeJson($this->file, ['failures' => $failures, 'openUntil' => $openUntil]);
    }
}
