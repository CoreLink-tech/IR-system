<?php
declare(strict_types=1);

namespace App\Security;

/**
 * A bounded on-disk queue for events that could not be delivered, so a short outage
 * of the Security API loses nothing. Events keep their original timestamps. When the
 * file passes its size limit, the oldest half is discarded: losing the oldest events
 * is better than filling the disk.
 */
final class EventSpool
{
    private const FILE = 'events.spool.jsonl';

    /** @var FileStore */
    private $store;
    /** @var int */
    private $maxBytes;
    /** @var callable|null */
    private $logger;

    public function __construct(FileStore $store, int $maxBytes = 524288, ?callable $logger = null)
    {
        $this->store = $store;
        $this->maxBytes = max(4096, $maxBytes);
        $this->logger = $logger;
    }

    public function append(array $event): bool
    {
        $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($line === false) {
            return false;
        }
        $ok = $this->store->withLock(self::FILE, function ($h) use ($line) {
            fseek($h, 0, SEEK_END);
            if (ftell($h) >= $this->maxBytes) {
                $this->dropOldestHalf($h);
            }
            fseek($h, 0, SEEK_END);
            return fwrite($h, $line . "\n") !== false;
        });
        return $ok === true;
    }

    public function count(): int
    {
        $raw = $this->store->usable() ? @file_get_contents($this->store->path(self::FILE)) : false;
        return $raw === false || $raw === '' ? 0 : substr_count($raw, "\n");
    }

    /**
     * Removes up to $max events from the front of the queue and returns them. The
     * caller sends them and gives back any that failed with putBack().
     *
     * @return array<int,array<string,mixed>>
     */
    public function take(int $max): array
    {
        $taken = $this->store->withLock(self::FILE, function ($h) use ($max) {
            rewind($h);
            $lines = [];
            while (($l = fgets($h)) !== false) {
                $lines[] = $l;
            }
            if ($lines === []) {
                return [];
            }
            $head = array_slice($lines, 0, $max);
            $rest = array_slice($lines, $max);
            ftruncate($h, 0);
            rewind($h);
            fwrite($h, implode('', $rest));
            return $head;
        });
        $events = [];
        foreach ((array) $taken as $line) {
            $e = json_decode((string) $line, true);
            if (is_array($e)) {
                $events[] = $e;
            }
        }
        return $events;
    }

    /** @param array<int,array<string,mixed>> $events Returned to the end of the queue. */
    public function putBack(array $events): void
    {
        foreach ($events as $e) {
            $this->append($e);
        }
    }

    /** @param resource $h */
    private function dropOldestHalf($h): void
    {
        rewind($h);
        $lines = [];
        while (($l = fgets($h)) !== false) {
            $lines[] = $l;
        }
        $keep = array_slice($lines, (int) floor(count($lines) / 2));
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, implode('', $keep));
        if ($this->logger !== null) {
            ($this->logger)('warn', 'security_spool_full', ['dropped' => count($lines) - count($keep)]);
        }
    }
}
