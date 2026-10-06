<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Sends events to the Security API without slowing down or breaking the website.
 *
 *  - Events are collected during the request and sent AFTER the response has gone
 *    to the visitor (fastcgi_finish_request), so the visitor never waits on them.
 *  - The whole send has a time budget. Whatever does not fit is queued on disk.
 *  - After several failures in a row a circuit breaker stops further attempts for a
 *    short time, and events go straight to the disk queue.
 *  - Queued events are sent later, oldest first, when the API is back, keeping their
 *    original timestamps.
 *  - An event the server rejects (a 4xx other than 429) is dropped, never retried.
 */
final class SecurityReporter
{
    /** @var EventSender */
    private $client;
    /** @var EventSpool */
    private $spool;
    /** @var CircuitBreaker */
    private $breaker;
    /** @var float */
    private $budget;
    /** @var int */
    private $replayMax;
    /** @var callable|null */
    private $logger;
    /** @var array<int,array<string,mixed>> */
    private $buffer = [];
    /** @var bool */
    private $shutdownRegistered = false;

    public function __construct(
        EventSender $client,
        EventSpool $spool,
        CircuitBreaker $breaker,
        float $flushBudgetSeconds = 1.5,
        int $replayMax = 20,
        ?callable $logger = null
    ) {
        $this->client = $client;
        $this->spool = $spool;
        $this->breaker = $breaker;
        $this->budget = max(0.2, $flushBudgetSeconds);
        $this->replayMax = max(0, $replayMax);
        $this->logger = $logger;
    }

    /** Adds an event to this request's outgoing batch. Never throws. */
    public function report(array $payload): void
    {
        if (empty($payload['timestamp'])) {
            $payload['timestamp'] = gmdate('c');
        }
        // One id per event, fixed now. If delivery times out after the server already stored
        // the event and it has to be sent again, the server recognises the id and keeps one copy.
        if (empty($payload['event_id'])) {
            $payload['event_id'] = bin2hex(random_bytes(12));
        }
        $this->buffer[] = $payload;
        $this->scheduleFlush();
    }

    /**
     * Sends the queued backlog even on a page that reports nothing. Without this, events
     * queued during an outage would sit on disk until something new happened to be
     * reported, which on a quiet shop could be hours. It costs one file check per page.
     */
    public function replayIfNeeded(): void
    {
        if ($this->replayMax > 0 && $this->spool->hasEvents() && $this->breaker->allow()) {
            $this->scheduleFlush();
        }
    }

    public function isScheduled(): bool
    {
        return $this->shutdownRegistered;
    }

    private function scheduleFlush(): void
    {
        if (!$this->shutdownRegistered) {
            $this->shutdownRegistered = true;
            register_shutdown_function([$this, 'flushAfterResponse']);
        }
    }

    public function flushAfterResponse(): void
    {
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        }
        try {
            $this->flush();
        } catch (\Throwable $e) {
            $this->log('error', 'security_flush_failed', ['error' => $e->getMessage()]);
        }
    }

    /** Sends what has been collected, then some of the backlog, within the time budget. */
    public function flush(): void
    {
        $deadline = microtime(true) + $this->budget;
        $batch = $this->buffer;
        $this->buffer = [];

        $failed = false;
        foreach ($batch as $i => $payload) {
            if (microtime(true) >= $deadline || !$this->breaker->allow()) {
                $this->queue(array_slice($batch, $i));
                break;
            }
            if ($this->deliver($payload) === 'failed') {
                // Keep the original order: the event that failed, then those after it.
                $this->queue(array_slice($batch, $i));
                $failed = true;
                break;
            }
        }
        // The API just failed, so retrying the backlog right now would only waste time.
        if (!$failed) {
            $this->replay($deadline);
        }
    }

    /** Number of events waiting on disk. */
    public function backlog(): int
    {
        return $this->spool->count();
    }

    /** @param array<int,array<string,mixed>> $events */
    private function queue(array $events): void
    {
        foreach ($events as $e) {
            if (!$this->spool->append($e)) {
                $this->log('error', 'security_event_dropped', ['reason' => 'queue unavailable']);
            }
        }
    }

    private function replay(float $deadline): void
    {
        if ($this->replayMax === 0 || !$this->breaker->allow() || microtime(true) >= $deadline || $this->spool->count() === 0) {
            return;
        }
        $events = $this->spool->take($this->replayMax);
        $unsent = [];
        foreach ($events as $i => $e) {
            if (microtime(true) >= $deadline || !$this->breaker->allow()) {
                $unsent = array_merge($unsent, array_slice($events, $i));
                break;
            }
            if ($this->deliver($e) === 'failed') {
                $unsent = array_merge($unsent, array_slice($events, $i));
                break;
            }
        }
        $this->spool->putBack($unsent);
    }

    /** @return string "sent", "rejected" or "failed" */
    private function deliver(array $payload): string
    {
        $r = $this->client->sendEvent($payload);
        if ($r['result'] === 'sent') {
            $this->breaker->success();
            return 'sent';
        }
        if ($r['result'] === 'rejected') {
            // 401 and 403 mean the key is wrong or lacks permission: a setup problem that
            // affects every event, so it counts against the breaker and is logged loudly.
            if ($r['status'] === 401 || $r['status'] === 403) {
                $this->breaker->failure();
                $this->log('error', 'security_api_key_rejected', ['status' => $r['status']]);
            } else {
                $this->log('warn', 'security_event_rejected', ['status' => $r['status'], 'event_type' => $payload['event_type'] ?? null]);
            }
            return 'rejected';
        }
        $this->breaker->failure();
        return 'failed';
    }

    private function log(string $level, string $message, array $context): void
    {
        if ($this->logger !== null) {
            ($this->logger)($level, $message, $context);
        }
    }
}
