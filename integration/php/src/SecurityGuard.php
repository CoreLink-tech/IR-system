<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Turns the blocklist into a decision for the current request.
 *
 * Modes:
 *   monitor  nothing is blocked; a would-be block is logged. Use this first, to check
 *            that the right addresses are being identified before enforcing.
 *   enforce  a blocked visitor gets "403 Access denied".
 *
 * Addresses that must never be blocked (loopback, private networks) always pass, and
 * an unknown address always passes.
 */
final class SecurityGuard
{
    public const MONITOR = 'monitor';
    public const ENFORCE = 'enforce';

    /** @var callable */
    private $isBlocked;
    /** @var string */
    private $mode;
    /** @var callable|null */
    private $logger;
    /** @var callable */
    private $deny;

    /**
     * @param callable      $isBlocked function(string $ip): bool
     * @param callable|null $deny      Ends the request. Replaceable so tests can observe it.
     */
    public function __construct(callable $isBlocked, string $mode = self::MONITOR, ?callable $logger = null, ?callable $deny = null)
    {
        $this->isBlocked = $isBlocked;
        $this->mode = $mode === self::ENFORCE ? self::ENFORCE : self::MONITOR;
        $this->logger = $logger;
        $this->deny = $deny ?? [self::class, 'defaultDeny'];
    }

    /** Returns true if the visitor is on the blocklist (whether or not it was enforced). */
    public function check(?string $ip): bool
    {
        if ($ip === null || IpAddress::isInternal($ip)) {
            return false;
        }
        try {
            $blocked = (bool) ($this->isBlocked)($ip);
        } catch (\Throwable $e) {
            if ($this->logger !== null) {
                ($this->logger)('error', 'security_blocklist_check_failed', ['error' => $e->getMessage()]);
            }
            return false; // never fail the page because of the security layer
        }
        if (!$blocked) {
            return false;
        }
        if ($this->mode === self::ENFORCE) {
            ($this->deny)();
        } elseif ($this->logger !== null) {
            ($this->logger)('warn', 'security_would_block', ['ip' => $ip, 'mode' => 'monitor']);
        }
        return true;
    }

    public function mode(): string
    {
        return $this->mode;
    }

    public static function defaultDeny(): void
    {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo 'Access denied';
        exit;
    }
}
