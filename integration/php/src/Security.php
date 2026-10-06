<?php
declare(strict_types=1);

namespace App\Security;

/**
 * The one class a website needs. Two steps:
 *
 *   1. Once, as early as possible in each request:   Security::boot();
 *   2. Where something security-relevant happens:    Security::loginFailed($userId);
 *
 * Every method is safe to call at any time. Nothing here ever throws into the page or
 * makes the visitor wait on the Security API: a problem is logged and the request
 * carries on.
 */
final class Security
{
    /** @var self|null */
    private static $instance = null;

    /** @var SecurityConfig */
    private $config;
    /** @var ClientIp */
    private $clientIp;
    /** @var SecurityGuard */
    private $guard;
    /** @var SecurityReporter */
    private $reporter;
    /** @var BlocklistCache */
    private $cache;
    /** @var array<string,mixed> */
    private $server;
    /** @var string|null */
    private $ip;
    /** @var callable */
    private $logger;

    private const EVENTS = [
        'login_failed' => 'MEDIUM', 'login_success' => 'INFO', 'logout' => 'INFO', 'password_reset' => 'LOW',
        'account_change' => 'MEDIUM', 'admin_access' => 'INFO', 'suspicious_request' => 'HIGH',
        'rate_limit_exceeded' => 'LOW', 'payment_security_event' => 'MEDIUM', 'session_anomaly' => 'MEDIUM',
        'application_error' => 'LOW', 'server_error' => 'MEDIUM',
    ];

    private function __construct()
    {
    }

    /**
     * Starts the library for this request: works out the visitor's address, checks the
     * blocklist (blocking in "enforce" mode), and prepares to send events.
     *
     * @param array<string,mixed>|null $server Defaults to $_SERVER.
     * @param callable|null            $logger function(string $level, string $message, array $context)
     * @param callable|null            $deny   Replaces the "403 Access denied" response (used by tests).
     * @return bool true if the visitor is on the blocklist
     */
    public static function boot(?SecurityConfig $config = null, ?array $server = null, ?callable $logger = null, ?callable $deny = null): bool
    {
        try {
            $config = $config ?? SecurityConfig::fromEnv();
            if (!$config->get('enabled')) {
                return false;
            }
            $log = $logger ?? [self::class, 'defaultLog'];
            $problems = $config->problems();
            if ($problems !== []) {
                $log('error', 'security_not_configured', ['problems' => $problems]);
                return false;
            }
            foreach ($config->warnings() as $w) {
                $log('warn', 'security_config_warning', ['message' => $w]);
            }

            $self = new self();
            $self->config = $config;
            $self->server = $server ?? $_SERVER;
            $self->logger = $log;
            $self->clientIp = new ClientIp((array) $config->get('trusted'), (string) $config->get('ipHeader') ?: null);
            $self->ip = $self->clientIp->resolve($self->server);

            $store = new FileStore((string) $config->get('stateDir'), $log);
            $client = new SecurityClient((string) $config->get('base'), (string) $config->get('key'), (float) $config->get('timeout'), 0, $log);
            $self->cache = new BlocklistCache($store, [$client, 'fetchBlocklist'], (int) $config->get('ttl'), 15, null, $log);
            $self->guard = new SecurityGuard([$self->cache, 'isBlocked'], (string) $config->get('mode'), $log, $deny);
            $self->reporter = new SecurityReporter(
                new SecurityClient((string) $config->get('base'), (string) $config->get('key'), (float) $config->get('timeout'), 1, $log),
                new EventSpool($store, 524288, $log),
                new CircuitBreaker($store, 'events', 3, (int) $config->get('breakerOpen')),
                (float) $config->get('flushBudget'),
                20,
                $log
            );
            self::$instance = $self;
            // Deliver anything queued during an earlier outage, after this response is sent.
            $self->reporter->replayIfNeeded();

            if ($self->clientIp->looksMisconfigured($self->server)) {
                $self->warnOnce($store, 'proxy-hint', 'security_proxy_not_trusted', [
                    'hint' => 'Forwarded headers are present but the connection is not from a trusted proxy, so the proxy address is being used as the visitor address. If the site is behind a proxy or CDN, set SECURITY_TRUSTED_PROXIES.',
                ]);
            }
            return $self->guard->check($self->ip);
        } catch (\Throwable $e) {
            // Includes the case where the guard's deny callback ends the request in tests.
            if ($e instanceof SecurityStop) {
                throw $e;
            }
            self::defaultLog('error', 'security_boot_failed', ['error' => $e->getMessage()]);
            return false;
        }
    }

    public static function booted(): bool
    {
        return self::$instance !== null;
    }

    /** Forgets the current instance. For tests. */
    public static function reset(): void
    {
        self::$instance = null;
    }

    /** The visitor's address as determined by boot(), or null. */
    public static function clientIp(): ?string
    {
        return self::$instance !== null ? self::$instance->ip : null;
    }

    public static function reporter(): ?SecurityReporter
    {
        return self::$instance !== null ? self::$instance->reporter : null;
    }

    /** Call when a login attempt fails. Never pass the password. */
    public static function loginFailed(?string $userId = null, array $details = []): void
    {
        self::send('login_failed', $userId, $details);
    }

    public static function loginSuccess(?string $userId = null, array $details = []): void
    {
        self::send('login_success', $userId, $details);
    }

    public static function logout(?string $userId = null): void
    {
        self::send('logout', $userId, []);
    }

    /** Call when a password reset is requested or completed. */
    public static function passwordReset(?string $userId = null, array $details = []): void
    {
        self::send('password_reset', $userId, $details);
    }

    /** Call when someone opens an administrative area. */
    public static function adminAccess(?string $userId = null, array $details = []): void
    {
        self::send('admin_access', $userId, $details);
    }

    /** Call when an account's email, password, phone or address changes. */
    public static function accountChange(?string $userId = null, string $what = '', array $details = []): void
    {
        self::send('account_change', $userId, $what === '' ? $details : array_merge(['change' => $what], $details));
    }

    /** Call for payment failures that look like fraud or testing of stolen cards. Never pass card data. */
    public static function paymentIssue(?string $userId = null, array $details = []): void
    {
        self::send('payment_security_event', $userId, $details);
    }

    /** Call when a session behaves oddly, for example it appears from a different device. */
    public static function sessionAnomaly(?string $userId = null, string $reason = ''): void
    {
        self::send('session_anomaly', $userId, $reason === '' ? [] : ['reason' => $reason]);
    }

    /** Call when a request looks malicious, for example input that your own filter caught. */
    public static function suspiciousRequest(string $reason = '', ?string $userId = null): void
    {
        self::send('suspicious_request', $userId, $reason === '' ? [] : ['reason' => $reason]);
    }

    public static function rateLimited(?string $userId = null): void
    {
        self::send('rate_limit_exceeded', $userId, []);
    }

    /**
     * Any other event. Only the known event types are accepted, so a typo is logged
     * instead of silently producing an event that no rule will ever look at.
     */
    public static function event(string $type, ?string $userId = null, array $details = [], ?string $severity = null): void
    {
        self::send($type, $userId, $details, $severity);
    }

    private static function send(string $type, ?string $userId, array $details, ?string $severity = null): void
    {
        $self = self::$instance;
        if ($self === null) {
            return; // not booted: disabled, not configured, or boot() was never called
        }
        try {
            if (!isset(self::EVENTS[$type])) {
                ($self->logger)('error', 'security_unknown_event_type', ['type' => $type, 'known' => array_keys(self::EVENTS)]);
                return;
            }
            $sev = $severity !== null && in_array($severity, ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], true) ? $severity : self::EVENTS[$type];
            $session = function_exists('session_status') && session_status() === PHP_SESSION_ACTIVE ? session_id() : null;
            $payload = array_merge(
                ['event_type' => $type, 'severity' => $sev],
                RequestContext::fields($self->server, $self->ip, $session ?: null)
            );
            if ($userId !== null && $userId !== '') {
                $payload['user_id'] = substr($userId, 0, 128);
            }
            if ($details !== []) {
                $payload['metadata'] = Redactor::clean($details);
            }
            $self->reporter->report($payload);
        } catch (\Throwable $e) {
            ($self->logger)('error', 'security_event_failed', ['error' => $e->getMessage()]);
        }
    }

    /** Logs a message at most once an hour, using a marker file. */
    private function warnOnce(FileStore $store, string $key, string $message, array $context): void
    {
        $file = 'warned-' . $key . '.json';
        $last = (int) (($store->readJson($file) ?? [])['at'] ?? 0);
        if (time() - $last >= 3600) {
            $store->writeJson($file, ['at' => time()]);
            ($this->logger)('warn', $message, $context);
        }
    }

    public static function defaultLog(string $level, string $message, array $context = []): void
    {
        error_log(sprintf('[pishon-security][%s] %s %s', $level, $message, json_encode($context, JSON_UNESCAPED_SLASHES)));
    }
}
