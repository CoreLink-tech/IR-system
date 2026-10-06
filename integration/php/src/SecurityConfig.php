<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Settings, read from environment variables.
 *
 *   SECURITY_API_BASE            https://security.example.com           (required)
 *   SECURITY_API_KEY             PMS_...                                (required)
 *   SECURITY_ENABLED             true | false      kill switch, default true
 *   SECURITY_MODE                monitor | enforce default monitor
 *   SECURITY_TRUSTED_PROXIES     comma list of addresses/CIDRs, or "private"
 *   SECURITY_CLIENT_IP_HEADER    e.g. CF-Connecting-IP (only used behind a trusted proxy)
 *   SECURITY_STATE_DIR           folder for cache and queue
 *   SECURITY_API_TIMEOUT         seconds per API call, default 1.0
 *   SECURITY_BLOCKLIST_TTL       seconds between blocklist refreshes, default 30
 *   SECURITY_FLUSH_BUDGET        seconds allowed for sending events after the response, default 1.5
 *   SECURITY_BREAKER_OPEN        seconds to stop calling the API after repeated failures, default 30
 */
final class SecurityConfig
{
    /** @var array<string,mixed> */
    public $values;

    /** @param array<string,mixed> $values */
    private function __construct(array $values)
    {
        $this->values = $values;
    }

    /** @param array<string,string|false>|null $env Defaults to the process environment. */
    public static function fromEnv(?array $env = null): self
    {
        $get = function (string $k, string $default = '') use ($env): string {
            $v = $env !== null ? ($env[$k] ?? false) : getenv($k);
            return ($v === false || $v === null || $v === '') ? $default : (string) $v;
        };
        $base = rtrim($get('SECURITY_API_BASE'), '/');
        $key = $get('SECURITY_API_KEY');
        $mode = strtolower($get('SECURITY_MODE', 'monitor'));
        $stateDir = $get('SECURITY_STATE_DIR');
        if ($stateDir === '') {
            $stateDir = sys_get_temp_dir() . '/pishon-security-' . substr(hash('sha256', $base . '|' . $key), 0, 10);
        }
        return new self([
            'enabled'      => strtolower($get('SECURITY_ENABLED', 'true')) !== 'false' && $get('SECURITY_ENABLED', 'true') !== '0',
            'base'         => $base,
            'key'          => $key,
            'mode'         => $mode === SecurityGuard::ENFORCE ? SecurityGuard::ENFORCE : SecurityGuard::MONITOR,
            'trusted'      => array_values(array_filter(array_map('trim', explode(',', $get('SECURITY_TRUSTED_PROXIES'))), 'strlen')),
            'ipHeader'     => $get('SECURITY_CLIENT_IP_HEADER'),
            'stateDir'     => $stateDir,
            'timeout'      => max(0.2, (float) $get('SECURITY_API_TIMEOUT', '1.0')),
            'ttl'          => max(1, (int) $get('SECURITY_BLOCKLIST_TTL', '30')),
            'flushBudget'  => max(0.2, (float) $get('SECURITY_FLUSH_BUDGET', '1.5')),
            'breakerOpen'  => max(1, (int) $get('SECURITY_BREAKER_OPEN', '30')),
        ]);
    }

    /** @return string[] Problems that stop the library from working. */
    public function problems(): array
    {
        $p = [];
        if ($this->values['base'] === '') {
            $p[] = 'SECURITY_API_BASE is not set';
        } elseif (!preg_match('#^https?://#i', (string) $this->values['base'])) {
            $p[] = 'SECURITY_API_BASE must start with http:// or https://';
        }
        if ($this->values['key'] === '') {
            $p[] = 'SECURITY_API_KEY is not set';
        }
        return $p;
    }

    /** @return string[] Things that work but are risky. */
    public function warnings(): array
    {
        $w = [];
        if (stripos((string) $this->values['base'], 'http://') === 0 && !preg_match('#^http://(localhost|127\.|\[::1\])#i', (string) $this->values['base'])) {
            $w[] = 'SECURITY_API_BASE uses http://, so the API key and events cross the network unencrypted. Use https://.';
        }
        if ($this->values['ipHeader'] !== '' && $this->values['trusted'] === []) {
            $w[] = 'SECURITY_CLIENT_IP_HEADER is set but SECURITY_TRUSTED_PROXIES is empty, so the header is ignored.';
        }
        return $w;
    }

    /** @return mixed */
    public function get(string $key)
    {
        return $this->values[$key] ?? null;
    }
}
