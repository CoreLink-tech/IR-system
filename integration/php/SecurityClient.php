<?php
declare(strict_types=1);

namespace App\Security;

final class SecurityClient
{
    private string $baseUrl;
    private string $apiKey;
    private float  $timeout;
    private int    $retries;
    private $logger;

    public function __construct(string $baseUrl, string $apiKey, float $timeout = 2.0, int $retries = 1, ?callable $logger = null)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey  = $apiKey;
        $this->timeout = max(0.2, $timeout);
        $this->retries = max(0, $retries);
        $this->logger  = $logger;
    }

    public static function fromEnv(?callable $logger = null): self
    {
        $base = getenv('SECURITY_API_BASE') ?: '';
        $key  = getenv('SECURITY_API_KEY') ?: '';
        $to   = (float)(getenv('SECURITY_API_TIMEOUT') ?: '2');
        if ($base === '' || $key === '') {
            throw new \RuntimeException('SECURITY_API_BASE / SECURITY_API_KEY not configured');
        }
        return new self($base, $key, $to, 1, $logger);
    }

    public function event(string $eventType, string $severity, array $fields = []): ?array
    {
        $payload = array_merge([
            'event_type' => $eventType,
            'severity'   => $severity,
        ], $fields);

        if (empty($payload['request_id'])) {
            $payload['request_id'] = self::requestId();
        }
        if (empty($payload['timestamp'])) {
            $payload['timestamp'] = gmdate('c');
        }

        return $this->request('POST', '/api/v1/events', $payload);
    }

    public function blockedIps(): array
    {
        $res = $this->request('GET', '/api/v1/security/blocked-ips', null);
        if (!is_array($res) || !isset($res['data']) || !is_array($res['data'])) {
            return [];
        }
        $out = [];
        foreach ($res['data'] as $row) {
            if (!empty($row['ipAddress'])) {
                $out[] = (string) $row['ipAddress'];
            }
        }
        return $out;
    }

    private function request(string $method, string $path, ?array $body): ?array
    {
        $url = $this->baseUrl . $path;
        $attempts = $this->retries + 1;
        $lastError = null;

        for ($i = 0; $i < $attempts; $i++) {
            $ch = curl_init();
            $headers = [
                'Authorization: Bearer ' . $this->apiKey,
                'Accept: application/json',
                'X-Request-Id: ' . self::requestId(),
                'User-Agent: PishonSecurityClient/1.0',
            ];
            if ($body !== null) {
                $headers[] = 'Content-Type: application/json';
            }

            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST  => $method,
                CURLOPT_HTTPHEADER     => $headers,
                // Milliseconds, not seconds. CURLOPT_TIMEOUT only takes whole seconds, so a
                // value like 0.5 would be cut to 0, which means "wait forever" and could
                // hang the website whenever the security API is slow.
                CURLOPT_TIMEOUT_MS        => (int) round($this->timeout * 1000),
                CURLOPT_CONNECTTIMEOUT_MS => (int) round($this->timeout * 1000),
                CURLOPT_NOSIGNAL          => true,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            }

            $raw  = curl_exec($ch);
            $err  = curl_error($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($raw === false || $err !== '') {
                $lastError = 'curl: ' . $err;
                continue;
            }
            if ($code >= 500) {
                $lastError = "http {$code}";
                continue;
            }
            if ($code >= 400) {
                $this->log('warn', 'security_api_client_error', ['code' => $code, 'path' => $path]);
                return null;
            }
            $decoded = json_decode((string) $raw, true);
            return is_array($decoded) ? $decoded : null;
        }

        $this->log('error', 'security_api_unreachable', ['path' => $path, 'error' => $lastError]);
        return null;
    }

    private static function requestId(): string
    {
        return bin2hex(random_bytes(12));
    }

    private function log(string $level, string $message, array $context = []): void
    {
        if ($this->logger !== null) {
            ($this->logger)($level, $message, $context);
            return;
        }
        error_log(sprintf('[security-client][%s] %s %s', $level, $message, json_encode($context)));
    }
}
