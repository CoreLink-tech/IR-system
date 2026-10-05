<?php
declare(strict_types=1);

namespace App\Security;

final class SecurityClient implements EventSender
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

    /**
     * Sends one complete event payload and says what happened to it, so the caller
     * can tell a delivery problem (try again later) from a rejection (never retry).
     *
     * @return array{result:string,status:int} result is "sent", "rejected" or "failed".
     */
    public function sendEvent(array $payload): array
    {
        $r = $this->perform('POST', '/api/v1/events', $payload);
        if ($r['status'] >= 200 && $r['status'] < 300) {
            return ['result' => 'sent', 'status' => $r['status']];
        }
        if ($r['status'] >= 400 && $r['status'] < 500 && $r['status'] !== 429 && $r['status'] !== 408) {
            return ['result' => 'rejected', 'status' => $r['status']];
        }
        return ['result' => 'failed', 'status' => $r['status']];
    }

    /**
     * The blocklist as the server sent it, or null if it could not be fetched.
     * Null is not the same as an empty list: "nothing is blocked" and "I could not
     * ask" must never be confused, or an outage would unblock every address.
     *
     * @return array<int,array<string,mixed>>|null
     */
    public function fetchBlocklist(): ?array
    {
        $res = $this->request('GET', '/api/v1/security/blocked-ips', null);
        if (!is_array($res) || !isset($res['data']) || !is_array($res['data'])) {
            return null;
        }
        return array_values(array_filter($res['data'], 'is_array'));
    }

    /** Just the addresses. An empty list also results when the API is unreachable; prefer fetchBlocklist(). */
    public function blockedIps(): array
    {
        $rows = $this->fetchBlocklist();
        $out = [];
        foreach ($rows ?? [] as $row) {
            if (!empty($row['ipAddress'])) {
                $out[] = (string) $row['ipAddress'];
            }
        }
        return $out;
    }

    private function request(string $method, string $path, ?array $body): ?array
    {
        $r = $this->perform($method, $path, $body);
        if ($r['status'] >= 200 && $r['status'] < 300) {
            return $r['body'];
        }
        return null;
    }

    /**
     * Makes the HTTP call, with retries for network errors and 5xx answers.
     *
     * @return array{status:int,body:?array} status 0 means no answer was received.
     */
    private function perform(string $method, string $path, ?array $body): array
    {
        $url = $this->baseUrl . $path;
        $attempts = $this->retries + 1;
        $lastError = null;
        $lastStatus = 0;

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
                $lastStatus = 0;
                continue;
            }
            if ($code >= 500) {
                $lastError = "http {$code}";
                $lastStatus = $code;
                continue;
            }
            if ($code >= 400) {
                $this->log('warn', 'security_api_client_error', ['code' => $code, 'path' => $path]);
                return ['status' => $code, 'body' => null];
            }
            $decoded = json_decode((string) $raw, true);
            return ['status' => $code, 'body' => is_array($decoded) ? $decoded : null];
        }

        $this->log('error', 'security_api_unreachable', ['path' => $path, 'error' => $lastError]);
        return ['status' => $lastStatus, 'body' => null];
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
