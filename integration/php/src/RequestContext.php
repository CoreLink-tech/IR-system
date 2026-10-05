<?php
declare(strict_types=1);

namespace App\Security;

/** Builds the request details attached to every event, within the server's size limits. */
final class RequestContext
{
    /**
     * @param array<string,mixed> $server Usually $_SERVER.
     * @return array<string,string>
     */
    public static function fields(array $server, ?string $clientIp, ?string $sessionId = null): array
    {
        $out = [];
        if ($clientIp !== null) {
            $out['ip_address'] = $clientIp;
        }
        if (!empty($server['HTTP_USER_AGENT']) && is_string($server['HTTP_USER_AGENT'])) {
            $out['user_agent'] = self::cut(self::printable($server['HTTP_USER_AGENT']), 512);
        }
        if (!empty($server['REQUEST_METHOD']) && is_string($server['REQUEST_METHOD'])) {
            $out['request_method'] = self::cut(strtoupper(preg_replace('/[^A-Za-z]/', '', $server['REQUEST_METHOD'])), 10);
        }
        if (!empty($server['REQUEST_URI']) && is_string($server['REQUEST_URI'])) {
            $out['request_path'] = self::cut(self::printable($server['REQUEST_URI']), 1024);
        }
        $rid = $server['HTTP_X_REQUEST_ID'] ?? null;
        $out['request_id'] = (is_string($rid) && preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $rid)) ? $rid : bin2hex(random_bytes(12));
        if ($sessionId !== null && $sessionId !== '') {
            $out['session_id'] = self::sessionToken($sessionId);
        }
        return $out;
    }

    /**
     * The session id is a login credential: anyone holding it IS that user. It is never
     * sent. A one-way hash lets the server tell that two events came from the same
     * session without being able to use it.
     */
    public static function sessionToken(string $sessionId): string
    {
        return substr(hash('sha256', $sessionId), 0, 32);
    }

    private static function printable(string $s): string
    {
        return (string) preg_replace('/[\x00-\x1F\x7F]/', '', $s);
    }

    private static function cut(string $s, int $max): string
    {
        return strlen($s) > $max ? substr($s, 0, $max) : $s;
    }
}
