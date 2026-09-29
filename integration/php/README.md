# PHP Integration

## Files
- SecurityClient.php - the client class. Copy into your Pishon PHP tree.

## Quick usage

    require __DIR__ . '/SecurityClient.php';
    use App\Security\SecurityClient;

    $sec = SecurityClient::fromEnv();
    $sec->event('login_failed', 'MEDIUM', [
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? null,
        'user_id'    => $user->id ?? null,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'request_method' => $_SERVER['REQUEST_METHOD'] ?? null,
        'request_path'   => $_SERVER['REQUEST_URI'] ?? null,
        'metadata'   => ['reason' => 'bad_password'],
    ]);

## Blocklist enforcement with APCu cache

    $cacheKey = 'security_blocked_ips';
    $ttl = 30;

    $blocked = apcu_fetch($cacheKey);
    if ($blocked === false) {
        $blocked = $sec->blockedIps();
        apcu_store($cacheKey, $blocked, $ttl);
    }

    if (in_array($_SERVER['REMOTE_ADDR'] ?? '', $blocked, true)) {
        http_response_code(403);
        exit('Access denied');
    }
