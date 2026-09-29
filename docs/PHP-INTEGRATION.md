# Pishon PHP Integration

## Install
Copy integration/php/SecurityClient.php into your Pishon codebase.

## Configure
Add to .env or config:

    SECURITY_API_BASE=https://security.pishon.example
    SECURITY_API_KEY=PMS_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    SECURITY_API_TIMEOUT=2

Create the API key once:

    curl -X POST https://security.pishon.example/api/v1/api-keys \
      -H "Authorization: Bearer <accessToken>" \
      -H "Content-Type: application/json" \
      -d '{"name":"Pishon PHP","scopes":["events:write","block:read"],"expiresInDays":365}'

Raw key returned ONCE.

## Send a login event

    use App\Security\SecurityClient;
    $sec = SecurityClient::fromEnv();
    $sec->event('login_failed', 'MEDIUM', [
        'ip_address'     => $_SERVER['REMOTE_ADDR'] ?? null,
        'user_id'        => $user->id ?? null,
        'session_id'     => session_id() ?: null,
        'user_agent'     => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'request_method' => $_SERVER['REQUEST_METHOD'] ?? null,
        'request_path'   => $_SERVER['REQUEST_URI'] ?? null,
        'request_id'     => $requestId,
        'metadata'       => ['reason' => 'bad_password'],
    ]);

## Enforce the blocklist

    $blocked = $sec->blockedIps();
    if (in_array($clientIp, $blocked, true)) {
        http_response_code(403);
        exit('Access denied');
    }

Cache in APCu / Redis / file. Do not call on every request.

## Failure behavior
- Times out after SECURITY_API_TIMEOUT seconds.
- Retries once on 5xx or network error.
- Never throws into your request path.
