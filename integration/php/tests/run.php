<?php
declare(strict_types=1);

// Test runner for SecurityClient. Needs only PHP with the curl extension.
//   php integration/php/tests/run.php
// It starts PHP's built-in web server as a fake Security API and exits non-zero
// if any check fails.

require __DIR__ . '/../SecurityClient.php';

use App\Security\SecurityClient;

$port    = 18080 + random_int(0, 500);
$control = sys_get_temp_dir() . '/fake-api-control-' . getmypid() . '.json';
$log     = sys_get_temp_dir() . '/fake-api-log-' . getmypid() . '.jsonl';
putenv("FAKE_API_CONTROL=$control");
putenv("FAKE_API_LOG=$log");

$server = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fake_api.php'],
    [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes,
    null,
    ['FAKE_API_CONTROL' => $control, 'FAKE_API_LOG' => $log, 'PATH' => getenv('PATH') ?: '']
);
register_shutdown_function(function () use ($server, $control, $log) {
    proc_terminate($server);
    @unlink($control);
    @unlink($log);
});
for ($i = 0; $i < 50; $i++) {
    $s = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1);
    if ($s) { fclose($s); break; }
    usleep(100000);
}

$passed = 0;
$failed = 0;
$base = "http://127.0.0.1:$port";
const KEY = 'PMS_0123456789abcdefSECRETSECRETSECRET';

function script(array $c): void { global $control, $log; file_put_contents($control, json_encode($c)); @unlink($log); }
function requests(): array {
    global $log;
    if (!is_file($log)) return [];
    return array_map(fn($l) => json_decode($l, true), array_filter(explode("\n", (string) file_get_contents($log))));
}
function check(string $name, bool $ok, string $detail = ''): void {
    global $passed, $failed;
    if ($ok) { $passed++; echo "  ok    $name\n"; }
    else { $failed++; echo "  FAIL  $name" . ($detail !== '' ? "  ($detail)" : '') . "\n"; }
}
/** Builds a client whose log output is captured instead of written to the error log. */
function client(string $base, array &$logs, float $timeout = 2.0, int $retries = 1): SecurityClient {
    return new SecurityClient($base, KEY, $timeout, $retries, function ($level, $msg, $ctx) use (&$logs) {
        $logs[] = ['level' => $level, 'message' => $msg, 'context' => $ctx];
    });
}

echo "SecurityClient\n";

// 1. A normal event
$logs = []; script(['status' => 201, 'body' => ['id' => 'e1', 'riskScore' => 5]]);
$r = client($base, $logs)->event('login_failed', 'MEDIUM', ['ip_address' => '198.51.100.7', 'user_id' => 'u1']);
$req = requests()[0] ?? [];
$body = json_decode($req['body'] ?? '', true) ?: [];
check('returns the decoded response', $r === ['id' => 'e1', 'riskScore' => 5]);
check('POSTs to /api/v1/events', ($req['method'] ?? '') === 'POST' && ($req['path'] ?? '') === '/api/v1/events');
check('authenticates with the key as a bearer token', ($req['headers']['authorization'] ?? '') === 'Bearer ' . KEY);
check('sends JSON', ($req['headers']['content-type'] ?? '') === 'application/json');
check('identifies itself and sends a request id header', str_starts_with($req['headers']['user-agent'] ?? '', 'PishonSecurityClient') && strlen($req['headers']['x-request-id'] ?? '') === 24);
check('sends the event type, severity and fields', ($body['event_type'] ?? '') === 'login_failed' && ($body['severity'] ?? '') === 'MEDIUM' && ($body['ip_address'] ?? '') === '198.51.100.7' && ($body['user_id'] ?? '') === 'u1');
check('adds a request id to the event', strlen($body['request_id'] ?? '') === 24);
check('adds a UTC ISO 8601 timestamp that is current', isset($body['timestamp']) && abs(strtotime($body['timestamp']) - time()) < 5 && str_ends_with($body['timestamp'], '+00:00'));

// 2. Caller supplied values are kept
script([]);
client($base, $logs)->event('login_failed', 'LOW', ['request_id' => 'my-id', 'timestamp' => '2026-10-02T10:00:00+00:00']);
$body = json_decode(requests()[0]['body'], true);
check('keeps a request id and timestamp the caller supplied', $body['request_id'] === 'my-id' && $body['timestamp'] === '2026-10-02T10:00:00+00:00');

// 3. JSON encoding
script([]);
client($base, $logs)->event('suspicious_request', 'HIGH', ['request_path' => '/a/b?q=Ibadan é', 'metadata' => ['note' => 'naïve']]);
$raw = requests()[0]['body'];
check('does not escape slashes or unicode', str_contains($raw, '/a/b?q=Ibadan é') && str_contains($raw, 'naïve'));

// 4. Client errors are not retried, and are logged without the key
$logs = []; script(['status' => 401, 'body' => ['message' => 'Unauthorized']]);
$r = client($base, $logs)->event('login_failed', 'LOW');
check('returns null on a 4xx', $r === null);
check('does not retry a 4xx', count(requests()) === 1);
check('logs a warning for a 4xx', ($logs[0]['level'] ?? '') === 'warn' && ($logs[0]['context']['code'] ?? 0) === 401);

// 5. Server errors are retried, then give up quietly
$logs = []; script(['status' => 500]);
$r = client($base, $logs, 2.0, 1)->event('login_failed', 'LOW');
check('returns null after repeated 5xx', $r === null);
check('retries a 5xx once', count(requests()) === 2);
check('logs the outage as an error', ($logs[0]['level'] ?? '') === 'error' && ($logs[0]['message'] ?? '') === 'security_api_unreachable');
$logs = []; script(['status' => 500]);
client($base, $logs, 2.0, 0)->event('login_failed', 'LOW');
check('retries nothing when retries is 0', count(requests()) === 1);

// 6. A transient failure recovers
$logs = []; script(['fail_first' => 1, 'status' => 201, 'body' => ['id' => 'e2']]);
$r = client($base, $logs, 2.0, 1)->event('login_failed', 'LOW');
check('succeeds when the retry gets through', $r === ['id' => 'e2'] && count(requests()) === 2 && $logs === []);

// 7. Nothing listening
$logs = [];
$t = microtime(true);
$r = client('http://127.0.0.1:1', $logs, 1.0, 0)->event('login_failed', 'LOW');
check('returns null instead of throwing when the API is unreachable', $r === null && ($logs[0]['level'] ?? '') === 'error');
check('fails fast when the connection is refused', microtime(true) - $t < 1.5);

// 8. Slow API
$logs = []; script(['delay_ms' => 2000]);
$t = microtime(true);
$r = client($base, $logs, 0.3, 0)->event('login_failed', 'LOW');
$elapsed = microtime(true) - $t;
check('gives up on a slow API after the timeout', $r === null && $elapsed < 1.2, sprintf('%.2fs', $elapsed));
usleep(2200000);

// 9. Unexpected responses
$logs = []; script(['status' => 200, 'body' => 'this is not json']);
check('returns null for a response that is not JSON', client($base, $logs)->event('login_failed', 'LOW') === null);

// 10. Blocklist
$logs = []; script(['body' => ['data' => [['ipAddress' => '198.51.100.7'], ['ipAddress' => '203.0.113.9'], ['reason' => 'no address'], ['ipAddress' => '']]]]);
$list = client($base, $logs)->blockedIps();
$req = requests()[0];
check('reads the blocklist from /api/v1/security/blocked-ips with GET', $req['method'] === 'GET' && $req['path'] === '/api/v1/security/blocked-ips');
check('sends no body on a GET', ($req['body'] ?? '') === '' && !isset($req['headers']['content-type']));
check('returns just the addresses, skipping malformed rows', $list === ['198.51.100.7', '203.0.113.9']);
script(['body' => ['unexpected' => true]]);
check('returns an empty list for an unexpected shape', client($base, $logs)->blockedIps() === []);
script(['status' => 500]);
check('returns an empty list when the API is down', client($base, $logs, 2.0, 0)->blockedIps() === []);

// 11. The key must never reach the logs
$logs = []; script(['status' => 500]); client($base, $logs, 2.0, 1)->event('login_failed', 'LOW');
script(['status' => 403]); client($base, $logs, 2.0, 1)->event('login_failed', 'LOW');
client('http://127.0.0.1:1', $logs, 0.3, 0)->event('login_failed', 'LOW');
check('never writes the API key to the log', !str_contains(json_encode($logs), 'SECRETSECRET') && !str_contains(json_encode($logs), 'PMS_'));

// 12. Configuration
$logs = []; script([]);
client($base . '///', $logs)->event('login_failed', 'LOW');
check('copes with trailing slashes on the base URL', (requests()[0]['path'] ?? '') === '/api/v1/events');

putenv('SECURITY_API_BASE'); putenv('SECURITY_API_KEY');
$threw = false; try { SecurityClient::fromEnv(); } catch (RuntimeException $e) { $threw = true; }
check('fromEnv refuses to start without configuration', $threw);
putenv("SECURITY_API_BASE=$base"); putenv('SECURITY_API_KEY=' . KEY);
script(['body' => ['data' => []]]);
check('fromEnv builds a working client', SecurityClient::fromEnv(function () {}) instanceof SecurityClient);

echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
