<?php
declare(strict_types=1);

// End-to-end tests of the Security facade: boot, blocking and event reporting against a
// fake Security API (PHP's built-in web server).
//   php integration/php/tests/facade.php

require __DIR__ . '/../autoload.php';

use App\Security\Security;
use App\Security\SecurityConfig;
use App\Security\SecurityStop;

// A session must be started before any output is printed, so it is done first.
session_id('rawsessionid0123456789abcdef');
@session_start(['use_cookies' => 0, 'cache_limiter' => '', 'save_path' => sys_get_temp_dir()]);

$port    = 19080 + random_int(0, 400);
$control = sys_get_temp_dir() . '/fake-api-control-f' . getmypid() . '.json';
$log     = sys_get_temp_dir() . '/fake-api-log-f' . getmypid() . '.jsonl';
$stateRoot = sys_get_temp_dir() . '/pishon-facade-' . getmypid();
putenv("FAKE_API_CONTROL=$control");
putenv("FAKE_API_LOG=$log");
$server = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fake_api.php'],
    [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes, null, ['FAKE_API_CONTROL' => $control, 'FAKE_API_LOG' => $log, 'PATH' => getenv('PATH') ?: '']
);
function rrm(string $d): void { if (!is_dir($d)) { return; } foreach (scandir($d) ?: [] as $f) { if ($f === '.' || $f === '..') { continue; } $p = "$d/$f"; is_dir($p) ? rrm($p) : @unlink($p); } @rmdir($d); }
register_shutdown_function(function () use ($server, $control, $log, $stateRoot) { proc_terminate($server); @unlink($control); @unlink($log); rrm($stateRoot); });
for ($i = 0; $i < 50; $i++) { $s = @fsockopen('127.0.0.1', $port, $e, $m, 0.1); if ($s) { fclose($s); break; } usleep(100000); }

$passed = 0; $failed = 0;
function check(string $name, bool $ok, string $detail = ''): void { global $passed, $failed; if ($ok) { $passed++; echo "  ok    $name\n"; } else { $failed++; echo "  FAIL  $name" . ($detail !== '' ? "  ($detail)" : '') . "\n"; } }
function script(array $c): void { global $control, $log; file_put_contents($control, json_encode($c)); @unlink($log); }
function posts(): array { global $log; if (!is_file($log)) { return []; } $out = []; foreach (array_filter(explode("\n", (string) file_get_contents($log))) as $l) { $r = json_decode($l, true); if ($r['method'] === 'POST') { $out[] = json_decode($r['body'], true); } } return $out; }
function gets(): int { global $log; if (!is_file($log)) { return 0; } $n = 0; foreach (array_filter(explode("\n", (string) file_get_contents($log))) as $l) { if (json_decode($l, true)['method'] === 'GET') { $n++; } } return $n; }
$base = "http://127.0.0.1:$port";
$n = 0;
$cfg = function (array $over = []) use ($base, $stateRoot, &$n): SecurityConfig {
    $n++;
    return SecurityConfig::fromEnv(array_merge([
        'SECURITY_API_BASE' => $base, 'SECURITY_API_KEY' => 'PMS_testkey', 'SECURITY_STATE_DIR' => "$stateRoot/$n",
        'SECURITY_API_TIMEOUT' => '1', 'SECURITY_BLOCKLIST_TTL' => '30',
    ], $over));
};
$logs = [];
$logger = function ($level, $msg, $ctx) use (&$logs) { $logs[] = [$level, $msg, $ctx]; };
function logged(array $logs, string $msg): bool { foreach ($logs as $l) { if ($l[1] === $msg) { return true; } } return false; }
$deny = function () { throw new SecurityStop('denied'); };
$blocklist = ['body' => ['data' => [['ipAddress' => '198.51.100.7', 'permanent' => true, 'expiresAt' => null, 'reason' => 'x']]]];

echo "Security facade\n";

// -- blocking
script($blocklist); $logs = [];
$stopped = false;
try { Security::boot($cfg(['SECURITY_MODE' => 'enforce']), ['REMOTE_ADDR' => '198.51.100.7'], $logger, $deny); } catch (SecurityStop $e) { $stopped = true; }
check('enforce mode: a blocked visitor is stopped', $stopped);

script($blocklist); $logs = [];
$r = Security::boot($cfg(), ['REMOTE_ADDR' => '198.51.100.7'], $logger, $deny);
check('monitor mode (the default): reported as blocked but let through', $r === true && logged($logs, 'security_would_block'));

script($blocklist);
check('an address that is not blocked passes', Security::boot($cfg(['SECURITY_MODE' => 'enforce']), ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny) === false);

script($blocklist);
$stopped = false;
try { Security::boot($cfg(['SECURITY_MODE' => 'enforce', 'SECURITY_TRUSTED_PROXIES' => '10.0.0.1']), ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'], $logger, $deny); } catch (SecurityStop $e) { $stopped = true; }
check('behind a trusted proxy the real visitor is checked, not the proxy', $stopped && Security::clientIp() === '198.51.100.7');

script($blocklist);
$r = Security::boot($cfg(['SECURITY_MODE' => 'enforce', 'SECURITY_TRUSTED_PROXIES' => '10.0.0.1']), ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9'], $logger, $deny);
check('the proxy itself is never blocked because of a visitor', $r === false && Security::clientIp() === '203.0.113.9');

script($blocklist);
$r = Security::boot($cfg(['SECURITY_MODE' => 'enforce']), ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'], $logger, $deny);
check('without trusted proxies a forged X-Forwarded-For cannot get a visitor blocked or hide them', $r === false && Security::clientIp() === '203.0.113.9');

script($blocklist);
$r = Security::boot($cfg(['SECURITY_MODE' => 'enforce']), ['REMOTE_ADDR' => '127.0.0.1'], $logger, $deny);
check('loopback and private visitors are never stopped', $r === false);

script($blocklist); $logs = [];
Security::boot($cfg(), ['REMOTE_ADDR' => '10.9.9.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7'], $logger, $deny);
check('forwarded headers from an untrusted connection raise a configuration hint', logged($logs, 'security_proxy_not_trusted'));

// -- blocklist caching
script($blocklist);
$c = $cfg();
Security::boot($c, ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
Security::boot($c, ['REMOTE_ADDR' => '203.0.113.10'], $logger, $deny);
Security::boot($c, ['REMOTE_ADDR' => '203.0.113.11'], $logger, $deny);
check('three page views make one API call, not three', gets() === 1, 'calls=' . gets());

// -- events
script(['status' => 201, 'body' => ['id' => 'e1']]); $logs = [];
Security::boot($cfg(['SECURITY_TRUSTED_PROXIES' => 'private']), [
    'REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.7', 'HTTP_USER_AGENT' => 'TestBrowser/1.0',
    'REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/login?next=/account',
], $logger, $deny);
Security::loginFailed('user-42', ['password' => 'hunter2', 'attempt' => 3, 'shipping_address' => '12 Marina Rd']);
Security::reporter()->flush();
$sent = posts();
$body = $sent[0] ?? [];
check('a login failure is sent as one event', count($sent) === 1 && ($body['event_type'] ?? '') === 'login_failed' && ($body['severity'] ?? '') === 'MEDIUM');
check('it carries the real visitor, user, agent, method and path', ($body['ip_address'] ?? '') === '203.0.113.7' && ($body['user_id'] ?? '') === 'user-42' && ($body['user_agent'] ?? '') === 'TestBrowser/1.0' && ($body['request_method'] ?? '') === 'POST' && ($body['request_path'] ?? '') === '/login?next=/account');
check('the password never leaves the website', strpos(json_encode($body), 'hunter2') === false && ($body['metadata']['password'] ?? '') === '[REDACTED]' && ($body['metadata']['shipping_address'] ?? '') === '12 Marina Rd');
check('the raw session id never leaves the website, only a one-way token', strpos(json_encode($body), 'rawsessionid') === false && strlen($body['session_id'] ?? '') === 32);
check('it has its own event id, so a repeat delivery is recognised by the server', strlen($body['event_id'] ?? '') === 24);
check('it has a request id and a current timestamp', strlen($body['request_id'] ?? '') === 24 && abs(strtotime($body['timestamp'] ?? '') - time()) < 10);

$types = ['loginSuccess' => ['login_success', 'INFO'], 'passwordReset' => ['password_reset', 'LOW'], 'adminAccess' => ['admin_access', 'INFO'], 'paymentIssue' => ['payment_security_event', 'MEDIUM']];
script(['status' => 201, 'body' => ['id' => 'e']]);
Security::boot($cfg(), ['REMOTE_ADDR' => '203.0.113.7'], $logger, $deny);
foreach (array_keys($types) as $m) { Security::$m('u1'); }
Security::sessionAnomaly('u1', 'new device'); Security::suspiciousRequest('sql in search', 'u1'); Security::rateLimited(); Security::logout('u1'); Security::accountChange('u1', 'email');
Security::reporter()->flush();
$got = array_map(function ($b) { return $b['event_type'] . ':' . $b['severity']; }, posts());
$want = ['login_success:INFO', 'password_reset:LOW', 'admin_access:INFO', 'payment_security_event:MEDIUM', 'session_anomaly:MEDIUM', 'suspicious_request:HIGH', 'rate_limit_exceeded:LOW', 'logout:INFO', 'account_change:MEDIUM'];
check('every helper sends the event type and severity the server expects', $got === $want, json_encode($got));

script(['status' => 201]); $logs = [];
Security::boot($cfg(), ['REMOTE_ADDR' => '203.0.113.7'], $logger, $deny);
Security::event('login-failed', 'u1');
Security::event('made_up_type');
Security::reporter()->flush();
check('an unknown event type is logged and dropped, not sent', posts() === [] && logged($logs, 'security_unknown_event_type'));

script(['status' => 201]);
Security::boot($cfg(), ['REMOTE_ADDR' => '203.0.113.7'], $logger, $deny);
Security::event('server_error', null, [], 'HIGH');
Security::event('server_error', null, [], 'BOGUS');
Security::reporter()->flush();
$sev = array_column(posts(), 'severity');
check('a custom severity is honoured only if valid', $sev === ['HIGH', 'MEDIUM'], json_encode($sev));

// -- failure handling
Security::reset(); $logs = [];
Security::loginFailed('u1'); Security::event('logout'); Security::passwordReset();
check('calling the helpers before boot does nothing and never throws', !Security::booted() && Security::reporter() === null && Security::clientIp() === null);

$logs = [];
$r = Security::boot(SecurityConfig::fromEnv(['SECURITY_ENABLED' => 'false']), ['REMOTE_ADDR' => '198.51.100.7'], $logger, $deny);
check('the kill switch turns everything off', $r === false && !Security::booted());
$logs = [];
$r = Security::boot(SecurityConfig::fromEnv([]), ['REMOTE_ADDR' => '198.51.100.7'], $logger, $deny);
check('missing configuration is logged, and the page still works', $r === false && !Security::booted() && logged($logs, 'security_not_configured'));

$logs = [];
$dead = $cfg(['SECURITY_API_BASE' => 'http://127.0.0.1:1', 'SECURITY_MODE' => 'enforce']);
$t = microtime(true);
$r = Security::boot($dead, ['REMOTE_ADDR' => '198.51.100.7'], $logger, $deny);
$bootTime = microtime(true) - $t;
check('API down at boot: the visitor is let in (fail open) quickly', $r === false && $bootTime < 2.0 && logged($logs, 'security_blocklist_refresh_failed'), sprintf('%.2fs', $bootTime));
Security::loginFailed('u1');
Security::reporter()->flush();
check('API down: the event is kept on disk instead of lost', Security::reporter()->backlog() === 1);
Security::boot($dead, ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
Security::loginFailed('u2'); Security::reporter()->flush();
Security::boot($dead, ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
Security::loginFailed('u3'); Security::reporter()->flush();
$t = microtime(true);
Security::boot($dead, ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
Security::loginFailed('u4'); Security::reporter()->flush();
$later = microtime(true) - $t;
check('after repeated failures the breaker stops the waiting; events are still kept', $later < 0.5 && Security::reporter()->backlog() === 4, sprintf('%.2fs backlog=%d', $later, Security::reporter()->backlog()));

// -- a quiet page delivers the backlog left by an earlier outage
script(['status' => 201, 'body' => ['id' => 'e']]);
$shared = ['SECURITY_STATE_DIR' => "$stateRoot/shared"];
Security::boot($cfg($shared + ['SECURITY_API_BASE' => 'http://127.0.0.1:1']), ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
Security::loginFailed('q1'); Security::loginFailed('q2'); Security::reporter()->flush();
check('events reported while the API is down are queued', Security::reporter()->backlog() === 2);
Security::boot($cfg($shared), ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
check('the next page, even one that reports nothing, schedules their delivery', Security::reporter()->isScheduled() === true);
Security::reporter()->flush();
$ids = array_column(posts(), 'event_id');
check('the queued events are delivered, each with the id it was given when it happened', count($ids) === 2 && $ids[0] !== $ids[1] && Security::reporter()->backlog() === 0);
Security::boot($cfg(['SECURITY_STATE_DIR' => "$stateRoot/empty"]), ['REMOTE_ADDR' => '203.0.113.9'], $logger, $deny);
check('a page with nothing queued schedules nothing', Security::reporter()->isScheduled() === false);

echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
