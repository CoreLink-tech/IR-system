<?php
declare(strict_types=1);

// Unit tests for the integration library. Needs only PHP 7.4+ with curl.
//   php integration/php/tests/unit.php
// Exits non-zero if any check fails.

require __DIR__ . '/../autoload.php';

use App\Security\BlocklistCache;
use App\Security\CircuitBreaker;
use App\Security\ClientIp;
use App\Security\EventSender;
use App\Security\EventSpool;
use App\Security\FileStore;
use App\Security\IpAddress;
use App\Security\Redactor;
use App\Security\RequestContext;
use App\Security\Security;
use App\Security\SecurityConfig;
use App\Security\SecurityGuard;
use App\Security\SecurityReporter;
use App\Security\SecurityStop;

$passed = 0;
$failed = 0;
$section = '';
function section(string $name): void { global $section; $section = $name; echo "\n$name\n"; }
function check(string $name, bool $ok, string $detail = ''): void
{
    global $passed, $failed;
    if ($ok) { $passed++; echo "  ok    $name\n"; return; }
    $failed++;
    echo "  FAIL  $name" . ($detail !== '' ? "  ($detail)" : '') . "\n";
}
function same($a, $b): bool { return $a === $b; }
function show($v): string { return json_encode($v, JSON_UNESCAPED_SLASHES); }
function tmpdir(): string
{
    $d = sys_get_temp_dir() . '/pishon-test-' . bin2hex(random_bytes(5));
    return $d;
}
function rrmdir(string $d): void
{
    if (!is_dir($d)) { return; }
    foreach (scandir($d) ?: [] as $f) {
        if ($f === '.' || $f === '..') { continue; }
        $p = "$d/$f";
        is_dir($p) && !is_link($p) ? rrmdir($p) : @unlink($p);
    }
    @rmdir($d);
}
$cleanup = [];
register_shutdown_function(function () use (&$cleanup) { foreach ($cleanup as $d) { rrmdir($d); } });
function newStore(?callable $logger = null): FileStore
{
    global $cleanup;
    $d = tmpdir();
    $cleanup[] = $d;
    return new FileStore($d, $logger);
}

// ---------------------------------------------------------------- address parsing
section('IpAddress: shared vectors (identical to the server)');
$vectors = json_decode((string) file_get_contents(__DIR__ . '/../../shared/ip-vectors.json'), true)['vectors'];
$bad = [];
foreach ($vectors as $v) {
    $n = IpAddress::normalize($v['input']);
    if ($n !== $v['normalized'] || ($n !== null && IpAddress::isInternal($n) !== $v['internal'])) {
        $bad[] = show($v['input']) . ' => ' . show($n);
    }
}
check(count($vectors) . ' vectors all agree with the server', $bad === [], implode('; ', $bad));
check('non-strings are rejected', IpAddress::normalize(null) === null && IpAddress::normalize(1234) === null && IpAddress::normalize(['1.1.1.1']) === null);

section('IpAddress: CIDR matching');
$cases = [
    ['10.1.2.3', '10.0.0.0/8', true], ['11.1.2.3', '10.0.0.0/8', false],
    ['172.16.5.5', '172.16.0.0/12', true], ['172.32.0.1', '172.16.0.0/12', false],
    ['203.0.113.5', '203.0.113.5', true], ['203.0.113.6', '203.0.113.5', false],
    ['203.0.113.6', '203.0.113.5/32', false], ['1.2.3.4', '0.0.0.0/0', true],
    ['192.168.1.200', '192.168.1.128/25', true], ['192.168.1.100', '192.168.1.128/25', false],
    ['2001:db8::1', '2001:db8::/32', true], ['2001:db9::1', '2001:db8::/32', false],
    ['fd12::1', 'fc00::/7', true], ['2001:db8::1', '2001:db8::1', true],
    ['10.0.0.1', '2001:db8::/32', false], ['2001:db8::1', '10.0.0.0/8', false],
    ['10.0.0.1', '10.0.0.0/33', false], ['10.0.0.1', '10.0.0.0/abc', false], ['10.0.0.1', 'garbage/8', false],
    ['not-an-ip', '10.0.0.0/8', false], ['::ffff:10.0.0.1', '10.0.0.0/8', true],
];
$bad = [];
foreach ($cases as $c) { if (IpAddress::inCidr($c[0], $c[1]) !== $c[2]) { $bad[] = "$c[0] in $c[1]"; } }
check(count($cases) . ' CIDR cases', $bad === [], implode('; ', $bad));

// ---------------------------------------------------------------- client address
section('ClientIp: who is the visitor?');
$srv = function (string $remote, ?string $xff = null, array $extra = []): array {
    $s = ['REMOTE_ADDR' => $remote] + $extra;
    if ($xff !== null) { $s['HTTP_X_FORWARDED_FOR'] = $xff; }
    return $s;
};
$none = new ClientIp([]);
check('no trusted proxies: REMOTE_ADDR is used', same($none->resolve($srv('203.0.113.9')), '203.0.113.9'));
check('no trusted proxies: a forged X-Forwarded-For is ignored', same($none->resolve($srv('203.0.113.9', '1.1.1.1')), '203.0.113.9'));
check('no trusted proxies: even a private REMOTE_ADDR is not "unwrapped"', same($none->resolve($srv('10.0.0.5', '203.0.113.7')), '10.0.0.5'));

$proxy = new ClientIp(['10.0.0.1']);
check('trusted proxy: the forwarded visitor is used', same($proxy->resolve($srv('10.0.0.1', '203.0.113.7')), '203.0.113.7'));
check('a request from some other address cannot use the header', same($proxy->resolve($srv('198.51.100.9', '203.0.113.7')), '198.51.100.9'));
check('a forged left-hand entry is ignored: the rightmost untrusted address wins', same($proxy->resolve($srv('10.0.0.1', '1.1.1.1, 203.0.113.7')), '203.0.113.7'));
check('empty or missing header falls back to the proxy', same($proxy->resolve($srv('10.0.0.1', '')), '10.0.0.1') && same($proxy->resolve($srv('10.0.0.1')), '10.0.0.1'));

$two = new ClientIp(['10.0.0.1', '10.0.0.2']);
check('two proxies in a row are both skipped', same($two->resolve($srv('10.0.0.1', '203.0.113.7, 10.0.0.2')), '203.0.113.7'));
check('a chain made only of trusted proxies falls back to the connection', same($two->resolve($srv('10.0.0.1', '10.0.0.2')), '10.0.0.1'));

$private = new ClientIp(['private']);
check('"private" trusts loopback and private networks', same($private->resolve($srv('127.0.0.1', '203.0.113.7')), '203.0.113.7') && same($private->resolve($srv('192.168.5.5', '203.0.113.7')), '203.0.113.7') && same($private->resolve($srv('172.20.1.1', '203.0.113.7')), '203.0.113.7'));
check('"private" does not trust public addresses', same($private->resolve($srv('198.51.100.9', '203.0.113.7')), '198.51.100.9'));

$cidr = new ClientIp(['173.245.48.0/20', '2400:cb00::/32']);
check('CIDR proxy lists work, IPv4 and IPv6', same($cidr->resolve($srv('173.245.50.1', '203.0.113.7')), '203.0.113.7') && same($cidr->resolve($srv('2400:cb00::5', '203.0.113.7')), '203.0.113.7') && same($cidr->resolve($srv('173.245.64.1', '203.0.113.7')), '173.245.64.1'));

check('ports are removed', same($proxy->resolve($srv('10.0.0.1', '203.0.113.7:51234')), '203.0.113.7'));
check('bracketed IPv6 with a port is understood', same($proxy->resolve($srv('10.0.0.1', '[2001:db8::7]:443')), '2001:db8::7'));
check('an IPv6 visitor is normalized', same($proxy->resolve($srv('10.0.0.1', '2001:DB8:0:0:0:0:0:7')), '2001:db8::7'));
check('a malformed entry makes the header untrustworthy: fall back to the connection', same($proxy->resolve($srv('10.0.0.1', 'garbage')), '10.0.0.1') && same($proxy->resolve($srv('10.0.0.1', '203.0.113.7, garbage')), '10.0.0.1'));
check('shorthand and octal forms in the header are rejected', same($proxy->resolve($srv('10.0.0.1', '127.1')), '10.0.0.1') && same($proxy->resolve($srv('10.0.0.1', '010.0.0.1')), '10.0.0.1'));
check('an invalid or missing REMOTE_ADDR gives null', $proxy->resolve(['REMOTE_ADDR' => 'junk']) === null && $proxy->resolve([]) === null);
check('an IPv4-mapped connection address is seen as IPv4', same($proxy->resolve($srv('::ffff:10.0.0.1', '203.0.113.7')), '203.0.113.7') && same($none->resolve($srv('::ffff:203.0.113.9')), '203.0.113.9'));

$cf = new ClientIp(['173.245.48.0/20'], 'CF-Connecting-IP');
check('a client-address header is used when the connection is trusted', same($cf->resolve($srv('173.245.50.1', '8.8.8.8', ['HTTP_CF_CONNECTING_IP' => '203.0.113.7'])), '203.0.113.7'));
check('the header is ignored when the connection is not trusted', same($cf->resolve($srv('198.51.100.9', null, ['HTTP_CF_CONNECTING_IP' => '203.0.113.7'])), '198.51.100.9'));
check('an invalid header value falls back to X-Forwarded-For', same($cf->resolve($srv('173.245.50.1', '203.0.113.8', ['HTTP_CF_CONNECTING_IP' => 'junk'])), '203.0.113.8'));

check('misconfiguration is noticed: proxy headers from an untrusted connection', $none->looksMisconfigured($srv('10.0.0.5', '203.0.113.7')) === true);
check('no warning without forwarding headers, or when the proxy is trusted', $none->looksMisconfigured($srv('203.0.113.9')) === false && $proxy->looksMisconfigured($srv('10.0.0.1', '203.0.113.7')) === false);

// ---------------------------------------------------------------- redaction
section('Redactor: secrets never leave the website');
foreach (['password', 'user_password', 'passwd', 'secret', 'token', 'reset_token', 'resetToken', 'api_key', 'apiKey', 'authorization', 'cookie', 'set-cookie', 'card_number', 'cardNumber', 'cvv', 'card_pin', 'cardPin', 'pin', 'otp', 'ssn', 'private_key'] as $k) {
    check("redacts '$k'", Redactor::isSensitiveKey($k));
}
foreach (['shipping_address', 'shippingMethod', 'mapping', 'typing', 'keyboard', 'monkey', 'author', 'ip_address', 'user_id', 'email', 'order_id', 'amount'] as $k) {
    check("keeps '$k'", !Redactor::isSensitiveKey($k));
}
$out = Redactor::clean(['email' => 'a@b.ng', 'password' => 'hunter2', 'nested' => ['reset_token' => 'abc', 'ok' => 1, 'deep' => [['cardPin' => '1234', 'note' => 'x']]], 'shipping_address' => '12 Marina Rd']);
check('redacts at any depth and keeps ordinary fields', same($out, ['email' => 'a@b.ng', 'password' => '[REDACTED]', 'nested' => ['reset_token' => '[REDACTED]', 'ok' => 1, 'deep' => [['cardPin' => '[REDACTED]', 'note' => 'x']]], 'shipping_address' => '12 Marina Rd']), show($out));
check('truncates long strings, large arrays and deep nesting', strlen(Redactor::clean(['a' => str_repeat('x', 5000)])['a']) === 1003 && count(Redactor::clean(array_fill(0, 200, 1))) === 50 && strpos(show(Redactor::clean([[[[[[['x']]]]]]])), '[truncated]') !== false);
check('objects and resources are not leaked', same(Redactor::clean(['o' => new stdClass()]), ['o' => '[unsupported]']));

// ---------------------------------------------------------------- request context
section('RequestContext: what is attached to an event');
$f = RequestContext::fields(['HTTP_USER_AGENT' => "Mozilla/5.0\r\nX-Evil: 1", 'REQUEST_METHOD' => 'post', 'REQUEST_URI' => '/login?next=/a'], '203.0.113.7', 'SESSIONID123');
check('carries address, agent, method and path', $f['ip_address'] === '203.0.113.7' && $f['request_method'] === 'POST' && $f['request_path'] === '/login?next=/a' && strpos($f['user_agent'], 'Mozilla/5.0') === 0);
check('control characters are stripped from headers', strpos($f['user_agent'], "\r") === false && strpos($f['user_agent'], "\n") === false);
check('the session id is never sent, only a stable one-way token', $f['session_id'] !== 'SESSIONID123' && strlen($f['session_id']) === 32 && $f['session_id'] === RequestContext::sessionToken('SESSIONID123') && $f['session_id'] !== RequestContext::sessionToken('SESSIONID124') && strpos(show($f), 'SESSIONID123') === false);
$big = RequestContext::fields(['HTTP_USER_AGENT' => str_repeat('u', 900), 'REQUEST_URI' => '/' . str_repeat('p', 3000), 'REQUEST_METHOD' => 'GET;DROP'], null);
check('values are cut to the server limits', strlen($big['user_agent']) === 512 && strlen($big['request_path']) === 1024 && $big['request_method'] === 'GETDROP' && !isset($big['ip_address']));
check('a valid request id is kept, an unsafe one is replaced', RequestContext::fields(['HTTP_X_REQUEST_ID' => 'abc-123'], null)['request_id'] === 'abc-123' && preg_match('/^[0-9a-f]{24}$/', RequestContext::fields(['HTTP_X_REQUEST_ID' => 'bad id; drop'], null)['request_id']) === 1);
check('no session means no session field', !isset(RequestContext::fields([], null, null)['session_id']) && !isset(RequestContext::fields([], null, '')['session_id']));

// ---------------------------------------------------------------- file store
section('FileStore: private shared state');
$logs = [];
$store = newStore(function ($l, $m, $c) use (&$logs) { $logs[] = $m; });
check('creates its folder, private', $store->usable() && (fileperms($store->path('')) & 0777) === 0700);
check('round-trips JSON', $store->writeJson('a.json', ['x' => [1, 2]]) && same($store->readJson('a.json'), ['x' => [1, 2]]));
check('leaves no temporary files behind', count(glob($store->path('*.tmp'))) === 0);
file_put_contents($store->path('bad.json'), '{not json');
check('a corrupt file reads as missing, not as an error', $store->readJson('bad.json') === null && $store->readJson('missing.json') === null);
$h1 = $store->tryLock('l');
check('a lock can be taken once at a time', $h1 !== null && $store->tryLock('l') === null);
$store->release($h1);
$h2 = $store->tryLock('l');
check('and again after release', $h2 !== null);
$store->release($h2);
check('withLock runs the callback and returns its value', $store->withLock('w', function () { return 42; }) === 42);
$held = $store->tryLock('w2');
check('withLock gives up if the lock stays busy', $store->withLock('w2', function () { return 1; }, 0.05) === null);
$store->release($held);

$d = tmpdir(); $cleanup[] = $d; mkdir($d, 0777); chmod($d, 0777);
check('a folder that others can write to is tightened, then used', (new FileStore($d))->usable() && (fileperms($d) & 0022) === 0);
$target = tmpdir(); $cleanup[] = $target; mkdir($target, 0700);
$link = tmpdir(); symlink($target, $link); $cleanup[] = $link;
$logs = [];
check('a symbolic link is refused', (new FileStore($link, function ($l, $m, $c) use (&$logs) { $logs[] = $m; }))->usable() === false && $logs === ['security_state_dir_unusable']);
$bad = new FileStore('/proc/definitely/not/creatable');
check('an unusable folder never throws; every operation quietly does nothing', !$bad->usable() && $bad->readJson('a') === null && $bad->writeJson('a', [1]) === false && $bad->tryLock('a') === null);

// ---------------------------------------------------------------- blocklist cache
section('BlocklistCache: blocking without calling the API on every page');
$clock = 1000000;
$now = function () use (&$clock) { return $clock; };
$mk = function (&$calls, &$rowsRef, ?FileStore $st = null, int $ttl = 30) use ($now): BlocklistCache {
    return new BlocklistCache($st ?? newStore(), function () use (&$calls, &$rowsRef) { $calls++; return $rowsRef; }, $ttl, 15, $now);
};
$calls = 0; $rows = [['ipAddress' => '198.51.100.7', 'permanent' => true, 'expiresAt' => null]];
$c = $mk($calls, $rows);
check('a listed address is blocked, others are not', $c->isBlocked('198.51.100.7') && !$c->isBlocked('203.0.113.9'));
check('the first request fetches once and later ones use the cache', $calls === 1);
$c->isBlocked('198.51.100.7'); $c->isBlocked('1.1.1.1');
check('no refetch inside the refresh interval', $calls === 1);
$clock += 31; $c->isBlocked('198.51.100.7');
check('refetch once the interval has passed', $calls === 2);
check('the same address in another spelling matches', $c->isBlocked('::ffff:198.51.100.7') && $c->isBlocked(' 198.51.100.7 '));
check('an invalid address is never blocked', !$c->isBlocked('not-an-ip') && !$c->isBlocked(''));

$calls = 0; $rows = [['ipAddress' => '198.51.100.7', 'permanent' => true]];
$store = newStore(); $c = $mk($calls, $rows, $store);
$c->isBlocked('198.51.100.7');
$rows = null; $clock += 31;
check('if the refresh fails, the previous list stays in force', $c->isBlocked('198.51.100.7') === true && $calls === 2);
$c->isBlocked('198.51.100.7'); $clock += 5; $c->isBlocked('198.51.100.7');
check('and it is not retried until the backoff has passed', $calls === 2);
$clock += 20; $c->isBlocked('198.51.100.7');
check('then it tries again', $calls === 3);
$rows = [['ipAddress' => '203.0.113.9', 'permanent' => true]]; $clock += 31;
check('and picks up the new list once the API is back', $c->isBlocked('203.0.113.9') && !$c->isBlocked('198.51.100.7'));

$calls = 0; $rows = null; $c = $mk($calls, $rows);
check('API down and no list yet: fail open (allow), do not hammer the API', !$c->isBlocked('198.51.100.7') && !$c->isBlocked('198.51.100.7') && $calls === 1);

$calls = 0; $rows = []; $c = $mk($calls, $rows);
check('an empty list from a healthy API is a real answer', !$c->isBlocked('198.51.100.7') && $c->ageSeconds() === 0);

$calls = 0; $rows = [
    ['ipAddress' => '198.51.100.1', 'permanent' => false, 'expiresAt' => gmdate('c', $clock + 600)],
    ['ipAddress' => '198.51.100.2', 'permanent' => false, 'expiresAt' => gmdate('c', $clock - 60)],
    ['ipAddress' => '198.51.100.3', 'permanent' => true, 'expiresAt' => gmdate('c', $clock - 60)],
    ['ipAddress' => '198.51.100.4', 'permanent' => false, 'expiresAt' => null],
    ['ipAddress' => '198.51.100.5', 'permanent' => false, 'expiresAt' => 'not a date'],
    ['ipAddress' => '10.0.0.5', 'permanent' => true],
    ['ipAddress' => '127.0.0.1', 'permanent' => true],
    ['ipAddress' => 'garbage', 'permanent' => true],
    ['reason' => 'no address'],
];
$c = $mk($calls, $rows, null, 100000);
check('a temporary block is in force until its expiry', $c->isBlocked('198.51.100.1'));
check('an expired block is ignored even though the list is cached', !$c->isBlocked('198.51.100.2'));
check('a permanent block ignores any expiry', $c->isBlocked('198.51.100.3'));
check('a block with no expiry stays', $c->isBlocked('198.51.100.4'));
check('an unreadable expiry is skipped, not guessed', !$c->isBlocked('198.51.100.5'));
check('private and loopback addresses are never blocked, even if the server lists them', !$c->isBlocked('10.0.0.5') && !$c->isBlocked('127.0.0.1'));
$clock += 700;
check('a temporary block ends on time without a refresh', !$c->isBlocked('198.51.100.1') && $calls === 1);

$calls = 0; $rows = [['ipAddress' => '198.51.100.9', 'permanent' => false, 'expiresAt' => gmdate('c', $clock + 100)], ['ipAddress' => '198.51.100.9', 'permanent' => false, 'expiresAt' => gmdate('c', $clock + 900)]];
$c = $mk($calls, $rows);
$clock += 500;
check('a duplicated address keeps the later expiry', $c->isBlocked('198.51.100.9'));

$calls = 0; $rows = [['ipAddress' => '198.51.100.7', 'permanent' => true]];
$store = newStore(); $c = $mk($calls, $rows, $store);
$c->isBlocked('1.1.1.1'); $clock += 31;
$lock = $store->tryLock('blocklist.lock');
check('while another request refreshes, this one uses the old list and does not call the API', $c->isBlocked('198.51.100.7') === true && $calls === 1);
$store->release($lock);

$calls = 0; $rows = [['ipAddress' => '198.51.100.7', 'permanent' => true]];
$store = newStore(); $c = $mk($calls, $rows, $store); $c->isBlocked('1.1.1.1');
file_put_contents($store->path('blocklist.json'), 'corrupt{'); 
check('a corrupted cache file is rebuilt', $c->isBlocked('198.51.100.7') && $calls === 2);

$calls = 0; $rows = [['ipAddress' => '198.51.100.7', 'permanent' => true]];
$unusable = new FileStore('/proc/nope/nope');
$c = new BlocklistCache($unusable, function () use (&$calls, &$rows) { $calls++; return $rows; }, 30, 15, $now);
check('with no usable state folder it never throws and allows traffic', $c->isBlocked('198.51.100.7') === false && $c->ageSeconds() === null);

// ---------------------------------------------------------------- circuit breaker
section('CircuitBreaker: stop waiting on a dead API');
$clock = 5000; $store = newStore(); $b = new CircuitBreaker($store, 'events', 3, 30, $now);
check('starts closed', $b->allow());
$b->failure(); $b->failure();
check('two failures do not open it', $b->allow());
$b->failure();
check('the third failure opens it', !$b->allow());
$clock += 29;
check('it stays open for the set time', !$b->allow());
$clock += 2;
check('then lets a request through again', $b->allow());
$b->failure();
check('one more failure after that does not reopen it at once (count restarted)', $b->allow());
$b->success();
$b->failure(); $b->failure();
check('a success resets the count', $b->allow());
$other = new CircuitBreaker($store, 'other', 1, 30, $now);
$other->failure();
check('breakers with different names are independent', !$other->allow() && $b->allow());

// ---------------------------------------------------------------- spool
section('EventSpool: events survive an outage');
$store = newStore(); $sp = new EventSpool($store, 524288);
foreach ([1, 2, 3, 4, 5] as $i) { $sp->append(['n' => $i]); }
check('counts queued events', $sp->count() === 5);
check('hands out the oldest first', same($sp->take(2), [['n' => 1], ['n' => 2]]) && $sp->count() === 3);
$sp->putBack([['n' => 9]]);
check('events put back go to the end', same($sp->take(10), [['n' => 3], ['n' => 4], ['n' => 5], ['n' => 9]]) && $sp->count() === 0);
check('taking from an empty queue is fine', same($sp->take(5), []));
file_put_contents($store->path('events.spool.jsonl'), "{\"n\":1}\nnot json\n{\"n\":2}\n");
check('a damaged line is skipped, the rest survive', same($sp->take(10), [['n' => 1], ['n' => 2]]));
$logs = [];
$small = new EventSpool(newStore(), 4096, function ($l, $m, $c) use (&$logs) { $logs[] = $m; });
for ($i = 0; $i < 200; $i++) { $small->append(['n' => $i, 'pad' => str_repeat('x', 60)]); }
$left = $small->take(1000);
check('the queue is bounded, and keeps the newest events', count($left) < 200 && $left[count($left) - 1]['n'] === 199 && in_array('security_spool_full', $logs, true));

// ---------------------------------------------------------------- reporter
section('SecurityReporter: sending events safely');
class FakeSender implements EventSender
{
    public $sent = [];
    public $script = [];     // list of results to return, in order; defaults to "sent"
    public $delay = 0.0;
    public function sendEvent(array $payload): array
    {
        if ($this->delay > 0) { usleep((int) ($this->delay * 1000000)); }
        $r = array_shift($this->script) ?? ['result' => 'sent', 'status' => 201];
        if ($r['result'] === 'sent') { $this->sent[] = $payload; }
        return $r;
    }
}
$mkRep = function (FakeSender $s, &$store = null, &$spool = null, &$breaker = null, float $budget = 5.0, int $replay = 20) use ($now) {
    $store = $store ?? newStore();
    $spool = new EventSpool($store);
    $breaker = new CircuitBreaker($store, 'events', 3, 30, $now);
    return new SecurityReporter($s, $spool, $breaker, $budget, $replay);
};
$ev = function (int $n): array { return ['event_type' => 'login_failed', 'severity' => 'MEDIUM', 'n' => $n]; };
$ok = ['result' => 'sent', 'status' => 201];
$fail = ['result' => 'failed', 'status' => 503];
$rej = ['result' => 'rejected', 'status' => 400];

$s = new FakeSender(); $r = $mkRep($s);
$r->report($ev(1)); $r->report($ev(2)); $r->flush();
check('sends every event, in order', array_column($s->sent, 'n') === [1, 2] && $r->backlog() === 0);
check('stamps events that have no timestamp', preg_match('/^\d{4}-\d\d-\d\dT/', $s->sent[0]['timestamp']) === 1);
$s2 = new FakeSender(); $r2 = $mkRep($s2);
$r2->report($ev(1) + ['timestamp' => '2026-01-01T00:00:00+00:00']); $r2->flush();
check('keeps a timestamp the caller set', $s2->sent[0]['timestamp'] === '2026-01-01T00:00:00+00:00');
$s3 = new FakeSender(); $r3 = $mkRep($s3);
$r3->report($ev(1)); $r3->report($ev(2)); $r3->report($ev(3) + ['event_id' => 'mine-1']); $r3->flush();
$ids = array_column($s3->sent, 'event_id');
check('gives every event its own id, so a repeat delivery is recognised by the server', preg_match('/^[0-9a-f]{24}$/', $ids[0]) === 1 && $ids[0] !== $ids[1] && $ids[2] === 'mine-1');
$st4 = $sp4 = $br4 = null; $s4 = new FakeSender(); $s4->script = [$fail]; $r4 = $mkRep($s4, $st4, $sp4, $br4);
$r4->report($ev(1)); $r4->flush();
$queuedId = $sp4->take(5)[0]['event_id'] ?? null;
$sp4->append(['event_type' => 'login_failed', 'severity' => 'LOW', 'event_id' => $queuedId]);
$s4b = new FakeSender(); $r4b = $mkRep($s4b, $st4, $sp4, $br4); $r4b->flush();
check('an event keeps the same id when it is queued and sent again later', $queuedId !== null && ($s4b->sent[0]['event_id'] ?? null) === $queuedId);

$st = $sp = $br = null; $s = new FakeSender(); $s->script = [$ok, $fail]; $r = $mkRep($s, $st, $sp, $br);
$r->report($ev(1)); $r->report($ev(2)); $r->report($ev(3)); $r->flush();
check('a failure queues that event and the rest, in order, losing nothing', array_column($s->sent, 'n') === [1] && $r->backlog() === 2 && array_column($sp->take(5), 'n') === [2, 3]);

$st = $sp = $br = null; $s = new FakeSender(); $s->script = [$fail, $fail, $fail]; $r = $mkRep($s, $st, $sp, $br);
for ($i = 0; $i < 3; $i++) { $r->report($ev($i)); $r->flush(); }
$before = count($s->script);
$s->script = []; 
$r->report($ev(10)); $r->flush();
check('after three failures the breaker opens: nothing is sent, the event is queued', $s->sent === [] && $r->backlog() === 4 && !$br->allow());

$s = new FakeSender(); $s->script = [$rej]; $r = $mkRep($s);
$r->report($ev(1)); $r->flush();
check('an event the server rejects (400) is dropped, not queued and not retried', $r->backlog() === 0 && $s->sent === []);
$st = $sp = $br = null; $s = new FakeSender(); $s->script = [['result' => 'rejected', 'status' => 401], ['result' => 'rejected', 'status' => 401], ['result' => 'rejected', 'status' => 401]]; $r = $mkRep($s, $st, $sp, $br);
for ($i = 0; $i < 3; $i++) { $r->report($ev($i)); $r->flush(); }
check('a rejected API key counts against the breaker, so a bad key stops the retries', !$br->allow() && $r->backlog() === 0);

// replay
$store = newStore(); $sp = new EventSpool($store); $br = null;
foreach ([101, 102, 103, 104, 105] as $n) { $sp->append($ev($n)); }
$s = new FakeSender(); $r = $mkRep($s, $store, $sp, $br, 5.0, 3);
$r->report($ev(1)); $r->flush();
check('once the API is back, new events go first and then the backlog, oldest first, up to the limit', array_column($s->sent, 'n') === [1, 101, 102, 103] && $sp->count() === 2);
$store = newStore(); $sp = new EventSpool($store); $br = null;
foreach ([101, 102, 103] as $n) { $sp->append($ev($n)); }
$s = new FakeSender(); $s->script = [$ok, $fail]; $r = $mkRep($s, $store, $sp, $br);
$r->flush();
check('a failure during replay puts the unsent events back in their original order', array_column($s->sent, 'n') === [101] && array_column($sp->take(10), 'n') === [102, 103]);

// replay without a new event
$st5 = $sp5 = $br5 = null; $s5 = new FakeSender(); $r5 = $mkRep($s5, $st5, $sp5, $br5);
check('nothing is scheduled on a page when there is no backlog', ($r5->replayIfNeeded() ?? true) && $r5->isScheduled() === false);
$sp5->append($ev(77));
$r5->replayIfNeeded();
check('a page that reports nothing still schedules delivery of a waiting backlog', $r5->isScheduled() === true);
$st6 = $sp6 = $br6 = null; $s6 = new FakeSender(); $r6 = $mkRep($s6, $st6, $sp6, $br6);
$sp6->append($ev(78)); $br6->failure(); $br6->failure(); $br6->failure();
$r6->replayIfNeeded();
check('but not while the breaker is open (the API is known to be down)', $r6->isScheduled() === false);
check('hasEvents is false for an empty queue and true for a queued event', (new EventSpool(newStore()))->hasEvents() === false && $sp5->hasEvents() === true);

// budget
$st = $sp = $br = null; $s = new FakeSender(); $s->delay = 0.12; $r = $mkRep($s, $st, $sp, $br, 0.2);
foreach ([1, 2, 3, 4, 5] as $n) { $r->report($ev($n)); }
$t = microtime(true); $r->flush(); $took = microtime(true) - $t;
check('the time budget is respected: what does not fit is queued', $took < 0.6 && count($s->sent) >= 1 && count($s->sent) < 5 && $r->backlog() === 5 - count($s->sent), sprintf('%.2fs sent=%d backlog=%d', $took, count($s->sent), $r->backlog()));

// ---------------------------------------------------------------- guard
section('SecurityGuard: the decision for one request');
$logs = []; $log = function ($l, $m, $c) use (&$logs) { $logs[] = [$l, $m]; };
$denied = 0; $deny = function () use (&$denied) { $denied++; };
$g = new SecurityGuard(function ($ip) { return $ip === '198.51.100.7'; }, SecurityGuard::MONITOR, $log, $deny);
check('monitor mode reports a blocked visitor but does not block', $g->check('198.51.100.7') === true && $denied === 0 && in_array(['warn', 'security_would_block'], $logs, true));
check('an unblocked visitor passes', $g->check('203.0.113.9') === false);
$g = new SecurityGuard(function ($ip) { return $ip === '198.51.100.7'; }, SecurityGuard::ENFORCE, $log, $deny);
check('enforce mode ends the request for a blocked visitor', $g->check('198.51.100.7') === true && $denied === 1);
check('enforce mode lets everyone else through', $g->check('203.0.113.9') === false && $denied === 1);
$g = new SecurityGuard(function () { return true; }, SecurityGuard::ENFORCE, $log, $deny);
check('private and loopback visitors are never blocked, even if the blocklist says so', $g->check('10.0.0.5') === false && $g->check('127.0.0.1') === false && $g->check(null) === false && $denied === 1);
$logs = [];
$g = new SecurityGuard(function () { throw new RuntimeException('cache exploded'); }, SecurityGuard::ENFORCE, $log, $deny);
check('a failure in the check never fails the page', $g->check('198.51.100.7') === false && $denied === 1 && $logs[0][1] === 'security_blocklist_check_failed');
check('an unknown mode means monitor, the safe default', (new SecurityGuard(function () { return true; }, 'anything', null, $deny))->mode() === 'monitor');

// ---------------------------------------------------------------- config
section('SecurityConfig: settings');
$c = SecurityConfig::fromEnv([]);
check('defaults are safe: monitor mode, enabled, no trusted proxies', $c->get('mode') === 'monitor' && $c->get('enabled') === true && $c->get('trusted') === [] && $c->get('ttl') === 30 && $c->get('breakerOpen') === 30);
check('the breaker pause is configurable and never below one second', SecurityConfig::fromEnv(['SECURITY_BREAKER_OPEN' => '5'])->get('breakerOpen') === 5 && SecurityConfig::fromEnv(['SECURITY_BREAKER_OPEN' => '0'])->get('breakerOpen') === 1);
check('missing base and key are reported', count($c->problems()) === 2);
$c = SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'https://sec.example.com/', 'SECURITY_API_KEY' => 'PMS_x', 'SECURITY_MODE' => 'ENFORCE', 'SECURITY_TRUSTED_PROXIES' => ' 10.0.0.1 , private ,, 173.245.48.0/20', 'SECURITY_BLOCKLIST_TTL' => '60', 'SECURITY_API_TIMEOUT' => '0.5']);
check('a full configuration is read and tidied', $c->problems() === [] && $c->get('base') === 'https://sec.example.com' && $c->get('mode') === 'enforce' && $c->get('trusted') === ['10.0.0.1', 'private', '173.245.48.0/20'] && $c->get('ttl') === 60 && $c->get('timeout') === 0.5);
check('any mode other than enforce is monitor', SecurityConfig::fromEnv(['SECURITY_MODE' => 'block-everything'])->get('mode') === 'monitor');
check('the kill switch accepts false and 0', SecurityConfig::fromEnv(['SECURITY_ENABLED' => 'false'])->get('enabled') === false && SecurityConfig::fromEnv(['SECURITY_ENABLED' => '0'])->get('enabled') === false && SecurityConfig::fromEnv(['SECURITY_ENABLED' => 'true'])->get('enabled') === true);
check('a base address without http(s) is a problem', in_array('SECURITY_API_BASE must start with http:// or https://', SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'sec.example.com', 'SECURITY_API_KEY' => 'k'])->problems(), true));
check('plain http to a remote host is warned about, localhost is not', count(SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'http://sec.example.com', 'SECURITY_API_KEY' => 'k'])->warnings()) === 1 && SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'http://127.0.0.1:4000', 'SECURITY_API_KEY' => 'k'])->warnings() === []);
check('an IP header without trusted proxies is warned about', count(SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'https://s', 'SECURITY_API_KEY' => 'k', 'SECURITY_CLIENT_IP_HEADER' => 'CF-Connecting-IP'])->warnings()) === 1);
$a = SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'https://a', 'SECURITY_API_KEY' => 'k1'])->get('stateDir');
check('the default state folder is stable, and differs per site', $a === SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'https://a', 'SECURITY_API_KEY' => 'k1'])->get('stateDir') && $a !== SecurityConfig::fromEnv(['SECURITY_API_BASE' => 'https://b', 'SECURITY_API_KEY' => 'k1'])->get('stateDir') && strpos($a, 'k1') === false);

// ---------------------------------------------------------------- PHP 7.4 compatibility
section('Compatibility: the library must run on PHP 7.4');
$forbidden = [
    '/\bmatch\s*\(/' => 'match expression (PHP 8.0)', '/\?->/' => 'nullsafe operator (8.0)',
    '/\bstr_contains\s*\(/' => 'str_contains (8.0)', '/\bstr_starts_with\s*\(/' => 'str_starts_with (8.0)', '/\bstr_ends_with\s*\(/' => 'str_ends_with (8.0)',
    '/\breadonly\b/' => 'readonly (8.1)', '/^\s*enum\s+\w+/m' => 'enum (8.1)', '/\)\s*:\s*(mixed|never|static)\b/' => 'return type mixed/never/static (8.0/8.1)',
    '/#\[/' => 'attribute (8.0)', '/function\s+\w+\s*\([^)]*\b\w+\|\w+\s+\$/' => 'union type (8.0)',
    '/__construct\s*\([^)]*\b(public|private|protected)\s+/' => 'constructor promotion (8.0)', '/,\s*\)\s*\{/' => 'trailing comma in parameter list (8.0)',
    '/\bnew\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*\(/' => 'skip',
];
unset($forbidden['/\bnew\s+\w+\s*\([^)]*\)\s*->\s*\w+\s*\(/']);
$files = array_merge(glob(__DIR__ . '/../src/*.php'), [__DIR__ . '/../autoload.php', __DIR__ . '/../bootstrap.php', __DIR__ . '/../bin/doctor.php']);
$issues = [];
foreach ($files as $file) {
    $code = (string) file_get_contents($file);
    $code = preg_replace('#/\*.*?\*/#s', '', $code);
    $code = preg_replace('#^\s*//.*$#m', '', $code);
    foreach ($forbidden as $re => $what) {
        if (preg_match($re, $code)) { $issues[] = basename($file) . ': ' . $what; }
    }
}
check(count($files) . ' files use no syntax newer than PHP 7.4', $issues === [], implode('; ', $issues));

echo "\n$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
