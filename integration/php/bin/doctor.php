<?php
declare(strict_types=1);

/**
 * Checks that the setup works. Run it on the web server, as the same user as PHP:
 *
 *     php bin/doctor.php
 *
 * Optionally pretend to be a visitor behind a proxy:
 *     REMOTE_ADDR=10.0.0.5 HTTP_X_FORWARDED_FOR=203.0.113.9 php bin/doctor.php
 */
require __DIR__ . '/../autoload.php';

use App\Security\ClientIp;
use App\Security\FileStore;
use App\Security\IpAddress;
use App\Security\SecurityClient;
use App\Security\SecurityConfig;

$ok = true;
$say = function (string $status, string $msg) use (&$ok): void {
    if ($status === 'FAIL') {
        $ok = false;
    }
    printf("  %-5s %s\n", $status, $msg);
};

echo "Pishon security integration check\n\n";
$config = SecurityConfig::fromEnv();

echo "Settings\n";
$say(version_compare(PHP_VERSION, '7.4.0', '>=') ? 'ok' : 'FAIL', 'PHP ' . PHP_VERSION . ' (needs 7.4 or newer)');
$say(extension_loaded('curl') ? 'ok' : 'FAIL', 'curl extension');
foreach ($config->problems() as $p) {
    $say('FAIL', $p);
}
foreach ($config->warnings() as $w) {
    $say('warn', $w);
}
$say($config->get('enabled') ? 'ok' : 'warn', 'SECURITY_ENABLED = ' . ($config->get('enabled') ? 'true' : 'false'));
$say('ok', 'mode = ' . $config->get('mode') . ($config->get('mode') === 'monitor' ? ' (nothing is blocked yet; set SECURITY_MODE=enforce when ready)' : ' (visitors on the blocklist get 403)'));

echo "\nState folder\n";
$store = new FileStore((string) $config->get('stateDir'), function ($l, $m, $c) use ($say) { $say('FAIL', $m . ' ' . json_encode($c)); });
if ($store->usable()) {
    $say('ok', $config->get('stateDir') . ' is private and writable');
}

echo "\nVisitor address detection\n";
$server = [
    'REMOTE_ADDR' => getenv('REMOTE_ADDR') ?: '203.0.113.50',
    'HTTP_X_FORWARDED_FOR' => getenv('HTTP_X_FORWARDED_FOR') ?: '',
];
$resolver = new ClientIp((array) $config->get('trusted'), (string) $config->get('ipHeader') ?: null);
$resolved = $resolver->resolve($server);
$say('ok', 'REMOTE_ADDR ' . $server['REMOTE_ADDR'] . ($server['HTTP_X_FORWARDED_FOR'] !== '' ? ', X-Forwarded-For ' . $server['HTTP_X_FORWARDED_FOR'] : '') . ' => visitor ' . ($resolved ?? 'unknown'));
if ($resolver->looksMisconfigured($server)) {
    $say('FAIL', 'Forwarded headers are present but the connection is not from a trusted proxy. Set SECURITY_TRUSTED_PROXIES, or every visitor will look like the proxy.');
}
if ($resolved !== null && IpAddress::isInternal($resolved) && $config->get('trusted') === []) {
    $say('warn', 'The visitor address is a private address. If the site is behind a proxy, set SECURITY_TRUSTED_PROXIES.');
}

echo "\nSecurity API\n";
if ($config->problems() === []) {
    $logs = [];
    $client = new SecurityClient((string) $config->get('base'), (string) $config->get('key'), (float) $config->get('timeout'), 0, function ($l, $m, $c) use (&$logs) { $logs[] = [$m, $c]; });
    $t = microtime(true);
    $list = $client->fetchBlocklist();
    $ms = (int) round((microtime(true) - $t) * 1000);
    if ($list === null) {
        $detail = $logs !== [] ? ' (' . $logs[0][0] . ' ' . json_encode($logs[0][1]) . ')' : '';
        $say('FAIL', 'could not read the blocklist' . $detail . '. Check SECURITY_API_BASE, the key, and that it has the block:read scope.');
    } else {
        $say('ok', 'read the blocklist in ' . $ms . ' ms, ' . count($list) . ' address(es) currently blocked');
    }
}

echo "\n" . ($ok ? "All good.\n" : "Problems found. Fix the FAIL lines above and run this again.\n");
exit($ok ? 0 : 1);
