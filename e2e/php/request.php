<?php
// One simulated page view on the shop, used by the end-to-end suite.
// Settings come from the environment, exactly as in production.
//   E2E_ACTION  optional, e.g. "loginFailed:user-1" or "loginSuccess:user-1"
require __DIR__ . '/../../integration/php/bootstrap.php';

$action = getenv('E2E_ACTION') ?: '';
if ($action !== '') {
    [$method, $user] = array_pad(explode(':', $action, 2), 2, null);
    if (method_exists(\App\Security\Security::class, $method)) {
        // The password is passed deliberately, to prove it never leaves the website.
        \App\Security\Security::$method($user ?: null, ['password' => 'hunter2-e2e', 'shipping_address' => '12 Marina Rd']);
    }
}
echo 'PAGE_OK ip=' . (\App\Security\Security::clientIp() ?? 'unknown') . "\n";
