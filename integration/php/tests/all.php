<?php
// Runs every PHP test file and fails if any of them fails.
$status = 0;
foreach (['run.php', 'unit.php', 'facade.php'] as $file) {
    echo "\n=== $file ===\n";
    passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $file), $code);
    $status = $status ?: $code;
}
exit($status);
