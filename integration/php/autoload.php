<?php
declare(strict_types=1);

/**
 * Minimal autoloader, so the library works by copying the folder into any PHP
 * project with no Composer needed:
 *
 *     require '/path/to/security/autoload.php';
 *
 * Requires PHP 7.4 or newer and the curl extension.
 */
spl_autoload_register(function (string $class): void {
    $prefix = 'App\\Security\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});
