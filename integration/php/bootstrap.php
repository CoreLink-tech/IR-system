<?php
declare(strict_types=1);

/**
 * One-file setup. Include this at the very top of your front controller (index.php),
 * or set it as auto_prepend_file in php.ini or .user.ini so it covers every page:
 *
 *     auto_prepend_file = /var/www/pishon/security/bootstrap.php
 *
 * It reads its settings from environment variables (see README.md) and does nothing,
 * quietly, if the library is disabled or not configured.
 */
require_once __DIR__ . '/autoload.php';

\App\Security\Security::boot();
