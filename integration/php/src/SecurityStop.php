<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Thrown by a replacement "deny" callback to end a request in tests. In production the
 * default deny sends "403 Access denied" and exits, so this is never seen.
 */
final class SecurityStop extends \RuntimeException
{
}
