<?php
declare(strict_types=1);

namespace App\Security;

/**
 * A small private folder for the library's shared state (blocklist cache, circuit
 * breaker, event spool). Plain files work on any hosting and are shared by every
 * PHP worker on the server, with no Redis or APCu needed.
 *
 * The folder is created private (mode 0700). If it already exists and is owned by
 * someone else, or other users can write to it, it is NOT used: another local user
 * could otherwise plant a forged blocklist. In that case the library carries on
 * without shared state, never failing the request.
 *
 * Files are replaced atomically (write to a temporary file, then rename), so a
 * reader never sees a half-written file.
 */
final class FileStore
{
    /** @var string */
    private $dir;
    /** @var bool|null */
    private $usable = null;
    /** @var callable|null */
    private $logger;

    public function __construct(string $dir, ?callable $logger = null)
    {
        $this->dir = rtrim($dir, '/\\');
        $this->logger = $logger;
    }

    public function path(string $name): string
    {
        return $this->dir . '/' . $name;
    }

    public function usable(): bool
    {
        if ($this->usable !== null) {
            return $this->usable;
        }
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return $this->unusable('cannot create ' . $this->dir);
        }
        if (is_link($this->dir)) {
            return $this->unusable($this->dir . ' is a symbolic link');
        }
        if (function_exists('posix_geteuid')) {
            $owner = @fileowner($this->dir);
            if ($owner !== false && $owner !== posix_geteuid()) {
                return $this->unusable($this->dir . ' is owned by another user');
            }
        }
        $perms = @fileperms($this->dir);
        if ($perms !== false && ($perms & 0022) !== 0) {
            @chmod($this->dir, 0700);
            clearstatcache(true, $this->dir);
            $perms = @fileperms($this->dir);
            if ($perms !== false && ($perms & 0022) !== 0) {
                return $this->unusable($this->dir . ' is writable by other users');
            }
        }
        if (!is_writable($this->dir)) {
            return $this->unusable($this->dir . ' is not writable');
        }
        return $this->usable = true;
    }

    /** @return array<mixed>|null */
    public function readJson(string $name): ?array
    {
        if (!$this->usable()) {
            return null;
        }
        $raw = @file_get_contents($this->path($name));
        if ($raw === false || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    public function writeJson(string $name, array $data): bool
    {
        if (!$this->usable()) {
            return false;
        }
        $tmp = $this->path($name . '.' . bin2hex(random_bytes(6)) . '.tmp');
        if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES)) === false) {
            @unlink($tmp);
            return false;
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $this->path($name))) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    /**
     * Tries to take an exclusive lock without waiting. Returns a handle to pass to
     * release(), or null if someone else holds it. Used so that only one request at
     * a time refreshes the blocklist while the others carry on with the old copy.
     *
     * @return resource|null
     */
    public function tryLock(string $name)
    {
        if (!$this->usable()) {
            return null;
        }
        $h = @fopen($this->path($name), 'c');
        if ($h === false) {
            return null;
        }
        @chmod($this->path($name), 0600);
        if (!flock($h, LOCK_EX | LOCK_NB)) {
            fclose($h);
            return null;
        }
        return $h;
    }

    /** @param resource|null $handle */
    public function release($handle): void
    {
        if (is_resource($handle)) {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Runs $fn while holding an exclusive lock on a file, waiting briefly if needed.
     * Returns null if the lock could not be taken in time.
     *
     * @return mixed
     */
    public function withLock(string $name, callable $fn, float $waitSeconds = 0.5)
    {
        if (!$this->usable()) {
            return null;
        }
        $h = @fopen($this->path($name), 'c+');
        if ($h === false) {
            return null;
        }
        @chmod($this->path($name), 0600);
        $deadline = microtime(true) + $waitSeconds;
        while (!flock($h, LOCK_EX | LOCK_NB)) {
            if (microtime(true) >= $deadline) {
                fclose($h);
                return null;
            }
            usleep(5000);
        }
        try {
            return $fn($h);
        } finally {
            flock($h, LOCK_UN);
            fclose($h);
        }
    }

    private function unusable(string $why): bool
    {
        $this->usable = false;
        if ($this->logger !== null) {
            ($this->logger)('error', 'security_state_dir_unusable', ['reason' => $why]);
        }
        return false;
    }
}
