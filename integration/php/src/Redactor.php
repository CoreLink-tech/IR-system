<?php
declare(strict_types=1);

namespace App\Security;

/**
 * Removes secrets from event details BEFORE they leave the website. The Security API
 * redacts as well, but a password should never travel over the network or sit in an
 * outbound queue in the first place.
 */
final class Redactor
{
    private const MAX_STRING = 1000;
    private const MAX_DEPTH = 4;
    private const MAX_ITEMS = 50;

    /** Substrings that mark a field as secret anywhere in its name. */
    private const SUBSTRINGS = ['password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'authorization', 'cookie',
        'creditcard', 'cardnumber', 'privatekey', 'bearer', 'credential'];
    /** Short words that must match as a whole word, so "shipping" is not caught by "pin". */
    private const WORDS = ['pin', 'cvv', 'cvc', 'otp', 'ssn', 'auth', 'key'];

    public static function isSensitiveKey(string $key): bool
    {
        $compact = strtolower((string) preg_replace('/[^A-Za-z0-9]/', '', $key));
        foreach (self::SUBSTRINGS as $w) {
            if (strpos($compact, $w) !== false) {
                return true;
            }
        }
        $spaced = preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $key);
        foreach (preg_split('/[^A-Za-z0-9]+/', strtolower((string) $spaced), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $word) {
            if (in_array($word, self::WORDS, true)) {
                return true;
            }
        }
        return false;
    }

    /** @return mixed */
    public static function clean($value, int $depth = 0)
    {
        if ($depth > self::MAX_DEPTH) {
            return '[truncated]';
        }
        if (is_string($value)) {
            return strlen($value) > self::MAX_STRING ? substr($value, 0, self::MAX_STRING) . '...' : $value;
        }
        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }
        if (is_array($value)) {
            $out = [];
            $n = 0;
            foreach ($value as $k => $v) {
                if (++$n > self::MAX_ITEMS) {
                    break;
                }
                $out[$k] = (is_string($k) && self::isSensitiveKey($k)) ? '[REDACTED]' : self::clean($v, $depth + 1);
            }
            return $out;
        }
        return '[unsupported]';
    }
}
