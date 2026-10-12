<?php
/**
 * Bypass rules: anchored regular expressions judged against a normalised path.
 *
 * Same contract as the Python middleware and the edge worker, pinned by
 * sdk/testdata/path-normalisation.json: decoded exactly once; anything still containing '%', a
 * backslash, a control character or invalid UTF-8 is ambiguous and never bypassed; repeated
 * slashes collapsed and dot segments resolved; each rule must match the WHOLE path.
 * Not bypassing is always the safe direction — the request is then simply verified.
 */

declare(strict_types=1);

namespace AIDR;

final class Path
{
    public static function normalise(string $raw): ?string
    {
        $decoded = rawurldecode($raw);           // not urldecode: '+' is not a space in a path
        if (str_contains($decoded, '%') || str_contains($decoded, '\\')) {
            return null;
        }
        if (preg_match('//u', $decoded) !== 1 || preg_match('/[\x00-\x1f\x7f]/', $decoded) === 1) {
            return null;
        }
        if (!str_starts_with($decoded, '/')) {
            $decoded = '/' . $decoded;
        }
        $trailing = strlen($decoded) > 1 && str_ends_with($decoded, '/');
        $stack = [];
        foreach (explode('/', $decoded) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($stack);
                continue;
            }
            $stack[] = $segment;
        }
        $resolved = '/' . implode('/', $stack);
        return $trailing && $resolved !== '/' ? $resolved . '/' : $resolved;
    }

    /** Compile rules to anchored PCRE; returns null for any rule that is not a valid pattern. */
    public static function compile(string $rule): ?string
    {
        if ($rule === '') {
            return null;
        }
        $pattern = '#^(?:' . str_replace('#', '\#', $rule) . ')$#';
        return @preg_match($pattern, '') === false ? null : $pattern;
    }

    /** @param list<string> $compiled */
    public static function isBypassed(array $compiled, string $rawPath): bool
    {
        if ($compiled === []) {
            return false;
        }
        $path = self::normalise($rawPath);
        if ($path === null) {
            return false;
        }
        foreach ($compiled as $pattern) {
            if (preg_match($pattern, $path) === 1) {
                return true;
            }
        }
        return false;
    }
}
