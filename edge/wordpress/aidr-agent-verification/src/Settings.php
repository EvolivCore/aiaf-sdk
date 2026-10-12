<?php
/**
 * Plugin settings: defaults and validation. Used by the admin form's sanitize callback and by every
 * request, so a setting that would weaken verification can never be stored in the first place.
 */

declare(strict_types=1);

namespace AIDR;

final class Settings
{
    public const OPTION = 'aidr_settings';

    public const DEFAULTS = [
        'issuer' => '',
        'public_origin' => '',
        'min_agal' => 0,
        'min_oal' => 0,
        'min_kal' => 0,
        'required_capabilities' => [],
        'bypass' => [],
        'blocked_aids' => [],
        'blocked_domains' => [],
        'max_upheld_abuse_reports' => null,
        'log_retention_days' => 30,
    ];

    /**
     * Normalise raw input (form fields or stored option). Lists may arrive as newline- or
     * comma-separated strings. Invalid values are dropped and reported in `$errors`.
     *
     * @param array<string, mixed> $raw
     * @param list<string> $errors
     * @return array<string, mixed>
     */
    public static function normalise(array $raw, array &$errors = []): array
    {
        $out = self::DEFAULTS;

        $issuer = rtrim(trim((string) ($raw['issuer'] ?? '')), '/');
        if ($issuer !== '' && preg_match('~^https://[^/\s?#]+$~', $issuer) !== 1) {
            $errors[] = 'The registry issuer must be an https:// origin, e.g. https://registry.example.';
            $issuer = '';
        }
        $out['issuer'] = $issuer;

        $origin = rtrim(trim((string) ($raw['public_origin'] ?? '')), '/');
        if ($origin !== '' && preg_match('~^https?://[^/\s?#]+$~', $origin) !== 1) {
            $errors[] = 'The public origin must look like https://www.example.com (no path).';
            $origin = '';
        }
        $out['public_origin'] = $origin;

        foreach (['min_agal', 'min_oal', 'min_kal'] as $floor) {
            $value = (int) ($raw[$floor] ?? 0);
            $out[$floor] = max(0, min(3, $value));
        }

        $out['required_capabilities'] = self::lines($raw['required_capabilities'] ?? [], '/^[a-z0-9._-]+$/i');
        $out['blocked_aids'] = self::lines($raw['blocked_aids'] ?? [], '/^aid:v1:[a-z0-9-]+:[0-9A-Z]{26}:[a-z0-9]{4}$/');
        $out['blocked_domains'] = array_map('strtolower', self::lines($raw['blocked_domains'] ?? [], '/^[a-z0-9.-]+\.[a-z0-9-]+$/i'));

        $bypass = [];
        foreach (self::lines($raw['bypass'] ?? []) as $rule) {
            if (Path::compile($rule) === null) {
                $errors[] = "Bypass rule is not a valid regular expression and was dropped: $rule";
                continue;
            }
            $bypass[] = $rule;
        }
        $out['bypass'] = $bypass;

        $limit = $raw['max_upheld_abuse_reports'] ?? null;
        $out['max_upheld_abuse_reports'] = ($limit === null || $limit === '') ? null : max(0, (int) $limit);
        $out['log_retention_days'] = max(1, min(365, (int) ($raw['log_retention_days'] ?? 30)));
        return $out;
    }

    /** @return list<string> */
    private static function lines(mixed $value, ?string $pattern = null): array
    {
        $items = is_array($value) ? $value : preg_split('/[\r\n,]+/', (string) $value);
        $clean = [];
        foreach ($items ?: [] as $item) {
            $item = trim((string) $item);
            if ($item !== '' && ($pattern === null || preg_match($pattern, $item) === 1)) {
                $clean[] = $item;
            }
        }
        return array_values(array_unique($clean));
    }
}
