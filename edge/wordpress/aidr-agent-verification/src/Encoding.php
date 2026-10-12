<?php
declare(strict_types=1);

namespace AIDR;

final class Encoding
{
    /** Decode unpadded base64url, rejecting anything outside the alphabet. */
    public static function b64urlDecode(mixed $text): string
    {
        // A lenient decoder silently drops injected characters and decodes something plausible.
        if (!is_string($text) || preg_match('/^[A-Za-z0-9_-]*$/', $text) !== 1) {
            throw new AidrError(AidrError::INVALID_KEY, 'invalid base64url encoding');
        }
        $standard = strtr($text, '-_', '+/');
        $padded = $standard . str_repeat('=', (4 - strlen($standard) % 4) % 4);
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new AidrError(AidrError::INVALID_KEY, 'invalid base64url encoding');
        }
        return $decoded;
    }

    public static function b64urlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode a JSON object. Refuses arrays, scalars and invalid UTF-8.
     *
     * @return array<string, mixed>
     */
    public static function jsonObject(string $json, string $what): array
    {
        if (!str_starts_with(ltrim($json), '{')) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "$what must be a JSON object");
        }
        try {
            $value = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "$what is not valid JSON: " . $error->getMessage());
        }
        if (!is_array($value)) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "$what must be a JSON object");
        }
        return $value;
    }
}
