<?php
/**
 * JWS credentials and RFC 9421 request signatures, in PHP.
 *
 * A port of the SDK verifiers (sdk/node/src/crypto.mjs is the closest relative); it must reach the
 * same verdicts on sdk/testdata/vectors.json. Ed25519 uses libsodium; ES256 uses OpenSSL, which
 * wants a DER signature, so the fixed-width R‖S form JOSE and RFC 9421 use is converted here.
 */

declare(strict_types=1);

namespace AIDR;

final class Crypto
{
    /** Components every AIDR signature must cover. Dropping any one re-enables a real attack. */
    public const REQUIRED_COMPONENTS = ['@method', '@authority', '@path'];

    private const ALGORITHMS = [
        'EdDSA' => ['kty' => 'OKP', 'crv' => 'Ed25519', 'http' => 'ed25519'],
        'ES256' => ['kty' => 'EC', 'crv' => 'P-256', 'http' => 'ecdsa-p256-sha256'],
    ];

    /** DER SubjectPublicKeyInfo prefix for an uncompressed P-256 point. */
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /** Resolve the algorithm from the key's own kty/crv — never from its attacker-supplied `alg`. */
    public static function algorithmForJwk(mixed $jwk): string
    {
        foreach (self::ALGORITHMS as $jose => $spec) {
            if (is_array($jwk) && ($jwk['kty'] ?? null) === $spec['kty'] && ($jwk['crv'] ?? null) === $spec['crv']) {
                return $jose;
            }
        }
        throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, 'unsupported key type');
    }

    /** @return array{0: string, 1: mixed} [jose algorithm, key] */
    public static function importPublicKey(mixed $jwk): array
    {
        if (!is_array($jwk)) {
            throw new AidrError(AidrError::INVALID_KEY, 'JWK must be an object');
        }
        if (array_key_exists('d', $jwk)) {
            throw new AidrError(AidrError::INVALID_KEY, 'a private key was supplied where a public key is required');
        }
        $jose = self::algorithmForJwk($jwk);
        if ($jose === 'EdDSA') {
            $x = Encoding::b64urlDecode($jwk['x'] ?? null);
            if (strlen($x) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new AidrError(AidrError::INVALID_KEY, 'Ed25519 public key must be 32 bytes');
            }
            return [$jose, $x];
        }
        // Fixed-width coordinates (RFC 7518 §6.2.1.2): otherwise one key has several encodings.
        $x = Encoding::b64urlDecode($jwk['x'] ?? null);
        $y = Encoding::b64urlDecode($jwk['y'] ?? null);
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new AidrError(AidrError::INVALID_KEY, 'P-256 coordinates must be exactly 32 bytes each');
        }
        $der = hex2bin(self::P256_SPKI_PREFIX) . "\x04" . $x . $y;
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        // OpenSSL refuses an off-curve point here: an invalid-curve attack or a corrupt key.
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new AidrError(AidrError::INVALID_KEY, 'could not import P-256 public key');
        }
        return [$jose, $key];
    }

    public static function verifySignature(string $jose, mixed $key, string $signature, string $data): void
    {
        if (strlen($signature) !== 64) {
            throw new AidrError(AidrError::SIGNATURE_INVALID, "$jose signature must be 64 bytes");
        }
        $ok = match ($jose) {
            'EdDSA' => sodium_crypto_sign_verify_detached($signature, $data, $key),
            'ES256' => openssl_verify($data, self::rawToDer($signature), $key, OPENSSL_ALGO_SHA256) === 1,
            default => throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, "unsupported algorithm $jose"),
        };
        if (!$ok) {
            throw new AidrError(AidrError::SIGNATURE_INVALID, 'signature verification failed');
        }
    }

    /** Fixed-width R‖S → DER SEQUENCE { INTEGER r, INTEGER s }, minimally encoded. */
    public static function rawToDer(string $signature): string
    {
        $int = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\x00");
            if ($bytes === '') {
                $bytes = "\x00";
            }
            if ((ord($bytes[0]) & 0x80) !== 0) {
                $bytes = "\x00" . $bytes;
            }
            return "\x02" . chr(strlen($bytes)) . $bytes;
        };
        $body = $int(substr($signature, 0, 32)) . $int(substr($signature, 32, 32));
        return "\x30" . chr(strlen($body)) . $body;
    }

    // ------------------------------------------------------------------------------------------
    // Compact JWS
    // ------------------------------------------------------------------------------------------

    /**
     * Verify a compact JWS and return [header, payload]. There is no parse-without-verify path.
     *
     * @param callable(string): ?array $resolveKey
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    public static function verifyCompact(string $token, callable $resolveKey, string $expectedTyp = 'aidr-cred+jwt'): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'compact JWS must have three parts');
        }
        [$headerB64, $payloadB64, $signatureB64] = $parts;
        $header = Encoding::jsonObject(Encoding::b64urlDecode($headerB64), 'JWS header');

        // Refused before any key lookup: alg=none, HS256 confusion, RS256 and everything else.
        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !isset(self::ALGORITHMS[$alg])) {
            throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, 'unsupported or unsafe JWS algorithm');
        }
        if (($header['typ'] ?? null) !== $expectedTyp) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "unexpected token type; expected $expectedTyp");
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "JWS header is missing 'kid'");
        }
        $jwk = $resolveKey($kid);
        if ($jwk === null) {
            throw new AidrError(AidrError::UNKNOWN_ISSUER, "no trusted key for kid $kid", ['kid' => $kid]);
        }
        [$jose, $key] = self::importPublicKey($jwk);
        if ($jose !== $alg) {
            throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, "header declares $alg but the trusted key is $jose");
        }
        self::verifySignature($jose, $key, Encoding::b64urlDecode($signatureB64), "$headerB64.$payloadB64");
        return [$header, Encoding::jsonObject(Encoding::b64urlDecode($payloadB64), 'JWS payload')];
    }

    // ------------------------------------------------------------------------------------------
    // RFC 9421 structured fields — the narrow subset AIDR emits and accepts
    // ------------------------------------------------------------------------------------------

    /** @return list<string> */
    private static function splitTopLevel(string $text, string $separator): array
    {
        $parts = [];
        $current = '';
        $inQuotes = false;
        $escaped = false;
        $depth = 0;
        foreach (str_split($text) as $char) {
            if ($escaped) {
                $current .= $char;
                $escaped = false;
                continue;
            }
            if ($char === '\\' && $inQuotes) {
                $current .= $char;
                $escaped = true;
                continue;
            }
            if ($char === '"') {
                $inQuotes = !$inQuotes;
                $current .= $char;
                continue;
            }
            if (!$inQuotes) {
                if ($char === '(') {
                    $depth++;
                } elseif ($char === ')') {
                    if (--$depth < 0) {
                        throw new AidrError(AidrError::MALFORMED_TOKEN, "unbalanced ')' in structured field");
                    }
                } elseif ($char === $separator && $depth === 0) {
                    $parts[] = trim($current);
                    $current = '';
                    continue;
                }
            }
            $current .= $char;
        }
        if ($inQuotes || $depth !== 0) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'unbalanced quotes or parentheses in structured field');
        }
        $parts[] = trim($current);
        return array_values(array_filter($parts, static fn (string $p): bool => $p !== ''));
    }

    private static function unquote(string $token): string
    {
        if (strlen($token) >= 2 && $token[0] === '"' && str_ends_with($token, '"')) {
            return str_replace(['\\"', '\\\\'], ['"', '\\'], substr($token, 1, -1));
        }
        return $token;
    }

    /** @return array<string, string|int|bool> */
    private static function parseParams(string $text): array
    {
        $params = [];
        foreach (self::splitTopLevel($text, ';') as $item) {
            $index = strpos($item, '=');
            if ($index === false) {
                $params[trim($item)] = true;
                continue;
            }
            $key = trim(substr($item, 0, $index));
            $raw = trim(substr($item, $index + 1));
            if (str_starts_with($raw, '"')) {
                $params[$key] = self::unquote($raw);
            } elseif (preg_match('/^-?\d+$/', $raw) === 1) {
                $params[$key] = (int) $raw;
            } else {
                $params[$key] = $raw;
            }
        }
        return $params;
    }

    /** @return array<string, array{components: list<string>, params: array<string, mixed>, raw: string}> */
    public static function parseSignatureInput(string $value): array
    {
        $entries = [];
        foreach (self::splitTopLevel($value, ',') as $member) {
            $index = strpos($member, '=');
            $label = $index === false ? '' : trim(substr($member, 0, $index));
            $inner = $index === false ? '' : trim(substr($member, $index + 1));
            if ($label === '' || !str_starts_with($inner, '(')) {
                throw new AidrError(AidrError::MALFORMED_TOKEN, 'malformed Signature-Input member');
            }
            $close = strpos($inner, ')');
            $list = trim(substr($inner, 1, $close - 1));
            $paramsText = ltrim(substr($inner, $close + 1), ';');
            $entries[$label] = [
                'components' => $list === '' ? [] : array_map([self::class, 'unquote'], self::splitTopLevel($list, ' ')),
                'params' => $paramsText === '' ? [] : self::parseParams($paramsText),
                // Verbatim: re-serialising risks a canonicalisation mismatch that looks like a forgery.
                'raw' => $inner,
            ];
        }
        if ($entries === []) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'Signature-Input header contains no signatures');
        }
        return $entries;
    }

    /** @return array<string, string> */
    public static function parseSignatureHeader(string $value): array
    {
        $signatures = [];
        foreach (self::splitTopLevel($value, ',') as $member) {
            $index = strpos($member, '=');
            $label = $index === false ? '' : trim(substr($member, 0, $index));
            $encoded = $index === false ? '' : trim(substr($member, $index + 1));
            if (strlen($encoded) < 2 || $encoded[0] !== ':' || !str_ends_with($encoded, ':')) {
                throw new AidrError(AidrError::MALFORMED_TOKEN, 'malformed Signature member');
            }
            $decoded = preg_match('#^[A-Za-z0-9+/]*={0,2}$#', substr($encoded, 1, -1)) === 1
                ? base64_decode(substr($encoded, 1, -1), true) : false;
            if ($decoded === false) {
                throw new AidrError(AidrError::MALFORMED_TOKEN, 'signature is not valid base64');
            }
            $signatures[$label] = $decoded;
        }
        if ($signatures === []) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'Signature header contains no signatures');
        }
        return $signatures;
    }

    /** @param array<string, string> $headers lower-cased names */
    private static function deriveComponent(string $name, string $method, string $url, array $headers): string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'request URL cannot be parsed');
        }
        $scheme = strtolower($parts['scheme']);
        switch ($name) {
            case '@method':
                return strtoupper($method);
            case '@target-uri':
                return $url;
            case '@authority':
                // Lowercase, default port omitted: https://HOST:443/ and https://host/ are one origin.
                $port = $parts['port'] ?? null;
                $default = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);
                return strtolower($parts['host']) . ($port !== null && !$default ? ":$port" : '');
            case '@scheme':
                return $scheme;
            case '@path':
                return ($parts['path'] ?? '') === '' ? '/' : $parts['path'];
            case '@query':
                return isset($parts['query']) && $parts['query'] !== '' ? '?' . $parts['query'] : '?';
        }
        if (str_starts_with($name, '@')) {
            throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, "derived component $name is not supported");
        }
        $value = $headers[strtolower($name)] ?? null;
        if ($value === null) {
            throw new AidrError(AidrError::COMPONENT_MISMATCH, "signature covers header $name, which is absent");
        }
        return implode(' ', preg_split('/\s+/', trim($value)) ?: []);
    }

    /**
     * Verify an RFC 9421 signature on a received request.
     *
     * Cheapest checks first — except `$claimNonce`, which runs LAST, after the signature has
     * verified: it records what it is asked about, so running it earlier would let a forged request
     * occupy a genuine request's nonce.
     *
     * @param array<string, string> $headers lower-cased names
     * @param callable(string): ?array $resolvePublicKey
     * @param null|callable(string, int): bool $claimNonce (nonce, created) → true on first use
     * @return array{keyid: string, created: int, nonce: ?string}
     */
    public static function verifyRequestSignature(
        string $method,
        string $url,
        array $headers,
        callable $resolvePublicKey,
        float $now,
        int $maxAgeSeconds = 300,
        ?callable $claimNonce = null,
        ?string $expectedKeyid = null,
    ): array {
        $rawInput = $headers['signature-input'] ?? '';
        $rawSignature = $headers['signature'] ?? '';
        if ($rawInput === '' || $rawSignature === '') {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'request is missing Signature-Input or Signature headers');
        }
        $entries = self::parseSignatureInput($rawInput);
        $signatures = self::parseSignatureHeader($rawSignature);
        $label = array_key_first($entries);
        $entry = $entries[$label];
        $signature = $signatures[$label] ?? null;
        if ($signature === null) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "no Signature member labelled $label");
        }

        $declared = null;
        if (isset($entry['params']['alg'])) {
            foreach (self::ALGORITHMS as $jose => $spec) {
                if ($spec['http'] === $entry['params']['alg']) {
                    $declared = $jose;
                }
            }
            if ($declared === null) {
                throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, 'unsupported signature algorithm');
            }
        }

        $keyid = $entry['params']['keyid'] ?? null;
        if (!is_string($keyid) || $keyid === '') {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "signature parameters are missing 'keyid'");
        }
        if ($expectedKeyid !== null && $keyid !== $expectedKeyid) {
            throw new AidrError(AidrError::COMPONENT_MISMATCH, 'signature keyid does not match the presented credential');
        }

        $created = $entry['params']['created'] ?? null;
        if (!is_int($created)) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "signature parameters are missing 'created'");
        }
        $age = $now - $created;
        if ($age > $maxAgeSeconds) {
            throw new AidrError(AidrError::SIGNATURE_TOO_OLD, 'signature is older than the ' . $maxAgeSeconds . 's limit');
        }
        if ($age < -$maxAgeSeconds) {
            throw new AidrError(AidrError::SIGNATURE_TOO_OLD, 'signature was created in the future beyond clock-skew tolerance');
        }
        $expires = $entry['params']['expires'] ?? null;
        if (is_int($expires) && $now > $expires) {
            throw new AidrError(AidrError::SIGNATURE_TOO_OLD, 'signature has passed its stated expiry');
        }

        $covered = array_map('strtolower', $entry['components']);
        $missing = array_values(array_diff(self::REQUIRED_COMPONENTS, $covered));
        if ($missing !== []) {
            throw new AidrError(AidrError::COMPONENT_MISMATCH, 'signature does not cover required components: ' . implode(', ', $missing));
        }

        $nonce = $entry['params']['nonce'] ?? null;
        if ($claimNonce !== null && (!is_string($nonce) || $nonce === '')) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'replay protection is enabled but the signature carries no nonce');
        }

        $jwk = $resolvePublicKey($keyid);
        if ($jwk === null) {
            throw new AidrError(AidrError::SIGNATURE_INVALID, "no public key available for keyid $keyid");
        }
        [$jose, $key] = self::importPublicKey($jwk);
        if ($declared !== null && $declared !== $jose) {
            throw new AidrError(AidrError::UNSUPPORTED_ALGORITHM, "signature declares {$entry['params']['alg']} but the key is $jose");
        }

        $lines = [];
        foreach ($entry['components'] as $component) {
            $lines[] = '"' . strtolower($component) . '": ' . self::deriveComponent($component, $method, $url, $headers);
        }
        $lines[] = '"@signature-params": ' . $entry['raw'];
        self::verifySignature($jose, $key, $signature, implode("\n", $lines));

        if ($claimNonce !== null && !$claimNonce($nonce, $created)) {
            throw new AidrError(AidrError::REPLAY_DETECTED, 'signature nonce has already been used');
        }
        return ['keyid' => $keyid, 'created' => $created, 'nonce' => is_string($nonce) ? $nonce : null];
    }
}
