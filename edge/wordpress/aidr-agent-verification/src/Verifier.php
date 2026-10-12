<?php
/**
 * Trust material and agent verification.
 *
 * Like the edge worker, the plugin holds only an EXACT revocation set — a verified snapshot from
 * serial 0 — and has no soft-fail option: what it cannot answer definitively it refuses (503).
 */

declare(strict_types=1);

namespace AIDR;

final class TrustStore
{
    private const DELTA_TYP = 'aidr-crl+jwt';

    /** @var array<string, array<string, mixed>> */
    private array $keys = [];
    /** @var array<string, true> */
    public array $revoked = [];
    public int $serial = 0;
    public bool $exact = false;
    /** When the registry signed the revocation data held (its `iat`, Unix seconds), or null. */
    public ?float $issuedAt = null;

    /** @param array<string, mixed> $jwks */
    public function __construct(array $jwks, public readonly string $issuer)
    {
        foreach (is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [] as $jwk) {
            if (!is_array($jwk) || !is_string($jwk['kid'] ?? null)) {
                continue;
            }
            if (array_key_exists('d', $jwk)) {
                throw new AidrError(AidrError::MALFORMED_TOKEN, 'JWKS contains private key material — refusing it');
            }
            $this->keys[$jwk['kid']] = $jwk;
        }
        if ($this->keys === []) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'JWKS document contains no usable keys');
        }
    }

    /** @return array<string, mixed>|null */
    public function resolveKey(string $kid): ?array
    {
        return $this->keys[$kid] ?? null;
    }

    /**
     * Ingest a complete revocation snapshot: a signed delta from serial 0.
     *
     * `$stored` rebuilds from a snapshot the plugin already verified when it fetched it: signature
     * and issuer are checked again, not the delta's short `exp`. How old the data may be is
     * Verifier::MAX_REVOCATION_AGE_SECONDS, judged from the signed `iat`.
     */
    public function ingestSnapshot(string $deltaToken, float $now, bool $stored = false): int
    {
        [, $payload] = Crypto::verifyCompact($deltaToken, fn (string $kid): ?array => $this->resolveKey($kid), self::DELTA_TYP);
        if (($payload['iss'] ?? null) !== $this->issuer) {
            throw new AidrError(AidrError::UNKNOWN_ISSUER, 'revocation feed issued by another issuer');
        }
        if (!$stored) {
            Verifier::checkTime($payload, $now, false);
        }
        if ((int) ($payload['since'] ?? 0) !== 0 || ($payload['complete'] ?? true) === false) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, 'revocation snapshot is not complete (since != 0)');
        }
        foreach (is_array($payload['revocations'] ?? null) ? $payload['revocations'] : [] as $entry) {
            if (is_array($entry) && is_string($entry['subject_id'] ?? null)) {
                $this->revoked[$entry['subject_id']] = true;
            }
        }
        $this->serial = (int) ($payload['serial'] ?? 0);
        $this->issuedAt = is_numeric($payload['iat'] ?? null) ? (float) $payload['iat'] : null;
        $this->exact = true;
        return $this->serial;
    }
}

/** A verified agent, as the site sees it. */
final class Identity
{
    /**
     * @param 'anonymous'|'verified'|'bypassed' $status
     * @param list<string> $orgDomains
     * @param list<string> $capabilities
     * @param array<string, mixed> $declared self-asserted by the operator; NOT checked by the registry
     */
    public function __construct(
        public readonly string $status,
        public readonly ?string $aid = null,
        public readonly ?string $organization = null,
        public readonly array $orgDomains = [],
        public readonly int $agal = 0,
        public readonly int $oal = 0,
        public readonly int $kal = 0,
        public readonly array $capabilities = [],
        public readonly array $declared = [],
        public readonly int $abuseReportsUpheld = 0,
    ) {
    }

    public function isAgent(): bool
    {
        return $this->status === 'verified';
    }
}

final class Verifier
{
    private const LEEWAY_SECONDS = 60;

    /**
     * The oldest revocation data agents may be verified against: one 60 s refresh plus 600 s of
     * grace (11 minutes). The same limit in every AIDR verifier; sdk/testdata/vectors.json pins it.
     */
    public const MAX_REVOCATION_AGE_SECONDS = 660;

    /** @param array<string, mixed> $claims */
    public static function checkTime(array $claims, float $now, bool $requireExp): void
    {
        if (!array_key_exists('exp', $claims)) {
            if ($requireExp) {
                throw new AidrError(AidrError::MALFORMED_TOKEN, "credential has no 'exp' claim — non-expiring credentials are refused");
            }
        } elseif ($now > (float) $claims['exp'] + self::LEEWAY_SECONDS) {
            throw new AidrError(AidrError::CREDENTIAL_EXPIRED, 'credential has expired');
        }
        if (array_key_exists('nbf', $claims) && $now < (float) $claims['nbf'] - self::LEEWAY_SECONDS) {
            throw new AidrError(AidrError::CREDENTIAL_NOT_YET_VALID, 'credential is not yet valid');
        }
    }

    /**
     * Verify one request. Throws AidrError on any failure.
     *
     * Policy: expected_issuer, expected_audience, min_agal, min_oal, min_kal, required_capabilities,
     * max_upheld_abuse_reports, blocked_aids, blocked_domains, max_revocation_age_seconds (default
     * 660; null disables it).
     *
     * `$claimNonce(aid, nonce, created)` is consulted only after the signature has verified AND the
     * site's policy has passed, so a refused request never occupies a nonce.
     *
     * @param array<string, mixed> $policy
     * @param array<string, string> $headers lower-cased names
     * @param null|callable(string, string, int): bool $claimNonce
     */
    public static function verifyAgent(TrustStore $trust, array $policy, string $method, string $url,
                                       array $headers, float $now, ?callable $claimNonce): Identity
    {
        // 1. credential present
        $raw = trim($headers['agent-credential'] ?? '');
        if ($raw === '') {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'request carries no Agent-Credential header');
        }
        if (stripos($raw, 'bearer ') === 0) {
            $raw = trim(substr($raw, 7));
        }

        // 2. the registry's signature over it
        [, $claims] = Crypto::verifyCompact($raw, static fn (string $kid): ?array => $trust->resolveKey($kid));

        // 3. validity window
        self::checkTime($claims, $now, true);

        // 4. issuer and audience
        if (($claims['iss'] ?? null) !== ($policy['expected_issuer'] ?? null)) {
            throw new AidrError(AidrError::UNKNOWN_ISSUER, 'credential issued by an unexpected issuer');
        }
        if (isset($claims['aud'])) {
            $allowed = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];
            // Not configured: the site being visited (the request signature covers @authority).
            $expected = $policy['expected_audience'] ?? self::origin($url);
            if ($expected === null || !in_array($expected, $allowed, true)) {
                throw new AidrError(AidrError::POLICY_VIOLATION, 'credential is bound to another audience');
            }
        }
        $aid = $claims['sub'] ?? null;
        if (!is_string($aid) || $aid === '') {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'credential has no subject');
        }

        // 5. revocation — exact state or nothing
        if (!$trust->exact) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, 'revocation state not loaded; refusing rather than guessing');
        }
        $limit = array_key_exists('max_revocation_age_seconds', $policy)
            ? $policy['max_revocation_age_seconds'] : self::MAX_REVOCATION_AGE_SECONDS;
        if ($limit !== null && $trust->issuedAt !== null && $now - $trust->issuedAt > (float) $limit) {
            $age = (int) floor($now - $trust->issuedAt);
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE,
                "revocation data is $age s old (limit $limit s): agents are refused until it is refreshed");
        }
        if (isset($trust->revoked[$aid])) {
            throw new AidrError(AidrError::AGENT_REVOKED, 'agent identity has been revoked', ['aid' => $aid]);
        }

        // 6. the sender holds the credential's key, for THIS request
        $agentJwk = $claims['cnf']['jwk'] ?? null;
        if (!is_array($agentJwk)) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, "credential carries no key confirmation ('cnf.jwk')");
        }
        Crypto::importPublicKey($agentJwk);
        $identity = self::identityFrom($claims, $aid);

        Crypto::verifyRequestSignature(
            $method, $url, $headers,
            static fn (): array => $agentJwk,
            $now,
            300,
            $claimNonce === null ? null : static function (string $nonce, int $created) use ($policy, $identity, $aid, $claimNonce): bool {
                self::applyPolicy($policy, $identity);
                return $claimNonce($aid, $nonce, $created);
            },
            $aid,
        );

        // 7. the site's policy (already applied before the claim when there is one)
        self::applyPolicy($policy, $identity);
        return $identity;
    }

    /** @param array<string, mixed> $claims */
    private static function identityFrom(array $claims, string $aid): Identity
    {
        $strings = static fn (mixed $value): array => is_array($value)
            ? array_values(array_filter($value, 'is_string')) : [];
        return new Identity(
            status: 'verified',
            aid: $aid,
            organization: is_string($claims['org'] ?? null) ? $claims['org'] : '',
            orgDomains: $strings($claims['org_domains'] ?? null),
            // AgAL never falls back to the legacy `assurance` claim, which is OAL only.
            agal: (int) ($claims['agal'] ?? 0),
            oal: (int) ($claims['oal'] ?? $claims['assurance'] ?? 0),
            kal: (int) ($claims['kal'] ?? 0),
            capabilities: $strings($claims['capabilities'] ?? null),
            declared: is_array($claims['declared'] ?? null) ? $claims['declared'] : [],
            abuseReportsUpheld: (int) ($claims['standing']['abuse_reports_upheld'] ?? 0),
        );
    }

    /** @param array<string, mixed> $policy */
    private static function applyPolicy(array $policy, Identity $identity): void
    {
        foreach ([['AgAL', $identity->agal, 'min_agal'], ['OAL', $identity->oal, 'min_oal'], ['KAL', $identity->kal, 'min_kal']] as [$axis, $have, $key]) {
            $need = (int) ($policy[$key] ?? 0);
            if ($have < $need) {
                throw new AidrError(AidrError::ASSURANCE_TOO_LOW, "agent $axis $have is below this site's required $need",
                    ['axis' => $axis, 'have' => $have, 'required' => $need]);
            }
        }
        $missing = array_values(array_diff($policy['required_capabilities'] ?? [], $identity->capabilities));
        if ($missing !== []) {
            throw new AidrError(AidrError::CAPABILITY_DENIED, 'agent lacks required capabilities: ' . implode(', ', $missing));
        }
        $limit = $policy['max_upheld_abuse_reports'] ?? null;
        if ($limit !== null && $identity->abuseReportsUpheld > (int) $limit) {
            throw new AidrError(AidrError::POLICY_VIOLATION, "agent has more upheld abuse reports than this site's limit");
        }
        // The site's own blocklist: by identifier, or by proven domain — blocking only the
        // identifier is evaded by registering another agent.
        if (in_array($identity->aid, $policy['blocked_aids'] ?? [], true)) {
            throw new AidrError(AidrError::BLOCKED_BY_SITE, 'this agent is blocked by the site');
        }
        if (array_intersect($identity->orgDomains, $policy['blocked_domains'] ?? []) !== []) {
            throw new AidrError(AidrError::BLOCKED_BY_SITE, "this agent's organisation is blocked by the site");
        }
    }

    /** scheme://host[:port], host lower-cased, the default port dropped; null if not a URL. */
    public static function origin(string $url): ?string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }
        $scheme = strtolower($parts['scheme']);
        $origin = $scheme . '://' . rtrim(strtolower($parts['host']), '.');
        $port = $parts['port'] ?? null;
        if ($port !== null && !(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))) {
            $origin .= ':' . $port;
        }
        return $origin;
    }
}
