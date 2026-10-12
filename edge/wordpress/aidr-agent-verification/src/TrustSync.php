<?php
/**
 * The registry's trust material: fetched in the background, verified, stored as one snapshot.
 *
 * A snapshot is the JWKS (refreshed hourly) plus a complete signed revocation feed (every 60 s).
 * It is only stored after it verifies, and requests re-verify it when they load it: the database is
 * ours, but a signed feed is the only kind that cannot be quietly stripped of a revocation.
 *
 * Where to fetch from comes from the registry's discovery document, and every endpoint it names
 * must be on the issuer's own origin: the JWKS is not itself signed, so its authenticity rests on
 * TLS to the issuer.
 *
 * Refreshes are serialised by an atomic lock (`add_option` fails if the row exists), so a burst of
 * requests after a quiet spell triggers one fetch, not hundreds.
 */

declare(strict_types=1);

namespace AIDR;

interface Http
{
    /** @return array{status: int, body: string} */
    public function get(string $url): array;
}

interface Options
{
    public function get(string $name): mixed;
    public function set(string $name, mixed $value): void;
    /** Atomic: false if the option already exists. */
    public function add(string $name, mixed $value): bool;
    public function delete(string $name): void;
}

final class TrustSync
{
    public const SNAPSHOT = 'aidr_trust_snapshot';
    public const STATUS = 'aidr_sync_status';
    public const LOCK = 'aidr_sync_lock';
    public const KEYS_REQUESTED = 'aidr_keys_requested_at';

    /** Reload after this; the request that notices schedules a background refresh. */
    public const REFRESH_AFTER = 60;
    /** A snapshot the registry has not refreshed for this long is too old to decide revocation. */
    public const MAX_AGE = 660;
    private const JWKS_REFRESH = 3600;
    private const LOCK_TTL = 60;
    private const KEY_REFRESH_MIN_INTERVAL = 60;

    public function __construct(
        private readonly string $issuer,
        private readonly Http $http,
        private readonly Options $options,
        private readonly \Closure $clock,
    ) {
    }

    /** @return array<string, mixed>|null */
    public function snapshot(): ?array
    {
        $snapshot = $this->options->get(self::SNAPSHOT);
        return is_array($snapshot) && ($snapshot['issuer'] ?? null) === $this->issuer ? $snapshot : null;
    }

    public function age(): ?float
    {
        $snapshot = $this->snapshot();
        return $snapshot === null ? null : ($this->clock)() - (float) $snapshot['fetched_at'];
    }

    public function needsRefresh(): bool
    {
        $age = $this->age();
        return $age === null || $age >= self::REFRESH_AFTER;
    }

    /** Build verified trust from the stored snapshot, or refuse (503) if there is none fit to use. */
    public function trust(): TrustStore
    {
        $snapshot = $this->snapshot();
        if ($snapshot === null) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, 'registry trust not yet loaded');
        }
        if ($this->age() >= self::MAX_AGE) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, 'revocation data is too old to rely on; refusing agent requests');
        }
        $trust = new TrustStore($snapshot['jwks'], $this->issuer);
        $trust->ingestSnapshot((string) $snapshot['delta'], ($this->clock)(), true);
        return $trust;
    }

    /**
     * Fetch, verify and store. Returns false if another process holds the lock.
     *
     * @throws AidrError on failure; the previous snapshot is left in place.
     */
    public function refresh(string $source, bool $forceKeys = false): bool
    {
        $now = ($this->clock)();
        if (!$this->options->add(self::LOCK, $now + self::LOCK_TTL)) {
            $held = (float) $this->options->get(self::LOCK);
            if ($held > $now) {
                return false;
            }
            // A crashed holder's lock; take it over.
            $this->options->delete(self::LOCK);
            if (!$this->options->add(self::LOCK, $now + self::LOCK_TTL)) {
                return false;
            }
        }
        $status = is_array($this->options->get(self::STATUS)) ? $this->options->get(self::STATUS) : [];
        $status['last_attempt'] = $now;
        $status['source'] = $source;
        try {
            $this->fetchAndStore($forceKeys);
            $status['last_success'] = $now;
            $status['last_error'] = null;
            return true;
        } catch (AidrError $error) {
            $status['last_error'] = $error->getMessage();
            throw $error;
        } finally {
            $this->options->set(self::STATUS, $status);
            $this->options->delete(self::LOCK);
        }
    }

    /** A credential named a key we do not have: perhaps a rotation. Rate-limited. */
    public function refreshKeysIfAllowed(string $source): void
    {
        $now = ($this->clock)();
        if ($now - (float) $this->options->get(self::KEYS_REQUESTED) < self::KEY_REFRESH_MIN_INTERVAL) {
            return;
        }
        $this->options->set(self::KEYS_REQUESTED, $now);
        $this->refresh($source, true);
    }

    private function fetchAndStore(bool $forceKeys): void
    {
        if (preg_match('#^https://#', $this->issuer) !== 1) {
            throw new AidrError(AidrError::MISCONFIGURED, 'the registry issuer must be an https:// URL');
        }
        $endpoints = $this->endpoints();
        $now = ($this->clock)();
        $previous = $this->snapshot();

        $jwks = $previous['jwks'] ?? null;
        $jwksAt = (float) ($previous['jwks_fetched_at'] ?? 0);
        if ($forceKeys || $jwks === null || $now - $jwksAt > self::JWKS_REFRESH) {
            $jwks = $this->getJson($endpoints['jwks'], 'jwks');
            $jwksAt = $now;
        }
        $separator = str_contains($endpoints['delta'], '?') ? '&' : '?';
        $delta = (string) ($this->getJson($endpoints['delta'] . $separator . 'since=0', 'revocation')['delta'] ?? '');

        try {
            $trust = new TrustStore($jwks, $this->issuer);
            $trust->ingestSnapshot($delta, $now);
        } catch (AidrError $error) {
            if ($forceKeys) {
                throw $error;
            }
            // Perhaps the registry rotated its key: once more, with fresh keys.
            $this->fetchAndStore(true);
            return;
        }
        $this->options->set(self::SNAPSHOT, [
            'issuer' => $this->issuer, 'jwks' => $jwks, 'jwks_fetched_at' => $jwksAt,
            'delta' => $delta, 'serial' => $trust->serial, 'fetched_at' => $now,
        ]);
    }

    /** @return array{jwks: string, delta: string} */
    private function endpoints(): array
    {
        $document = $this->getJson($this->issuer . '/.well-known/aiaf-registry', 'discovery');
        if (rtrim((string) ($document['issuer'] ?? ''), '/') !== $this->issuer) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, 'discovery document names a different issuer');
        }
        $found = ['jwks' => (string) ($document['jwks_uri'] ?? ''), 'delta' => (string) ($document['revocation_delta_endpoint'] ?? '')];
        foreach ($found as $url) {
            if (self::origin($url) !== self::origin($this->issuer)) {
                throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, "discovery points trust material off the issuer's origin; refusing it");
            }
        }
        return $found;
    }

    private static function origin(string $url): ?string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }
        return strtolower($parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : ''));
    }

    /** @return array<string, mixed> */
    private function getJson(string $url, string $what): array
    {
        $response = $this->http->get($url);
        if ($response['status'] !== 200) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, "$what: GET $url returned HTTP {$response['status']}");
        }
        try {
            return Encoding::jsonObject($response['body'], $what);
        } catch (AidrError $error) {
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, "$what: " . $error->getMessage());
        }
    }
}
