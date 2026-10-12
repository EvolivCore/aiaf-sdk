<?php
/**
 * Replay protection: remember each (agent, nonce) for exactly as long as its signature could still
 * be accepted, shared by every PHP worker and every web server using the same database.
 */

declare(strict_types=1);

namespace AIDR;

interface NonceStore
{
    /** Record the key; true only on its first use within the TTL. Throws AidrError if it cannot answer. */
    public function claim(string $key, int $ttlSeconds): bool;
}

/** Tests, and nothing else: one PHP request is one process, so memory is not shared. */
final class MemoryNonceStore implements NonceStore
{
    /** @var array<string, float> */
    private array $expires = [];

    public function __construct(private readonly \Closure $clock)
    {
    }

    public function claim(string $key, int $ttlSeconds): bool
    {
        $now = ($this->clock)();
        if (($this->expires[$key] ?? 0) > $now) {
            return false;
        }
        $this->expires[$key] = $now + $ttlSeconds;
        return true;
    }
}

/**
 * The database store: `{prefix}aidr_nonces (nonce_key CHAR(64) PRIMARY KEY, expires BIGINT)`.
 *
 * A claim is two statements whose atomicity comes from the primary key, not from locking:
 *
 *   DELETE the row if — and only if — it has expired;
 *   INSERT IGNORE the row: exactly one concurrent inserter can create it.
 *
 * Two requests racing on one nonce can both run the DELETE, but only one INSERT affects a row, so
 * only one is told the nonce is fresh. A live row is never deleted, so it can never be re-used.
 */
final class WpdbNonceStore implements NonceStore
{
    public function __construct(private readonly object $wpdb, private readonly string $table)
    {
    }

    public function claim(string $key, int $ttlSeconds): bool
    {
        if (preg_match('/^[0-9a-f]{64}$/', $key) !== 1) {
            throw new AidrError(AidrError::MALFORMED_TOKEN, 'invalid nonce key');
        }
        $now = time();
        $db = $this->wpdb;
        $deleted = $db->query($db->prepare("DELETE FROM {$this->table} WHERE nonce_key = %s AND expires <= %d", $key, $now));
        $inserted = $db->query($db->prepare("INSERT IGNORE INTO {$this->table} (nonce_key, expires) VALUES (%s, %d)", $key, $now + $ttlSeconds));
        if ($deleted === false || $inserted === false || $db->last_error !== '') {
            // An unanswerable replay check is not a passed one.
            throw new AidrError(AidrError::REGISTRY_UNAVAILABLE, 'replay store unavailable');
        }
        return $inserted === 1;
    }

    public function sweep(): int
    {
        $db = $this->wpdb;
        return (int) $db->query($db->prepare("DELETE FROM {$this->table} WHERE expires <= %d", time()));
    }
}
