<?php
declare(strict_types=1);

namespace AIDR\WP;

use AIDR\TrustSync;

/**
 * Keep AIDR trust material current and inspect it.
 *
 * Run `wp aidr sync` from the system crontab every minute: unlike WP-Cron it does not depend on
 * visitors, and it keeps revocations no more than a minute old.
 */
final class Cli
{
    /**
     * Refresh the registry's keys and revocations, sweep expired nonces, prune the log.
     *
     * [--quiet]
     * : Print nothing on success.
     */
    public function sync(array $args, array $assoc): void
    {
        $error = Plugin::runSync('cli');
        if ($error !== null) {
            \WP_CLI::error("sync failed: $error");
        }
        if (empty($assoc['quiet'])) {
            $this->status([], []);
        }
    }

    /** Show the stored snapshot's age and the last sync result. */
    public function status(array $args, array $assoc): void
    {
        $sync = Plugin::sync();
        $snapshot = $sync->snapshot();
        $status = (new StateTable())->get(TrustSync::STATUS) ?: [];
        \WP_CLI::line(wp_json_encode([
            'issuer' => Plugin::settings()['issuer'],
            'snapshot_age_seconds' => $sync->age() === null ? null : (int) $sync->age(),
            'serial' => $snapshot['serial'] ?? null,
            'keys' => count($snapshot['jwks']['keys'] ?? []),
            'last_success' => $status['last_success'] ?? null,
            'last_source' => $status['source'] ?? null,
            'last_error' => $status['last_error'] ?? null,
        ], JSON_PRETTY_PRINT));
    }
}
