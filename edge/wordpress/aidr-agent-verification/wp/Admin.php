<?php
/**
 * Settings → AIDR Agents: policy, sync status, and the decision log with manual blocking.
 */

declare(strict_types=1);

namespace AIDR\WP;

use AIDR\Settings;
use AIDR\TrustSync;

final class Admin
{
    private const SLUG = 'aidr-agents';
    private const OUTCOMES = ['verified', 'refused'];
    private const LEVELS = [
        0 => '0 — no floor',
        1 => '1 — identified (domain proven)',
        2 => '2 — verified publisher',
        3 => '3 — accountable enterprise',
    ];

    public static function boot(): void
    {
        add_action('admin_menu', static function (): void {
            add_options_page('AIDR agent verification', 'AIDR Agents', 'manage_options', self::SLUG, [self::class, 'render']);
        });
        add_action('admin_init', static function (): void {
            register_setting('aidr', Settings::OPTION, ['type' => 'array', 'sanitize_callback' => [self::class, 'sanitize']]);
        });
        add_action('admin_post_aidr_sync_now', [self::class, 'syncNow']);
        add_action('admin_post_aidr_block_agent', [self::class, 'blockAgent']);
    }

    public static function sanitize(mixed $raw): array
    {
        $errors = [];
        $settings = Settings::normalise(is_array($raw) ? $raw : [], $errors);
        foreach ($errors as $error) {
            add_settings_error(Settings::OPTION, 'aidr', $error);
        }
        return $settings;
    }

    public static function syncNow(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('Not allowed.', 403);
        }
        check_admin_referer('aidr_sync_now');
        $error = Plugin::runSync('admin');
        self::back($error === null ? 'synced' : 'sync_failed');
    }

    /** Manual blacklisting from the log: adds the identifier to the site's blocklist. */
    public static function blockAgent(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('Not allowed.', 403);
        }
        check_admin_referer('aidr_block_agent');
        $aid = sanitize_text_field(wp_unslash($_POST['aid'] ?? ''));
        $settings = Plugin::settings();
        $settings['blocked_aids'][] = $aid;
        // normalise() drops anything that is not a well-formed identifier.
        update_option(Settings::OPTION, Settings::normalise($settings));
        self::back('blocked');
    }

    private static function back(string $notice): never
    {
        wp_safe_redirect(add_query_arg(['page' => self::SLUG, 'aidr_notice' => $notice], admin_url('options-general.php')));
        exit;
    }

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $settings = Plugin::settings();
        $sync = Plugin::sync($settings);
        $state = new StateTable();
        $status = $state->get(TrustSync::STATUS) ?: [];
        $snapshot = $sync->snapshot();
        $age = $sync->age();
        $notice = sanitize_key($_GET['aidr_notice'] ?? '');
        $filter = sanitize_key($_GET['outcome'] ?? '');
        $filter = in_array($filter, self::OUTCOMES, true) ? $filter : null;
        $list = static fn (array $items): string => esc_textarea(implode("\n", $items));
        ?>
        <div class="wrap">
            <h1>AIDR agent verification</h1>
            <?php settings_errors(Settings::OPTION); ?>
            <?php if ($notice === 'synced'): ?><div class="notice notice-success"><p>Trust material synced.</p></div><?php endif; ?>
            <?php if ($notice === 'sync_failed'): ?><div class="notice notice-error"><p>Sync failed: <?php echo esc_html((string) ($status['last_error'] ?? 'unknown error')); ?></p></div><?php endif; ?>
            <?php if ($notice === 'blocked'): ?><div class="notice notice-success"><p>Agent added to the blocklist.</p></div><?php endif; ?>

            <?php if (defined('WP_CACHE') && WP_CACHE && file_exists(WP_CONTENT_DIR . '/advanced-cache.php')): ?>
                <div class="notice notice-warning"><p><strong>A page cache is active.</strong> It can answer requests
                    before any plugin runs, so a cached page could be served to an agent without verification (it
                    will never serve an agent's own response to others: those are marked uncacheable). Exclude
                    requests carrying an <code>Agent-Credential</code> or <code>Signature</code> header from the page
                    cache, or place the cache behind something that honours <code>Vary</code>.</p></div>
            <?php endif; ?>

            <h2>Registry sync</h2>
            <table class="widefat striped" style="max-width:720px"><tbody>
                <tr><th>Issuer</th><td><?php echo $settings['issuer'] !== '' ? esc_html($settings['issuer']) : '<em>not configured — agent requests are refused (503)</em>'; ?></td></tr>
                <tr><th>Snapshot age</th><td><?php echo $age === null ? '<em>none yet</em>' : esc_html(sprintf('%d s%s', (int) $age, $age >= TrustSync::MAX_AGE ? ' — too old; agent requests are refused (503)' : '')); ?></td></tr>
                <tr><th>Revocation serial / keys</th><td><?php echo $snapshot === null ? '—' : esc_html(sprintf('%d / %d', (int) $snapshot['serial'], count($snapshot['jwks']['keys'] ?? []))); ?></td></tr>
                <tr><th>Last sync</th><td><?php echo esc_html(isset($status['last_success']) ? gmdate('Y-m-d H:i:s', (int) $status['last_success']) . ' UTC via ' . ($status['source'] ?? '?') : 'never'); ?></td></tr>
                <tr><th>Last error</th><td><?php echo esc_html((string) ($status['last_error'] ?? 'none')); ?></td></tr>
            </tbody></table>
            <p>For a sync every minute that does not depend on visitors, run from the system crontab:
                <code>* * * * * wp --path=<?php echo esc_html(ABSPATH); ?> aidr sync --quiet</code></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="aidr_sync_now">
                <?php wp_nonce_field('aidr_sync_now'); ?>
                <?php submit_button('Sync now', 'secondary', 'submit', false); ?>
            </form>

            <h2>Policy</h2>
            <form method="post" action="options.php">
                <?php settings_fields('aidr'); ?>
                <table class="form-table" role="presentation">
                    <tr><th><label for="aidr-issuer">Registry issuer</label></th>
                        <td><input id="aidr-issuer" class="regular-text" name="<?php echo esc_attr(Settings::OPTION); ?>[issuer]" value="<?php echo esc_attr($settings['issuer']); ?>" placeholder="https://registry.example">
                        <p class="description">Exactly as in credentials' <code>iss</code>. https only.</p></td></tr>
                    <tr><th><label for="aidr-origin">Public origin</label></th>
                        <td><input id="aidr-origin" class="regular-text" name="<?php echo esc_attr(Settings::OPTION); ?>[public_origin]" value="<?php echo esc_attr($settings['public_origin']); ?>" placeholder="https://www.example.com">
                        <p class="description">Signatures are checked against this site's own address (Settings → General). Set this only if agents reach the site under a different address, for example through a CDN.</p></td></tr>
                    <?php foreach (['min_agal' => ['AgAL floor', 'Composite assurance, the weaker of OAL and KAL. The level most sites should set.'],
                                    'min_oal' => ['OAL floor', 'Operator assurance: how well the organisation behind the agent is verified.'],
                                    'min_kal' => ['KAL floor', 'Key assurance: how well the agent’s key is protected (2+ means hardware-backed).']] as $key => [$label, $help]): ?>
                    <tr><th><label for="aidr-<?php echo esc_attr($key); ?>"><?php echo esc_html($label); ?></label></th>
                        <td><select id="aidr-<?php echo esc_attr($key); ?>" name="<?php echo esc_attr(Settings::OPTION . "[$key]"); ?>">
                            <?php foreach (self::LEVELS as $level => $name): ?>
                                <option value="<?php echo (int) $level; ?>" <?php selected($settings[$key], $level); ?>><?php echo esc_html($name); ?></option>
                            <?php endforeach; ?>
                        </select><p class="description"><?php echo esc_html($help); ?> Below the floor: 403 <code>aidr.verify.assurance_too_low</code>.</p></td></tr>
                    <?php endforeach; ?>
                    <tr><th><label for="aidr-caps">Required capabilities</label></th>
                        <td><textarea id="aidr-caps" rows="2" class="large-text code" name="<?php echo esc_attr(Settings::OPTION); ?>[required_capabilities]"><?php echo $list($settings['required_capabilities']); ?></textarea></td></tr>
                    <tr><th><label for="aidr-bypass">Bypass rules</label></th>
                        <td><textarea id="aidr-bypass" rows="3" class="large-text code" name="<?php echo esc_attr(Settings::OPTION); ?>[bypass]"><?php echo $list($settings['bypass']); ?></textarea>
                        <p class="description">One regular expression per line, matched against the <em>whole</em> decoded path, e.g. <code>/health</code> or <code>/wp-content/uploads/.*</code>. Requests there are not verified at all.</p></td></tr>
                    <tr><th><label for="aidr-aids">Blocked agents</label></th>
                        <td><textarea id="aidr-aids" rows="3" class="large-text code" name="<?php echo esc_attr(Settings::OPTION); ?>[blocked_aids]"><?php echo $list($settings['blocked_aids']); ?></textarea></td></tr>
                    <tr><th><label for="aidr-domains">Blocked organisations (by proven domain)</label></th>
                        <td><textarea id="aidr-domains" rows="2" class="large-text code" name="<?php echo esc_attr(Settings::OPTION); ?>[blocked_domains]"><?php echo $list($settings['blocked_domains']); ?></textarea>
                        <p class="description">Blocking only an agent identifier is evaded by registering another agent; a domain the organisation proved is not.</p></td></tr>
                    <tr><th><label for="aidr-retention">Log retention (days)</label></th>
                        <td><input id="aidr-retention" type="number" min="1" max="365" name="<?php echo esc_attr(Settings::OPTION); ?>[log_retention_days]" value="<?php echo (int) $settings['log_retention_days']; ?>"></td></tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <h2>Recent agent requests</h2>
            <p><a href="<?php echo esc_url(add_query_arg(['page' => self::SLUG], admin_url('options-general.php'))); ?>">All</a>
                <?php foreach (self::OUTCOMES as $outcome): ?> | <a href="<?php echo esc_url(add_query_arg(['page' => self::SLUG, 'outcome' => $outcome], admin_url('options-general.php'))); ?>"><?php echo esc_html(ucfirst($outcome)); ?></a><?php endforeach; ?></p>
            <table class="widefat striped">
                <thead><tr><th>Time (UTC)</th><th>Outcome</th><th>Status</th><th>Reason</th><th>Agent</th><th>Organisation</th><th>AgAL</th><th>Request</th><th></th></tr></thead>
                <tbody>
                <?php foreach (AuditLog::recent(100, $filter) as $row): ?>
                    <tr>
                        <td><?php echo esc_html($row->logged_at); ?></td>
                        <td><?php echo esc_html($row->outcome); ?></td>
                        <td><?php echo (int) $row->status; ?></td>
                        <td><code><?php echo esc_html($row->code); ?></code></td>
                        <td><code><?php echo esc_html($row->aid); ?></code></td>
                        <td><?php echo esc_html($row->organization); ?></td>
                        <td><?php echo (int) $row->agal; ?></td>
                        <td><?php echo esc_html($row->method . ' ' . $row->path); ?></td>
                        <td><?php if ($row->aid !== '' && !in_array($row->aid, $settings['blocked_aids'], true)): ?>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="aidr_block_agent">
                                <input type="hidden" name="aid" value="<?php echo esc_attr($row->aid); ?>">
                                <?php wp_nonce_field('aidr_block_agent'); ?>
                                <button class="button button-small">Block</button>
                            </form>
                        <?php endif; ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}
