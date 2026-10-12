<?php
/**
 * Plugin Name:       AIDR Agent Verification
 * Description:       Verifies AI agents by their AIDR credentials: anonymous visitors pass, invalid agents are refused (401/403), and verified agents are available to your site with their assurance levels.
 * Version:           0.1.3
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * License:           Apache-2.0
 * License URI:       https://www.apache.org/licenses/LICENSE-2.0
 * Text Domain:       aidr-agent-verification
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

const AIDR_PLUGIN_VERSION = '0.1.3';

foreach (['Errors', 'Encoding', 'Crypto', 'Verifier', 'Path', 'NonceStore', 'TrustSync', 'Settings', 'Gate'] as $aidr_file) {
    require_once __DIR__ . "/src/$aidr_file.php";
}
foreach (['Storage', 'Plugin', 'Admin', 'Cli'] as $aidr_file) {
    require_once __DIR__ . "/wp/$aidr_file.php";
}
unset($aidr_file);

if (!extension_loaded('sodium') || !extension_loaded('openssl')) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p>AIDR Agent Verification needs the PHP sodium and openssl extensions. Agent requests are refused until they are available.</p></div>';
    });
}

register_activation_hook(__FILE__, [AIDR\WP\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [AIDR\WP\Plugin::class, 'deactivate']);
AIDR\WP\Plugin::boot();

/** The verified agent behind the current request, or an anonymous identity. */
function aidr_agent(): AIDR\Identity
{
    return AIDR\WP\Plugin::identity();
}

/**
 * For a REST route's permission_callback: require a verified agent, optionally with floors.
 *
 *     'permission_callback' => fn () => aidr_require_agent(['min_agal' => 2]),
 *
 * @param array{min_agal?: int, min_oal?: int, min_kal?: int, capabilities?: list<string>} $requirements
 */
function aidr_require_agent(array $requirements = []): bool|WP_Error
{
    $agent = aidr_agent();
    if (!$agent->isAgent()) {
        return new WP_Error('aidr.verify.agent_required', 'This endpoint serves verified agents only.', ['status' => 401]);
    }
    foreach (['min_agal' => $agent->agal, 'min_oal' => $agent->oal, 'min_kal' => $agent->kal] as $key => $have) {
        if ($have < (int) ($requirements[$key] ?? 0)) {
            return new WP_Error('aidr.verify.assurance_too_low', "Agent assurance is below this endpoint's $key.", ['status' => 403]);
        }
    }
    if (array_diff($requirements['capabilities'] ?? [], $agent->capabilities) !== []) {
        return new WP_Error('aidr.verify.capability_denied', 'Agent lacks a required capability.', ['status' => 403]);
    }
    return true;
}
