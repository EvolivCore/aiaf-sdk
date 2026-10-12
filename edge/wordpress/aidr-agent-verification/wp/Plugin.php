<?php
/**
 * The request path, background sync, cron and the public helpers.
 */

declare(strict_types=1);

namespace AIDR\WP;

use AIDR\AidrError;
use AIDR\Decision;
use AIDR\Gate;
use AIDR\Identity;
use AIDR\Settings;
use AIDR\TrustStore;
use AIDR\TrustSync;
use AIDR\WpdbNonceStore;

final class Plugin
{
    public const CRON_HOOK = 'aidr_sync_event';
    public const CRON_SCHEDULE = 'aidr_every_minute';
    public const VARY = 'Agent-Credential, Signature, Signature-Input';

    private static ?Decision $decision = null;
    private static bool $refreshScheduled = false;

    public static function boot(): void
    {
        add_filter('cron_schedules', [self::class, 'cronSchedules']);
        add_action(self::CRON_HOOK, [self::class, 'runSync']);
        add_action('rest_api_init', [self::class, 'registerRoutes']);
        // As early as a plugin can run: before themes, before other plugins' init handlers, so a
        // refused request never reaches them.
        add_action('plugins_loaded', [self::class, 'handleRequest'], -1000);
        if (is_admin()) {
            Admin::boot();
        }
        if (defined('WP_CLI') && WP_CLI) {
            \WP_CLI::add_command('aidr', Cli::class);
        }
    }

    public static function activate(): void
    {
        Schema::install();
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time(), self::CRON_SCHEDULE, self::CRON_HOOK);
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook(self::CRON_HOOK);
    }

    /** @param array<string, array<string, mixed>> $schedules */
    public static function cronSchedules(array $schedules): array
    {
        $schedules[self::CRON_SCHEDULE] = ['interval' => 60, 'display' => 'Every minute (AIDR revocation sync)'];
        return $schedules;
    }

    /** @return array<string, mixed> */
    public static function settings(): array
    {
        $stored = get_option(Settings::OPTION, []);
        return Settings::normalise(is_array($stored) ? $stored : []);
    }

    public static function sync(?array $settings = null): TrustSync
    {
        $settings ??= self::settings();
        return new TrustSync($settings['issuer'], new WpHttp(), new StateTable(), static fn (): float => microtime(true));
    }

    /** The decision for the current request; anonymous before one is made or outside HTTP. */
    public static function identity(): Identity
    {
        return self::$decision?->identity ?? new Identity('anonymous');
    }

    public static function decision(): ?Decision
    {
        return self::$decision;
    }

    // ------------------------------------------------------------------------------------------

    public static function handleRequest(): void
    {
        if ((defined('WP_CLI') && WP_CLI) || wp_doing_cron() || (defined('WP_INSTALLING') && WP_INSTALLING)) {
            return;
        }
        $settings = self::settings();

        // Every response varies on the agent headers, so an HTTP cache (CDN, Varnish) never answers
        // an agent's request with a copy made for someone else — the request always reaches here.
        header('Vary: ' . self::VARY, false);

        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $requestUri = (string) wp_unslash($_SERVER['REQUEST_URI'] ?? '/');
        $rawPath = (string) (parse_url($requestUri, PHP_URL_PATH) ?? '/');
        $sync = self::sync($settings);

        $gate = new Gate(
            $settings,
            static function () use ($sync): TrustStore {
                $age = $sync->age();
                if ($age === null || $age >= TrustSync::MAX_AGE) {
                    // Nothing usable stored (a fresh install, or no cron for a long while): the
                    // only way this agent can be served is to fetch now. Bounded by WpHttp's timeout.
                    try {
                        $sync->refresh('request');
                    } catch (AidrError) {
                        // trust() below refuses with 503.
                    }
                }
                if ($sync->needsRefresh()) {
                    self::scheduleBackgroundRefresh();
                }
                return $sync->trust();
            },
            new WpdbNonceStore($GLOBALS['wpdb'], Schema::table('nonces')),
            static fn (): float => microtime(true),
        );
        $decision = $gate->decide($method, self::effectiveUrl($settings, $requestUri), $rawPath, self::requestHeaders());
        self::$decision = $decision;

        if ($decision->isAgentResponse()) {
            self::forbidCaching();
            AuditLog::record($decision, $method, $rawPath);
        }
        if ($decision->code === AidrError::UNKNOWN_ISSUER && isset($decision->context['kid'])) {
            // Perhaps the registry rotated its key. Refresh after the response, rate-limited.
            register_shutdown_function(static function () use ($sync): void {
                self::finishResponse();
                try {
                    $sync->refreshKeysIfAllowed('unknown-kid');
                } catch (AidrError) {
                }
            });
        }
        do_action('aidr_request_decided', $decision);

        if ($decision->outcome === 'refused') {
            self::refuse($decision);
        }
    }

    /**
     * The URI a signature is judged against: the configured public origin, else this site's own
     * address (Settings → General). Never the Host header the client sent: a request signed for
     * another site, replayed here with that site's Host, would otherwise verify (found 2026-10-10).
     */
    private static function effectiveUrl(array $settings, string $requestUri): string
    {
        $origin = $settings['public_origin'] !== '' ? $settings['public_origin'] : self::siteOrigin();
        return $origin . (str_starts_with($requestUri, '/') ? $requestUri : '/' . $requestUri);
    }

    /** scheme://host[:port] of home_url(): WordPress's own address for the current site. */
    private static function siteOrigin(): string
    {
        $home = wp_parse_url(home_url('/'));
        $origin = strtolower(($home['scheme'] ?? 'https') . '://' . ($home['host'] ?? ''));
        return isset($home['port']) ? $origin . ':' . (int) $home['port'] : $origin;
    }

    /**
     * Request headers, lower-cased. $_SERVER values are unslashed: WordPress adds slashes to them,
     * which would corrupt the quoted parameters of Signature-Input.
     *
     * @return array<string, string>
     */
    private static function requestHeaders(): array
    {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (is_string($value) && str_starts_with((string) $key, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr((string) $key, 5)))] = (string) wp_unslash($value);
            }
        }
        foreach (['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $key => $name) {
            if (isset($_SERVER[$key]) && is_string($_SERVER[$key])) {
                $headers[$name] = (string) wp_unslash($_SERVER[$key]);
            }
        }
        return $headers;
    }

    /** A response that depends on who the agent is must never be stored by any cache. */
    private static function forbidCaching(): void
    {
        if (!defined('DONOTCACHEPAGE')) {
            define('DONOTCACHEPAGE', true);   // WP Super Cache, W3 Total Cache, WP Rocket, others
        }
        do_action('litespeed_control_set_nocache', 'aidr: agent request');
        header('Cache-Control: private, no-store, max-age=0');
        add_action('send_headers', 'nocache_headers');
        add_filter('rest_post_dispatch', static function ($response) {
            if ($response instanceof \WP_REST_Response) {
                $response->header('Cache-Control', 'private, no-store, max-age=0');
            }
            return $response;
        });
    }

    private static function refuse(Decision $decision): never
    {
        status_header($decision->status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: private, no-store, max-age=0');
        if ($decision->status === 503) {
            header('Retry-After: 30');
        }
        echo wp_json_encode(['error' => $decision->code, 'reason' => $decision->reason]);
        exit;
    }

    // ------------------------------------------------------------------------------------------
    // Background sync. Preferred: a real cron running `wp aidr sync` every minute. Without it, a
    // request that finds the snapshot due refreshes it AFTER its response has been sent
    // (fastcgi_finish_request), or, where the server cannot detach, asks WP-Cron to (a non-blocking
    // loopback). Either way the refresh holds the lock, so a burst of requests causes one fetch.
    // ------------------------------------------------------------------------------------------

    private static function scheduleBackgroundRefresh(): void
    {
        if (self::$refreshScheduled) {
            return;
        }
        self::$refreshScheduled = true;
        if (function_exists('fastcgi_finish_request') || function_exists('litespeed_finish_request')) {
            register_shutdown_function(static function (): void {
                self::finishResponse();
                self::runSync('after-response');
            });
            return;
        }
        if (!wp_next_scheduled(self::CRON_HOOK, ['wp-cron-spawn'])) {
            wp_schedule_single_event(time(), self::CRON_HOOK, ['wp-cron-spawn']);
        }
    }

    private static function finishResponse(): void
    {
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } elseif (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
        }
    }

    /** Refresh trust, sweep expired nonces, prune the log. Safe to run from anywhere, any time. */
    public static function runSync(string $source = 'wp-cron'): ?string
    {
        $settings = self::settings();
        $error = null;
        if ($settings['issuer'] !== '') {
            try {
                self::sync($settings)->refresh($source);
            } catch (AidrError $e) {
                $error = $e->getMessage();
            }
        }
        (new WpdbNonceStore($GLOBALS['wpdb'], Schema::table('nonces')))->sweep();
        AuditLog::prune($settings['log_retention_days']);
        return $error;
    }

    // ------------------------------------------------------------------------------------------

    public static function registerRoutes(): void
    {
        if (!apply_filters('aidr_enable_whoami', true)) {
            return;
        }
        // Tells the caller what this site verified about it — only ever its own identity.
        register_rest_route('aidr/v1', '/whoami', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => static function (): \WP_REST_Response {
                $identity = self::identity();
                $body = ['status' => $identity->status];
                if ($identity->isAgent()) {
                    $body += ['aid' => $identity->aid, 'organization' => $identity->organization,
                        'org_domains' => $identity->orgDomains, 'agal' => $identity->agal, 'oal' => $identity->oal,
                        'kal' => $identity->kal, 'capabilities' => $identity->capabilities,
                        'declared' => $identity->declared];
                }
                $response = new \WP_REST_Response($body);
                $response->header('Cache-Control', 'private, no-store, max-age=0');
                return $response;
            },
        ]);
    }
}
