<?php
/**
 * WordPress-side storage: schema, the state table, the HTTP adapter and the decision log.
 */

declare(strict_types=1);

namespace AIDR\WP;

use AIDR\Decision;
use AIDR\Http;
use AIDR\Options;

final class Schema
{
    public const VERSION = '1';

    public static function table(string $name): string
    {
        global $wpdb;
        return $wpdb->prefix . 'aidr_' . $name;
    }

    public static function install(): void
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        dbDelta('CREATE TABLE ' . self::table('nonces') . " (
  nonce_key char(64) NOT NULL,
  expires bigint(20) unsigned NOT NULL,
  PRIMARY KEY  (nonce_key),
  KEY expires (expires)
) $charset;");
        dbDelta('CREATE TABLE ' . self::table('state') . " (
  name varchar(64) NOT NULL,
  value longtext NOT NULL,
  PRIMARY KEY  (name)
) $charset;");
        dbDelta('CREATE TABLE ' . self::table('log') . " (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  logged_at datetime NOT NULL,
  outcome varchar(16) NOT NULL,
  status smallint(5) unsigned NOT NULL,
  code varchar(64) NOT NULL DEFAULT '',
  aid varchar(191) NOT NULL DEFAULT '',
  organization varchar(191) NOT NULL DEFAULT '',
  agal tinyint(3) unsigned NOT NULL DEFAULT 0,
  method varchar(10) NOT NULL,
  path varchar(255) NOT NULL,
  PRIMARY KEY  (id),
  KEY logged_at (logged_at),
  KEY aid (aid)
) $charset;");
        update_option('aidr_schema_version', self::VERSION, false);
    }

    public static function uninstall(): void
    {
        global $wpdb;
        foreach (['nonces', 'state', 'log'] as $name) {
            $wpdb->query('DROP TABLE IF EXISTS ' . self::table($name));   // phpcs:ignore WordPress.DB
        }
        delete_option('aidr_schema_version');
        delete_option(\AIDR\Settings::OPTION);
    }
}

/**
 * Plugin state in its own table rather than wp_options: `add` is a real atomic INSERT IGNORE (which
 * add_option() is not — it upserts), values bypass the options cache, which can be stale across
 * servers, and none of it is autoloaded on every page. Values are JSON, never PHP-serialised.
 */
final class StateTable implements Options
{
    private string $table;

    public function __construct()
    {
        $this->table = Schema::table('state');
    }

    public function get(string $name): mixed
    {
        global $wpdb;
        $value = $wpdb->get_var($wpdb->prepare("SELECT value FROM {$this->table} WHERE name = %s", $name));
        return $value === null ? null : json_decode((string) $value, true);
    }

    public function set(string $name, mixed $value): void
    {
        global $wpdb;
        $wpdb->query($wpdb->prepare("INSERT INTO {$this->table} (name, value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE value = VALUES(value)",
            $name, wp_json_encode($value)));
    }

    public function add(string $name, mixed $value): bool
    {
        global $wpdb;
        return $wpdb->query($wpdb->prepare("INSERT IGNORE INTO {$this->table} (name, value) VALUES (%s, %s)",
            $name, wp_json_encode($value))) === 1;
    }

    public function delete(string $name): void
    {
        global $wpdb;
        $wpdb->query($wpdb->prepare("DELETE FROM {$this->table} WHERE name = %s", $name));
    }
}

final class WpHttp implements Http
{
    public function get(string $url): array
    {
        $args = [
            'timeout' => 5,
            'redirection' => 0,          // a redirect could lead trust material off the issuer's origin
            'sslverify' => true,
            'headers' => ['Accept' => 'application/json'],
            'user-agent' => 'aidr-wordpress/' . AIDR_PLUGIN_VERSION,
        ];
        // A private registry CA, set in wp-config.php (never from the admin UI).
        if (defined('AIDR_REGISTRY_CA_FILE') && is_readable(AIDR_REGISTRY_CA_FILE)) {
            $args['sslcertificates'] = AIDR_REGISTRY_CA_FILE;
        }
        $response = wp_remote_get($url, $args);
        if (is_wp_error($response)) {
            return ['status' => 0, 'body' => ''];
        }
        return ['status' => (int) wp_remote_retrieve_response_code($response), 'body' => (string) wp_remote_retrieve_body($response)];
    }
}

/**
 * One row per request that claimed to be an agent. Never the credential, the signature, the query
 * string or the client address: the log must not become a store of replayable requests or of
 * personal data.
 */
final class AuditLog
{
    public static function record(Decision $decision, string $method, string $path): void
    {
        global $wpdb;
        $wpdb->insert(Schema::table('log'), [
            'logged_at' => gmdate('Y-m-d H:i:s'),
            'outcome' => $decision->outcome,
            'status' => $decision->status,
            'code' => (string) $decision->code,
            'aid' => (string) $decision->identity->aid,
            'organization' => (string) $decision->identity->organization,
            'agal' => $decision->identity->agal,
            'method' => substr(strtoupper($method), 0, 10),
            'path' => substr($path, 0, 255),
        ], ['%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s', '%s']);
    }

    /** @return list<object> */
    public static function recent(int $limit, ?string $outcome): array
    {
        global $wpdb;
        $table = Schema::table('log');
        $rows = $outcome === null
            ? $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit))
            : $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table} WHERE outcome = %s ORDER BY id DESC LIMIT %d", $outcome, $limit));
        return is_array($rows) ? $rows : [];
    }

    public static function prune(int $retentionDays): void
    {
        global $wpdb;
        $wpdb->query($wpdb->prepare('DELETE FROM ' . Schema::table('log') . ' WHERE logged_at < %s',
            gmdate('Y-m-d H:i:s', time() - $retentionDays * DAY_IN_SECONDS)));
    }
}
