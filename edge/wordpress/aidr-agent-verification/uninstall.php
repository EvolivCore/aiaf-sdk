<?php
declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

require_once __DIR__ . '/src/Settings.php';
require_once __DIR__ . '/wp/Storage.php';

wp_clear_scheduled_hook('aidr_sync_event');
AIDR\WP\Schema::uninstall();
