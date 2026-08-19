<?php

declare(strict_types=1);

namespace Honeypot\WP;

/**
 * Activation/deactivation side effects (design §5): the custom tables (dbDelta), the per-install
 * sensor id, and the degrade-safe mu-loader shim. Integration-level (needs $wpdb / WP); the pure
 * decisions it drives (SensorId, MuLoaderInstaller) are unit-tested. 7.3-clean.
 */
final class Installer
{
    public static function activate($pluginFile)
    {
        self::createTables();
        self::ensureSensorId();
        self::installShim($pluginFile);
    }

    public static function deactivate($pluginFile)
    {
        if (function_exists('wp_upload_dir')) {
            // best-effort shim removal; the mu-plugins dir is the WP standard location
        }
        $muDir = self::muPluginsDir();
        MuLoaderInstaller::uninstall($muDir);
    }

    private static function createTables()
    {
        global $wpdb;
        if ($wpdb === null || !function_exists('dbDelta')) {
            if (defined('ABSPATH') && file_exists(ABSPATH . 'wp-admin/includes/upgrade.php')) {
                require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            } else {
                return;
            }
        }
        $charset = method_exists($wpdb, 'get_charset_collate') ? $wpdb->get_charset_collate() : '';
        $p = $wpdb->prefix;

        $sql = array();
        $sql[] = "CREATE TABLE {$p}honeypot_wp_hits (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ts BIGINT UNSIGNED NOT NULL,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            method VARCHAR(10) NOT NULL DEFAULT '',
            path VARCHAR(255) NOT NULL DEFAULT '',
            action VARCHAR(16) NOT NULL DEFAULT '',
            reason VARCHAR(32) NOT NULL DEFAULT '',
            status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            KEY ts (ts)
        ) {$charset};";

        $sql[] = "CREATE TABLE {$p}honeypot_wp_report_queue (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            categories VARCHAR(64) NOT NULL DEFAULT '',
            comment VARCHAR(1024) NOT NULL DEFAULT '',
            created_at VARCHAR(32) NOT NULL DEFAULT '',
            attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            signals TEXT NULL,
            PRIMARY KEY (id),
            KEY created_at (created_at)
        ) {$charset};";

        $sql[] = "CREATE TABLE {$p}honeypot_wp_report_sidecar (
            dedup_key VARCHAR(191) NOT NULL,
            reported_at VARCHAR(32) NOT NULL DEFAULT '',
            sent INT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY (dedup_key)
        ) {$charset};";

        foreach ($sql as $stmt) {
            dbDelta($stmt);
        }
    }

    private static function ensureSensorId()
    {
        if (!function_exists('get_option')) {
            return;
        }
        SensorId::resolve(
            static function () {
                return get_option(SensorId::OPTION, '');
            },
            static function ($id) {
                update_option(SensorId::OPTION, $id, true);
            },
            static function () {
                return function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : SensorId::randomUuidV4();
            }
        );
    }

    private static function installShim($pluginFile)
    {
        $muDir = self::muPluginsDir();
        $bootstrap = dirname((string) $pluginFile) . '/mu-entry.php';
        $ok = MuLoaderInstaller::install($muDir, $bootstrap);
        if (!$ok && function_exists('update_option')) {
            // Signal the plugins_loaded fallback so the admin notice can flag the degraded mount.
            update_option('honeypot_wp_mu_shim_failed', 1, false);
        } elseif (function_exists('delete_option')) {
            delete_option('honeypot_wp_mu_shim_failed');
        }
    }

    private static function muPluginsDir()
    {
        if (defined('WPMU_PLUGIN_DIR')) {
            return (string) constant('WPMU_PLUGIN_DIR');
        }
        if (defined('WP_CONTENT_DIR')) {
            return constant('WP_CONTENT_DIR') . '/mu-plugins';
        }

        return sys_get_temp_dir() . '/mu-plugins';
    }
}
