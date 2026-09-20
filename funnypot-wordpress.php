<?php
/**
 * Plugin Name:       funnypot for WordPress
 * Plugin URI:        https://github.com/metrictower/funnypot-wordpress
 * Description:        Thin WordPress adapter over the funnypot-policy decision engine. Deceives scanners, optionally blocks known-bad actors, and reports abuse — inert by default.
 * Version:           0.1.0-dev
 * Requires PHP:      7.3
 * Requires at least: 5.5
 * Author:            metrictower
 * License:           Proprietary
 * Text Domain:       honeypot-wp
 *
 * @package Funnypot\WordPress
 */

// Never run outside WordPress. Also keeps a direct hit from fataling / disclosing anything.
if (!defined('ABSPATH')) {
    return;
}

// The bundled Composer autoloader (policy + core + mainnet-client + plugin classes).
$honeypot_wp_autoload = __DIR__ . '/vendor/autoload.php';
if (is_file($honeypot_wp_autoload)) {
    require_once $honeypot_wp_autoload;
}

// Wiring (hooks, admin menu, WP-CLI, activation) is registered by the bootstrap, which is a
// no-op if the autoloader / classes are unavailable — degrade-safe by construction (SF-4).
if (class_exists(\Honeypot\WP\Plugin::class)) {
    \Honeypot\WP\Plugin::register(__FILE__);
}
