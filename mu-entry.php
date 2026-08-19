<?php
/**
 * Stable, versioned entry the must-use loader shim require's (SF-4). Kept tiny and skew-tolerant: it
 * only loads the plugin's autoloader and hands off to Honeypot\WP\MuEntry::boot(). The shim wraps the
 * call in class_exists/method_exists + try/catch, so shim/plugin version skew degrades to inert.
 *
 * @package Honeypot\WP
 */

if (!defined('ABSPATH')) {
    return;
}

$honeypot_wp_autoload = __DIR__ . '/vendor/autoload.php';
if (is_file($honeypot_wp_autoload)) {
    require_once $honeypot_wp_autoload;
}

// The shim's guard checks these before calling boot(); loading this file must never fatal on its own.
