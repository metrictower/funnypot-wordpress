<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Admin;

use Funnypot\WordPress\Plugin;
use Funnypot\WordPress\Settings;

/**
 * Settings -> Honeypot (design §4.7). The screen's one job is to produce the stored settings that
 * Settings::toPolicyConfig() renders into the policy §8 config array — it authors no decision logic.
 * manage_options-gated, nonce-protected (WP settings API), sanitized through SettingsSanitizer (the
 * same whitelist the runtime uses). Integration-level; the sanitizer + policy mapping are unit-tested.
 * 7.3-clean.
 */
final class SettingsScreen
{
    const GROUP = 'honeypot_wp_group';

    public static function register()
    {
        if (!function_exists('add_options_page')) {
            return;
        }
        add_options_page('Honeypot', 'Honeypot', 'manage_options', 'honeypot-wp', array(__CLASS__, 'render'));
    }

    public static function registerSetting()
    {
        if (!function_exists('register_setting')) {
            return;
        }
        register_setting(self::GROUP, Plugin::OPTION, array(
            'type' => 'array',
            'sanitize_callback' => array(SettingsSanitizer::class, 'sanitize'),
            'default' => array(),
        ));
    }

    public static function render()
    {
        if (function_exists('current_user_can') && !current_user_can('manage_options')) {
            return;
        }
        $s = Plugin::settings();
        $d = $s->toArray();

        echo '<div class="wrap"><h1>Honeypot for WordPress</h1>';
        echo '<p>Inert by default. Enabling a posture is an explicit choice. Reputation checking and reporting each require a <code>MAINNET_KEY</code>.</p>';
        echo '<form method="post" action="options.php">';
        if (function_exists('settings_fields')) {
            settings_fields(self::GROUP);
        }
        $opt = Plugin::OPTION;

        echo '<table class="form-table" role="presentation">';
        self::checkbox($opt, 'enabled', 'Enabled', $d['enabled']);
        self::select($opt, 'posture', 'Posture', $d['posture'], array('honeypot' => 'Honeypot (404 upgrade)', 'WAF' => 'WAF (before)', 'both' => 'Both'));
        self::select($opt, 'response_style', 'Response style', $d['response_style'], array('minimal' => 'minimal', 'realistic' => 'realistic', 'taunt' => 'taunt'));
        self::select($opt, 'severity_ceiling', 'Severity ceiling', $d['severity_ceiling'], array('low' => 'low', 'medium' => 'medium', 'high' => 'high', 'critical' => 'critical'));
        self::checkbox($opt, 'attack_emulation', 'Attack-class emulation', $d['attack_emulation']);
        self::checkbox($opt, 'nuclei_reflection', 'Nuclei reflection', $d['nuclei_reflection']);

        echo '<tr><th colspan="2"><h2>Reputation (verdict-first)</h2></th></tr>';
        self::nestedCheckbox($opt, 'reputation', 'check_enabled', 'Enable reputation check', isset($d['check_enabled']) ? $d['check_enabled'] : false);
        self::select($opt . '[reputation]', 'fail_mode', 'Fail mode', $d['fail_mode'], array('open' => 'open (fail-open)', 'closed' => 'closed'));

        echo '<tr><th colspan="2"><h2>Country policy</h2></th></tr>';
        self::select($opt, 'country_posture', 'Country posture', $d['country_posture'], array('off' => 'off', 'deny_list' => 'deny list', 'allow_list' => 'allow list (stricter, higher FP)'));
        self::select($opt, 'country_action', 'Country action', $d['country_action'], array('score-modifier' => 'score modifier (default)', 'deceive' => 'deceive', 'block' => 'block (a tell — eyes-open opt-in)'));

        echo '<tr><th colspan="2"><h2>Reporting</h2></th></tr>';
        self::checkbox($opt, 'report_enabled', 'Enable reporting', $d['report_enabled']);
        self::text($opt, 'mainnet_base_url', 'Mainnet base URL (scheme+host only)', $d['mainnet_base_url']);
        self::password($opt, 'mainnet_key', 'Mainnet key (sensor tier)', $d['mainnet_key']);
        self::textarea($opt, 'self_ips', 'Self IPs (one per line — never reported)', implode("\n", $d['self_ips']));
        echo '</table>';

        if (function_exists('submit_button')) {
            submit_button();
        } else {
            echo '<p><input type="submit" class="button button-primary" value="Save"></p>';
        }
        echo '</form></div>';
    }

    // --- field helpers (escaped) -----------------------------------------------------------------

    private static function checkbox($opt, $key, $label, $checked)
    {
        $name = $opt . '[' . $key . ']';
        echo '<tr><th scope="row">' . self::esc($label) . '</th><td><label><input type="checkbox" name="' . self::esc($name) . '" value="1" ' . ($checked ? 'checked' : '') . '> ' . self::esc($label) . '</label></td></tr>';
    }

    private static function nestedCheckbox($opt, $group, $key, $label, $checked)
    {
        $name = $opt . '[' . $group . '][' . $key . ']';
        echo '<tr><th scope="row">' . self::esc($label) . '</th><td><label><input type="checkbox" name="' . self::esc($name) . '" value="1" ' . ($checked ? 'checked' : '') . '></label></td></tr>';
    }

    private static function select($opt, $key, $label, $value, array $choices)
    {
        $name = $opt . '[' . $key . ']';
        echo '<tr><th scope="row">' . self::esc($label) . '</th><td><select name="' . self::esc($name) . '">';
        foreach ($choices as $v => $text) {
            echo '<option value="' . self::esc((string) $v) . '" ' . ((string) $v === (string) $value ? 'selected' : '') . '>' . self::esc((string) $text) . '</option>';
        }
        echo '</select></td></tr>';
    }

    private static function text($opt, $key, $label, $value)
    {
        $name = $opt . '[' . $key . ']';
        echo '<tr><th scope="row">' . self::esc($label) . '</th><td><input type="text" class="regular-text" name="' . self::esc($name) . '" value="' . self::esc((string) $value) . '"></td></tr>';
    }

    private static function password($opt, $key, $label, $value)
    {
        $name = $opt . '[' . $key . ']';
        echo '<tr><th scope="row">' . self::esc($label) . '</th><td><input type="password" class="regular-text" name="' . self::esc($name) . '" value="' . self::esc((string) $value) . '" autocomplete="new-password"></td></tr>';
    }

    private static function textarea($opt, $key, $label, $value)
    {
        $name = $opt . '[' . $key . ']';
        echo '<tr><th scope="row">' . self::esc($label) . '</th><td><textarea name="' . self::esc($name) . '" rows="3" class="large-text">' . self::esc((string) $value) . '</textarea></td></tr>';
    }

    private static function esc($v)
    {
        if (function_exists('esc_attr')) {
            return esc_attr($v);
        }

        return htmlspecialchars((string) $v, ENT_QUOTES);
    }
}
