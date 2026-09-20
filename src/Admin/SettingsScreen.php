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
        self::select($opt, 'response_mode', 'Response mode', $d['response_mode'], array(
            'stealth' => 'stealth — capture-only, plain 404 on every band (lowest fingerprint)',
            'realistic' => 'realistic — believable template fakes + decoys',
            'taunt' => 'taunt — troll persona layered over the decoy',
            'blocked' => 'blocked — generic "access denied" 403 page (looks hardened, does NOT lure)',
        ));
        self::help('Stealth logs + reports, then serves the site\'s plain 404 (no decoy, no 403). Realistic serves byte-exact fakes. Taunt only ever upgrades a 404. Blocked returns a generic security block page (403) instead of a decoy on every non-allow band — it ADVERTISES a defense (a fingerprint tradeoff vs the stay-hidden default) and can 403 a borderline "suspicious" visitor (a false-positive risk), so it is opt-in; clean traffic and the relocated login are never blocked.');
        self::select($opt, 'severity_ceiling', 'Severity ceiling', $d['severity_ceiling'], array('low' => 'low', 'medium' => 'medium', 'high' => 'high', 'critical' => 'critical'));
        self::checkbox($opt, 'attack_emulation', 'Attack-class emulation', $d['attack_emulation']);
        self::checkbox($opt, 'nuclei_reflection', 'Nuclei reflection', $d['nuclei_reflection']);

        echo '<tr><th colspan="2"><h2>Decoys</h2></th></tr>';
        self::checkbox($opt, 'decoy_xmlrpc', 'xmlrpc.php decoy', $d['decoy_xmlrpc']);
        self::checkbox($opt, 'decoy_wp_login', 'wp-login mock-auth authed dashboard decoy', $d['decoy_wp_login']);
        self::password($opt, 'decoy_session_key', 'Decoy session key (per-deploy secret; arms the authed skin)', $d['decoy_session_key']);
        self::help('Decoys are forced off in stealth mode. The authed skin arms only when wp-login decoy is on and a session key is set.');

        echo '<tr><th colspan="2"><h2>Login relocation</h2></th></tr>';
        self::checkbox($opt, 'login_relocation_enabled', 'Relocate the login endpoint', $d['login_relocation_enabled']);
        self::text($opt, 'login_slug', 'Secret login slug (e.g. my-secret-login)', $d['login_slug']);
        self::help('Moves the real login to /your-slug and turns the default /wp-login.php into the wp-login decoy (auto-armed). Bookmark the slug — /wp-admin does NOT bounce to the real login by design (that would leak the slug to attackers). Does NOT hide REST (/wp-json) or XML-RPC auth. Most effective in realistic/taunt (stealth serves no decoy). Single-site only in v1. An invalid/empty slug leaves relocation off and the real login untouched.');

        echo '<tr><th colspan="2"><h2>Advanced: real-route actions</h2></th></tr>';
        $actionChoices = array('allow' => 'allow', 'log' => 'log', 'block' => 'block', 'deceive' => 'deceive');
        self::select($opt . '[actions]', 'clean', 'Clean traffic', $d['actions']['clean'], $actionChoices);
        self::select($opt . '[actions]', 'suspicious', 'Suspicious', $d['actions']['suspicious'], $actionChoices);
        self::select($opt . '[actions]', 'attack_class', 'Attack class', $d['actions']['attack_class'], $actionChoices);
        self::select($opt . '[actions]', 'scanner_probe', 'Scanner probe', $d['actions']['scanner_probe'], $actionChoices);
        self::help('Advanced override within realistic/taunt. Stealth clamps every non-allow band to log regardless of these.');

        echo '<tr><th colspan="2"><h2>Plugin/theme enumeration absorber</h2></th></tr>';
        self::checkbox($opt, 'plugin_enum_absorber', 'Absorb plugin/theme enumeration sweeps', $d['plugin_enum_absorber']);
        self::text($opt, 'enum_window_secs', 'Absorber window (seconds)', $d['enum_window_secs']);
        self::text($opt, 'enum_escalate_threshold', 'Escalate after N probes / window', $d['enum_escalate_threshold']);
        self::checkbox($opt, 'enum_auto_ban', 'Auto-ban on escalation (a stronger action — opt-in)', $d['enum_auto_ban']);
        self::text($opt, 'enum_ban_ttl_secs', 'Auto-ban TTL (seconds)', $d['enum_ban_ttl_secs']);

        echo '<tr><th colspan="2"><h2>WP-native capture</h2></th></tr>';
        self::checkbox($opt, 'wp_native_capture', 'Capture WP-native attacks (login / xmlrpc / REST)', $d['wp_native_capture']);
        self::help('Logs credential-stuffing, XML-RPC abuse and REST user-enumeration that WordPress handles itself. Local intel only — never sent to mainnet. Never changes what WordPress serves.');

        echo '<tr><th colspan="2"><h2>Login honeypot field</h2></th></tr>';
        self::checkbox($opt, 'login_honeypot_field', 'Invisible honeypot field on the real login form', $d['login_honeypot_field']);
        self::help('Injects a hidden decoy field into the real WordPress login form. A real user or browser never fills it; a credential-stuffing bot that fills every input does, so a non-empty submit is captured as a bot signal. Local intel only — never sent to mainnet. Never blocks or alters a real login. Independent of WP-native capture.');

        echo '<tr><th colspan="2"><h2>Bot-gated fake lockout</h2></th></tr>';
        self::checkbox($opt, 'login_fake_lockout', 'Show a fake lockout page to suspected bots on the real login', $d['login_fake_lockout']);
        self::text($opt, 'login_lockout_velocity', 'Velocity threshold (failed logins per 60s that arms it)', $d['login_lockout_velocity']);
        self::help('Shown ONLY to a suspected bot after a failed login — either the invisible honeypot field above was filled, or a per-IP failed-login rate well above any human (default 15 / 60s, min 5) was reached. It is NEVER shown on a plain failed-login count, so a real user who mistypes their password never sees it. It never actually locks an account: no persistent lock is written and the credential check is untouched, so a real user — or even a false-positive IP behind a shared address — always logs in on the next correct password. Cosmetic, per-request deception only; forced off in stealth/blocked and when the plugin is disabled (requires realistic or taunt response mode).');

        echo '<tr><th colspan="2"><h2>XML-RPC pingback shield</h2></th></tr>';
        self::checkbox($opt, 'wp_pingback_shield', 'Neutralize XML-RPC pingback SSRF (capture target + refuse)', $d['wp_pingback_shield']);
        self::help('Captures the attacker-supplied pingback target URL as local intel and returns the standard XML-RPC error WITHOUT fetching it, so this site cannot be used as an SSRF/DDoS pingback relay. Local intel only — the URL is never sent to mainnet. Changes what xmlrpc.php returns for pingback.ping only.');

        echo '<tr><th colspan="2"><h2>Reputation (verdict-first)</h2></th></tr>';
        self::nestedCheckbox($opt, 'reputation', 'check_enabled', 'Enable reputation check', isset($d['check_enabled']) ? $d['check_enabled'] : false);
        self::select($opt . '[reputation]', 'fail_mode', 'Fail mode', $d['fail_mode'], array('open' => 'open (fail-open)', 'closed' => 'closed'));

        echo '<tr><th colspan="2"><h2>Country policy</h2></th></tr>';
        self::select($opt, 'country_posture', 'Country posture', $d['country_posture'], array('off' => 'off', 'deny_list' => 'deny list', 'allow_list' => 'allow list (stricter, higher FP)'));
        self::select($opt, 'country_action', 'Country action', $d['country_action'], array('score-modifier' => 'score modifier (default)', 'deceive' => 'deceive', 'block' => 'block (a tell — eyes-open opt-in)'));

        echo '<tr><th colspan="2"><h2>Deception corpus auto-update</h2></th></tr>';
        self::checkbox($opt, 'rules_autoupdate_enabled', 'Auto-update the deception corpus (data only)', $d['rules_autoupdate_enabled']);
        self::select($opt, 'rules_channel', 'Update channel', $d['rules_channel'], array('stable' => 'stable', 'beta' => 'beta'));
        self::select($opt, 'rules_update_interval', 'Check interval', $d['rules_update_interval'], array('hourly' => 'hourly', 'twicedaily' => 'twice daily', 'daily' => 'daily'));
        self::help('Pulls new signed detection DATA (corpus, templates, fingerprints) on a schedule using the engine\'s signature-verified rules-update (ed25519 + per-file sha256 + array-literal validation before load; exec-free). Engine CODE still updates via the normal plugin auto-update / composer bump. Off by default. Single-site only in v1. A failed, unsigned or tampered pull is rejected and the current/bundled corpus is kept.');
        self::rulesStatusRow();

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

    /** A read-only status line for the corpus auto-update: source, version, last-applied/last-checked. */
    private static function rulesStatusRow()
    {
        $line = 'Corpus source: bundled (no update applied yet).';
        try {
            $svc = Plugin::services();
            if (isset($svc['rules']) && $svc['rules'] !== null) {
                $st = $svc['rules']->status();
                if ($st !== null) {
                    $version = $st->version !== null ? $st->version : 'n/a';
                    $line = sprintf(
                        'Corpus source: %s · version: %s · last applied: %s · last checked: %s',
                        $st->source,
                        $version,
                        $st->appliedAt !== null ? $st->appliedAt : 'never',
                        $st->checkedAt !== null ? $st->checkedAt : 'never'
                    );
                }
            }
        } catch (\Throwable $e) {
            // fall back to the bundled default line
        }
        echo '<tr><td colspan="2"><p class="description"><strong>Status:</strong> ' . self::esc($line) . '</p></td></tr>';
    }

    private static function help($text)
    {
        echo '<tr><td colspan="2"><p class="description">' . self::esc($text) . '</p></td></tr>';
    }

    private static function esc($v)
    {
        if (function_exists('esc_attr')) {
            return esc_attr($v);
        }

        return htmlspecialchars((string) $v, ENT_QUOTES);
    }
}
