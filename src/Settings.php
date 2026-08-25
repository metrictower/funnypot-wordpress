<?php

declare(strict_types=1);

namespace Funnypot\WordPress;

use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\ReputationVerdict;

/**
 * Immutable settings value object (design §5). Carries three families of knobs — policy,
 * STYLE/engine, and request/report — and renders the funnypot-policy §8 config array via
 * toPolicyConfig(). Pure: it never calls a WP function directly; the env-constant lookup is an
 * injected resolver so it stays unit-testable. 7.3-clean (no promotion / typed props / enums).
 *
 * The plugin is INERT by default: enabled=false, posture=honeypot, reporting/check off, no key.
 */
final class Settings
{
    const POSTURE_HONEYPOT = 'honeypot';
    const POSTURE_WAF      = 'WAF';
    const POSTURE_BOTH     = 'both';

    const BACKEND_OBJECT_CACHE = 'object-cache';
    const BACKEND_FILE         = 'file';

    const COUNTRY_OFF        = 'off';
    const COUNTRY_DENY_LIST  = 'deny_list';
    const COUNTRY_ALLOW_LIST = 'allow_list';

    /** Base URL default is a PLACEHOLDER host — never AbuseIPDB (D2). Scheme+host only. */
    const DEFAULT_MAINNET_BASE_URL = 'https://mainnet.funnypot.example';

    const CONST_BASE_URL = 'HONEYPOT_WP_MAINNET_BASE_URL';
    const CONST_KEY      = 'HONEYPOT_WP_MAINNET_KEY';

    /** @var array normalized settings */
    private $data;

    /** @var callable(string):mixed resolves a wp-config.php constant, or null */
    private $constResolver;

    private function __construct(array $data, $constResolver)
    {
        $this->data = $data;
        $this->constResolver = $constResolver;
    }

    /**
     * @param array         $raw          the stored option array
     * @param callable|null $constResolver fn(string $name): mixed|null — env-constant lookup
     * @return self
     */
    public static function fromArray(array $raw, $constResolver = null)
    {
        if ($constResolver === null) {
            $constResolver = array(__CLASS__, 'defaultConstResolver');
        }

        return new self(self::normalize($raw), $constResolver);
    }

    /** Default env-constant resolver over PHP's define()/constant(). */
    public static function defaultConstResolver($name)
    {
        return defined($name) ? constant($name) : null;
    }

    // ---------------------------------------------------------------------------------------------
    // normalization / whitelisting
    // ---------------------------------------------------------------------------------------------

    private static function normalize(array $r)
    {
        $d = array();

        $d['enabled'] = isset($r['enabled']) ? (bool) $r['enabled'] : false;
        $d['posture'] = self::whitelist(
            isset($r['posture']) ? (string) $r['posture'] : self::POSTURE_HONEYPOT,
            array(self::POSTURE_HONEYPOT, self::POSTURE_WAF, self::POSTURE_BOTH),
            self::POSTURE_HONEYPOT
        );

        // Optional per-field position override; absent => posture preset governs.
        $pos = array();
        if (isset($r['position']) && is_array($r['position'])) {
            if (array_key_exists('before', $r['position'])) {
                $pos['before'] = (bool) $r['position']['before'];
            }
            if (array_key_exists('fallback', $r['position'])) {
                $pos['fallback'] = (bool) $r['position']['fallback'];
            }
        }
        $d['position'] = $pos;

        // Per-band real-route actions.
        $actions = isset($r['actions']) && is_array($r['actions']) ? $r['actions'] : array();
        $actionEnum = array('allow', 'log', 'block', 'deceive');
        $d['actions'] = array(
            'clean' => self::whitelist(isset($actions['clean']) ? (string) $actions['clean'] : 'allow', $actionEnum, 'allow'),
            'suspicious' => self::whitelist(isset($actions['suspicious']) ? (string) $actions['suspicious'] : 'log', $actionEnum, 'log'),
            'attack_class' => self::whitelist(isset($actions['attack_class']) ? (string) $actions['attack_class'] : 'block', $actionEnum, 'block'),
            'scanner_probe' => self::whitelist(isset($actions['scanner_probe']) ? (string) $actions['scanner_probe'] : 'deceive', $actionEnum, 'deceive'),
        );

        $d['pin_ttl_seconds'] = self::clampInt(isset($r['pin_ttl_seconds']) ? $r['pin_ttl_seconds'] : 3600, 60, 86400, 3600);

        // learn-then-enforce.
        $learn = isset($r['learn']) && is_array($r['learn']) ? $r['learn'] : array();
        $d['learn'] = array(
            'shadow_days' => self::clampInt(isset($learn['shadow_days']) ? $learn['shadow_days'] : 7, 0, 365, 7),
            'shadow_min_reqs' => self::clampInt(isset($learn['shadow_min_reqs']) ? $learn['shadow_min_reqs'] : 5000, 0, 100000000, 5000),
            'baseline_excluded' => isset($learn['baseline_excluded']) && is_array($learn['baseline_excluded'])
                ? array_values(array_map('strval', $learn['baseline_excluded'])) : array(),
            'kill_switch' => isset($learn['kill_switch']) ? (bool) $learn['kill_switch'] : false,
        );

        // Suppression: pass through as-is (policy §9 defaults fill unmapped keys). Kept as a plain
        // sub-array so the operator can tune it; the policy owns the semantics.
        $d['suppression'] = isset($r['suppression']) && is_array($r['suppression']) ? $r['suppression'] : array();

        // Allowlist + self ips.
        $al = isset($r['allowlist']) && is_array($r['allowlist']) ? $r['allowlist'] : array();
        $d['allowlist'] = array(
            'ips' => self::strList(isset($al['ips']) ? $al['ips'] : array()),
            'cidrs' => self::strList(isset($al['cidrs']) ? $al['cidrs'] : array()),
            'asns' => self::strList(isset($al['asns']) ? $al['asns'] : array()),
            'safe_paths' => self::strList(isset($al['safe_paths']) ? $al['safe_paths'] : array()),
        );
        $d['self_ips'] = self::strList(isset($r['self_ips']) ? $r['self_ips'] : array());

        // STYLE / engine.
        $d['response_style'] = self::whitelist(
            isset($r['response_style']) ? (string) $r['response_style'] : 'minimal',
            array('minimal', 'realistic', 'taunt'),
            'minimal'
        );
        $d['severity_ceiling'] = self::whitelist(
            isset($r['severity_ceiling']) ? (string) $r['severity_ceiling'] : 'high',
            array('low', 'medium', 'high', 'critical'),
            'high'
        );
        $d['attack_emulation'] = isset($r['attack_emulation']) ? (bool) $r['attack_emulation'] : false;
        $d['nuclei_reflection'] = isset($r['nuclei_reflection']) ? (bool) $r['nuclei_reflection'] : true;
        $d['catalog_disabled'] = self::strList(isset($r['catalog_disabled']) ? $r['catalog_disabled'] : array());
        $d['seed_salt'] = isset($r['seed_salt']) ? (string) $r['seed_salt'] : '';
        $d['latency_ms'] = self::clampInt(isset($r['latency_ms']) ? $r['latency_ms'] : 0, 0, 60000, 0);
        $d['latency_jitter_ms'] = self::clampInt(isset($r['latency_jitter_ms']) ? $r['latency_jitter_ms'] : 0, 0, 60000, 0);

        // Request / report.
        $d['trusted_proxies'] = self::strList(isset($r['trusted_proxies']) ? $r['trusted_proxies'] : array());
        $d['report_enabled'] = isset($r['report_enabled']) ? (bool) $r['report_enabled'] : false;
        $d['mainnet_base_url'] = self::baseUrlOnly(
            isset($r['mainnet_base_url']) && (string) $r['mainnet_base_url'] !== ''
                ? (string) $r['mainnet_base_url'] : self::DEFAULT_MAINNET_BASE_URL
        );
        $d['mainnet_key'] = isset($r['mainnet_key']) ? (string) $r['mainnet_key'] : '';
        $d['daily_cap'] = self::clampInt(isset($r['daily_cap']) ? $r['daily_cap'] : 1000, 0, 100000, 1000);

        // Reputation (verdict-first; NO score block_threshold).
        $rep = isset($r['reputation']) && is_array($r['reputation']) ? $r['reputation'] : array();
        $d['check_enabled'] = isset($rep['check_enabled']) ? (bool) $rep['check_enabled']
            : (isset($r['check_enabled']) ? (bool) $r['check_enabled'] : false);
        $verdictEnum = array(
            ReputationVerdict::VERDICT_CLEAN,
            ReputationVerdict::VERDICT_SUSPICIOUS,
            ReputationVerdict::VERDICT_MALICIOUS,
            ReputationVerdict::VERDICT_CRITICAL,
        );
        $bv = isset($rep['block_verdicts']) ? $rep['block_verdicts'] : (isset($r['block_verdicts']) ? $r['block_verdicts'] : null);
        $d['block_verdicts'] = self::whitelistList(
            is_array($bv) ? $bv : array(ReputationVerdict::VERDICT_MALICIOUS, ReputationVerdict::VERDICT_CRITICAL),
            $verdictEnum,
            array(ReputationVerdict::VERDICT_MALICIOUS, ReputationVerdict::VERDICT_CRITICAL)
        );
        $mbs = isset($rep['min_block_score']) ? $rep['min_block_score'] : (isset($r['min_block_score']) ? $r['min_block_score'] : null);
        $d['min_block_score'] = ($mbs === null || $mbs === '') ? null : self::clampInt($mbs, 0, 100, 0);
        $cth = isset($rep['cache_ttl_hours']) ? $rep['cache_ttl_hours'] : (isset($r['cache_ttl_hours']) ? $r['cache_ttl_hours'] : 24);
        $d['cache_ttl_hours'] = self::clampInt($cth, 1, 720, 24);
        $d['fail_mode'] = self::whitelist(
            isset($rep['fail_mode']) ? (string) $rep['fail_mode'] : (isset($r['fail_mode']) ? (string) $r['fail_mode'] : 'open'),
            array('open', 'closed'),
            'open'
        );

        // Local-state / mirror (RS-10 / O1).
        $d['local_state_backend'] = self::whitelist(
            isset($r['local_state_backend']) ? (string) $r['local_state_backend'] : self::BACKEND_OBJECT_CACHE,
            array(self::BACKEND_OBJECT_CACHE, self::BACKEND_FILE),
            self::BACKEND_OBJECT_CACHE
        );
        $d['mirror_enabled'] = isset($r['mirror_enabled']) ? (bool) $r['mirror_enabled'] : false;
        $d['mirror_pull_interval_secs'] = self::clampInt(isset($r['mirror_pull_interval_secs']) ? $r['mirror_pull_interval_secs'] : 3600, 300, 86400, 3600);

        // SF-6 drain bounds (decision N canonical numbers).
        $d['drain_budget_secs'] = self::clampInt(isset($r['drain_budget_secs']) ? $r['drain_budget_secs'] : 10, 1, 60, 10);
        $d['drain_max_attempts'] = self::clampInt(isset($r['drain_max_attempts']) ? $r['drain_max_attempts'] : 3, 1, 20, 3);
        $d['drain_max_age_secs'] = self::clampInt(isset($r['drain_max_age_secs']) ? $r['drain_max_age_secs'] : 604800, 3600, 2592000, 604800);
        $d['queue_cap'] = self::clampInt(isset($r['queue_cap']) ? $r['queue_cap'] : 10000, 100, 1000000, 10000);

        // Country policy (R).
        $d['country_posture'] = self::whitelist(
            isset($r['country_posture']) ? (string) $r['country_posture'] : self::COUNTRY_OFF,
            array(self::COUNTRY_OFF, self::COUNTRY_DENY_LIST, self::COUNTRY_ALLOW_LIST),
            self::COUNTRY_OFF
        );
        $d['country_list'] = self::alpha2List(isset($r['country_list']) ? $r['country_list'] : array());
        $d['country_action'] = self::whitelist(
            isset($r['country_action']) ? (string) $r['country_action'] : 'score-modifier',
            array('block', 'deceive', 'score-modifier'),
            'score-modifier'
        );
        $d['geoip_refresh_interval_secs'] = self::clampInt(isset($r['geoip_refresh_interval_secs']) ? $r['geoip_refresh_interval_secs'] : 2592000, 86400, 31536000, 2592000);

        return $d;
    }

    // ---------------------------------------------------------------------------------------------
    // getters
    // ---------------------------------------------------------------------------------------------

    public function enabled()
    {
        return $this->data['enabled'];
    }

    public function posture()
    {
        return $this->data['posture'];
    }

    /** Is the BEFORE/FALLBACK position active for the current posture (preset + explicit override)? */
    public function positionActive($which)
    {
        $preset = self::presetPosition($this->data['posture']);
        $pos = $this->data['position'];
        if (isset($pos[$which])) {
            return $pos[$which] === true;
        }

        return isset($preset[$which]) ? $preset[$which] : false;
    }

    public function localStateBackend()
    {
        return $this->data['local_state_backend'];
    }

    public function mirrorEnabled()
    {
        return $this->data['mirror_enabled'];
    }

    public function mirrorPullIntervalSecs()
    {
        return $this->data['mirror_pull_interval_secs'];
    }

    public function drainBudgetSecs()
    {
        return $this->data['drain_budget_secs'];
    }

    public function drainMaxAttempts()
    {
        return $this->data['drain_max_attempts'];
    }

    public function drainMaxAgeSecs()
    {
        return $this->data['drain_max_age_secs'];
    }

    public function queueCap()
    {
        return $this->data['queue_cap'];
    }

    public function dailyCap()
    {
        return $this->data['daily_cap'];
    }

    public function selfIps()
    {
        return $this->data['self_ips'];
    }

    public function trustedProxies()
    {
        return $this->data['trusted_proxies'];
    }

    // --- STYLE / engine ---

    public function responseStyle()
    {
        return $this->data['response_style'];
    }

    public function severityCeiling()
    {
        return $this->data['severity_ceiling'];
    }

    public function attackEmulation()
    {
        return $this->data['attack_emulation'];
    }

    public function nucleiReflection()
    {
        return $this->data['nuclei_reflection'];
    }

    public function catalogDisabled()
    {
        return $this->data['catalog_disabled'];
    }

    public function seedSalt()
    {
        return $this->data['seed_salt'];
    }

    public function latencyMs()
    {
        return $this->data['latency_ms'];
    }

    public function latencyJitterMs()
    {
        return $this->data['latency_jitter_ms'];
    }

    // --- reputation ---

    public function checkEnabled()
    {
        return $this->data['check_enabled'];
    }

    public function blockVerdicts()
    {
        return $this->data['block_verdicts'];
    }

    public function minBlockScore()
    {
        return $this->data['min_block_score'];
    }

    public function cacheTtlHours()
    {
        return $this->data['cache_ttl_hours'];
    }

    public function failMode()
    {
        return $this->data['fail_mode'];
    }

    // --- country (R) ---

    public function countryPosture()
    {
        return $this->data['country_posture'];
    }

    public function countryList()
    {
        return $this->data['country_list'];
    }

    public function countryAction()
    {
        return $this->data['country_action'];
    }

    public function geoipRefreshIntervalSecs()
    {
        return $this->data['geoip_refresh_interval_secs'];
    }

    // --- mainnet address + key (env-constant override wins; D1/D2) ---

    /**
     * The single MAINNET_KEY. It is a `sensor`-tier key carrying BOTH report rights AND an
     * escalation-check quota (O2) — one key, both jobs. Empty => reporting AND reputation inert (D2).
     */
    public function mainnetKey()
    {
        $env = call_user_func($this->constResolver, self::CONST_KEY);
        if ($env !== null && (string) $env !== '') {
            return (string) $env;
        }

        return $this->data['mainnet_key'];
    }

    /** Scheme+host only — the reporter/mirror append the path (D1). */
    public function mainnetBaseUrl()
    {
        $env = call_user_func($this->constResolver, self::CONST_BASE_URL);
        if ($env !== null && (string) $env !== '') {
            return self::baseUrlOnly((string) $env);
        }

        return $this->data['mainnet_base_url'];
    }

    public function reportEnabled()
    {
        return $this->data['report_enabled'];
    }

    /** Reporting is active only when enabled AND a key is set (D2: inert without a key). */
    public function reportingActive()
    {
        return $this->data['report_enabled'] === true && $this->mainnetKey() !== '';
    }

    /** Reputation is active only when checking is enabled AND a key is set (F: inert without a key). */
    public function checkActive()
    {
        return $this->data['check_enabled'] === true && $this->mainnetKey() !== '';
    }

    /** Raw normalized settings (for the admin screen / debugging). */
    public function toArray()
    {
        return $this->data;
    }

    // ---------------------------------------------------------------------------------------------
    // the one settings -> policy §8 array mapping (the thin-adapter responsibility)
    // ---------------------------------------------------------------------------------------------

    /**
     * Render the funnypot-policy §8 config array, forcing the given position (and only it) on so the
     * shared engine runs exactly the pass this hook represents (D drives one position per WP hook).
     *
     * @param string $position 'before' | 'fallback'
     * @return array
     */
    public function toPolicyConfig($position)
    {
        $before = ($position === PolicyConfig::POSITION_BEFORE);

        $country = array('enabled' => false, 'mode' => 'deny', 'countries' => array(), 'action' => 'modifier');
        if ($this->data['country_posture'] !== self::COUNTRY_OFF) {
            $country = array(
                'enabled' => true,
                'mode' => $this->data['country_posture'] === self::COUNTRY_ALLOW_LIST ? 'allow' : 'deny',
                'countries' => $this->data['country_list'],
                // 'score-modifier' is the policy's 'modifier'.
                'action' => $this->data['country_action'] === 'score-modifier' ? 'modifier' : $this->data['country_action'],
            );
        }

        return array(
            'posture' => $this->data['posture'],
            'position' => array('before' => $before, 'fallback' => !$before),
            'actions' => $this->data['actions'],
            'reputation' => array(
                'enabled' => $this->checkActive(),
                'block_verdicts' => $this->data['block_verdicts'],
                'min_block_score' => $this->data['min_block_score'],
            ),
            'learn' => $this->data['learn'],
            'country' => $country,
            'pin' => array('ttl_seconds' => $this->data['pin_ttl_seconds']),
            'suppression' => $this->data['suppression'],
            'allowlist' => $this->data['allowlist'],
            'self_ips' => $this->data['self_ips'],
        );
    }

    /**
     * The mainnet-client Config array for the ReputationInterface/Reporter adapters (verdict-first;
     * NO block_threshold). Kept here so the F-Config mapping has one source.
     *
     * @return array
     */
    public function toMainnetConfig()
    {
        return array(
            'base_url' => $this->mainnetBaseUrl(),
            'key' => $this->mainnetKey(),
            'check_enabled' => $this->data['check_enabled'],
            'fail_mode' => $this->data['fail_mode'],
            'block_verdicts' => $this->data['block_verdicts'],
            'min_block_score' => $this->data['min_block_score'],
            'cache_ttl_hours' => $this->data['cache_ttl_hours'],
            'timeout_ms' => 1500,
            'self_ips' => $this->data['self_ips'],
            'daily_cap' => $this->data['daily_cap'],
        );
    }

    // ---------------------------------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------------------------------

    private static function presetPosition($posture)
    {
        if ($posture === self::POSTURE_WAF) {
            return array('fallback' => false, 'before' => true);
        }
        if ($posture === self::POSTURE_BOTH) {
            return array('fallback' => true, 'before' => true);
        }

        return array('fallback' => true, 'before' => false); // honeypot
    }

    private static function whitelist($value, array $allowed, $default)
    {
        return in_array($value, $allowed, true) ? $value : $default;
    }

    private static function whitelistList($values, array $allowed, array $default)
    {
        if (!is_array($values)) {
            return $default;
        }
        $out = array();
        foreach ($values as $v) {
            $v = (string) $v;
            if (in_array($v, $allowed, true) && !in_array($v, $out, true)) {
                $out[] = $v;
            }
        }

        return $out === array() ? $default : $out;
    }

    private static function strList($values)
    {
        if (!is_array($values)) {
            return array();
        }
        $out = array();
        foreach ($values as $v) {
            $v = trim((string) $v);
            if ($v !== '') {
                $out[] = $v;
            }
        }

        return array_values(array_unique($out));
    }

    private static function alpha2List($values)
    {
        if (!is_array($values)) {
            return array();
        }
        $out = array();
        foreach ($values as $v) {
            $v = strtoupper(trim((string) $v));
            if (preg_match('/^[A-Z]{2}$/', $v) && !in_array($v, $out, true)) {
                $out[] = $v;
            }
        }

        return $out;
    }

    private static function clampInt($value, $min, $max, $default)
    {
        if (!is_numeric($value)) {
            return $default;
        }
        $n = (int) $value;
        if ($n < $min) {
            return $min;
        }
        if ($n > $max) {
            return $max;
        }

        return $n;
    }

    /** Strip everything except scheme://host[:port] (base-URL-only convention, D1). */
    private static function baseUrlOnly($url)
    {
        $url = trim($url);
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'])) {
            // Not a parseable absolute URL: fall back to the placeholder rather than store junk.
            return self::DEFAULT_MAINNET_BASE_URL;
        }
        $scheme = isset($parts['scheme']) && $parts['scheme'] !== '' ? $parts['scheme'] : 'https';
        $out = $scheme . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $out .= ':' . $parts['port'];
        }

        return $out;
    }
}
