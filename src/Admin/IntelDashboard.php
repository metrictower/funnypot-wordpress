<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Admin;

use Funnypot\WordPress\Geo\WpGeoIp;
use Funnypot\WordPress\Plugin;

/**
 * Settings -> Honeypot Intel: a read-only wp-admin view of the local hit store (design: the operator's
 * reason to install — the Wordfence "Live Traffic" analog). Renders summary tiles, paginated recent
 * events, top attacker IPs (best-effort UA/country/velocity), mass_plugin_scan rollups, mainnet queue
 * depth and blacklist-mirror age.
 *
 * Split into a pure gather() (bounded, prepared reads over honeypot_wp_hits + WpStateStore/reporter via
 * injected seams) and an escaping renderView(), so output escaping — the one dangerous concern — is
 * unit-testable without a live $wpdb.
 *
 * Security contract (this class exists to avoid stored XSS): every value is escaped at output. Attacker-
 * controlled values (ip/path/ua/method/country) are text-node cell content only (esc_html); the only
 * attribute values on the page are absint-coerced pagination integers and a fixed action-filter
 * whitelist. Read-only: no network I/O on render (GeoIP is a local reader only, country degrades to "—";
 * never triggers GeoIpRefresh or a reporter drain). 7.3-clean (no `?->`; explicit null-guards).
 */
final class IntelDashboard
{
    /** wp-admin page slug (also the pagination href base — never attacker input). */
    const SLUG = 'honeypot-wp-intel';

    /** Recent-events page size. */
    const PER_PAGE = 50;

    /** Upper bound on the page number so a hostile ?paged can never build an unbounded OFFSET. */
    const MAX_PAGE = 10000;

    /** Top-IP enrichment fan-out cap (bounds the per-IP state-slot reads). */
    const TOP_IPS = 20;

    /** The events table (unqualified) — the prefix comes from $wpdb, never user input. */
    const TABLE = 'honeypot_wp_hits';

    /** Whitelist of action values the recent-events filter may select (never free-text / raw $_GET). */
    private static function filterChoices()
    {
        return array(
            '' => 'All actions',
            'log' => 'log',
            'deceive' => 'deceive',
            'block' => 'block',
        );
    }

    public static function register()
    {
        if (!function_exists('add_submenu_page')) {
            return;
        }
        add_submenu_page(
            'options-general.php',
            'Honeypot Intel',
            'Honeypot Intel',
            'manage_options',
            self::SLUG,
            array(__CLASS__, 'render')
        );
    }

    /** WP callback: cap-guard -> build seams from services() -> gather() -> renderView(). */
    public static function render()
    {
        if (function_exists('current_user_can') && !current_user_can('manage_options')) {
            return;
        }
        try {
            $data = self::gather(self::depsFromServices());
        } catch (\Throwable $e) {
            $data = self::emptyData();
        }
        self::renderView($data);
    }

    /** Build the injected seams from the shared services bundle (prod wiring). */
    private static function depsFromServices()
    {
        global $wpdb;
        $svc = Plugin::services();
        $store = isset($svc['store']) ? $svc['store'] : null;
        $reporter = isset($svc['reporter']) ? $svc['reporter'] : null;

        // Country is strictly a LOCAL lookup. No mmdb reader is wired in the plugin today, so this
        // degrades to "—"; never pull services()['geoip'] (that is GeoIpRefresh, the network refresher).
        $geo = new WpGeoIp(null);

        $rawPaged = isset($_GET['paged']) ? $_GET['paged'] : 1;
        $rawFilter = isset($_GET['fp_action']) ? (string) $_GET['fp_action'] : '';

        return array(
            'wpdb' => $wpdb,
            'store' => $store,
            'reporter' => $reporter,
            'geo' => $geo,
            'paged' => $rawPaged,
            'filterAction' => self::validateFilter($rawFilter),
        );
    }

    /** Keep only a known action value; anything else (incl. hostile $_GET) collapses to "no filter". */
    private static function validateFilter($v)
    {
        $choices = self::filterChoices();

        return (is_string($v) && $v !== '' && isset($choices[$v])) ? $v : '';
    }

    // --- data (pure) -----------------------------------------------------------------------------

    /**
     * Aggregate the dashboard data over injected seams. Pure (no output, no echo). Each section is
     * guarded so a query fault degrades that section to empty rather than fataling the page.
     *
     * @param array $deps {wpdb, store, reporter, geo, paged, filterAction, now?}
     * @return array
     */
    public static function gather(array $deps)
    {
        $wpdb = isset($deps['wpdb']) ? $deps['wpdb'] : null;
        $store = isset($deps['store']) ? $deps['store'] : null;
        $reporter = isset($deps['reporter']) ? $deps['reporter'] : null;
        $geo = isset($deps['geo']) ? $deps['geo'] : null;
        $now = isset($deps['now']) ? (int) $deps['now'] : time();
        $filterAction = self::validateFilter(isset($deps['filterAction']) ? $deps['filterAction'] : '');
        $paged = self::clampPage(isset($deps['paged']) ? $deps['paged'] : 1);

        $data = self::emptyData();
        $data['paged'] = $paged;
        $data['perPage'] = self::PER_PAGE;
        $data['filterAction'] = $filterAction;

        if ($wpdb === null) {
            return $data; // no DB -> render the empty shell, never an error
        }

        $table = self::table($wpdb);
        $cutoff = $now - 86400;
        $arrayA = defined('ARRAY_A') ? ARRAY_A : 'ARRAY_A';

        // Summary tiles.
        $data['tiles']['total'] = self::guardInt(static function () use ($wpdb, $table) {
            return $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        });
        $data['tiles']['events24h'] = self::guardInt(static function () use ($wpdb, $table, $cutoff) {
            return $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE ts > %d", $cutoff));
        });

        // Counts by action / reason.
        $data['byAction'] = self::guardRows(static function () use ($wpdb, $table, $arrayA) {
            return $wpdb->get_results("SELECT action, COUNT(*) c FROM {$table} GROUP BY action ORDER BY c DESC LIMIT 10", $arrayA);
        });
        $data['byReason'] = self::guardRows(static function () use ($wpdb, $table, $arrayA) {
            return $wpdb->get_results("SELECT reason, COUNT(*) c FROM {$table} GROUP BY reason ORDER BY c DESC LIMIT 20", $arrayA);
        });

        // Recent events (paginated, optional whitelist action filter).
        $offset = ($paged - 1) * self::PER_PAGE;
        $perPage = self::PER_PAGE;
        $data['recent'] = self::guardRows(static function () use ($wpdb, $table, $arrayA, $filterAction, $perPage, $offset) {
            if ($filterAction !== '') {
                $sql = $wpdb->prepare(
                    "SELECT id, ts, ip, method, path, action, reason, status FROM {$table} WHERE action = %s ORDER BY ts DESC LIMIT %d OFFSET %d",
                    $filterAction,
                    $perPage,
                    $offset
                );
            } else {
                $sql = $wpdb->prepare(
                    "SELECT id, ts, ip, method, path, action, reason, status FROM {$table} ORDER BY ts DESC LIMIT %d OFFSET %d",
                    $perPage,
                    $offset
                );
            }

            return $wpdb->get_results($sql, $arrayA);
        });
        // A full page suggests there may be a next one (bounded by MAX_PAGE regardless).
        $data['hasNext'] = (count($data['recent']) >= self::PER_PAGE) && ($paged < self::MAX_PAGE);

        // Top attacker IPs (24h), enriched best-effort with UA/country/current-window velocity.
        $topIps = self::guardRows(static function () use ($wpdb, $table, $arrayA, $cutoff) {
            return $wpdb->get_results(
                $wpdb->prepare("SELECT ip, COUNT(*) c, MAX(ts) last FROM {$table} WHERE ts > %d GROUP BY ip ORDER BY c DESC LIMIT %d", $cutoff, self::TOP_IPS),
                $arrayA
            );
        });
        $data['topIps'] = self::enrichTopIps($topIps, $store, $geo);

        // mass_plugin_scan rollups.
        $data['rollups'] = self::guardRows(static function () use ($wpdb, $table, $arrayA) {
            return $wpdb->get_results(
                $wpdb->prepare("SELECT ip, path, MAX(ts) last, COUNT(*) c FROM {$table} WHERE reason = %s GROUP BY ip, path ORDER BY last DESC LIMIT 20", 'mass_plugin_scan'),
                $arrayA
            );
        });

        // Queue depth + mirror age (explicit null-guards; reporter/mirror-meta can genuinely be null).
        $data['queueDepth'] = ($reporter !== null) ? self::guardInt(array($reporter, 'queueCount')) : null;
        $data['mirrorAgeSecs'] = self::mirrorAge($store, $now);

        return $data;
    }

    /** For each top IP, add a recent UA (from the FP-0488 / absorber per-IP slots), country, velocity. */
    private static function enrichTopIps(array $rows, $store, $geo)
    {
        $out = array();
        foreach ($rows as $row) {
            $ip = isset($row['ip']) ? (string) $row['ip'] : '';
            $ua = '';
            $velocity = null; // current-60s-window count from the aggregate slot (NOT a cumulative total)
            if ($store !== null && $ip !== '') {
                $keys = array(
                    'capture_agg:login:' . $ip,
                    'capture_agg:xmlrpc:' . $ip,
                    'capture_agg:rest:' . $ip,
                    'enumscan_agg:' . $ip,
                );
                foreach ($keys as $key) {
                    $agg = self::slot($store, $key);
                    if (!is_array($agg)) {
                        continue;
                    }
                    if ($ua === '' && isset($agg['ua']) && (string) $agg['ua'] !== '') {
                        $ua = (string) $agg['ua'];
                    }
                    if (isset($agg['count'])) {
                        $c = (int) $agg['count'];
                        if ($velocity === null || $c > $velocity) {
                            $velocity = $c;
                        }
                    }
                }
            }

            $country = null;
            if ($geo !== null && $ip !== '') {
                $country = $geo->country($ip); // local reader only; null -> render "—"
            }

            $out[] = array(
                'ip' => $ip,
                'c' => isset($row['c']) ? (int) $row['c'] : 0,
                'last' => isset($row['last']) ? (int) $row['last'] : 0,
                'ua' => $ua,
                'country' => is_string($country) ? $country : '',
                'velocity' => $velocity,
            );
        }

        return $out;
    }

    /** Compute mirror staleness in seconds (null when no mirror meta yet). Explicit null-guard, no `?->`. */
    private static function mirrorAge($store, $now)
    {
        if ($store === null) {
            return null;
        }
        try {
            $meta = $store->mirrorMeta();
        } catch (\Throwable $e) {
            return null;
        }
        if (is_array($meta) && isset($meta['generated_at'])) {
            return $now - (int) $meta['generated_at'];
        }

        return null;
    }

    /** One bounded state-slot read, fault-safe. */
    private static function slot($store, $key)
    {
        try {
            return $store->backend()->get($key);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** Clamp a raw page value to [1, MAX_PAGE] via absint (hostile input coerces to a bounded int). */
    private static function clampPage($raw)
    {
        $p = self::absInt($raw);
        if ($p < 1) {
            $p = 1;
        }
        if ($p > self::MAX_PAGE) {
            $p = self::MAX_PAGE;
        }

        return $p;
    }

    private static function table($wpdb)
    {
        $prefix = isset($wpdb->prefix) ? (string) $wpdb->prefix : 'wp_';

        return $prefix . self::TABLE;
    }

    private static function emptyData()
    {
        return array(
            'tiles' => array('total' => 0, 'events24h' => 0),
            'byAction' => array(),
            'byReason' => array(),
            'recent' => array(),
            'topIps' => array(),
            'rollups' => array(),
            'queueDepth' => null,
            'mirrorAgeSecs' => null,
            'paged' => 1,
            'perPage' => self::PER_PAGE,
            'hasNext' => false,
            'filterAction' => '',
        );
    }

    /** Run a scalar query callable, coerce to a non-negative int, degrade to 0 on any fault. */
    private static function guardInt($fn)
    {
        try {
            $v = call_user_func($fn);
        } catch (\Throwable $e) {
            return 0;
        }

        return ($v === null) ? 0 : (int) $v;
    }

    /** Run a rows query callable, always return a list of assoc arrays, degrade to [] on any fault. */
    private static function guardRows($fn)
    {
        try {
            $rows = call_user_func($fn);
        } catch (\Throwable $e) {
            return array();
        }
        if (!is_array($rows)) {
            return array();
        }
        $out = array();
        foreach ($rows as $r) {
            if (is_array($r)) {
                $out[] = $r;
            }
        }

        return $out;
    }

    // --- render (escapes every value at output) --------------------------------------------------

    /**
     * Echo the dashboard HTML. EVERY value is escaped here: attacker-controlled values (ip/path/ua/
     * method/country) go through esc() as text-node content only; the only attribute values are
     * absint-coerced pagination integers and the fixed action-filter whitelist.
     *
     * @param array $data the gather() result
     * @return void
     */
    public static function renderView(array $data)
    {
        echo '<div class="wrap"><h1>Honeypot Intel</h1>';
        echo '<p class="description">Read-only local intel from the honeypot hit store. Nothing here is sent to mainnet.</p>';

        self::renderTiles($data);
        self::renderCounts($data);
        self::renderTopIps($data['topIps']);
        self::renderRollups($data['rollups']);
        self::renderRecent($data);

        echo '</div>';
    }

    private static function renderTiles(array $data)
    {
        $total = (int) $data['tiles']['total'];
        $events24h = (int) $data['tiles']['events24h'];
        $queue = $data['queueDepth'];
        $age = $data['mirrorAgeSecs'];

        echo '<h2>Summary</h2><table class="widefat striped"><tbody>';
        echo '<tr><th scope="row">Total events</th><td>' . (int) $total . '</td></tr>';
        echo '<tr><th scope="row">Events (24h)</th><td>' . (int) $events24h . '</td></tr>';
        echo '<tr><th scope="row">Report queue depth</th><td>' . ($queue === null ? 'n/a' : (int) $queue) . '</td></tr>';
        echo '<tr><th scope="row">Blacklist mirror age</th><td>' . ($age === null ? 'never' : self::esc(self::humanAge((int) $age))) . '</td></tr>';
        echo '</tbody></table>';
    }

    private static function renderCounts(array $data)
    {
        echo '<h2>By action</h2>';
        self::renderKeyCount($data['byAction'], 'action', 'No events yet.');
        echo '<h2>By reason</h2>';
        self::renderKeyCount($data['byReason'], 'reason', 'No events yet.');
    }

    private static function renderKeyCount(array $rows, $keyField, $emptyMsg)
    {
        if ($rows === array()) {
            echo '<p>' . self::esc($emptyMsg) . '</p>';

            return;
        }
        echo '<table class="widefat striped"><tbody>';
        foreach ($rows as $row) {
            $label = isset($row[$keyField]) ? (string) $row[$keyField] : '';
            $count = isset($row['c']) ? (int) $row['c'] : 0;
            echo '<tr><td>' . self::esc($label) . '</td><td>' . (int) $count . '</td></tr>';
        }
        echo '</tbody></table>';
    }

    private static function renderTopIps(array $rows)
    {
        echo '<h2>Top attacker IPs (24h)</h2>';
        if ($rows === array()) {
            echo '<p>' . self::esc('No events yet.') . '</p>';

            return;
        }
        echo '<table class="widefat striped"><thead><tr>';
        echo '<th>IP</th><th>Hits (24h)</th><th>Last seen</th><th>Velocity (current 60s window)</th><th>Country</th><th>Recent UA</th>';
        echo '</tr></thead><tbody>';
        foreach ($rows as $row) {
            $ip = isset($row['ip']) ? (string) $row['ip'] : '';
            $c = isset($row['c']) ? (int) $row['c'] : 0;
            $last = isset($row['last']) ? (int) $row['last'] : 0;
            $velocity = isset($row['velocity']) ? $row['velocity'] : null;
            $country = isset($row['country']) ? (string) $row['country'] : '';
            $ua = isset($row['ua']) ? (string) $row['ua'] : '';
            echo '<tr>';
            echo '<td>' . self::esc($ip) . '</td>';
            echo '<td>' . (int) $c . '</td>';
            echo '<td>' . self::esc(self::humanTs($last)) . '</td>';
            echo '<td>' . ($velocity === null ? self::esc('—') : (int) $velocity) . '</td>';
            echo '<td>' . ($country === '' ? self::esc('—') : self::esc($country)) . '</td>';
            echo '<td>' . ($ua === '' ? self::esc('—') : self::esc($ua)) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

    private static function renderRollups(array $rows)
    {
        echo '<h2>Mass plugin/theme scan rollups</h2>';
        if ($rows === array()) {
            echo '<p>' . self::esc('No events yet.') . '</p>';

            return;
        }
        echo '<table class="widefat striped"><thead><tr>';
        echo '<th>IP</th><th>Path</th><th>Last seen</th><th>Rows</th>';
        echo '</tr></thead><tbody>';
        foreach ($rows as $row) {
            $ip = isset($row['ip']) ? (string) $row['ip'] : '';
            $path = isset($row['path']) ? (string) $row['path'] : '';
            $last = isset($row['last']) ? (int) $row['last'] : 0;
            $c = isset($row['c']) ? (int) $row['c'] : 0;
            echo '<tr>';
            echo '<td>' . self::esc($ip) . '</td>';
            echo '<td>' . self::esc($path) . '</td>';
            echo '<td>' . self::esc(self::humanTs($last)) . '</td>';
            echo '<td>' . (int) $c . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

    private static function renderRecent(array $data)
    {
        $rows = $data['recent'];
        $paged = (int) $data['paged'];
        $filterAction = self::validateFilter($data['filterAction']);

        echo '<h2>Recent events</h2>';
        self::renderFilter($filterAction);

        if ($rows === array()) {
            echo '<p>' . self::esc('No events yet.') . '</p>';

            return;
        }
        echo '<table class="widefat striped"><thead><tr>';
        echo '<th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Action</th><th>Reason</th><th>Status</th>';
        echo '</tr></thead><tbody>';
        foreach ($rows as $row) {
            $ts = isset($row['ts']) ? (int) $row['ts'] : 0;
            $ip = isset($row['ip']) ? (string) $row['ip'] : '';
            $method = isset($row['method']) ? (string) $row['method'] : '';
            $path = isset($row['path']) ? (string) $row['path'] : '';
            $action = isset($row['action']) ? (string) $row['action'] : '';
            $reason = isset($row['reason']) ? (string) $row['reason'] : '';
            $status = isset($row['status']) ? (int) $row['status'] : 0;
            echo '<tr>';
            echo '<td>' . self::esc(self::humanTs($ts)) . '</td>';
            echo '<td>' . self::esc($ip) . '</td>';
            echo '<td>' . self::esc($method) . '</td>';
            echo '<td>' . self::esc($path) . '</td>';
            echo '<td>' . self::esc($action) . '</td>';
            echo '<td>' . self::esc($reason) . '</td>';
            echo '<td>' . (int) $status . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';

        self::renderPagination($paged, $data['hasNext'], $filterAction);
    }

    /** Action filter: values come from a fixed whitelist, never from raw $_GET. */
    private static function renderFilter($selected)
    {
        $choices = self::filterChoices();
        echo '<form method="get" action="">';
        // The page slug is a constant, echoed into a hidden field as a safe attribute value.
        echo '<input type="hidden" name="page" value="' . self::escAttr(self::SLUG) . '">';
        echo '<label>Filter by action: <select name="fp_action">';
        foreach ($choices as $value => $label) {
            $isSel = ((string) $value === (string) $selected) ? ' selected' : '';
            echo '<option value="' . self::escAttr((string) $value) . '"' . $isSel . '>' . self::esc((string) $label) . '</option>';
        }
        echo '</select></label> ';
        echo '<button type="submit" class="button">Filter</button>';
        echo '</form>';
    }

    /** Pagination hrefs are built solely from absint integers + whitelist filter constants. */
    private static function renderPagination($paged, $hasNext, $filterAction)
    {
        $paged = self::absInt($paged);
        if ($paged < 1) {
            $paged = 1;
        }
        echo '<p class="tablenav-pages">';
        if ($paged > 1) {
            echo '<a class="button" href="' . self::escUrl(self::pageUrl($paged - 1, $filterAction)) . '">&laquo; Prev</a> ';
        }
        echo '<span class="paging-input">Page ' . (int) $paged . '</span> ';
        if ($hasNext) {
            echo '<a class="button" href="' . self::escUrl(self::pageUrl($paged + 1, $filterAction)) . '">Next &raquo;</a>';
        }
        echo '</p>';
    }

    /** Build a bookmarkable page URL from the constant slug + an absint page + a whitelist filter. */
    private static function pageUrl($page, $filterAction)
    {
        $page = self::absInt($page);
        if ($page < 1) {
            $page = 1;
        }
        if ($page > self::MAX_PAGE) {
            $page = self::MAX_PAGE;
        }
        $url = 'options-general.php?page=' . rawurlencode(self::SLUG) . '&paged=' . $page;
        $filter = self::validateFilter($filterAction);
        if ($filter !== '') {
            $url .= '&fp_action=' . rawurlencode($filter);
        }

        return $url;
    }

    // --- helpers ---------------------------------------------------------------------------------

    private static function humanTs($ts)
    {
        $ts = (int) $ts;
        if ($ts <= 0) {
            return '—';
        }

        return gmdate('Y-m-d H:i:s', $ts) . ' UTC';
    }

    private static function humanAge($secs)
    {
        $secs = (int) $secs;
        if ($secs < 0) {
            $secs = 0;
        }
        if ($secs < 60) {
            return $secs . 's ago';
        }
        if ($secs < 3600) {
            return (int) floor($secs / 60) . 'm ago';
        }
        if ($secs < 86400) {
            return (int) floor($secs / 3600) . 'h ago';
        }

        return (int) floor($secs / 86400) . 'd ago';
    }

    private static function absInt($v)
    {
        if (function_exists('absint')) {
            return (int) absint($v);
        }

        return abs((int) $v);
    }

    /** Escape a value for a TEXT node (esc_html, with the ENT_QUOTES fallback when WP is absent). */
    private static function esc($v)
    {
        if (function_exists('esc_html')) {
            return esc_html((string) $v);
        }

        return htmlspecialchars((string) $v, ENT_QUOTES);
    }

    /** Escape a value for an ATTRIBUTE (esc_attr, with the ENT_QUOTES fallback when WP is absent). */
    private static function escAttr($v)
    {
        if (function_exists('esc_attr')) {
            return esc_attr((string) $v);
        }

        return htmlspecialchars((string) $v, ENT_QUOTES);
    }

    /** Escape a URL (esc_url, with the ENT_QUOTES fallback when WP is absent). */
    private static function escUrl($v)
    {
        if (function_exists('esc_url')) {
            return esc_url((string) $v);
        }

        return htmlspecialchars((string) $v, ENT_QUOTES);
    }
}
