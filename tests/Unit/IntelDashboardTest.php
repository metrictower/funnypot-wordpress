<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Admin\IntelDashboard;
use Funnypot\WordPress\Geo\WpGeoIp;
use Funnypot\WordPress\Tests\Fakes\InMemoryBackend;
use Funnypot\WordPress\Tests\Fakes\MutableClock;
use Funnypot\WordPress\WpStateStore;

/**
 * Escaping tests run against REAL escaping: esc_html/esc_attr/esc_url are left UNSTUBBED, so
 * function_exists() is false in the unit process and the production helper's htmlspecialchars(ENT_QUOTES)
 * fallback performs the escaping. Never stub them as identity/returnArg — that would let a raw-echo bug
 * pass green. gather() is exercised over a fake $wpdb so the data path needs no live DB.
 */
final class IntelDashboardTest extends TestCase
{
    private function store(MutableClock $clock): WpStateStore
    {
        return new WpStateStore(new InMemoryBackend($clock->asCallable()), $clock);
    }

    /** The crux (text context): a hostile UA/path renders inert as escaped text, never raw markup. */
    public function testEscapesHostileUaAndPathText(): void
    {
        $data = self::emptyData();
        $data['recent'] = array(array(
            'id' => 1,
            'ts' => 1000000,
            'ip' => '203.0.113.5',
            'method' => 'GET',
            'path' => '/x"><script>alert(1)</script>',
            'action' => 'log',
            'reason' => 'login_failed',
            'status' => 0,
        ));
        $data['topIps'] = array(array(
            'ip' => '203.0.113.5',
            'c' => 9,
            'last' => 1000000,
            'ua' => '"><img src=x onerror=alert(1)>',
            'country' => '',
            'velocity' => 3,
        ));

        $html = self::capture($data);

        // The raw markup must be neutralised — no live tags, no quote-then-angle breakout...
        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringNotContainsString('"><script', $html);
        $this->assertStringNotContainsString('"><img', $html);
        // ...and the escaped form is present (proves the escaper actually ran, not a strip).
        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringContainsString('&lt;img', $html);
        $this->assertStringContainsString('&quot;', $html);
    }

    /** MUST-FIX 3: no attacker-controlled value ever lands in an attribute context. */
    public function testNoAttackerValueInAttributeContext(): void
    {
        $hostileIp = '1.2.3.4" onmouseover="alert(1)';
        $hostilePath = '/p"><script>evil()</script>';
        $hostileUa = '"></td><script>x()</script>';

        $data = self::emptyData();
        $data['paged'] = 2;
        $data['hasNext'] = true;
        $data['recent'] = array(array(
            'id' => 7,
            'ts' => 1000000,
            'ip' => $hostileIp,
            'method' => 'POST',
            'path' => $hostilePath,
            'action' => 'deceive',
            'reason' => 'xmlrpc_multicall',
            'status' => 0,
        ));
        $data['topIps'] = array(array(
            'ip' => $hostileIp,
            'c' => 5,
            'last' => 1000000,
            'ua' => $hostileUa,
            'country' => '',
            'velocity' => null,
        ));

        $html = self::capture($data);

        // No hostile substring appears immediately after an attribute opener (`="`) — i.e. never in an
        // attribute value. Attacker values live only inside `>...<` text nodes.
        foreach (array($hostileIp, $hostilePath, $hostileUa) as $needle) {
            $this->assertStringNotContainsString('="' . $needle, $html, 'attacker value leaked into an attribute');
        }
        // The hostile double-quote never appears raw (it is escaped to &quot; inside the text node),
        // so it can never close an attribute delimiter.
        $this->assertStringNotContainsString('1.2.3.4"', $html);
        $this->assertStringContainsString('&quot;', $html);
        // Pagination hrefs are built from the absint page + constant slug only.
        $this->assertMatchesRegularExpression('/href="[^"]*paged=\d+[^"]*"/', $html);
    }

    /** gather() over a fake $wpdb builds the tiles, ordered top IPs, and enriches from state slots. */
    public function testGatherBuildsTilesAndLists(): void
    {
        $clock = new MutableClock(2000000);
        $store = $this->store($clock);
        // A recent UA + current-window velocity for the top IP, via a FP-0488 aggregate slot.
        $store->backend()->set('capture_agg:login:9.9.9.9', array('ua' => 'BadBot/1', 'count' => 7), 3600);

        $wpdb = new FakeWpdb();
        $wpdb->total = 42;
        $wpdb->events24h = 10;
        $wpdb->byAction = array(array('action' => 'log', 'c' => 30), array('action' => 'deceive', 'c' => 12));
        $wpdb->byReason = array(array('reason' => 'mass_plugin_scan', 'c' => 20));
        $wpdb->recent = array(array('id' => 1, 'ts' => 1999000, 'ip' => '1.2.3.4', 'method' => 'GET', 'path' => '/wp-login.php', 'action' => 'log', 'reason' => 'login_failed', 'status' => 0));
        $wpdb->topIps = array(
            array('ip' => '9.9.9.9', 'c' => 100, 'last' => 1999500),
            array('ip' => '8.8.8.8', 'c' => 50, 'last' => 1999000),
        );
        $wpdb->rollups = array(array('ip' => '7.7.7.7', 'path' => '/wp-content/plugins/*', 'last' => 1998000, 'c' => 500));

        $data = IntelDashboard::gather(array(
            'wpdb' => $wpdb,
            'store' => $store,
            'reporter' => new FakeReporter(3),
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => '',
            'now' => 2000000,
        ));

        $this->assertSame(42, $data['tiles']['total']);
        $this->assertSame(10, $data['tiles']['events24h']);
        $this->assertCount(2, $data['byAction']);
        $this->assertSame('9.9.9.9', $data['topIps'][0]['ip']); // count desc
        $this->assertSame('BadBot/1', $data['topIps'][0]['ua']);
        $this->assertSame(7, $data['topIps'][0]['velocity']);
        $this->assertSame('', $data['topIps'][0]['country']); // no local reader -> degrades
        $this->assertSame('/wp-login.php', $data['recent'][0]['path']);
        $this->assertSame(3, $data['queueDepth']);

        // Renders without fatals over real data.
        $html = self::capture($data);
        $this->assertStringContainsString('9.9.9.9', $html);
        $this->assertStringContainsString('BadBot/1', $html);
    }

    /** Empty result sets -> empty arrays from gather(), "No events yet." from renderView, no fatal. */
    public function testEmptyTablesDegrade(): void
    {
        $clock = new MutableClock(2000000);
        $data = IntelDashboard::gather(array(
            'wpdb' => new FakeWpdb(), // all-empty defaults
            'store' => $this->store($clock),
            'reporter' => null,
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => '',
            'now' => 2000000,
        ));

        $this->assertSame(array(), $data['recent']);
        $this->assertSame(array(), $data['topIps']);
        $this->assertNull($data['queueDepth']);

        $html = self::capture($data);
        $this->assertStringContainsString('No events yet.', $html);
    }

    /** Hostile ?paged values coerce to a bounded page/offset (never negative, never beyond MAX_PAGE). */
    public function testPaginationIsBounded(): void
    {
        foreach (array('abc' => 1, '-5' => 5, '99999999' => IntelDashboard::MAX_PAGE) as $raw => $expectedPage) {
            $wpdb = new FakeWpdb();
            $data = IntelDashboard::gather(array(
                'wpdb' => $wpdb,
                'store' => null,
                'reporter' => null,
                'geo' => new WpGeoIp(null),
                'paged' => (string) $raw,
                'filterAction' => '',
                'now' => 2000000,
            ));

            $this->assertSame($expectedPage, $data['paged'], "paged=$raw");
            $this->assertLessThanOrEqual(IntelDashboard::MAX_PAGE, $data['paged']);
            // The recent-events query's OFFSET is derived from the clamped page and is never negative.
            $offset = ($data['paged'] - 1) * $data['perPage'];
            $this->assertGreaterThanOrEqual(0, $offset);
            $this->assertStringContainsString('OFFSET ' . $offset, $wpdb->lastRecentSql);
        }
    }

    /** Render performs zero network I/O: the reporter is only asked for its count, never drained. */
    public function testNoNetworkOnRender(): void
    {
        $reporter = new FakeReporter(5);
        $data = IntelDashboard::gather(array(
            'wpdb' => new FakeWpdb(),
            'store' => $this->store(new MutableClock(2000000)),
            'reporter' => $reporter,
            'geo' => new WpGeoIp(null), // strictly local; null reader -> country "—"
            'paged' => 1,
            'filterAction' => '',
            'now' => 2000000,
        ));

        $this->assertSame(5, $data['queueDepth']);
        $this->assertContains('queueCount', $reporter->calls);
        $this->assertNotContains('drain', $reporter->calls); // no drain / no socket on render
    }

    /** MUST-FIX 1: null reporter + null mirror meta degrade to n/a / never with no fatal, no `?->`. */
    public function testQueueAndMirrorNullSafe(): void
    {
        $clock = new MutableClock(2000000);
        $store = $this->store($clock); // no mirror meta set -> mirrorMeta() returns null
        $data = IntelDashboard::gather(array(
            'wpdb' => new FakeWpdb(),
            'store' => $store,
            'reporter' => null,
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => '',
            'now' => 2000000,
        ));

        $this->assertNull($data['queueDepth']);
        $this->assertNull($data['mirrorAgeSecs']);

        $html = self::capture($data);
        $this->assertStringContainsString('n/a', $html);   // queue depth
        $this->assertStringContainsString('never', $html);  // mirror age
    }

    /** Mirror age is computed from mirror meta when present. */
    public function testMirrorAgeFromMeta(): void
    {
        $clock = new MutableClock(2000000);
        $store = $this->store($clock);
        $store->putMirror(array(), 'etag', 1999000, 86400); // generated_at 1000s before now

        $data = IntelDashboard::gather(array(
            'wpdb' => new FakeWpdb(),
            'store' => $store,
            'reporter' => null,
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => '',
            'now' => 2000000,
        ));

        $this->assertSame(1000, $data['mirrorAgeSecs']);
    }

    /** The action filter is CONSUMED: a whitelist value reaches the recent-events WHERE clause. */
    public function testFilterActionIsConsumed(): void
    {
        $wpdb = new FakeWpdb();
        IntelDashboard::gather(array(
            'wpdb' => $wpdb,
            'store' => null,
            'reporter' => null,
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => 'block',
            'now' => 2000000,
        ));
        $this->assertStringContainsString('WHERE action =', $wpdb->lastRecentSql);
        $this->assertStringContainsString('block', $wpdb->lastRecentSql);

        // A hostile filter value is dropped (no WHERE action clause).
        $wpdb2 = new FakeWpdb();
        IntelDashboard::gather(array(
            'wpdb' => $wpdb2,
            'store' => null,
            'reporter' => null,
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => '"><script>',
            'now' => 2000000,
        ));
        $this->assertStringNotContainsString('WHERE action =', $wpdb2->lastRecentSql);
    }

    // --- helpers ---------------------------------------------------------------------------------

    /**
     * FP-0493 N1 (stored-XSS guard): the captured pingback `targets` field is verbatim attacker input.
     * renderView MUST escape every target as text — never emit it raw or in an attribute.
     */
    public function testEscapesHostilePingbackTargets(): void
    {
        $data = self::emptyData();
        $data['pingbackTargets'] = array(array(
            'ip' => '203.0.113.9',
            'count' => 4,
            'targets' => array(
                'http://169.254.169.254/latest/meta-data/',
                '"><script>alert(document.cookie)</script>',
                'http://evil.example/"><img src=x onerror=alert(1)>',
            ),
        ));

        $html = self::capture($data);

        // No live markup breaks out of the cell...
        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringNotContainsString('"><script', $html);
        $this->assertStringNotContainsString('"><img', $html);
        // ...the escaped form proves the escaper ran (not a strip)...
        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringContainsString('&quot;', $html);
        // ...and the benign metadata target still renders (escaped text).
        $this->assertStringContainsString('169.254.169.254', $html);
    }

    /** gather() reads the pingback SSRF targets from the local aggregate slot for each top IP. */
    public function testGatherPingbackTargetsFromSlot(): void
    {
        $clock = new MutableClock(2000000);
        $store = $this->store($clock);
        $store->backend()->set('capture_agg:pingback:9.9.9.9', array(
            'count' => 3,
            'ua' => 'BadBot/1',
            'targets' => array('http://169.254.169.254/', 'http://internal.host/'),
        ), 3600);

        $wpdb = new FakeWpdb();
        $wpdb->topIps = array(array('ip' => '9.9.9.9', 'c' => 30, 'last' => 1999500));

        $data = IntelDashboard::gather(array(
            'wpdb' => $wpdb,
            'store' => $store,
            'reporter' => null,
            'geo' => new WpGeoIp(null),
            'paged' => 1,
            'filterAction' => '',
            'now' => 2000000,
        ));

        $this->assertCount(1, $data['pingbackTargets']);
        $this->assertSame('9.9.9.9', $data['pingbackTargets'][0]['ip']);
        $this->assertContains('http://169.254.169.254/', $data['pingbackTargets'][0]['targets']);
    }

    private static function capture(array $data): string
    {
        ob_start();
        IntelDashboard::renderView($data);

        return (string) ob_get_clean();
    }

    private static function emptyData(): array
    {
        return array(
            'tiles' => array('total' => 0, 'events24h' => 0),
            'byAction' => array(),
            'byReason' => array(),
            'recent' => array(),
            'topIps' => array(),
            'pingbackTargets' => array(),
            'rollups' => array(),
            'queueDepth' => null,
            'mirrorAgeSecs' => null,
            'paged' => 1,
            'perPage' => 50,
            'hasNext' => false,
            'filterAction' => '',
        );
    }
}

/**
 * A minimal $wpdb double: prepare() does naive printf-style %d/%s substitution (WP placeholders are
 * printf-compatible) and get_var/get_results return canned rows keyed by the query shape.
 */
final class FakeWpdb
{
    public $prefix = 'wp_';
    public $total = 0;
    public $events24h = 0;
    public $byAction = array();
    public $byReason = array();
    public $recent = array();
    public $topIps = array();
    public $rollups = array();
    public $lastRecentSql = '';

    public function prepare($sql, ...$args)
    {
        $out = str_replace('%s', "'%s'", $sql);

        return vsprintf($out, $args);
    }

    public function get_var($sql)
    {
        return (strpos($sql, 'WHERE ts') !== false) ? $this->events24h : $this->total;
    }

    public function get_results($sql, $type = null)
    {
        if (strpos($sql, 'GROUP BY ip, path') !== false) {
            return $this->rollups;
        }
        if (strpos($sql, 'GROUP BY action') !== false) {
            return $this->byAction;
        }
        if (strpos($sql, 'GROUP BY reason') !== false) {
            return $this->byReason;
        }
        if (strpos($sql, 'GROUP BY ip') !== false) {
            return $this->topIps;
        }
        if (strpos($sql, 'SELECT id, ts, ip') !== false) {
            $this->lastRecentSql = $sql;

            return $this->recent;
        }

        return array();
    }
}

/** A reporter double that records which methods were called (drain must never fire on render). */
final class FakeReporter
{
    /** @var int */
    private $count;
    /** @var array<int,string> */
    public $calls = array();

    public function __construct($count = 0)
    {
        $this->count = (int) $count;
    }

    public function queueCount()
    {
        $this->calls[] = 'queueCount';

        return $this->count;
    }

    public function drain($limit = 200)
    {
        $this->calls[] = 'drain';

        return 0;
    }
}
