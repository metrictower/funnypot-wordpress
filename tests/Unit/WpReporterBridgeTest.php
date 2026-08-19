<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Funnypot\Policy\ReportIntent;
use Honeypot\WP\Report\WpReporterBridge;
use Honeypot\WP\Settings;
use Honeypot\WP\Tests\Fakes\InMemoryReportQueue;
use Honeypot\WP\Tests\Fakes\RecordingTransport;

final class WpReporterBridgeTest extends TestCase
{
    private function settings(array $extra = array())
    {
        return Settings::fromArray(array_merge(array(
            'report_enabled' => true,
            'mainnet_base_url' => 'https://mainnet.example',
            'mainnet_key' => 'KEY123',
            'self_ips' => array('192.0.2.55'),
        ), $extra), static function () {
            return null;
        });
    }

    public function testEnqueueIntentMapsArgOrderM8(): void
    {
        $queue = new InMemoryReportQueue();
        $bridge = new WpReporterBridge($this->settings(), $queue, new RecordingTransport());

        $intent = new ReportIntent('203.0.113.9', 'attack-class', 'honeypot', 200, array('bad-bot'), 'dk1');
        $bridge->enqueueIntent($intent);

        $this->assertCount(1, $queue->rows);
        $row = $queue->rows[0];
        // comment is the comment, categories is the category CSV — NOT swapped (M8 regression guard).
        $this->assertSame('attack-class', $row['comment']);
        $this->assertSame('bad-bot', $row['categories']);
        $this->assertSame('203.0.113.9', $row['ip']);
    }

    public function testInertWithoutKey(): void
    {
        $queue = new InMemoryReportQueue();
        $bridge = new WpReporterBridge($this->settings(array('mainnet_key' => '')), $queue, new RecordingTransport());

        $res = $bridge->enqueue('203.0.113.9', 'attack-class', '21');
        $this->assertFalse($res['queued']);
        $this->assertCount(0, $queue->rows, 'empty MAINNET_KEY => nothing queued (D2)');
    }

    public function testSkipsSelfIp(): void
    {
        $queue = new InMemoryReportQueue();
        $bridge = new WpReporterBridge($this->settings(), $queue, new RecordingTransport());

        $res = $bridge->enqueue('192.0.2.55', 'x', '21'); // the configured self ip
        $this->assertFalse($res['queued']);
        $this->assertSame('self', $res['reason']);
    }

    public function testSkipsPrivateIp(): void
    {
        $queue = new InMemoryReportQueue();
        $bridge = new WpReporterBridge($this->settings(), $queue, new RecordingTransport());

        $res = $bridge->enqueue('10.0.0.9', 'x', '21');
        $this->assertFalse($res['queued']);
        $this->assertSame('not a public ip', $res['reason']);
    }

    public function testFailSafeWhenSelfIpsEmpty(): void
    {
        $queue = new InMemoryReportQueue();
        $bridge = new WpReporterBridge($this->settings(array('self_ips' => array())), $queue, new RecordingTransport());

        $res = $bridge->enqueue('203.0.113.9', 'x', '21');
        $this->assertFalse($res['queued']);
        $this->assertSame('self ips not configured', $res['reason']);
    }

    public function testDedupWithinWindow(): void
    {
        $queue = new InMemoryReportQueue();
        $bridge = new WpReporterBridge($this->settings(), $queue, new RecordingTransport());

        $first = $bridge->enqueue('203.0.113.9', 'x', '21');
        $this->assertTrue($first['queued']);
        $second = $bridge->enqueue('203.0.113.9', 'y', '21');
        $this->assertFalse($second['queued']);
        $this->assertSame('deduped', $second['reason']);
    }

    public function testDrainPostsToV1ReportWithSensorIdBody(): void
    {
        $queue = new InMemoryReportQueue('sensor-abc');
        $transport = new RecordingTransport(array(
            array('status' => 200, 'body' => '{"data":{"ok":true}}', 'headers' => array()),
        ));
        $bridge = new WpReporterBridge($this->settings(), $queue, $transport);

        $bridge->enqueue('203.0.113.9', 'attack-class', '21');
        $result = $bridge->drain(50);

        $this->assertSame(1, $result['sent']);
        $this->assertCount(1, $transport->posts);
        $post = $transport->posts[0];

        // Base URL had no path; the reporter appended /v1/report itself (D1).
        $this->assertSame('https://mainnet.example/v1/report', $post['url']);
        $this->assertContains('Key: KEY123', $post['headers']);

        parse_str($post['body'], $fields);
        $this->assertSame('203.0.113.9', $fields['ip']);
        $this->assertSame('21', $fields['categories']);
        $this->assertSame('attack-class', $fields['comment']);
        $this->assertArrayHasKey('timestamp', $fields);
        $this->assertSame('sensor-abc', $fields['sensor_id']);
    }

    public function testDrain5xxRetriesThenDropsAtMaxAttempts(): void
    {
        $queue = new InMemoryReportQueue();
        // Always 500 -> transport-class failure; F's Reporter retries up to MAX_ATTEMPTS then drops.
        $transport = new RecordingTransport(array(), array('status' => 500, 'body' => '', 'headers' => array()));
        $bridge = new WpReporterBridge($this->settings(), $queue, $transport);

        $bridge->enqueue('203.0.113.9', 'attack-class', '21');
        // 3 drains -> 3 attempts -> dropped.
        $bridge->drain(50);
        $bridge->drain(50);
        $r3 = $bridge->drain(50);
        $this->assertSame(0, $queue->count(), 'the row is dropped after MAX_ATTEMPTS transport failures');
        $this->assertSame(1, $r3['failed']);
    }
}
