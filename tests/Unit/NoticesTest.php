<?php

declare(strict_types=1);

namespace Honeypot\WP\Tests\Unit;

use Honeypot\WP\Admin\Notices;

final class NoticesTest extends TestCase
{
    public function testNoNoticeWhenBeforeNotConfigured(): void
    {
        $this->assertNull(Notices::noticeFor('not running', false));
        $this->assertNull(Notices::noticeFor('n/a', false));
    }

    public function testNoNoticeWhenMountedAtMuPlugin(): void
    {
        $this->assertNull(Notices::noticeFor('mu-plugin', true));
    }

    public function testDegradedMountRaisesNotice(): void
    {
        $degraded = Notices::noticeFor('plugins_loaded (degraded)', true);
        $this->assertNotNull($degraded);
        $this->assertStringContainsString('plugins_loaded', $degraded);

        $notRunning = Notices::noticeFor('not running', true);
        $this->assertNotNull($notRunning);
        $this->assertStringContainsString('not running', $notRunning);
    }
}
