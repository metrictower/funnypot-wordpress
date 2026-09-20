<?php

declare(strict_types=1);

namespace Funnypot\WordPress\Tests\Unit;

use Funnypot\WordPress\Plugin;
use Funnypot\WordPress\Rules\RulesAutoUpdate;
use Funnypot\WordPress\Settings;

/**
 * The cron schedule decision + the deactivate() unschedule set — the unit-testable seams of the
 * otherwise integration-level Plugin wiring. desiredSchedule() is the pure helper Plugin::scheduleEvents
 * uses; cronHooks() is the set Plugin::deactivate() clears.
 */
final class RulesCronWiringTest extends TestCase
{
    private function settings(array $raw): Settings
    {
        return Settings::fromArray($raw, static function () {
            return null;
        });
    }

    public function testDesiredScheduleIsNullWhenOff(): void
    {
        $this->assertNull(RulesAutoUpdate::desiredSchedule($this->settings(array('rules_autoupdate_enabled' => false))));
    }

    public function testDesiredScheduleIsTheConfiguredIntervalWhenOn(): void
    {
        $daily = $this->settings(array('rules_autoupdate_enabled' => true)); // default interval
        $this->assertSame('daily', RulesAutoUpdate::desiredSchedule($daily));

        $hourly = $this->settings(array('rules_autoupdate_enabled' => true, 'rules_update_interval' => 'hourly'));
        $this->assertSame('hourly', RulesAutoUpdate::desiredSchedule($hourly));

        $twice = $this->settings(array('rules_autoupdate_enabled' => true, 'rules_update_interval' => 'twicedaily'));
        $this->assertSame('twicedaily', RulesAutoUpdate::desiredSchedule($twice));

        // A junk interval whitelists back to the default.
        $junk = $this->settings(array('rules_autoupdate_enabled' => true, 'rules_update_interval' => 'weekly'));
        $this->assertSame('daily', RulesAutoUpdate::desiredSchedule($junk));
    }

    public function testRulesPullHookIsInTheDeactivateUnscheduleSet(): void
    {
        $this->assertContains(Plugin::HOOK_RULES_PULL, Plugin::cronHooks());
    }
}
