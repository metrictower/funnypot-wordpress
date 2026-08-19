<?php

/**
 * Unit-suite bootstrap. Pure PHPUnit + Brain Monkey — no real WordPress, no DB.
 * WP functions are mocked per-test via Brain\Monkey (see tests/Unit/TestCase.php).
 */

declare(strict_types=1);

$autoload = __DIR__ . '/../vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "Run `composer install` first (vendor/autoload.php missing).\n");
    exit(1);
}

require $autoload;
