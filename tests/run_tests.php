<?php

declare(strict_types=1);

// Zero-dependency PSR-4 autoloader for tests
spl_autoload_register(function (string $class) {
    $prefix = 'EidCloud\\LinuxTroubleshooter\\';
    $baseDir = __DIR__ . '/../src/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);

    // If it's in Tests namespace
    if (str_starts_with($relativeClass, 'Tests\\')) {
        $file = __DIR__ . '/' . substr($relativeClass, 6) . '.php';
    } else {
        $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';
    }

    if (file_exists($file)) {
        require_once $file;
    }
});

use EidCloud\LinuxTroubleshooter\Tests\TroubleshooterTest;

$runner = new TroubleshooterTest();
$success = $runner->runAll();

exit($success ? 0 : 1);
