<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\System;

interface CommandExecutorInterface
{
    /**
     * Executes a system command and returns stdout, stderr, and exit code.
     *
     * @param string $command
     * @return ExecutionResult
     */
    public function execute(string $command): ExecutionResult;

    /**
     * Checks if a file exists on the target system.
     */
    public function fileExists(string $path): bool;

    /**
     * Reads file contents if available.
     */
    public function readFile(string $path): ?string;
}
