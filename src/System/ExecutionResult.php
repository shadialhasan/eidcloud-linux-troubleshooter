<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\System;

final class ExecutionResult
{
    public function __construct(
        public readonly int $exitCode,
        public readonly string $stdout,
        public readonly string $stderr = '',
        public readonly string $command = ''
    ) {}

    public function isSuccess(): bool
    {
        return $this->exitCode === 0;
    }

    public function getOutput(): string
    {
        return trim($this->stdout !== '' ? $this->stdout : $this->stderr);
    }
}
