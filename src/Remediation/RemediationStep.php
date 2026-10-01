<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Remediation;

use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;
use EidCloud\LinuxTroubleshooter\System\ExecutionResult;

final class RemediationStep
{
    public function __construct(
        public readonly string $description,
        public readonly string $command,
        public readonly bool $isIdempotent = true,
        public readonly bool $requiresSudo = true,
        public readonly ?string $verificationCommand = null
    ) {}

    public function toArray(): array
    {
        return [
            'description' => $this->description,
            'command' => $this->command,
            'is_idempotent' => $this->isIdempotent,
            'requires_sudo' => $this->requiresSudo,
            'verification_command' => $this->verificationCommand,
        ];
    }
}
