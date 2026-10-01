<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Remediation;

use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;

final class RemediationPlan
{
    /**
     * @param string $title
     * @param array<RemediationStep> $steps
     * @param string|null $postCheckDescription
     */
    public function __construct(
        public readonly string $title,
        public readonly array $steps = [],
        public readonly ?string $postCheckDescription = null
    ) {}

    /**
     * Executes the plan steps sequentially.
     *
     * @param CommandExecutorInterface $executor
     * @return array{success: bool, executed: array<array{step: string, command: string, exit_code: int, output: string}>, error: ?string}
     */
    public function execute(CommandExecutorInterface $executor): array
    {
        $executed = [];

        foreach ($this->steps as $step) {
            $result = $executor->execute($step->command);
            $executed[] = [
                'step' => $step->description,
                'command' => $step->command,
                'exit_code' => $result->exitCode,
                'output' => $result->getOutput(),
            ];

            if (!$result->isSuccess()) {
                return [
                    'success' => false,
                    'executed' => $executed,
                    'error' => "Step failed [{$step->description}]: " . ($result->stderr ?: $result->stdout),
                ];
            }
        }

        return [
            'success' => true,
            'executed' => $executed,
            'error' => null,
        ];
    }

    public function toArray(): array
    {
        return [
            'title' => $this->title,
            'step_count' => count($this->steps),
            'steps' => array_map(fn(RemediationStep $s) => $s->toArray(), $this->steps),
            'post_check' => $this->postCheckDescription,
        ];
    }
}
