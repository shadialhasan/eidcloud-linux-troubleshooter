<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Rules;

use EidCloud\LinuxTroubleshooter\Models\DiagnosticReport;
use EidCloud\LinuxTroubleshooter\Collectors\LogCollector;
use EidCloud\LinuxTroubleshooter\Collectors\ProcessCollector;
use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;

interface RuleInterface
{
    /**
     * Unique identifier for the rule (e.g. 'nginx-502-bad-gateway').
     */
    public function getId(): string;

    /**
     * Human-readable description of what this rule inspects.
     */
    public function getDescription(): string;

    /**
     * Checks if this rule should evaluate based on query or general audit.
     */
    public function supports(string $context): bool;

    /**
     * Evaluates system status and returns a DiagnosticReport or null if no issue found.
     */
    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport;
}
