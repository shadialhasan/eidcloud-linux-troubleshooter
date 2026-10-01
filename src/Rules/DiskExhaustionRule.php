<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Rules;

use EidCloud\LinuxTroubleshooter\Collectors\LogCollector;
use EidCloud\LinuxTroubleshooter\Collectors\ProcessCollector;
use EidCloud\LinuxTroubleshooter\Models\DiagnosticReport;
use EidCloud\LinuxTroubleshooter\Models\Evidence;
use EidCloud\LinuxTroubleshooter\Remediation\RemediationPlan;
use EidCloud\LinuxTroubleshooter\Remediation\RemediationStep;
use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;

class DiskExhaustionRule implements RuleInterface
{
    public function getId(): string
    {
        return 'disk-space-exhaustion';
    }

    public function getDescription(): string
    {
        return 'Detects root and data filesystem storage exhaustion (>= 90% capacity).';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, 'disk')
            || str_contains($context, 'space')
            || str_contains($context, 'storage')
            || str_contains($context, 'full')
            || str_contains($context, 'inode')
            || str_contains($context, 'all');
    }

    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport {
        $disks = $processCollector->getDiskUsage();
        $criticalDisks = [];
        $evidence = [];

        foreach ($disks as $disk) {
            if ($disk['percent'] >= 90) {
                $criticalDisks[] = $disk;
                $evidence[] = new Evidence(
                    source: "df -hP {$disk['mount']}",
                    logSnippet: "Filesystem: {$disk['filesystem']} | Size: {$disk['size']} | Used: {$disk['used']} ({$disk['percent']}%) | Mount: {$disk['mount']}",
                    significance: "Critical disk capacity reached ({$disk['percent']}%). Services may fail to write logs, temp files, or session data."
                );
            }
        }

        if (empty($criticalDisks)) {
            return null;
        }

        $highestUsage = max(array_column($criticalDisks, 'percent'));
        $mountPoints = implode(', ', array_column($criticalDisks, 'mount'));

        $steps = [
            new RemediationStep(
                description: 'Vacuum systemd journal logs older than 3 days',
                command: 'journalctl --vacuum-time=3d',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'journalctl --disk-usage'
            ),
            new RemediationStep(
                description: 'Clean APT package cache archives',
                command: 'apt-get clean && apt-get autoremove -y',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'du -sh /var/cache/apt/archives 2>/dev/null'
            ),
            new RemediationStep(
                description: 'Rotate and compress oversized log files in /var/log',
                command: 'logrotate -f /etc/logrotate.conf 2>/dev/null || true',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'df -h /var'
            ),
        ];

        $plan = new RemediationPlan(
            title: 'Reclaim emergency disk space on ' . $mountPoints,
            steps: $steps,
            postCheckDescription: 'Verify disk usage is below 85% via `df -h`.'
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('disk', true)), 0, 8),
            issueType: 'DISK_SPACE_EXHAUSTION',
            service: 'filesystem / ' . $mountPoints,
            summary: "Storage exhaustion detected! Filesystem on {$mountPoints} is at {$highestUsage}% utilization.",
            confidence: 0.95,
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
