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

class OomKillRule implements RuleInterface
{
    public function getId(): string
    {
        return 'kernel-oom-killer';
    }

    public function getDescription(): string
    {
        return 'Detects Linux kernel Out-Of-Memory (OOM) killer terminating processes and high memory pressure.';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, 'oom')
            || str_contains($context, 'memory')
            || str_contains($context, 'ram')
            || str_contains($context, 'killed')
            || str_contains($context, 'crash')
            || str_contains($context, 'all');
    }

    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport {
        $evidence = [];
        $confidence = 0.0;
        $killedProcesses = [];

        // 1. Inspect dmesg logs for OOM invocation
        $dmesg = $logCollector->getDmesgLogs(150);
        $journal = $logCollector->getJournalLogs('', 100);
        $combined = $dmesg . "\n" . $journal;

        if (preg_match_all('/(Out of memory: Kill process \d+ \(([^)]+)\)|Killed process \d+ \(([^)]+)\)|invoked oom-killer)/i', $combined, $matches)) {
            $matchedLines = [];
            foreach (explode("\n", $combined) as $line) {
                if (stripos($line, 'out of memory') !== false || stripos($line, 'oom-killer') !== false || stripos($line, 'killed process') !== false) {
                    $matchedLines[] = trim($line);
                }
            }

            // Extract names of killed processes
            foreach ($matches[2] as $name) {
                if (!empty($name)) {
                    $killedProcesses[] = $name;
                }
            }
            foreach ($matches[3] as $name) {
                if (!empty($name)) {
                    $killedProcesses[] = $name;
                }
            }
            $killedProcesses = array_unique($killedProcesses);

            $evidence[] = new Evidence(
                source: 'dmesg / kernel ring buffer',
                logSnippet: implode("\n", array_slice($matchedLines, -3)),
                significance: 'Kernel OOM Killer was triggered due to exhausted physical RAM and swap space.'
            );
            $confidence += 0.65;
        }

        // 2. Inspect current memory pressure
        $mem = $processCollector->getMemoryInfo();
        if ($mem['total_mb'] > 0 && $mem['percent_used'] > 90.0) {
            $evidence[] = new Evidence(
                source: 'free -m',
                logSnippet: "Total: {$mem['total_mb']}MB | Used: {$mem['used_mb']}MB | Avail: {$mem['available_mb']}MB ({$mem['percent_used']}% used)",
                significance: 'Critical memory pressure: System has less than 10% available memory.'
            );
            $confidence += 0.30;
        }

        if (empty($evidence) || $confidence < 0.40) {
            return null;
        }

        $killedStr = !empty($killedProcesses) ? implode(', ', $killedProcesses) : 'system services';
        $summary = "Kernel Out-Of-Memory (OOM) Killer activated! Terminated processes: {$killedStr}.";

        $steps = [
            new RemediationStep(
                description: 'Flush pagecache, dentries and inodes cache',
                command: 'sync && sysctl -w vm.drop_caches=3',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'free -m'
            ),
            new RemediationStep(
                description: 'Verify/create 2GB emergency swapfile if none exists',
                command: 'test -f /swapfile || (fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile)',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'swapon --show'
            ),
        ];

        // If php-fpm or nginx were victimized, add recovery restart
        foreach ($killedProcesses as $p) {
            if (str_contains($p, 'php')) {
                $steps[] = new RemediationStep(
                    description: "Restart OOM victim PHP-FPM service",
                    command: "systemctl restart php*-fpm || systemctl restart php-fpm",
                    isIdempotent: true,
                    requiresSudo: true,
                    verificationCommand: "systemctl is-active php*-fpm || systemctl is-active php-fpm"
                );
            }
            if (str_contains($p, 'nginx')) {
                $steps[] = new RemediationStep(
                    description: "Restart OOM victim Nginx service",
                    command: "systemctl restart nginx",
                    isIdempotent: true,
                    requiresSudo: true,
                    verificationCommand: "systemctl is-active nginx"
                );
            }
        }

        $plan = new RemediationPlan(
            title: 'Mitigate OOM memory starvation & restore killed services',
            steps: $steps,
            postCheckDescription: 'Check available system memory with `free -m` and verify process availability.'
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('oom', true)), 0, 8),
            issueType: 'KERNEL_OOM_KILL',
            service: 'kernel / memory-subsystem',
            summary: $summary,
            confidence: min(1.0, $confidence),
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
