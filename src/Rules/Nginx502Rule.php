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

class Nginx502Rule implements RuleInterface
{
    public function getId(): string
    {
        return 'nginx-502-bad-gateway';
    }

    public function getDescription(): string
    {
        return 'Detects Nginx 502/504 Bad Gateway caused by PHP-FPM service stoppage or socket connection refusal.';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, '502')
            || str_contains($context, '504')
            || str_contains($context, 'bad gateway')
            || str_contains($context, 'nginx')
            || str_contains($context, 'php-fpm')
            || str_contains($context, 'all');
    }

    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport {
        $evidence = [];
        $confidence = 0.0;
        $summary = '';
        $remediationSteps = [];

        // 1. Inspect Nginx Error Log
        $nginxLogSnippet = $logCollector->getLogFileSnippet('/var/log/nginx/error.log', 30);
        $journalNginx = $logCollector->getJournalLogs('nginx', 30);
        $combinedNginxLogs = ($nginxLogSnippet ?? '') . "\n" . $journalNginx;

        $hasConnectionRefused = str_contains($combinedNginxLogs, 'connect() failed (111: Connection refused) while connecting to upstream')
            || str_contains($combinedNginxLogs, '111: Connection refused');

        $hasNoRouteOrNotFound = str_contains($combinedNginxLogs, 'connect() to unix:/var/run/php/')
            && (str_contains($combinedNginxLogs, 'No such file or directory') || str_contains($combinedNginxLogs, 'failed (2: No such file or directory)'));

        if ($hasConnectionRefused || $hasNoRouteOrNotFound) {
            $lines = explode("\n", $combinedNginxLogs);
            $matchedLines = array_filter($lines, fn($l) => str_contains($l, 'Connection refused') || str_contains($l, 'failed (2: No such file or directory)'));
            $snippet = implode("\n", array_slice($matchedLines, -3));

            $evidence[] = new Evidence(
                source: '/var/log/nginx/error.log',
                logSnippet: $snippet ?: 'connect() failed (111: Connection refused) while connecting to upstream',
                significance: 'Nginx upstream proxy failed to establish connection to FastCGI backend.'
            );
            $confidence += 0.45;
        }

        // 2. Inspect PHP-FPM service status
        $fpmVersions = ['php-fpm', 'php8.3-fpm', 'php8.2-fpm', 'php8.1-fpm', 'php8.0-fpm', 'php7.4-fpm'];
        $activeFpmService = null;
        $failedFpmService = null;

        foreach ($fpmVersions as $service) {
            if ($processCollector->isServiceActive($service)) {
                $activeFpmService = $service;
                break;
            } else {
                $statusText = $processCollector->getServiceStatus($service);
                if (str_contains($statusText, 'inactive (dead)') || str_contains($statusText, 'failed')) {
                    $failedFpmService = $service;
                    break;
                }
            }
        }

        if ($failedFpmService !== null && $activeFpmService === null) {
            $evidence[] = new Evidence(
                source: "systemctl status {$failedFpmService}",
                logSnippet: "Active: inactive (dead) / failed",
                significance: "PHP-FPM daemon {$failedFpmService} is stopped or crashed, preventing socket listener from accepting requests."
            );
            $confidence += 0.50;

            $summary = "Nginx returned 502 Bad Gateway because upstream backend service '{$failedFpmService}' is inactive/stopped.";
            $remediationSteps[] = new RemediationStep(
                description: "Start and enable {$failedFpmService} daemon",
                command: "systemctl enable --now {$failedFpmService}",
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: "systemctl is-active {$failedFpmService}"
            );
            $remediationSteps[] = new RemediationStep(
                description: "Reload Nginx to re-establish proxy socket connections",
                command: "systemctl reload nginx",
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: "systemctl is-active nginx"
            );
        } elseif ($activeFpmService === null && $hasConnectionRefused) {
            $targetFpm = 'php8.2-fpm';
            $confidence += 0.40;
            $summary = "Nginx 502 Bad Gateway: Upstream FastCGI backend is unreachable. PHP-FPM is not responding.";
            $remediationSteps[] = new RemediationStep(
                description: "Start PHP-FPM service",
                command: "systemctl restart php-fpm || systemctl restart {$targetFpm}",
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: "systemctl is-active php-fpm || systemctl is-active {$targetFpm}"
            );
        }

        if (empty($evidence) || $confidence < 0.40) {
            return null;
        }

        $plan = new RemediationPlan(
            title: "Restore PHP-FPM socket & restart upstream connection",
            steps: $remediationSteps,
            postCheckDescription: "Verify Nginx upstream responds with HTTP 200/302 and FastCGI socket is active."
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('nginx502', true)), 0, 8),
            issueType: 'NGINX_502_BAD_GATEWAY',
            service: 'nginx / php-fpm',
            summary: $summary,
            confidence: min(1.0, $confidence),
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
