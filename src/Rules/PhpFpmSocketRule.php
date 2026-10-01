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

class PhpFpmSocketRule implements RuleInterface
{
    public function getId(): string
    {
        return 'php-fpm-socket-starvation';
    }

    public function getDescription(): string
    {
        return 'Detects PHP-FPM socket starvation, max_children saturation, queue overflow, and permission denials.';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, 'php')
            || str_contains($context, 'fpm')
            || str_contains($context, 'socket')
            || str_contains($context, 'starvation')
            || str_contains($context, 'children')
            || str_contains($context, 'pool')
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

        // 1. Check PHP-FPM logs for max_children reached
        $logPaths = [
            '/var/log/php-fpm.log',
            '/var/log/php8.2-fpm.log',
            '/var/log/php8.3-fpm.log',
            '/var/log/php-fpm/www-error.log',
        ];

        $fpmLogContent = '';
        foreach ($logPaths as $path) {
            $snippet = $logCollector->getLogFileSnippet($path, 50);
            if ($snippet) {
                $fpmLogContent .= "\n" . $snippet;
            }
        }

        // Also check journalctl
        $fpmLogContent .= "\n" . $logCollector->getJournalLogs('php8.2-fpm', 40);
        $fpmLogContent .= "\n" . $logCollector->getJournalLogs('php-fpm', 40);

        if (str_contains($fpmLogContent, 'server reached pm.max_children setting')) {
            $lines = explode("\n", $fpmLogContent);
            $matched = array_filter($lines, fn($l) => str_contains($l, 'server reached pm.max_children'));
            $evidence[] = new Evidence(
                source: 'php-fpm log / journalctl',
                logSnippet: implode("\n", array_slice($matched, -2)),
                significance: 'All PHP-FPM child worker processes are saturated. New client connections are stalling in backlog queue.'
            );
            $confidence += 0.55;
            $summary = 'PHP-FPM worker pool is starved: pm.max_children threshold reached.';

            $remediationSteps[] = new RemediationStep(
                description: 'Increase pm.max_children and tune worker pool in /etc/php/*/fpm/pool.d/www.conf',
                command: 'sed -i "s/^pm.max_children = .*/pm.max_children = 50/" /etc/php/*/fpm/pool.d/www.conf 2>/dev/null || true',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'grep "pm.max_children" /etc/php/*/fpm/pool.d/www.conf 2>/dev/null'
            );
            $remediationSteps[] = new RemediationStep(
                description: 'Reload PHP-FPM service to apply tuned worker pool allocation',
                command: 'systemctl reload php*-fpm || systemctl reload php-fpm',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'systemctl is-active php*-fpm || systemctl is-active php-fpm'
            );
        }

        // 2. Check for Permission Denied on unix socket
        $nginxLog = $logCollector->getLogFileSnippet('/var/log/nginx/error.log', 40) ?? '';
        if (str_contains($nginxLog, 'Permission denied') && str_contains($nginxLog, '.sock')) {
            $lines = explode("\n", $nginxLog);
            $matched = array_filter($lines, fn($l) => str_contains($l, 'Permission denied') && str_contains($l, '.sock'));
            $evidence[] = new Evidence(
                source: '/var/log/nginx/error.log',
                logSnippet: implode("\n", array_slice($matched, -2)),
                significance: 'Nginx process (www-data) lacks file read/write permissions to connect to the PHP-FPM unix socket.'
            );
            $confidence += 0.50;
            if (empty($summary)) {
                $summary = 'PHP-FPM socket permission denied: www-data cannot connect to FastCGI unix domain socket.';
            } else {
                $summary .= ' Additionally, unix socket permissions are blocking connection.';
            }

            $remediationSteps[] = new RemediationStep(
                description: 'Fix unix socket file ownership to www-data:www-data',
                command: 'chown -R www-data:www-data /run/php/ 2>/dev/null || true',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'ls -la /run/php/*.sock 2>/dev/null'
            );
            $remediationSteps[] = new RemediationStep(
                description: 'Restart PHP-FPM to re-create unix socket with proper permissions',
                command: 'systemctl restart php*-fpm || systemctl restart php-fpm',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'systemctl is-active php*-fpm || systemctl is-active php-fpm'
            );
        }

        if (empty($evidence) || $confidence < 0.40) {
            return null;
        }

        $plan = new RemediationPlan(
            title: 'Resolve PHP-FPM worker saturation & socket access restrictions',
            steps: $remediationSteps,
            postCheckDescription: 'Check php-fpm status and verify active child processes and backlog drop.'
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('fpm', true)), 0, 8),
            issueType: 'PHP_FPM_SOCKET_STARVATION',
            service: 'php-fpm',
            summary: $summary,
            confidence: min(1.0, $confidence),
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
