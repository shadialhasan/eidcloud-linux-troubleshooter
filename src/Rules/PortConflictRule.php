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

class PortConflictRule implements RuleInterface
{
    public function getId(): string
    {
        return 'listening-port-conflict';
    }

    public function getDescription(): string
    {
        return 'Detects port binding conflicts (e.g. Apache binding to port 80/443 blocking Nginx).';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, 'port')
            || str_contains($context, 'bind')
            || str_contains($context, 'address already in use')
            || str_contains($context, 'apache')
            || str_contains($context, 'nginx')
            || str_contains($context, 'conflict')
            || str_contains($context, 'all');
    }

    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport {
        $ports = [80, 443];
        $conflicts = [];
        $evidence = [];

        // Check if Nginx or Apache has bind failures in journalctl
        $nginxJournal = $logCollector->getJournalLogs('nginx', 50);
        $hasBindError = str_contains($nginxJournal, 'bind() to 0.0.0.0:80 failed (98: Address already in use)')
            || str_contains($nginxJournal, 'Address already in use');

        foreach ($ports as $port) {
            $info = $processCollector->getListeningPortStatus($port);
            if ($info['listening'] && $info['process'] !== null) {
                // If apache2 is listening on 80/443 while nginx is failing
                if ((str_contains($info['process'], 'apache') || str_contains($info['process'], 'httpd')) && $hasBindError) {
                    $conflicts[] = [
                        'port' => $port,
                        'process' => $info['process'],
                        'pid' => $info['pid'],
                        'raw' => $info['raw'],
                    ];
                }
            }
        }

        if (empty($conflicts) && !$hasBindError) {
            return null;
        }

        $conflictingProc = !empty($conflicts) ? $conflicts[0]['process'] : 'another daemon';
        $portNum = !empty($conflicts) ? $conflicts[0]['port'] : 80;

        $evidence[] = new Evidence(
            source: 'ss / netstat / journalctl',
            logSnippet: !empty($conflicts) ? $conflicts[0]['raw'] : 'bind() to 0.0.0.0:80 failed (98: Address already in use)',
            significance: "Port {$portNum} is occupied by '{$conflictingProc}', preventing Nginx from binding to its designated listener."
        );

        $steps = [
            new RemediationStep(
                description: "Stop and disable conflicting service ({$conflictingProc})",
                command: "systemctl stop {$conflictingProc} && systemctl disable {$conflictingProc}",
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: "systemctl is-active {$conflictingProc}"
            ),
            new RemediationStep(
                description: "Restart Nginx web server to bind to port {$portNum}",
                command: 'systemctl restart nginx',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'systemctl is-active nginx'
            ),
        ];

        $plan = new RemediationPlan(
            title: "Release port {$portNum} from {$conflictingProc} & start Nginx",
            steps: $steps,
            postCheckDescription: "Verify Nginx is listening on port {$portNum} via `ss -tulpn`."
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('port', true)), 0, 8),
            issueType: 'PORT_BIND_CONFLICT',
            service: "port:{$portNum} / {$conflictingProc}",
            summary: "Port {$portNum} conflict: Process '{$conflictingProc}' is already bound to port {$portNum}, blocking Nginx.",
            confidence: 0.90,
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
