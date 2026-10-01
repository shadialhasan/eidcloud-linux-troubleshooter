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

class UfwFirewallRule implements RuleInterface
{
    public function getId(): string
    {
        return 'ufw-firewall-block';
    }

    public function getDescription(): string
    {
        return 'Detects UFW active firewall blocking HTTP (80) or HTTPS (443) traffic.';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, 'firewall')
            || str_contains($context, 'ufw')
            || str_contains($context, 'iptables')
            || str_contains($context, 'blocked')
            || str_contains($context, 'timeout')
            || str_contains($context, 'cannot reach')
            || str_contains($context, 'all');
    }

    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport {
        $ufw = $processCollector->getUfwStatus();

        if (!$ufw['active']) {
            return null;
        }

        // Check if 80 and 443 are allowed
        $rulesJoined = implode(' ', $ufw['rules']);
        $has80 = str_contains($rulesJoined, '80') || str_contains($rulesJoined, 'Nginx Full') || str_contains($rulesJoined, 'Nginx HTTP') || str_contains($rulesJoined, 'Apache');
        $has443 = str_contains($rulesJoined, '443') || str_contains($rulesJoined, 'Nginx Full') || str_contains($rulesJoined, 'Nginx HTTPS');

        if ($has80 && $has443) {
            return null;
        }

        $missingPorts = [];
        if (!$has80) {
            $missingPorts[] = '80 (HTTP)';
        }
        if (!$has443) {
            $missingPorts[] = '443 (HTTPS)';
        }

        $evidence = [
            new Evidence(
                source: 'ufw status',
                logSnippet: "UFW Status: Active\nAllowed Rules: " . (!empty($ufw['rules']) ? implode("\n", array_slice($ufw['rules'], 0, 5)) : 'None'),
                significance: 'Firewall is active but missing inbound ALLOW rules for essential web ports: ' . implode(', ', $missingPorts) . '.'
            )
        ];

        $steps = [];
        if (!$has80) {
            $steps[] = new RemediationStep(
                description: 'Allow inbound HTTP (port 80) in UFW firewall',
                command: 'ufw allow 80/tcp comment "eidcloud: allow HTTP"',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'ufw status | grep 80'
            );
        }
        if (!$has443) {
            $steps[] = new RemediationStep(
                description: 'Allow inbound HTTPS (port 443) in UFW firewall',
                command: 'ufw allow 443/tcp comment "eidcloud: allow HTTPS"',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'ufw status | grep 443'
            );
        }

        $plan = new RemediationPlan(
            title: 'Authorize web ingress ports on UFW firewall',
            steps: $steps,
            postCheckDescription: 'Verify port accessibility via `ufw status numbered`.'
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('ufw', true)), 0, 8),
            issueType: 'UFW_FIREWALL_BLOCK',
            service: 'firewall / ufw',
            summary: 'UFW Firewall is active and blocking incoming connections on ' . implode(', ', $missingPorts) . '.',
            confidence: 0.85,
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
