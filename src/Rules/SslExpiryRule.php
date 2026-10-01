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

class SslExpiryRule implements RuleInterface
{
    public function getId(): string
    {
        return 'ssl-cert-expiration';
    }

    public function getDescription(): string
    {
        return 'Detects expired or expiring SSL/TLS certificates and Let\'s Encrypt renewal errors.';
    }

    public function supports(string $context): bool
    {
        $context = strtolower($context);
        return empty($context)
            || str_contains($context, 'ssl')
            || str_contains($context, 'cert')
            || str_contains($context, 'tls')
            || str_contains($context, 'expire')
            || str_contains($context, 'https')
            || str_contains($context, 'all');
    }

    public function evaluate(
        LogCollector $logCollector,
        ProcessCollector $processCollector,
        CommandExecutorInterface $executor
    ): ?DiagnosticReport {
        $evidence = [];

        // 1. Inspect certbot renewal logs
        $certbotLog = $logCollector->getLogFileSnippet('/var/log/letsencrypt/letsencrypt.log', 40);
        $nginxLog = $logCollector->getLogFileSnippet('/var/log/nginx/error.log', 40);

        $hasCertError = false;
        $snippet = '';

        if ($certbotLog && (str_contains($certbotLog, 'The certificate has expired') || str_contains($certbotLog, 'Renewal configuration file failed') || str_contains($certbotLog, 'Certbot failed to authenticate some domains'))) {
            $hasCertError = true;
            $lines = explode("\n", $certbotLog);
            $matched = array_filter($lines, fn($l) => str_contains($l, 'expired') || str_contains($l, 'failed') || str_contains($l, 'Error'));
            $snippet = implode("\n", array_slice($matched, -3));
        }

        if ($nginxLog && (str_contains($nginxLog, 'SSL: error:0A000086:SSL routines::certificate verify failed') || str_contains($nginxLog, 'cannot load certificate'))) {
            $hasCertError = true;
            $lines = explode("\n", $nginxLog);
            $matched = array_filter($lines, fn($l) => str_contains($l, 'SSL') || str_contains($l, 'certificate'));
            $snippet = ($snippet ? $snippet . "\n" : '') . implode("\n", array_slice($matched, -2));
        }

        // 2. Also check system certificates with openssl command if certificate exists
        $certCheck = $executor->execute('certbot certificates 2>&1');
        if (str_contains($certCheck->stdout, 'INVALID: EXPIRED') || str_contains($certCheck->stdout, 'VALID: 0 days')) {
            $hasCertError = true;
            $snippet = ($snippet ? $snippet . "\n" : '') . trim($certCheck->stdout);
        }

        if (!$hasCertError) {
            return null;
        }

        $evidence[] = new Evidence(
            source: '/var/log/letsencrypt/letsencrypt.log / certbot',
            logSnippet: $snippet ?: 'SSL Certificate is expired or validation failed.',
            significance: 'Active SSL/TLS certificate has lapsed, causing browser HTTPS security warnings (ERR_CERT_DATE_INVALID).'
        );

        $steps = [
            new RemediationStep(
                description: 'Execute Certbot non-interactive renewal',
                command: 'certbot renew --non-interactive --quiet',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'certbot certificates'
            ),
            new RemediationStep(
                description: 'Reload Nginx to mount renewed SSL certificates',
                command: 'systemctl reload nginx',
                isIdempotent: true,
                requiresSudo: true,
                verificationCommand: 'systemctl is-active nginx'
            ),
        ];

        $plan = new RemediationPlan(
            title: 'Renew expired SSL/TLS certificates and reload web server',
            steps: $steps,
            postCheckDescription: 'Check SSL expiry date with `certbot certificates` or OpenSSL.'
        );

        return new DiagnosticReport(
            incidentId: 'INC-' . substr(md5(uniqid('ssl', true)), 0, 8),
            issueType: 'SSL_CERT_EXPIRED',
            service: 'tls / letsencrypt',
            summary: 'SSL/TLS certificate has expired or failed automated renewal.',
            confidence: 0.90,
            evidence: $evidence,
            remediationPlan: $plan,
            status: 'ACTION_REQUIRED'
        );
    }
}
