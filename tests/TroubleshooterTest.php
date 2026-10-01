<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Tests;

use EidCloud\LinuxTroubleshooter\Troubleshooter;
use EidCloud\LinuxTroubleshooter\System\MockCommandExecutor;
use EidCloud\LinuxTroubleshooter\Models\DiagnosticReport;
use EidCloud\LinuxTroubleshooter\Remediation\RemediationPlan;
use EidCloud\LinuxTroubleshooter\Remediation\RemediationStep;

final class TroubleshooterTest
{
    private int $passes = 0;
    private int $fails = 0;

    public function runAll(): bool
    {
        echo "Running EidCloud Linux Troubleshooter Test Suite...\n\n";

        $this->testNginx502Diagnosis();
        $this->testPhpFpmSaturationDiagnosis();
        $this->testOomKillDiagnosis();
        $this->testDiskExhaustionDiagnosis();
        $this->testPortConflictDiagnosis();
        $this->testSslExpiryDiagnosis();
        $this->testUfwFirewallDiagnosis();
        $this->testAutonomousRemediationFlow();
        $this->testSystemAuditJson();

        echo "\n" . str_repeat('=', 50) . "\n";
        echo "Total Tests Executed: " . ($this->passes + $this->fails) . "\n";
        echo "Passed: \033[32m{$this->passes}\033[0m\n";
        echo "Failed: " . ($this->fails > 0 ? "\033[31m{$this->fails}\033[0m" : "0") . "\n";

        return $this->fails === 0;
    }

    private function assert(string $testName, bool $condition, string $message = ''): void
    {
        if ($condition) {
            echo "  \033[32m✓ PASS\033[0m: {$testName}\n";
            $this->passes++;
        } else {
            echo "  \033[31m✗ FAIL\033[0m: {$testName} - {$message}\n";
            $this->fails++;
        }
    }

    private function testNginx502Diagnosis(): void
    {
        echo "[Test Suite: Nginx 502 Bad Gateway]\n";
        $mock = new MockCommandExecutor();
        $mock->mockFile(
            '/var/log/nginx/error.log',
            "2026/10/01 12:00:00 [error] 1234#0: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 127.0.0.1, server: example.com, request: \"GET / HTTP/1.1\", upstream: \"fastcgi://unix:/run/php/php8.2-fpm.sock:\""
        );
        $mock->mockCommand('systemctl is-active php8.2-fpm', 3, 'inactive');
        $mock->mockCommand('systemctl is-active php-fpm', 3, 'inactive');
        $mock->mockCommand('systemctl is-active php8.3-fpm', 3, 'inactive');
        $mock->mockCommand('systemctl status php8.2-fpm', 3, "● php8.2-fpm.service - The PHP FastCGI Process Manager\n   Loaded: loaded\n   Active: inactive (dead)");

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('why is nginx returning 502?');

        $this->assert('Detects Nginx 502 incident', count($reports) > 0);
        $this->assert('Incident is NGINX_502_BAD_GATEWAY', $reports[0]->issueType === 'NGINX_502_BAD_GATEWAY');
        $this->assert('Confidence is high (>= 90%)', $reports[0]->confidence >= 0.90);
        $this->assert('Remediation plan is attached', $reports[0]->remediationPlan !== null);
        $this->assert('Remediation contains php8.2-fpm enable/start', str_contains($reports[0]->remediationPlan->steps[0]->command, 'php8.2-fpm'));
    }

    private function testPhpFpmSaturationDiagnosis(): void
    {
        echo "[Test Suite: PHP-FPM Saturation]\n";
        $mock = new MockCommandExecutor();
        $mock->mockFile(
            '/var/log/php8.2-fpm.log',
            "[01-Oct-2026 12:01:00] WARNING: [pool www] server reached pm.max_children setting (5), consider raising it"
        );

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('php-fpm socket starvation');

        $this->assert('Detects PHP-FPM pool saturation', count($reports) > 0);
        $this->assert('Issue type is PHP_FPM_SOCKET_STARVATION', $reports[0]->issueType === 'PHP_FPM_SOCKET_STARVATION');
        $this->assert('Confidence is >= 50%', $reports[0]->confidence >= 0.50);
    }

    private function testOomKillDiagnosis(): void
    {
        echo "[Test Suite: Kernel OOM Killer]\n";
        $mock = new MockCommandExecutor();
        $mock->mockCommand(
            'dmesg -T',
            0,
            "[Thu Oct  1 12:05:00 2026] Out of memory: Kill process 4567 (php-fpm) score 850 or sacrifice child\n[Thu Oct  1 12:05:00 2026] Killed process 4567 (php-fpm) total-vm:450000kB, anon-rss:210000kB"
        );
        $mock->mockCommand(
            'free -m',
            0,
            "               total        used        free      shared  buff/cache   available\nMem:            1980        1890          20          10          70          50\nSwap:              0           0           0"
        );

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('oom crash');

        $this->assert('Detects OOM killer event', count($reports) > 0);
        $this->assert('Issue type is KERNEL_OOM_KILL', $reports[0]->issueType === 'KERNEL_OOM_KILL');
        $this->assert('Proposes drop_caches & swap creation', str_contains($reports[0]->remediationPlan->steps[1]->command, 'swapfile'));
    }

    private function testDiskExhaustionDiagnosis(): void
    {
        echo "[Test Suite: Disk Space Exhaustion]\n";
        $mock = new MockCommandExecutor();
        $mock->mockCommand(
            'df -hP',
            0,
            "Filesystem      Size  Used Avail Use% Mounted on\n/dev/root        50G   48G  2.0G  96% /\n/dev/sda2       100G   20G   80G  20% /data"
        );

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('disk');

        $this->assert('Detects storage crisis', count($reports) > 0);
        $this->assert('Issue type is DISK_SPACE_EXHAUSTION', $reports[0]->issueType === 'DISK_SPACE_EXHAUSTION');
        $this->assert('Identifies root mount at 96%', str_contains($reports[0]->summary, '96%'));
    }

    private function testPortConflictDiagnosis(): void
    {
        echo "[Test Suite: Port Binding Conflict]\n";
        $mock = new MockCommandExecutor();
        $mock->mockCommand(
            'journalctl -u nginx',
            0,
            "nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)"
        );
        $mock->mockCommand(
            'ss -tulpn',
            0,
            "tcp   LISTEN 0      128          0.0.0.0:80        0.0.0.0:*    users:((\"apache2\",pid=8888,fd=4))"
        );

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('port conflict');

        $this->assert('Detects port 80 conflict', count($reports) > 0);
        $this->assert('Issue type is PORT_BIND_CONFLICT', $reports[0]->issueType === 'PORT_BIND_CONFLICT');
        $this->assert('Identifies apache2 as culprit', str_contains($reports[0]->summary, 'apache2'));
    }

    private function testSslExpiryDiagnosis(): void
    {
        echo "[Test Suite: SSL Certificate Expiry]\n";
        $mock = new MockCommandExecutor();
        $mock->mockFile(
            '/var/log/letsencrypt/letsencrypt.log',
            "2026-10-01 12:00:00,000:ERROR:certbot.renewal:The certificate has expired for domain example.com"
        );
        $mock->mockCommand(
            'certbot certificates',
            0,
            "Certificate Name: example.com\n  Domains: example.com\n  Expiry Date: 2026-10-01 00:00:00+00:00 (INVALID: EXPIRED)"
        );

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('ssl');

        $this->assert('Detects expired SSL certificate', count($reports) > 0);
        $this->assert('Issue type is SSL_CERT_EXPIRED', $reports[0]->issueType === 'SSL_CERT_EXPIRED');
    }

    private function testUfwFirewallDiagnosis(): void
    {
        echo "[Test Suite: UFW Firewall Block]\n";
        $mock = new MockCommandExecutor();
        $mock->mockCommand(
            'ufw status',
            0,
            "Status: active\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere"
        );

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('firewall blocked');

        $this->assert('Detects firewall blocking web traffic', count($reports) > 0);
        $this->assert('Issue type is UFW_FIREWALL_BLOCK', $reports[0]->issueType === 'UFW_FIREWALL_BLOCK');
    }

    private function testAutonomousRemediationFlow(): void
    {
        echo "[Test Suite: Autonomous Remediation & Re-verification]\n";
        $mock = new MockCommandExecutor();
        $mock->mockFile(
            '/var/log/nginx/error.log',
            "connect() failed (111: Connection refused) while connecting to upstream"
        );
        $mock->mockCommand('systemctl is-active php8.2-fpm', 3, 'inactive');
        $mock->mockCommand('systemctl status php8.2-fpm', 3, 'Active: inactive (dead)');
        $mock->mockCommand('systemctl enable --now php8.2-fpm', 0, 'Synchronizing state...');
        $mock->mockCommand('systemctl reload nginx', 0, '');

        $troubleshooter = new Troubleshooter($mock);
        $reports = $troubleshooter->diagnose('nginx 502');

        $this->assert('Initial report detected', count($reports) === 1);
        $report = $reports[0];

        // Simulate remediation succeeds and system heals
        $mock->mockCommand('systemctl is-active php8.2-fpm', 0, 'active');
        $mock->mockCommand('systemctl status php8.2-fpm', 0, 'Active: active (running)');
        $mock->mockFile('/var/log/nginx/error.log', ''); // log rotated/cleared

        $res = $troubleshooter->remediate($report);

        $this->assert('Remediation completed successfully', $res['success']);
        $this->assert('Status transitioned to RESOLVED', $res['post_status'] === 'RESOLVED');
    }

    private function testSystemAuditJson(): void
    {
        echo "[Test Suite: System Audit JSON Generation]\n";
        $mock = new MockCommandExecutor();
        $mock->mockCommand(
            'free -m',
            0,
            "Mem: 4000 2000 1000 100 1000 2000\nSwap: 1000 0 1000"
        );
        $mock->mockCommand(
            'df -hP',
            0,
            "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 40G 15G 25G 38% /"
        );
        $mock->mockCommand('ufw status', 0, "Status: inactive");
        $mock->mockCommand('systemctl is-active nginx', 0, 'active');
        $mock->mockCommand('systemctl is-active php8.2-fpm', 0, 'active');

        $troubleshooter = new Troubleshooter($mock);
        $audit = $troubleshooter->auditSystem();

        $this->assert('Audit contains memory info', isset($audit['memory']['percent_used']));
        $this->assert('Audit contains disk mounts', count($audit['disks']) === 1);
        $this->assert('Audit reports zero critical incidents', $audit['incidents_detected'] === 0);
    }
}
