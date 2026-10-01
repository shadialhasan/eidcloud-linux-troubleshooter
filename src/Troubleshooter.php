<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter;

use EidCloud\LinuxTroubleshooter\Collectors\LogCollector;
use EidCloud\LinuxTroubleshooter\Collectors\ProcessCollector;
use EidCloud\LinuxTroubleshooter\Models\DiagnosticReport;
use EidCloud\LinuxTroubleshooter\Rules\DiskExhaustionRule;
use EidCloud\LinuxTroubleshooter\Rules\Nginx502Rule;
use EidCloud\LinuxTroubleshooter\Rules\OomKillRule;
use EidCloud\LinuxTroubleshooter\Rules\PhpFpmSocketRule;
use EidCloud\LinuxTroubleshooter\Rules\PortConflictRule;
use EidCloud\LinuxTroubleshooter\Rules\RuleInterface;
use EidCloud\LinuxTroubleshooter\Rules\SslExpiryRule;
use EidCloud\LinuxTroubleshooter\Rules\UfwFirewallRule;
use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;
use EidCloud\LinuxTroubleshooter\System\LocalCommandExecutor;

class Troubleshooter
{
    private CommandExecutorInterface $executor;
    private LogCollector $logCollector;
    private ProcessCollector $processCollector;
    /** @var array<RuleInterface> */
    private array $rules = [];

    public function __construct(?CommandExecutorInterface $executor = null)
    {
        $this->executor = $executor ?? new LocalCommandExecutor();
        $this->logCollector = new LogCollector($this->executor);
        $this->processCollector = new ProcessCollector($this->executor);

        $this->registerDefaultRules();
    }

    private function registerDefaultRules(): void
    {
        $this->rules = [
            new Nginx502Rule(),
            new PhpFpmSocketRule(),
            new OomKillRule(),
            new DiskExhaustionRule(),
            new PortConflictRule(),
            new SslExpiryRule(),
            new UfwFirewallRule(),
        ];
    }

    public function addRule(RuleInterface $rule): self
    {
        $this->rules[] = $rule;
        return $this;
    }

    /**
     * @return array<RuleInterface>
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    public function getExecutor(): CommandExecutorInterface
    {
        return $this->executor;
    }

    public function getLogCollector(): LogCollector
    {
        return $this->logCollector;
    }

    public function getProcessCollector(): ProcessCollector
    {
        return $this->processCollector;
    }

    /**
     * Autonomous diagnosis step: evaluates registered rules against the context query.
     *
     * @param string $query Natural language issue description or service name (e.g. "why is nginx returning 502?")
     * @return array<DiagnosticReport>
     */
    public function diagnose(string $query = ''): array
    {
        $reports = [];

        foreach ($this->rules as $rule) {
            if ($rule->supports($query)) {
                $report = $rule->evaluate($this->logCollector, $this->processCollector, $this->executor);
                if ($report !== null) {
                    $reports[] = $report;
                }
            }
        }

        // Sort by confidence descending
        usort($reports, fn(DiagnosticReport $a, DiagnosticReport $b) => $b->confidence <=> $a->confidence);

        return $reports;
    }

    /**
     * Targeted health check for a specific service.
     */
    public function checkService(string $service): array
    {
        $isActive = $this->processCollector->isServiceActive($service);
        $statusRaw = $this->processCollector->getServiceStatus($service);
        $journal = $this->logCollector->getJournalLogs($service, 20);

        return [
            'service' => $service,
            'is_active' => $isActive,
            'status' => $isActive ? 'UP' : 'DOWN',
            'raw_status' => $statusRaw,
            'recent_logs' => $journal,
        ];
    }

    /**
     * Full systemic health audit of server resources & services.
     */
    public function auditSystem(): array
    {
        $mem = $this->processCollector->getMemoryInfo();
        $disks = $this->processCollector->getDiskUsage();
        $ufw = $this->processCollector->getUfwStatus();

        $services = ['nginx', 'php8.2-fpm', 'php8.3-fpm', 'php-fpm', 'apache2', 'mysql', 'redis-server'];
        $serviceStatuses = [];
        foreach ($services as $srv) {
            $serviceStatuses[$srv] = $this->processCollector->isServiceActive($srv);
        }

        $allDiagnostics = $this->diagnose('all');

        return [
            'timestamp' => date('c'),
            'memory' => $mem,
            'disks' => $disks,
            'firewall' => $ufw,
            'services' => $serviceStatuses,
            'incidents_detected' => count($allDiagnostics),
            'diagnostics' => array_map(fn(DiagnosticReport $r) => $r->toArray(), $allDiagnostics),
        ];
    }

    /**
     * Safely executes a remediation plan, re-checking health after execution.
     *
     * @param DiagnosticReport $report
     * @return array{success: bool, pre_status: string, post_status: string, execution_result: array}
     */
    public function remediate(DiagnosticReport $report): array
    {
        if ($report->remediationPlan === null) {
            return [
                'success' => false,
                'pre_status' => $report->status,
                'post_status' => $report->status,
                'execution_result' => ['error' => 'No remediation plan available for this incident.'],
            ];
        }

        $planResult = $report->remediationPlan->execute($this->executor);

        // Verification phase
        $postCheckReports = $this->diagnose($report->service);
        $isResolved = true;

        foreach ($postCheckReports as $pReport) {
            if ($pReport->issueType === $report->issueType) {
                $isResolved = false;
                break;
            }
        }

        $report->status = $isResolved ? 'RESOLVED' : 'FAILED_VERIFICATION';

        return [
            'success' => $planResult['success'] && $isResolved,
            'pre_status' => 'DETECTED',
            'post_status' => $report->status,
            'execution_result' => $planResult,
        ];
    }
}
