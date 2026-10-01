<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Models;

use EidCloud\LinuxTroubleshooter\Remediation\RemediationPlan;

final class DiagnosticReport
{
    /**
     * @param string $incidentId
     * @param string $issueType
     * @param string $service
     * @param string $summary
     * @param float $confidence (0.0 to 1.0)
     * @param array<Evidence> $evidence
     * @param RemediationPlan|null $remediationPlan
     * @param string $status ('DETECTED', 'RESOLVED', 'HEALTHY', 'ACTION_REQUIRED')
     */
    public function __construct(
        public readonly string $incidentId,
        public readonly string $issueType,
        public readonly string $service,
        public readonly string $summary,
        public readonly float $confidence,
        public readonly array $evidence = [],
        public ?RemediationPlan $remediationPlan = null,
        public string $status = 'DETECTED'
    ) {}

    public function toArray(): array
    {
        return [
            'incident_id' => $this->incidentId,
            'issue_type' => $this->issueType,
            'service' => $this->service,
            'summary' => $this->summary,
            'confidence' => $this->confidence,
            'confidence_percentage' => round($this->confidence * 100, 1) . '%',
            'status' => $this->status,
            'evidence' => array_map(fn(Evidence $e) => $e->toArray(), $this->evidence),
            'remediation_plan' => $this->remediationPlan?->toArray(),
        ];
    }
}
