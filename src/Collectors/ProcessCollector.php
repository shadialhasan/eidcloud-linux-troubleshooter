<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Collectors;

use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;

class ProcessCollector
{
    public function __construct(private readonly CommandExecutorInterface $executor) {}

    /**
     * Checks if a systemd unit is active.
     */
    public function isServiceActive(string $service): bool
    {
        $res = $this->executor->execute(sprintf('systemctl is-active %s 2>&1', escapeshellarg($service)));
        return trim($res->stdout) === 'active';
    }

    /**
     * Retrieves full systemctl status for a service.
     */
    public function getServiceStatus(string $service): string
    {
        $res = $this->executor->execute(sprintf('systemctl status %s --no-pager 2>&1', escapeshellarg($service)));
        return $res->getOutput();
    }

    /**
     * Checks if any process is listening on the specified port.
     * Parses ss -tulpn or netstat -tulpn output.
     *
     * @return array{listening: bool, process: ?string, pid: ?int, raw: string}
     */
    public function getListeningPortStatus(int $port): array
    {
        // Try ss first
        $res = $this->executor->execute(sprintf("ss -tulpn | grep ':%d ' 2>&1", $port));
        $output = $res->getOutput();

        if (empty($output)) {
            // Fallback to netstat
            $res = $this->executor->execute(sprintf("netstat -tulpn | grep ':%d ' 2>&1", $port));
            $output = $res->getOutput();
        }

        if (empty($output)) {
            return [
                'listening' => false,
                'process' => null,
                'pid' => null,
                'raw' => '',
            ];
        }

        $process = null;
        $pid = null;

        // Parse ss format: users:(("nginx",pid=1234,fd=6))
        if (preg_match('/users:\(\("([^"]+)",pid=(\d+)/', $output, $m)) {
            $process = $m[1];
            $pid = (int) $m[2];
        } elseif (preg_match('/(\d+)\/([^\s]+)/', $output, $m)) {
            // Netstat format: 1234/nginx
            $pid = (int) $m[1];
            $process = $m[2];
        }

        return [
            'listening' => true,
            'process' => $process,
            'pid' => $pid,
            'raw' => $output,
        ];
    }

    /**
     * Checks memory usage via `free -m`.
     *
     * @return array{total_mb: int, used_mb: int, free_mb: int, available_mb: int, percent_used: float}
     */
    public function getMemoryInfo(): array
    {
        $res = $this->executor->execute('free -m 2>&1');
        $lines = explode("\n", trim($res->stdout));

        $total = 0;
        $used = 0;
        $free = 0;
        $available = 0;

        foreach ($lines as $line) {
            if (str_starts_with(trim($line), 'Mem:')) {
                $cols = preg_split('/\s+/', trim($line));
                if (count($cols) >= 7) {
                    $total = (int) $cols[1];
                    $used = (int) $cols[2];
                    $free = (int) $cols[3];
                    $available = (int) $cols[6];
                }
            }
        }

        $percentUsed = $total > 0 ? round((($total - $available) / $total) * 100, 2) : 0.0;

        return [
            'total_mb' => $total,
            'used_mb' => $used,
            'free_mb' => $free,
            'available_mb' => $available,
            'percent_used' => $percentUsed,
        ];
    }

    /**
     * Checks disk space usage via `df -hP`.
     *
     * @return array<array{filesystem: string, size: string, used: string, avail: string, percent: int, mount: string}>
     */
    public function getDiskUsage(): array
    {
        $res = $this->executor->execute('df -hP 2>&1');
        $lines = explode("\n", trim($res->stdout));
        $disks = [];

        // Skip header
        array_shift($lines);

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $cols = preg_split('/\s+/', $line);
            if (count($cols) >= 6) {
                $disks[] = [
                    'filesystem' => $cols[0],
                    'size' => $cols[1],
                    'used' => $cols[2],
                    'avail' => $cols[3],
                    'percent' => (int) rtrim($cols[4], '%'),
                    'mount' => $cols[5],
                ];
            }
        }

        return $disks;
    }

    /**
     * Checks UFW firewall status.
     *
     * @return array{active: bool, rules: array<string>}
     */
    public function getUfwStatus(): array
    {
        $res = $this->executor->execute('ufw status 2>&1');
        $out = $res->getOutput();
        $isActive = str_contains($out, 'Status: active');

        $rules = [];
        $lines = explode("\n", $out);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '' && !str_starts_with($line, 'Status:') && !str_starts_with($line, 'To') && !str_starts_with($line, '--')) {
                $rules[] = $line;
            }
        }

        return [
            'active' => $isActive,
            'rules' => $rules,
        ];
    }
}
