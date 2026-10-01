<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Collectors;

use EidCloud\LinuxTroubleshooter\System\CommandExecutorInterface;

class LogCollector
{
    public function __construct(private readonly CommandExecutorInterface $executor) {}

    /**
     * Reads recent journalctl logs for a specific systemd unit.
     */
    public function getJournalLogs(string $unit, int $lines = 100): string
    {
        $cmd = sprintf('journalctl -u %s -n %d --no-pager 2>&1', escapeshellarg($unit), $lines);
        $res = $this->executor->execute($cmd);
        return $res->getOutput();
    }

    /**
     * Reads kernel ring buffer (dmesg) logs.
     */
    public function getDmesgLogs(int $lines = 100): string
    {
        $cmd = sprintf('dmesg -T | tail -n %d 2>&1', $lines);
        $res = $this->executor->execute($cmd);
        return $res->getOutput();
    }

    /**
     * Reads tail lines of a specific log file or system path.
     */
    public function getLogFileSnippet(string $path, int $lines = 50): ?string
    {
        if (!$this->executor->fileExists($path)) {
            // Also try reading via tail command
            $cmd = sprintf('tail -n %d %s 2>/dev/null', $lines, escapeshellarg($path));
            $res = $this->executor->execute($cmd);
            if ($res->isSuccess() && trim($res->stdout) !== '') {
                return trim($res->stdout);
            }
            return null;
        }

        $content = $this->executor->readFile($path);
        if ($content === null) {
            return null;
        }

        $allLines = explode("\n", trim($content));
        $slice = array_slice($allLines, -$lines);
        return implode("\n", $slice);
    }
}
