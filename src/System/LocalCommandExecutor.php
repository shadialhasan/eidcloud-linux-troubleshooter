<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\System;

class LocalCommandExecutor implements CommandExecutorInterface
{
    public function execute(string $command): ExecutionResult
    {
        $descriptorspec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];

        $process = proc_open($command, $descriptorspec, $pipes);
        if (!is_resource($process)) {
            return new ExecutionResult(1, '', 'Failed to spawn process', $command);
        }

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]) ?: '';
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        return new ExecutionResult($exitCode, $stdout, $stderr, $command);
    }

    public function fileExists(string $path): bool
    {
        return file_exists($path);
    }

    public function readFile(string $path): ?string
    {
        if (!file_exists($path) || !is_readable($path)) {
            return null;
        }
        $content = file_get_contents($path);
        return $content !== false ? $content : null;
    }
}
