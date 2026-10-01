<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\System;

class MockCommandExecutor implements CommandExecutorInterface
{
    /** @var array<string, ExecutionResult> */
    private array $commandMap = [];

    /** @var array<string, string> */
    private array $fileMap = [];

    /** @var array<string> */
    private array $executedCommands = [];

    public function mockCommand(string $commandPattern, int $exitCode, string $stdout, string $stderr = ''): self
    {
        $this->commandMap[$commandPattern] = new ExecutionResult($exitCode, $stdout, $stderr, $commandPattern);
        return $this;
    }

    public function mockFile(string $path, string $content): self
    {
        $this->fileMap[$path] = $content;
        return $this;
    }

    public function execute(string $command): ExecutionResult
    {
        $this->executedCommands[] = $command;

        // Exact match
        if (isset($this->commandMap[$command])) {
            return $this->commandMap[$command];
        }

        // Substring match
        $normalizedCommand = str_replace(["'", '"', '\\'], '', $command);
        foreach ($this->commandMap as $pattern => $result) {
            $normalizedPattern = str_replace(["'", '"', '\\'], '', $pattern);
            if (
                str_contains($command, $pattern)
                || str_contains($normalizedCommand, $normalizedPattern)
                || str_contains($normalizedPattern, $normalizedCommand)
            ) {
                return $result;
            }
        }

        // Default empty response
        return new ExecutionResult(0, '', '', $command);
    }

    public function fileExists(string $path): bool
    {
        return isset($this->fileMap[$path]);
    }

    public function readFile(string $path): ?string
    {
        return $this->fileMap[$path] ?? null;
    }

    /**
     * @return array<string>
     */
    public function getExecutedCommands(): array
    {
        return $this->executedCommands;
    }
}
