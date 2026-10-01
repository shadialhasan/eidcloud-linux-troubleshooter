<?php

declare(strict_types=1);

namespace EidCloud\LinuxTroubleshooter\Models;

final class Evidence
{
    public function __construct(
        public readonly string $source,
        public readonly string $logSnippet,
        public readonly string $significance,
        public readonly array $metadata = []
    ) {}

    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'log_snippet' => $this->logSnippet,
            'significance' => $this->significance,
            'metadata' => $this->metadata,
        ];
    }
}
