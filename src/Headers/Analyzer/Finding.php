<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Analyzer;

/**
 * A single security header finding
 */
final readonly class Finding
{
    public function __construct(
        public string $header,
        public FindingSeverity $severity,
        public string $message,
        public string $recommendation,
    ) {
    }
}
