<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Analyzer;

use Countable;

/**
 * Immutable collection of security header analysis findings
 */
final readonly class AnalysisResult implements Countable
{
    /** @var list<Finding> */
    private array $findings;

    public function __construct(Finding ...$findings)
    {
        $this->findings = array_values($findings);
    }

    /**
     * @return list<Finding>
     */
    public function findings(): array
    {
        return $this->findings;
    }

    /**
     * Get findings for a specific header
     *
     * @return list<Finding>
     */
    public function forHeader(string $header): array
    {
        return array_values(
            array_filter(
                $this->findings,
                static fn (Finding $finding): bool => strcasecmp($finding->header, $header) === 0,
            ),
        );
    }

    /**
     * Check if there are any findings with CRITICAL severity
     */
    public function hasCritical(): bool
    {
        return $this->hasSeverity(FindingSeverity::CRITICAL);
    }

    /**
     * Check if there are any findings with HIGH or CRITICAL severity
     */
    public function hasHighOrAbove(): bool
    {
        if ($this->hasCritical()) {
            return true;
        }

        return $this->hasSeverity(FindingSeverity::HIGH);
    }

    /**
     * Check if there are no findings at all
     */
    public function isClean(): bool
    {
        return $this->findings === [];
    }

    public function count(): int
    {
        return count($this->findings);
    }

    private function hasSeverity(FindingSeverity $severity): bool
    {
        return array_any($this->findings, static fn (Finding $finding): bool => $finding->severity === $severity);
    }
}
