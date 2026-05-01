<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Analyzer;

/**
 * Severity level for security header findings
 */
enum FindingSeverity: string
{
    case CRITICAL = 'critical';
    case HIGH     = 'high';
    case MEDIUM   = 'medium';
    case LOW      = 'low';
    case INFO     = 'info';
}
