<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8 interface, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use Stringable;
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;

/**
 * Records every warning so the rejection log can be asserted on
 */
final class RecordingLogger implements SecurityLoggerInterface
{
    /**
     * @var list<array{message: string, context: array<string, mixed>}>
     */
    public array $warnings = [];

    public function warning(string|Stringable $message, array $context = []): void
    {
        $this->warnings[] = ['message' => (string) $message, 'context' => $context];
    }

    public function alert(string|Stringable $message, array $context = []): void
    {
    }

    public function critical(string|Stringable $message, array $context = []): void
    {
    }

    public function securityEvent(SecurityEvent $event): void
    {
    }
}
