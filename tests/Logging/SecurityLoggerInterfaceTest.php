<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Stringable exists in PHP core and polyfills */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Logging;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Stringable;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;

/**
 * Tests for SecurityLoggerInterface
 *
 * Interfaces have no implementation to cover - tests verify contract only.
 */
#[CoversNothing]
final class SecurityLoggerInterfaceTest extends TestCase
{
    public function testInterfaceDefinesWarningMethod(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with('Test warning', ['key' => 'value']);

        $logger->warning('Test warning', ['key' => 'value']);
    }

    public function testInterfaceDefinesAlertMethod(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('alert')
            ->with('Test alert', ['key' => 'value']);

        $logger->alert('Test alert', ['key' => 'value']);
    }

    public function testWarningWithStringableMessage(): void
    {
        $stringable = new class implements Stringable {
            public function __toString(): string
            {
                return 'Stringable message';
            }
        };

        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with($stringable, []);

        /** @noinspection PhpRedundantOptionalArgumentInspection Test verifies interface contract with empty context */
        $logger->warning($stringable, []);
    }

    public function testAlertWithStringableMessage(): void
    {
        $stringable = new class implements Stringable {
            public function __toString(): string
            {
                return 'Stringable alert';
            }
        };

        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('alert')
            ->with($stringable, []);

        /** @noinspection PhpRedundantOptionalArgumentInspection Test verifies interface contract with empty context */
        $logger->alert($stringable, []);
    }

    public function testInterfaceDefinesCriticalMethod(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('critical')
            ->with('Test critical', ['key' => 'value']);

        $logger->critical('Test critical', ['key' => 'value']);
    }

    public function testCriticalWithStringableMessage(): void
    {
        $stringable = new class implements Stringable {
            public function __toString(): string
            {
                return 'Stringable critical';
            }
        };

        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('critical')
            ->with($stringable, []);

        /** @noinspection PhpRedundantOptionalArgumentInspection Test verifies interface contract with empty context */
        $logger->critical($stringable, []);
    }
}
