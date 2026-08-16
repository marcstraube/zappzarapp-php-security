<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Report;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Report\ReportDisposition;

#[CoversClass(ReportDisposition::class)]
final class ReportDispositionTest extends TestCase
{
    #[Test]
    public function testCasesUseTheSpecWireValues(): void
    {
        $this->assertSame('enforce', ReportDisposition::ENFORCE->value);
        $this->assertSame('report', ReportDisposition::REPORT->value);
    }

    #[Test]
    public function testEnforceIsBlocking(): void
    {
        $this->assertTrue(ReportDisposition::ENFORCE->isBlocking());
    }

    #[Test]
    public function testReportOnlyIsNotBlocking(): void
    {
        $this->assertFalse(ReportDisposition::REPORT->isBlocking());
    }

    #[Test]
    public function testUnknownDispositionHasNoCase(): void
    {
        $unknownDisposition = 'block';

        $this->assertNull(ReportDisposition::tryFrom($unknownDisposition));
    }
}
