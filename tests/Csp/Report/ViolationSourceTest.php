<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Report;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Exception\CspReportException;
use Zappzarapp\Security\Csp\Report\ViolationSource;

#[CoversClass(ViolationSource::class)]
#[CoversClass(CspReportException::class)]
final class ViolationSourceTest extends TestCase
{
    #[Test]
    public function testDefaultsToAnUnknownLocation(): void
    {
        $source = new ViolationSource();

        $this->assertSame('', $source->file);
        $this->assertNull($source->line);
        $this->assertNull($source->column);
    }

    #[Test]
    public function testKeepsTheReportedLocation(): void
    {
        $source = new ViolationSource('https://example.com/app.js', 12, 5);

        $this->assertSame('https://example.com/app.js', $source->file);
        $this->assertSame(12, $source->line);
        $this->assertSame(5, $source->column);
    }

    #[Test]
    public function testLogContextCarriesTheReportedLocation(): void
    {
        $source = new ViolationSource('https://example.com/app.js', 12, 5);

        $this->assertSame([
            'source_file'   => 'https://example.com/app.js',
            'line_number'   => 12,
            'column_number' => 5,
        ], $source->toLogContext());
    }

    #[Test]
    public function testLogContextReportsAnUnknownLocationAsNull(): void
    {
        $this->assertSame([
            'source_file'   => null,
            'line_number'   => null,
            'column_number' => null,
        ], (new ViolationSource())->toLogContext());
    }

    #[Test]
    public function testRejectsControlCharactersInTheSourceFile(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('control characters: source-file');

        new ViolationSource("https://example.com/app.js\nInjected: entry");
    }

    #[Test]
    public function testRejectsMalformedUtf8InTheSourceFile(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('not valid UTF-8: source-file');

        new ViolationSource("https://example.com/\xFF\xFE\napp.js");
    }

    #[Test]
    public function testAcceptsASourceFileAtTheLengthLimit(): void
    {
        $file = str_repeat('a', ViolationSource::MAX_FILE_LENGTH);

        $this->assertSame($file, (new ViolationSource($file))->file);
    }

    #[Test]
    public function testRejectsASourceFileBeyondTheLengthLimit(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('source-file exceeds the maximum of 2048 characters');

        new ViolationSource(str_repeat('a', ViolationSource::MAX_FILE_LENGTH + 1));
    }

    #[Test]
    public function testAcceptsZeroAsALineAndColumnNumber(): void
    {
        $source = new ViolationSource('', 0, 0);

        $this->assertSame(0, $source->line);
        $this->assertSame(0, $source->column);
    }

    /**
     * @return iterable<string, array{int|null, int|null, string}>
     */
    public static function negativeNumbersProvider(): iterable
    {
        yield 'line' => [-1, null, 'line-number'];
        yield 'column' => [null, -1, 'column-number'];
    }

    #[DataProvider('negativeNumbersProvider')]
    #[Test]
    public function testRejectsNegativeNumbers(?int $line, ?int $column, string $field): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('must not be negative: ' . $field);

        new ViolationSource('', $line, $column);
    }
}
