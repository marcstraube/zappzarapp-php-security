<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Uri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ValueError;
use Zappzarapp\Security\Sanitization\Uri\UriScheme;

#[CoversClass(UriScheme::class)]
final class UriSchemeTest extends TestCase
{
    // =========================================================================
    // Enum Cases and Values
    // =========================================================================

    #[Test]
    public function testAllEnumCasesExist(): void
    {
        $this->assertSame('http', UriScheme::HTTP->value);
        $this->assertSame('https', UriScheme::HTTPS->value);
        $this->assertSame('ftp', UriScheme::FTP->value);
        $this->assertSame('ftps', UriScheme::FTPS->value);
        $this->assertSame('mailto', UriScheme::MAILTO->value);
        $this->assertSame('tel', UriScheme::TEL->value);
        $this->assertSame('sms', UriScheme::SMS->value);
        $this->assertSame('data', UriScheme::DATA->value);
        $this->assertSame('javascript', UriScheme::JAVASCRIPT->value);
        $this->assertSame('vbscript', UriScheme::VBSCRIPT->value);
        $this->assertSame('file', UriScheme::FILE->value);
    }

    #[Test]
    public function testEnumCaseCount(): void
    {
        $cases = UriScheme::cases();

        $this->assertCount(11, $cases);
    }

    // =========================================================================
    // isDangerous() - XSS Prevention
    // =========================================================================

    #[DataProvider('dangerousSchemeProvider')]
    #[Test]
    public function testIsDangerousReturnsTrueForDangerousSchemes(UriScheme $scheme): void
    {
        $this->assertTrue($scheme->isDangerous());
    }

    /**
     * @return iterable<string, array{UriScheme}>
     */
    public static function dangerousSchemeProvider(): iterable
    {
        yield 'javascript' => [UriScheme::JAVASCRIPT];
        yield 'vbscript' => [UriScheme::VBSCRIPT];
        yield 'data' => [UriScheme::DATA];
    }

    #[DataProvider('safeSchemesProvider')]
    #[Test]
    public function testIsDangerousReturnsFalseForSafeSchemes(UriScheme $scheme): void
    {
        $this->assertFalse($scheme->isDangerous());
    }

    /**
     * @return iterable<string, array{UriScheme}>
     */
    public static function safeSchemesProvider(): iterable
    {
        yield 'http' => [UriScheme::HTTP];
        yield 'https' => [UriScheme::HTTPS];
        yield 'ftp' => [UriScheme::FTP];
        yield 'ftps' => [UriScheme::FTPS];
        yield 'mailto' => [UriScheme::MAILTO];
        yield 'tel' => [UriScheme::TEL];
        yield 'sms' => [UriScheme::SMS];
        yield 'file' => [UriScheme::FILE];
    }

    // =========================================================================
    // isSafeForWeb() - Web Usage
    // =========================================================================

    #[DataProvider('webSafeSchemeProvider')]
    #[Test]
    public function testIsSafeForWebReturnsTrueForWebSafeSchemes(UriScheme $scheme): void
    {
        $this->assertTrue($scheme->isSafeForWeb());
    }

    /**
     * @return iterable<string, array{UriScheme}>
     */
    public static function webSafeSchemeProvider(): iterable
    {
        yield 'http' => [UriScheme::HTTP];
        yield 'https' => [UriScheme::HTTPS];
        yield 'mailto' => [UriScheme::MAILTO];
        yield 'tel' => [UriScheme::TEL];
    }

    #[DataProvider('webUnsafeSchemeProvider')]
    #[Test]
    public function testIsSafeForWebReturnsFalseForUnsafeSchemes(UriScheme $scheme): void
    {
        $this->assertFalse($scheme->isSafeForWeb());
    }

    /**
     * @return iterable<string, array{UriScheme}>
     */
    public static function webUnsafeSchemeProvider(): iterable
    {
        yield 'ftp' => [UriScheme::FTP];
        yield 'ftps' => [UriScheme::FTPS];
        yield 'sms' => [UriScheme::SMS];
        yield 'data' => [UriScheme::DATA];
        yield 'javascript' => [UriScheme::JAVASCRIPT];
        yield 'vbscript' => [UriScheme::VBSCRIPT];
        yield 'file' => [UriScheme::FILE];
    }

    // =========================================================================
    // Relationship Between isDangerous() and isSafeForWeb()
    // =========================================================================

    #[Test]
    public function testDangerousSchemesAreNotSafeForWeb(): void
    {
        foreach (UriScheme::cases() as $scheme) {
            if ($scheme->isDangerous()) {
                $this->assertFalse(
                    $scheme->isSafeForWeb(),
                    sprintf('%s is dangerous but marked as safe for web', $scheme->name)
                );
            }
        }
    }

    #[Test]
    public function testWebSafeSchemesAreNotDangerous(): void
    {
        foreach (UriScheme::cases() as $scheme) {
            if ($scheme->isSafeForWeb()) {
                $this->assertFalse(
                    $scheme->isDangerous(),
                    sprintf('%s is safe for web but marked as dangerous', $scheme->name)
                );
            }
        }
    }

    // =========================================================================
    // tryFrom() - Creating from String Value
    // =========================================================================

    #[Test]
    public function testTryFromReturnsSchemeForValidValue(): void
    {
        $this->assertSame(UriScheme::HTTP, UriScheme::tryFrom('http'));
        $this->assertSame(UriScheme::HTTPS, UriScheme::tryFrom('https'));
        $this->assertSame(UriScheme::JAVASCRIPT, UriScheme::tryFrom('javascript'));
    }

    #[Test]
    public function testTryFromReturnsNullForInvalidValue(): void
    {
        $this->assertNull(UriScheme::tryFrom('invalid'));
        $this->assertNull(UriScheme::tryFrom(''));
        $this->assertNull(UriScheme::tryFrom('HTTP')); // Case sensitive
    }

    // =========================================================================
    // from() - Creating from String Value (throws on invalid)
    // =========================================================================

    #[Test]
    public function testFromReturnsSchemeForValidValue(): void
    {
        $this->assertSame(UriScheme::HTTP, UriScheme::from('http'));
        $this->assertSame(UriScheme::HTTPS, UriScheme::from('https'));
    }

    #[Test]
    public function testFromThrowsForInvalidValue(): void
    {
        $this->expectException(ValueError::class);

        UriScheme::from('invalid');
    }

    // =========================================================================
    // Security: Classification Correctness
    // =========================================================================

    #[Test]
    public function testJavascriptSchemeIsDangerous(): void
    {
        // javascript: is the most common XSS vector
        $this->assertTrue(UriScheme::JAVASCRIPT->isDangerous());
        $this->assertFalse(UriScheme::JAVASCRIPT->isSafeForWeb());
    }

    #[Test]
    public function testDataSchemeIsDangerous(): void
    {
        // data: can be used for XSS (e.g., data:text/html,<script>...)
        $this->assertTrue(UriScheme::DATA->isDangerous());
        $this->assertFalse(UriScheme::DATA->isSafeForWeb());
    }

    #[Test]
    public function testVbscriptSchemeIsDangerous(): void
    {
        // vbscript: is dangerous in IE
        $this->assertTrue(UriScheme::VBSCRIPT->isDangerous());
        $this->assertFalse(UriScheme::VBSCRIPT->isSafeForWeb());
    }

    #[Test]
    public function testFileSchemeIsNotWebSafe(): void
    {
        // file: can be used for local file access attacks
        $this->assertFalse(UriScheme::FILE->isSafeForWeb());
        // But it's not categorized as "dangerous" in the XSS sense
        $this->assertFalse(UriScheme::FILE->isDangerous());
    }

    #[Test]
    public function testHttpsIsPreferredScheme(): void
    {
        // HTTPS should be safe for web
        $this->assertTrue(UriScheme::HTTPS->isSafeForWeb());
        $this->assertFalse(UriScheme::HTTPS->isDangerous());
    }

    // =========================================================================
    // Complete Coverage: All Cases Tested
    // =========================================================================

    #[Test]
    public function testAllCasesHaveIsDangerousResult(): void
    {
        foreach (UriScheme::cases() as $scheme) {
            // Just ensure the method returns a boolean for all cases
            $this->assertIsBool($scheme->isDangerous());
        }
    }

    #[Test]
    public function testAllCasesHaveIsSafeForWebResult(): void
    {
        foreach (UriScheme::cases() as $scheme) {
            // Just ensure the method returns a boolean for all cases
            $this->assertIsBool($scheme->isSafeForWeb());
        }
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[Test]
    public function testSchemeValuesAreLowercase(): void
    {
        foreach (UriScheme::cases() as $scheme) {
            $this->assertSame(
                strtolower($scheme->value),
                $scheme->value,
                sprintf('Scheme %s value should be lowercase', $scheme->name)
            );
        }
    }

    #[Test]
    public function testSchemeValuesAreUnique(): void
    {
        $values = array_map(
            static fn(UriScheme $scheme): string => $scheme->value,
            UriScheme::cases()
        );

        $this->assertSame(
            count($values),
            count(array_unique($values)),
            'All scheme values should be unique'
        );
    }
}
