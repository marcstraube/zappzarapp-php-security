<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Scanner;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Scanner\Exception\ScanException;
use Zappzarapp\Security\Scanner\HeaderFetcherInterface;
use Zappzarapp\Security\Scanner\StreamHeaderFetcher;

#[CoversClass(StreamHeaderFetcher::class)]
#[CoversClass(ScanException::class)]
final class StreamHeaderFetcherTest extends TestCase
{
    #[Test]
    public function testImplementsHeaderFetcherInterface(): void
    {
        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(HeaderFetcherInterface::class, new StreamHeaderFetcher());
    }

    #[DataProvider('invalidUrlProvider')]
    #[Test]
    public function testFetchRejectsInvalidUrls(string $url): void
    {
        $fetcher = new StreamHeaderFetcher();

        $this->expectException(ScanException::class);
        $this->expectExceptionMessage('only http:// and https:// URLs can be scanned');

        $fetcher->fetch($url);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidUrlProvider(): array
    {
        return [
            'empty'             => [''],
            'not a url'         => ['not-a-url'],
            'missing scheme'    => ['example.com'],
            'ftp scheme'        => ['ftp://example.com'],
            'file scheme'       => ['file:///etc/hosts'],
            'javascript scheme' => ['javascript:alert(1)'],
        ];
    }

    #[Test]
    public function testNormalizeSkipsStatusLines(): void
    {
        $fetcher = new StreamHeaderFetcher();

        $normalized = $fetcher->normalizeHeaders([
            0                => 'HTTP/1.1 200 OK',
            'X-Test-Header'  => 'value',
        ]);

        $this->assertSame(['X-Test-Header' => 'value'], $normalized);
    }

    #[Test]
    public function testNormalizeUsesLastValueOfRedirectChains(): void
    {
        $fetcher = new StreamHeaderFetcher();

        $normalized = $fetcher->normalizeHeaders([
            0                           => 'HTTP/1.1 301 Moved Permanently',
            1                           => 'HTTP/1.1 200 OK',
            'X-Frame-Options'           => ['SAMEORIGIN', 'DENY'],
            'Strict-Transport-Security' => 'max-age=63072000',
        ]);

        $this->assertSame(
            [
                'X-Frame-Options'           => 'DENY',
                'Strict-Transport-Security' => 'max-age=63072000',
            ],
            $normalized
        );
    }

    #[Test]
    public function testNormalizeSkipsEmptyValueLists(): void
    {
        $fetcher = new StreamHeaderFetcher();

        $this->assertSame([], $fetcher->normalizeHeaders(['X-Empty' => []]));
    }

    #[Test]
    public function testNormalizeContinuesAfterEmptyValueList(): void
    {
        $fetcher = new StreamHeaderFetcher();

        $normalized = $fetcher->normalizeHeaders([
            'X-Empty' => [],
            'X-After' => 'still-processed',
        ]);

        $this->assertSame(['X-After' => 'still-processed'], $normalized);
    }

    #[Test]
    public function testNormalizeEmptyInput(): void
    {
        $this->assertSame([], (new StreamHeaderFetcher())->normalizeHeaders([]));
    }
}
