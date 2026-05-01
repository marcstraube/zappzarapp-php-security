<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Sri\CrossOrigin;
use Zappzarapp\Security\Sri\Exception\FetchException;
use Zappzarapp\Security\Sri\Exception\HashMismatchException;
use Zappzarapp\Security\Sri\HashAlgorithm;
use Zappzarapp\Security\Sri\HttpClientInterface;
use Zappzarapp\Security\Sri\IntegrityAttribute;
use Zappzarapp\Security\Sri\ResourceFetcher;
use Zappzarapp\Security\Sri\ResourceFetcherConfig;
use Zappzarapp\Security\Sri\SriHashGenerator;

#[CoversClass(SriHashGenerator::class)]
#[UsesClass(IntegrityAttribute::class)]
#[UsesClass(HashAlgorithm::class)]
#[UsesClass(ResourceFetcher::class)]
#[UsesClass(ResourceFetcherConfig::class)]
#[UsesClass(HashMismatchException::class)]
#[UsesClass(CrossOrigin::class)]
final class SriHashGeneratorTest extends TestCase
{
    #[Test]
    public function testHashWithDefaultAlgorithm(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'alert("Hello, world!");';

        $integrity = $generator->hash($content);

        $this->assertInstanceOf(IntegrityAttribute::class, $integrity);
        $this->assertStringStartsWith('sha384-', $integrity->value());
    }

    #[Test]
    public function testHashWithCustomDefaultAlgorithm(): void
    {
        $generator = new SriHashGenerator(HashAlgorithm::SHA512);
        $content   = 'test content';

        $integrity = $generator->hash($content);

        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    #[Test]
    public function testHashWithExplicitAlgorithm(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content';

        $integrity = $generator->hash($content, HashAlgorithm::SHA512);

        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    /**
     * @return array<string, array{HashAlgorithm, non-empty-string}>
     */
    public static function algorithmPrefixProvider(): array
    {
        return [
            'SHA384' => [HashAlgorithm::SHA384, 'sha384-'],
            'SHA512' => [HashAlgorithm::SHA512, 'sha512-'],
        ];
    }

    /**
     * @param non-empty-string $expectedPrefix
     */
    #[DataProvider('algorithmPrefixProvider')]
    #[Test]
    public function testHashGeneratesCorrectPrefix(HashAlgorithm $algorithm, string $expectedPrefix): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test', $algorithm);

        $this->assertStringStartsWith($expectedPrefix, $integrity->value());
    }

    #[Test]
    public function testHashFileReadsAndHashes(): void
    {
        $generator = new SriHashGenerator();
        $tempFile  = sys_get_temp_dir() . '/sri_test_' . uniqid() . '.js';
        $content   = 'console.log("test");';
        file_put_contents($tempFile, $content);

        try {
            $integrity = $generator->hashFile($tempFile);

            $expectedIntegrity = $generator->hash($content);
            $this->assertSame($expectedIntegrity->value(), $integrity->value());
        } finally {
            unlink($tempFile);
        }
    }

    #[Test]
    public function testHashFileWithExplicitAlgorithm(): void
    {
        $generator = new SriHashGenerator();
        $tempFile  = sys_get_temp_dir() . '/sri_test_' . uniqid() . '.js';
        $content   = 'console.log("test");';
        file_put_contents($tempFile, $content);

        try {
            $integrity = $generator->hashFile($tempFile, HashAlgorithm::SHA512);

            $this->assertStringStartsWith('sha512-', $integrity->value());
        } finally {
            unlink($tempFile);
        }
    }

    #[Test]
    public function testHashFileThrowsOnNonexistentFile(): void
    {
        $generator = new SriHashGenerator();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot read file');

        $generator->hashFile('/nonexistent/path/to/file.js');
    }

    #[Test]
    public function testHashFileThrowsOnUnreadableFile(): void
    {
        $generator = new SriHashGenerator();

        $this->expectException(RuntimeException::class);

        $generator->hashFile('/root/protected_file_that_does_not_exist.js');
    }

    #[Test]
    public function testHashUrlWithMockedFetcher(): void
    {
        $expectedContent = 'alert("fetched");';

        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn($expectedContent);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $generator = new SriHashGenerator(HashAlgorithm::SHA384, $fetcher);

        $integrity = $generator->hashUrl('https://cdn.example.com/lib.js');

        $expectedIntegrity = IntegrityAttribute::fromContent($expectedContent, HashAlgorithm::SHA384);
        $this->assertSame($expectedIntegrity->value(), $integrity->value());
    }

    #[Test]
    public function testHashUrlWithExplicitAlgorithm(): void
    {
        $expectedContent = 'var x = 1;';

        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn($expectedContent);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $generator = new SriHashGenerator(HashAlgorithm::SHA384, $fetcher);

        $integrity = $generator->hashUrl('https://cdn.example.com/lib.js', HashAlgorithm::SHA512);

        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    #[Test]
    public function testHashUrlThrowsWhenFetcherIsNull(): void
    {
        $generator = new SriHashGenerator(HashAlgorithm::SHA384, null);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ResourceFetcher is required');

        $generator->hashUrl('https://example.com/script.js');
    }

    #[Test]
    public function testHashUrlThrowsOnFetchFailure(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $generator = new SriHashGenerator(HashAlgorithm::SHA384, $fetcher);

        $this->expectException(FetchException::class);

        $generator->hashUrl('https://cdn.example.com/lib.js');
    }

    #[Test]
    public function testHashMultipleWithEmptyArrayUsesDefault(): void
    {
        $generator = new SriHashGenerator(HashAlgorithm::SHA384);
        $content   = 'test content';

        $integrity = $generator->hashMultiple($content, []);

        $this->assertCount(1, $integrity->hashes());
        $this->assertStringStartsWith('sha384-', $integrity->value());
    }

    #[Test]
    public function testHashMultipleWithSingleAlgorithm(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content';

        $integrity = $generator->hashMultiple($content, [HashAlgorithm::SHA512]);

        $this->assertCount(1, $integrity->hashes());
        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    #[Test]
    public function testHashMultipleWithMultipleAlgorithms(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content';

        $integrity = $generator->hashMultiple($content, [
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ]);

        $hashes = $integrity->hashes();
        $this->assertCount(2, $hashes);

        $value = $integrity->value();
        $this->assertStringContainsString('sha384-', $value);
        $this->assertStringContainsString('sha512-', $value);
    }

    #[Test]
    public function testVerifyWithMatchingContent(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'verified content';

        $integrity = $generator->hash($content);

        // Should not throw
        $generator->verify($content, $integrity);

        $this->assertTrue(true); // Reached here means verification passed
    }

    #[Test]
    public function testVerifyWithStringIntegrity(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'verified content';

        $integrity = $generator->hash($content);

        // Should not throw when passing string
        $generator->verify($content, $integrity->value());

        $this->assertTrue(true);
    }

    #[Test]
    public function testVerifyThrowsOnMismatch(): void
    {
        $generator  = new SriHashGenerator();
        $content    = 'original content';
        $integrity  = $generator->hash($content);

        $this->expectException(HashMismatchException::class);

        $generator->verify('modified content', $integrity);
    }

    #[Test]
    public function testVerifyThrowsOnMismatchWithStringIntegrity(): void
    {
        $generator  = new SriHashGenerator();
        $content    = 'original content';
        $integrity  = $generator->hash($content);

        $this->expectException(HashMismatchException::class);

        $generator->verify('modified content', $integrity->value());
    }

    #[Test]
    public function testIsValidReturnsTrueForMatchingContent(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content';
        $integrity = $generator->hash($content);

        $this->assertTrue($generator->isValid($content, $integrity));
    }

    #[Test]
    public function testIsValidReturnsFalseForMismatchedContent(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content';
        $integrity = $generator->hash($content);

        $this->assertFalse($generator->isValid('different content', $integrity));
    }

    #[Test]
    public function testIsValidAcceptsStringIntegrity(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content';
        $integrity = $generator->hash($content);

        $this->assertTrue($generator->isValid($content, $integrity->value()));
        $this->assertFalse($generator->isValid('other', $integrity->value()));
    }

    #[Test]
    public function testScriptTagGeneration(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'console.log("test");';
        $integrity = $generator->hash($content);

        $tag = $generator->scriptTag('https://cdn.example.com/lib.js', $integrity);

        $this->assertStringContainsString('<script src="https://cdn.example.com/lib.js"', $tag);
        $this->assertStringContainsString('integrity="sha384-', $tag);
        $this->assertStringContainsString('crossorigin="anonymous"', $tag);
        $this->assertStringContainsString('</script>', $tag);
    }

    #[Test]
    public function testScriptTagWithStringIntegrity(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'console.log("test");';
        $integrity = $generator->hash($content);

        $tag = $generator->scriptTag('https://cdn.example.com/lib.js', $integrity->value());

        $this->assertStringContainsString('integrity="sha384-', $tag);
    }

    #[Test]
    public function testScriptTagWithUseCredentials(): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test');

        $tag = $generator->scriptTag('https://cdn.example.com/lib.js', $integrity, CrossOrigin::USE_CREDENTIALS);

        $this->assertStringContainsString('crossorigin="use-credentials"', $tag);
    }

    #[Test]
    public function testScriptTagWithNoCrossOrigin(): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test');

        $tag = $generator->scriptTag('https://cdn.example.com/lib.js', $integrity, null);

        $this->assertStringNotContainsString('crossorigin', $tag);
    }

    #[Test]
    public function testScriptTagEscapesSpecialCharacters(): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test');

        $tag = $generator->scriptTag('https://cdn.example.com/lib.js?a=1&b=2', $integrity);

        $this->assertStringContainsString('&amp;', $tag);
    }

    #[Test]
    public function testLinkTagGeneration(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'body { color: red; }';
        $integrity = $generator->hash($content);

        $tag = $generator->linkTag('https://cdn.example.com/style.css', $integrity);

        $this->assertStringContainsString('<link rel="stylesheet" href="https://cdn.example.com/style.css"', $tag);
        $this->assertStringContainsString('integrity="sha384-', $tag);
        $this->assertStringContainsString('crossorigin="anonymous"', $tag);
        $this->assertStringContainsString('>', $tag);
        $this->assertStringNotContainsString('</link>', $tag);
    }

    #[Test]
    public function testLinkTagWithStringIntegrity(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'body {}';
        $integrity = $generator->hash($content);

        $tag = $generator->linkTag('https://cdn.example.com/style.css', $integrity->value());

        $this->assertStringContainsString('integrity="sha384-', $tag);
    }

    #[Test]
    public function testLinkTagWithUseCredentials(): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test');

        $tag = $generator->linkTag('https://cdn.example.com/style.css', $integrity, CrossOrigin::USE_CREDENTIALS);

        $this->assertStringContainsString('crossorigin="use-credentials"', $tag);
    }

    #[Test]
    public function testLinkTagWithNoCrossOrigin(): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test');

        $tag = $generator->linkTag('https://cdn.example.com/style.css', $integrity, null);

        $this->assertStringNotContainsString('crossorigin', $tag);
    }

    #[Test]
    public function testLinkTagEscapesSpecialCharacters(): void
    {
        $generator = new SriHashGenerator();
        $integrity = $generator->hash('test');

        $tag = $generator->linkTag('https://cdn.example.com/style.css?v=1&t=2', $integrity);

        $this->assertStringContainsString('&amp;', $tag);
    }

    #[Test]
    public function testHashGeneratesValidBase64(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'test content with special chars: <>&"\'';

        $integrity = $generator->hash($content);
        $value     = $integrity->value();

        // Extract base64 part after algorithm prefix
        $base64 = substr($value, strpos($value, '-') + 1);

        // Valid base64 should decode successfully
        $decoded = base64_decode($base64, true);
        $this->assertNotFalse($decoded);
        $this->assertSame(48, strlen($decoded)); // SHA384 = 48 bytes
    }

    #[Test]
    public function testDeterministicHashing(): void
    {
        $generator = new SriHashGenerator();
        $content   = 'consistent content';

        $integrity1 = $generator->hash($content);
        $integrity2 = $generator->hash($content);

        $this->assertSame($integrity1->value(), $integrity2->value());
    }
}
