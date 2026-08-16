<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\SignedUrl\Exception\InvalidUrlException;

#[CoversClass(InvalidUrlException::class)]
final class InvalidUrlExceptionTest extends TestCase
{
    #[Test]
    public function testContainsControlCharactersFactoryMethod(): void
    {
        $exception = InvalidUrlException::containsControlCharacters();

        $this->assertSame('URL must not contain control characters', $exception->getMessage());
    }

    #[Test]
    public function testMalformedFactoryMethod(): void
    {
        $exception = InvalidUrlException::malformed();

        $this->assertSame('URL cannot be parsed', $exception->getMessage());
    }

    #[Test]
    public function testMissingSchemeFactoryMethod(): void
    {
        $exception = InvalidUrlException::missingScheme();

        $this->assertSame('URL must be absolute - the scheme is missing', $exception->getMessage());
    }

    #[Test]
    public function testUnsupportedSchemeFactoryMethod(): void
    {
        $exception = InvalidUrlException::unsupportedScheme('gopher');

        $this->assertSame('Unsupported URL scheme: gopher (supported: http, https)', $exception->getMessage());
    }

    #[Test]
    public function testMissingHostFactoryMethod(): void
    {
        $exception = InvalidUrlException::missingHost();

        $this->assertSame('URL host is missing or empty', $exception->getMessage());
    }

    #[Test]
    public function testUserInfoNotAllowedFactoryMethod(): void
    {
        $exception = InvalidUrlException::userInfoNotAllowed();

        $this->assertSame('URL must not contain user info (user:password@host)', $exception->getMessage());
    }

    #[Test]
    public function testFragmentNotAllowedFactoryMethod(): void
    {
        $exception = InvalidUrlException::fragmentNotAllowed();

        $this->assertSame(
            'URL must not contain a fragment - fragments are not sent to the server and cannot be signed',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testMalformedPercentEncodingFactoryMethod(): void
    {
        $exception = InvalidUrlException::malformedPercentEncoding();

        $this->assertSame(
            'URL contains malformed percent-encoding ("%" not followed by two hex digits)',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testReservedParameterFactoryMethod(): void
    {
        $exception = InvalidUrlException::reservedParameter('zzp_expires');

        $this->assertSame(
            'URL already contains the reserved query parameter: zzp_expires',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testMissingParameterFactoryMethod(): void
    {
        $exception = InvalidUrlException::missingParameter('zzp_signature');

        $this->assertSame(
            'Signed URL is missing the required query parameter: zzp_signature',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testDuplicateParameterFactoryMethod(): void
    {
        $exception = InvalidUrlException::duplicateParameter('zzp_signature');

        $this->assertSame(
            'Signed URL contains a duplicate query parameter: zzp_signature',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testMalformedExpiryFactoryMethod(): void
    {
        $exception = InvalidUrlException::malformedExpiry('tomorrow');

        $this->assertSame(
            'Signed URL expiry is not a Unix timestamp: tomorrow',
            $exception->getMessage()
        );
    }
}
