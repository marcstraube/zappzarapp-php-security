<?php

/** @noinspection PhpClassCanBeReadonlyInspection PHPMD/PDepend cannot parse new readonly class syntax */

/** @noinspection HttpUrlsUsage Plain-http URLs are intentional fixtures for scheme and default-port handling */

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\SignedUrl\Exception\InvalidContextException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidLifetimeException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidSignatureException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidUrlException;
use Zappzarapp\Security\SignedUrl\Exception\UrlExpiredException;
use Zappzarapp\Security\SignedUrl\SigningKey;
use Zappzarapp\Security\SignedUrl\UrlSigner;

#[CoversClass(UrlSigner::class)]
#[CoversClass(InvalidContextException::class)]
#[CoversClass(InvalidLifetimeException::class)]
#[CoversClass(InvalidSignatureException::class)]
#[CoversClass(InvalidUrlException::class)]
#[CoversClass(UrlExpiredException::class)]
#[UsesClass(SecretValue::class)]
#[UsesClass(SigningKey::class)]
final class UrlSignerTest extends TestCase
{
    private const int NOW = 1_800_000_000;

    /**
     * Known-answer signature for KAT_URL signed with the fixed key at NOW,
     * lifetime 3600, context "user:42" - pins the wire contract
     */
    private const string KAT_SIGNATURE = 'pI9Rh-EBAA17byiXc3fl0gDzlhSfI2puUWUpMS3LB_Q';

    private const string KAT_URL = 'https://example.com/download?file=report.pdf&b=2&a=1';

    // =========================================================
    // Signing
    // =========================================================

    #[Test]
    public function testSignAppendsExpiryAndSignatureParameters(): void
    {
        $signed = $this->signer()->sign(self::KAT_URL, 3600, 'user:42');

        $this->assertSame(
            self::KAT_URL . '&zzp_expires=1800003600&zzp_signature=' . self::KAT_SIGNATURE,
            $signed
        );
    }

    #[Test]
    public function testSignUsesQuestionMarkSeparatorWithoutExistingQuery(): void
    {
        $signed = $this->signer()->sign('http://example.com', 60);

        $this->assertSame(
            'http://example.com?zzp_expires=1800000060&zzp_signature=BHvgBBQ1FPkzVQjwozX7Zowx_gAU7rECICTBW2S-_TY',
            $signed
        );
    }

    #[Test]
    public function testSignatureMatchesDocumentedWireContract(): void
    {
        $input = '24:zappzarapp-signed-url-v1'
            . '5:https'
            . '11:example.com'
            . '3:443'
            . '9:/download'
            . '23:file=report.pdf&b=2&a=1'
            . '10:1800003600'
            . '1:1'
            . '7:user:42';

        $expected = sodium_bin2base64(
            hash_hmac('sha256', $input, str_repeat('k', 32), true),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        );

        $this->assertSame(self::KAT_SIGNATURE, $expected);
    }

    #[Test]
    public function testSignatureCoversExplicitPortQueryOrderAndKeyOnlyPairs(): void
    {
        $input = '24:zappzarapp-signed-url-v1'
            . '4:http'
            . '11:example.com'
            . '4:8080'
            . '1:/'
            . '13:9=a&10=b&flag'
            . '10:1800000060'
            . '1:0'
            . '0:';

        $expected = sodium_bin2base64(
            hash_hmac('sha256', $input, str_repeat('k', 32), true),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        );

        $signed = $this->signer()->sign('http://example.com:8080/?9=a&10=b&flag', 60);

        $this->assertSame(
            'http://example.com:8080/?9=a&10=b&flag&zzp_expires=1800000060&zzp_signature=' . $expected,
            $signed
        );
    }

    #[Test]
    public function testSignatureIsUrlSafeBase64WithoutPadding(): void
    {
        $signed = $this->signer()->sign('https://example.com/path', 3600);

        $this->assertMatchesRegularExpression(
            '/&zzp_signature=[A-Za-z0-9_-]{43}$/',
            $signed
        );
    }

    #[Test]
    public function testSignAppendsDirectlyAfterTrailingQuestionMark(): void
    {
        $signer = $this->signer();

        $signed = $signer->sign('http://example.com/p?', 60);

        $this->assertSame($signer->sign('http://example.com/p', 60), $signed);
        $this->assertVerifies($signer, $signed);
    }

    #[Test]
    public function testSignAppendsDirectlyAfterTrailingAmpersand(): void
    {
        $signer = $this->signer();

        $signed = $signer->sign('http://example.com/p?a=1&', 60);

        $this->assertSame($signer->sign('http://example.com/p?a=1', 60), $signed);
        $this->assertVerifies($signer, $signed);
    }

    #[Test]
    public function testSignAcceptsLifetimeOfOneSecond(): void
    {
        $signed = $this->signer()->sign('https://example.com/path', 1);

        $this->assertStringContainsString('zzp_expires=1800000001', $signed);
    }

    #[Test]
    public function testSignAcceptsMaximumLifetime(): void
    {
        $signer = $this->signer();

        $signed = $signer->sign('https://example.com/path', 3_153_600_000);

        $this->assertStringContainsString('zzp_expires=4953600000', $signed);
        $this->assertVerifies($signer, $signed);
    }

    #[Test]
    public function testSignRejectsLifetimeAboveMaximum(): void
    {
        $this->expectException(InvalidLifetimeException::class);
        $this->expectExceptionMessage(
            'Signed URL lifetime must not exceed 3153600000 seconds (100 years), got 3153600001'
        );

        $this->signer()->sign('https://example.com/path', 3_153_600_001);
    }

    #[DataProvider('nonPositiveLifetimeProvider')]
    #[Test]
    public function testSignRejectsNonPositiveLifetime(int $lifetime): void
    {
        $this->expectException(InvalidLifetimeException::class);
        $this->expectExceptionMessage(
            sprintf('Signed URL lifetime must be a positive number of seconds, got %d', $lifetime)
        );

        $this->signer()->sign('https://example.com/path', $lifetime);
    }

    /**
     * @return array<string, array{int}>
     */
    public static function nonPositiveLifetimeProvider(): array
    {
        return [
            'zero'     => [0],
            'negative' => [-3600],
        ];
    }

    #[DataProvider('reservedParameterProvider')]
    #[Test]
    public function testSignRejectsUrlsCarryingReservedParameters(string $url, string $name): void
    {
        $this->expectException(InvalidUrlException::class);
        $this->expectExceptionMessage(
            sprintf('URL already contains the reserved query parameter: %s', $name)
        );

        $this->signer()->sign($url, 3600);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function reservedParameterProvider(): array
    {
        return [
            'expires'           => ['https://example.com/?zzp_expires=1', 'zzp_expires'],
            'signature'         => ['https://example.com/?zzp_signature=x', 'zzp_signature'],
            'encoded signature' => ['https://example.com/?zzp_signatur%65=x', 'zzp_signature'],
        ];
    }

    // =========================================================
    // Verification - success paths and canonicalization
    // =========================================================

    #[Test]
    public function testVerifyAcceptsSignedUrl(): void
    {
        $signer = $this->signer();

        $this->assertVerifies($signer, $signer->sign(self::KAT_URL, 3600, 'user:42'), 'user:42');
    }

    #[Test]
    public function testVerifyWithSystemClock(): void
    {
        $signer = new UrlSigner(new SigningKey(str_repeat('k', 32)));

        $this->assertVerifies($signer, $signer->sign('https://example.com/path?a=1', 3600));
    }

    #[Test]
    public function testVerifyRejectsReorderedDistinctParameters(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?a=1&b=2', 3600);

        $this->assertVerifies($signer, $signed);

        $this->expectException(InvalidSignatureException::class);

        $signer->verify(str_replace('a=1&b=2', 'b=2&a=1', $signed));
    }

    #[Test]
    public function testVerifyAcceptsEquivalentPercentEncoding(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?x=%41', 3600);

        $this->assertVerifies($signer, str_replace('x=%41', 'x=A', $signed));
    }

    #[Test]
    public function testVerifyAcceptsDefaultHttpPortAsEquivalent(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('http://example.com/path', 3600);

        $this->assertVerifies($signer, str_replace('example.com', 'example.com:80', $signed));
    }

    #[Test]
    public function testVerifyAcceptsDefaultHttpsPortAsEquivalent(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path', 3600);

        $this->assertVerifies($signer, str_replace('example.com', 'example.com:443', $signed));
    }

    #[Test]
    public function testVerifyAcceptsRootPathAsEquivalentToEmptyPath(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('http://example.com', 3600);

        $this->assertVerifies($signer, str_replace('example.com?', 'example.com/?', $signed));
    }

    #[Test]
    public function testVerifyAcceptsLowercasedSchemeAndHostAsEquivalent(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('HTTPS://EXAMPLE.COM/path', 3600);

        $this->assertVerifies($signer, str_replace('HTTPS://EXAMPLE.COM', 'https://example.com', $signed));
    }

    #[Test]
    public function testVerifySkipsEmptyQuerySegments(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?a=1&&b=2', 3600);

        $this->assertVerifies($signer, str_replace('a=1&&b=2', 'a=1&b=2', $signed));
    }

    #[Test]
    public function testVerifyRejectsKeyOnlyParameterMutatedToEmptyValue(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?flag', 3600);

        $this->assertVerifies($signer, $signed);

        $this->expectException(InvalidSignatureException::class);

        $signer->verify(str_replace('?flag', '?flag=', $signed));
    }

    #[Test]
    public function testVerifyRejectsEmptyValueParameterMutatedToKeyOnly(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?flag=', 3600);

        $this->assertVerifies($signer, $signed);

        $this->expectException(InvalidSignatureException::class);

        $signer->verify(str_replace('?flag=', '?flag', $signed));
    }

    #[Test]
    public function testVerifyParsesSegmentsAfterKeyOnlyParameter(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?flag&a=1', 3600);

        $this->assertVerifies($signer, $signed);
    }

    #[Test]
    public function testVerifyAcceptsRepeatedKeysInOriginalOrder(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?a=1&a=2', 3600);

        $this->assertVerifies($signer, $signed);
    }

    #[Test]
    public function testVerifyRejectsReorderedRepeatedKeys(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?a=1&a=2', 3600);

        $this->expectException(InvalidSignatureException::class);

        $signer->verify(str_replace('a=1&a=2', 'a=2&a=1', $signed));
    }

    #[Test]
    public function testVerifyDoesNotTreatPlusAsSpace(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path?q=a+b', 3600);

        $this->assertVerifies($signer, $signed);

        $this->expectException(InvalidSignatureException::class);

        $signer->verify(str_replace('q=a+b', 'q=a%20b', $signed));
    }

    // =========================================================
    // Verification - tampering
    // =========================================================

    #[DataProvider('tamperProvider')]
    #[Test]
    public function testVerifyRejectsTamperedUrls(string $search, string $replace): void
    {
        $signer = $this->signer();
        $signed = $signer->sign(self::KAT_URL, 3600, 'user:42');

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('Signed URL signature does not match the URL contents');

        $signer->verify(str_replace($search, $replace, $signed), 'user:42');
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function tamperProvider(): array
    {
        return [
            'scheme changed'          => ['https://', 'http://'],
            'host changed'            => ['example.com', 'evil.example.org'],
            'port changed'            => ['example.com', 'example.com:8443'],
            'path changed'            => ['/download', '/admin'],
            'parameter value changed' => ['file=report.pdf', 'file=secrets.pdf'],
            'parameter added'         => ['?file', '?admin=1&file'],
            'parameter removed'       => ['file=report.pdf&', ''],
            'expiry extended'         => ['zzp_expires=1800003600', 'zzp_expires=1900000000'],
            'signature truncated'     => [self::KAT_SIGNATURE, substr(self::KAT_SIGNATURE, 0, 42)],
        ];
    }

    #[Test]
    public function testVerifyRejectsWrongContext(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign(self::KAT_URL, 3600, 'user:42');

        $this->expectException(InvalidSignatureException::class);

        $signer->verify($signed, 'user:43');
    }

    #[Test]
    public function testVerifyRejectsMissingContext(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign(self::KAT_URL, 3600, 'user:42');

        $this->expectException(InvalidSignatureException::class);

        $signer->verify($signed);
    }

    #[Test]
    public function testVerifyDistinguishesEmptyContextFromNoContext(): void
    {
        $signer = $this->signer();
        $signed = $signer->sign('https://example.com/path', 3600, '');

        $this->expectException(InvalidSignatureException::class);

        $signer->verify($signed);
    }

    #[Test]
    public function testVerifyRejectsSignatureFromDifferentKey(): void
    {
        $signed = $this->signer()->sign('https://example.com/path', 3600);
        $other  = new UrlSigner(new SigningKey(str_repeat('x', 32)), $this->frozenClock(self::NOW));

        $this->expectException(InvalidSignatureException::class);

        $other->verify($signed);
    }

    // =========================================================
    // Verification - expiry
    // =========================================================

    #[Test]
    public function testVerifyAcceptsUrlAtExactExpiryTimestamp(): void
    {
        $signed   = $this->signer()->sign('https://example.com/path', 3600);
        $atExpiry = new UrlSigner(new SigningKey(str_repeat('k', 32)), $this->frozenClock(self::NOW + 3600));

        $this->assertVerifies($atExpiry, $signed);
    }

    #[Test]
    public function testVerifyRejectsUrlOneSecondAfterExpiry(): void
    {
        $signed = $this->signer()->sign('https://example.com/path', 3600);
        $late   = new UrlSigner(new SigningKey(str_repeat('k', 32)), $this->frozenClock(self::NOW + 3601));

        $this->expectException(UrlExpiredException::class);
        $this->expectExceptionMessage('Signed URL expired at 1800003600 (now: 1800003601)');

        $late->verify($signed);
    }

    #[Test]
    public function testVerifyChecksSignatureBeforeExpiry(): void
    {
        $signed = $this->signer()->sign('https://example.com/path', 3600);
        $late   = new UrlSigner(new SigningKey(str_repeat('k', 32)), $this->frozenClock(self::NOW + 999_999));

        $this->expectException(InvalidSignatureException::class);

        $late->verify(str_replace('/path', '/other', $signed));
    }

    // =========================================================
    // Verification - reserved parameter handling
    // =========================================================

    #[DataProvider('missingParameterProvider')]
    #[Test]
    public function testVerifyRejectsMissingReservedParameters(string $url, string $name): void
    {
        $this->expectException(InvalidUrlException::class);
        $this->expectExceptionMessage(
            sprintf('Signed URL is missing the required query parameter: %s', $name)
        );

        $this->signer()->verify($url);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function missingParameterProvider(): array
    {
        return [
            'no parameters at all' => ['https://example.com/path', 'zzp_signature'],
            'signature missing'    => ['https://example.com/path?zzp_expires=1800003600', 'zzp_signature'],
            'expiry missing'       => ['https://example.com/path?zzp_signature=abc', 'zzp_expires'],
        ];
    }

    #[DataProvider('duplicateParameterProvider')]
    #[Test]
    public function testVerifyRejectsDuplicateReservedParameters(string $suffix, string $name): void
    {
        $signed = $this->signer()->sign('https://example.com/path', 3600);

        $this->expectException(InvalidUrlException::class);
        $this->expectExceptionMessage(
            sprintf('Signed URL contains a duplicate query parameter: %s', $name)
        );

        $this->signer()->verify($signed . $suffix);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function duplicateParameterProvider(): array
    {
        return [
            'second expiry'            => ['&zzp_expires=1900000000', 'zzp_expires'],
            'second signature'         => ['&zzp_signature=forged', 'zzp_signature'],
            'percent-encoded smuggle'  => ['&zzp_signatur%65=forged', 'zzp_signature'],
        ];
    }

    #[DataProvider('malformedExpiryProvider')]
    #[Test]
    public function testVerifyRejectsMalformedExpiryValues(string $expiry): void
    {
        $url = 'https://example.com/path?zzp_expires=' . $expiry . '&zzp_signature=abc';

        $this->expectException(InvalidUrlException::class);
        $this->expectExceptionMessage(
            'Signed URL expiry is not a Unix timestamp: ' . rawurldecode($expiry)
        );

        $this->signer()->verify($url);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedExpiryProvider(): array
    {
        return [
            'empty'            => [''],
            'negative'         => ['-1'],
            'float'            => ['1.5'],
            'hex'              => ['0x10'],
            'non-numeric'      => ['tomorrow'],
            'nineteen digits'  => ['1234567890123456789'],
            'leading zero'     => ['0123456789'],
            'all zeros'        => ['00'],
        ];
    }

    #[Test]
    public function testVerifyAcceptsZeroExpiryAsWellFormed(): void
    {
        $url = 'https://example.com/path?zzp_expires=0&zzp_signature=abc';

        $this->expectException(InvalidSignatureException::class);

        $this->signer()->verify($url);
    }

    #[Test]
    public function testVerifyAcceptsEighteenDigitExpiryAsWellFormed(): void
    {
        $url = 'https://example.com/path?zzp_expires=123456789012345678&zzp_signature=abc';

        $this->expectException(InvalidSignatureException::class);

        $this->signer()->verify($url);
    }

    // =========================================================
    // Malformed URLs - sign and verify are total
    // =========================================================

    #[DataProvider('invalidUrlProvider')]
    #[Test]
    public function testSignRejectsInvalidUrls(string $url, string $message): void
    {
        $this->expectException(InvalidUrlException::class);
        $this->expectExceptionMessage($message);

        $this->signer()->sign($url, 3600);
    }

    #[DataProvider('invalidUrlProvider')]
    #[Test]
    public function testVerifyRejectsInvalidUrls(string $url, string $message): void
    {
        $this->expectException(InvalidUrlException::class);
        $this->expectExceptionMessage($message);

        $this->signer()->verify($url);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function invalidUrlProvider(): array
    {
        return [
            'newline'             => ["https://example.com/\n", 'URL must not contain control characters'],
            'carriage return'     => ["https://example.com/\r", 'URL must not contain control characters'],
            'null byte'           => ["https://example.com/\0", 'URL must not contain control characters'],
            'unparseable'         => ['http://', 'URL cannot be parsed'],
            'empty host and port' => ['http://:80', 'URL cannot be parsed'],
            'relative path'       => ['/path/only', 'URL must be absolute - the scheme is missing'],
            'protocol relative'   => ['//example.com/path', 'URL must be absolute - the scheme is missing'],
            'ftp scheme'          => ['ftp://example.com/file', 'Unsupported URL scheme: ftp (supported: http, https)'],
            'javascript scheme'   => ['javascript:alert(1)', 'Unsupported URL scheme: javascript (supported: http, https)'],
            'scheme without host' => ['http:path', 'URL host is missing or empty'],
            'user info'           => ['https://user:pass@example.com/', 'URL must not contain user info (user:password@host)'],
            'user only'           => ['https://user@example.com/', 'URL must not contain user info (user:password@host)'],
            'fragment'            => ['https://example.com/path#section', 'URL must not contain a fragment'],
            'bad percent query'   => ['https://example.com/path?x=%ZZ', 'URL contains malformed percent-encoding'],
            'bad percent path'    => ['https://example.com/pa%Gth', 'URL contains malformed percent-encoding'],
            'trailing percent'    => ['https://example.com/path?x=%', 'URL contains malformed percent-encoding'],
        ];
    }

    // =========================================================
    // Context validation
    // =========================================================

    #[DataProvider('unsafeContextProvider')]
    #[Test]
    public function testSignRejectsContextWithControlCharacters(string $context): void
    {
        $this->expectException(InvalidContextException::class);
        $this->expectExceptionMessage('Context value must not contain control characters');

        $this->signer()->sign('https://example.com/path', 3600, $context);
    }

    #[DataProvider('unsafeContextProvider')]
    #[Test]
    public function testVerifyRejectsContextWithControlCharacters(string $context): void
    {
        $this->expectException(InvalidContextException::class);
        $this->expectExceptionMessage('Context value must not contain control characters');

        $this->signer()->verify('https://example.com/path', $context);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsafeContextProvider(): array
    {
        return [
            'newline'         => ["user\n42"],
            'carriage return' => ["user\r42"],
            'null byte'       => ["user\x0042"],
        ];
    }

    // =========================================================
    // Constants
    // =========================================================

    #[Test]
    public function testReservedParameterNames(): void
    {
        $this->assertSame('zzp_expires', UrlSigner::EXPIRES_PARAM);
        $this->assertSame('zzp_signature', UrlSigner::SIGNATURE_PARAM);
    }

    #[Test]
    public function testMaxLifetimeConstant(): void
    {
        $this->assertSame(3_153_600_000, UrlSigner::MAX_LIFETIME_SECONDS);
    }

    // =========================================================
    // Helpers
    // =========================================================

    /**
     * Signer with a fixed key, frozen at NOW
     */
    private function signer(): UrlSigner
    {
        return new UrlSigner(new SigningKey(str_repeat('k', 32)), $this->frozenClock(self::NOW));
    }

    private function frozenClock(int $timestamp): ClockInterface
    {
        return new class($timestamp) implements ClockInterface {
            public function __construct(private readonly int $timestamp)
            {
            }

            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('@' . $this->timestamp);
            }
        };
    }

    private function assertVerifies(UrlSigner $signer, string $url, ?string $context = null): void
    {
        $signer->verify($url, $context);

        $this->addToAssertionCount(1);
    }
}
