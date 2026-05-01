<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */
/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Builder;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Builder\SecurityHeadersBuilder;
use Zappzarapp\Security\Headers\Coep\CoepValue;
use Zappzarapp\Security\Headers\Coop\CoopValue;
use Zappzarapp\Security\Headers\Corp\CorpValue;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;
use Zappzarapp\Security\Headers\SecurityHeaders;
use Zappzarapp\Security\Headers\XFrameOptions\XFrameOptionsValue;

#[CoversClass(SecurityHeadersBuilder::class)]
final class SecurityHeadersBuilderTest extends TestCase
{
    #[Test]
    public function testBuildDefaultHeaders(): void
    {
        $headers = new SecurityHeaders();
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        // Default headers has xContentTypeOptions=true and xXssProtection=true
        $this->assertArrayHasKey('X-Content-Type-Options', $result);
        $this->assertArrayHasKey('X-XSS-Protection', $result);
        $this->assertSame('nosniff', $result['X-Content-Type-Options']);
        $this->assertSame('0', $result['X-XSS-Protection']);
    }

    #[Test]
    public function testBuildMinimalHeaders(): void
    {
        $headers = (new SecurityHeaders())
            ->withoutXContentTypeOptions()
            ->withoutXXssProtection();
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertSame([], $result);
    }

    #[Test]
    public function testBuildWithHsts(): void
    {
        $headers = (new SecurityHeaders())->withHsts(HstsConfig::strict());
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('Strict-Transport-Security', $result);
        $this->assertStringContainsString('max-age=', $result['Strict-Transport-Security']);
    }

    #[Test]
    public function testBuildWithCoop(): void
    {
        $headers = (new SecurityHeaders())->withCoop(CoopValue::SAME_ORIGIN);
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('Cross-Origin-Opener-Policy', $result);
        $this->assertSame('same-origin', $result['Cross-Origin-Opener-Policy']);
    }

    #[Test]
    public function testBuildWithCoep(): void
    {
        $headers = (new SecurityHeaders())->withCoep(CoepValue::REQUIRE_CORP);
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('Cross-Origin-Embedder-Policy', $result);
        $this->assertSame('require-corp', $result['Cross-Origin-Embedder-Policy']);
    }

    #[Test]
    public function testBuildWithCorp(): void
    {
        $headers = (new SecurityHeaders())->withCorp(CorpValue::SAME_ORIGIN);
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('Cross-Origin-Resource-Policy', $result);
        $this->assertSame('same-origin', $result['Cross-Origin-Resource-Policy']);
    }

    #[Test]
    public function testBuildWithReferrerPolicy(): void
    {
        $headers = (new SecurityHeaders())->withReferrerPolicy(ReferrerPolicyValue::NO_REFERRER);
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('Referrer-Policy', $result);
        $this->assertSame('no-referrer', $result['Referrer-Policy']);
    }

    #[Test]
    public function testBuildWithXFrameOptions(): void
    {
        $headers = (new SecurityHeaders())->withXFrameOptions(XFrameOptionsValue::DENY);
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('X-Frame-Options', $result);
        $this->assertSame('DENY', $result['X-Frame-Options']);
    }

    #[Test]
    public function testBuildWithXContentTypeOptions(): void
    {
        $headers = new SecurityHeaders(); // xContentTypeOptions is true by default
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('X-Content-Type-Options', $result);
        $this->assertSame('nosniff', $result['X-Content-Type-Options']);
    }

    #[Test]
    public function testBuildWithXXssProtection(): void
    {
        $headers = new SecurityHeaders(); // xXssProtection is true by default
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('X-XSS-Protection', $result);
        $this->assertSame('0', $result['X-XSS-Protection']);
    }

    #[Test]
    public function testBuildWithAllHeaders(): void
    {
        $headers = SecurityHeaders::strict();
        $builder = new SecurityHeadersBuilder($headers);

        $result = $builder->build();

        $this->assertArrayHasKey('Strict-Transport-Security', $result);
        $this->assertArrayHasKey('Cross-Origin-Opener-Policy', $result);
        $this->assertArrayHasKey('Cross-Origin-Embedder-Policy', $result);
        $this->assertArrayHasKey('Cross-Origin-Resource-Policy', $result);
        $this->assertArrayHasKey('Referrer-Policy', $result);
        $this->assertArrayHasKey('X-Frame-Options', $result);
        $this->assertArrayHasKey('X-Content-Type-Options', $result);
        // X-XSS-Protection is disabled in strict preset (causes issues in modern browsers)
        $this->assertArrayNotHasKey('X-XSS-Protection', $result);
        $this->assertArrayHasKey('Permissions-Policy', $result);
    }

    #[Test]
    public function testFromStaticFactory(): void
    {
        $headers = new SecurityHeaders();
        $builder = SecurityHeadersBuilder::from($headers);

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(SecurityHeadersBuilder::class, $builder);
    }
}
