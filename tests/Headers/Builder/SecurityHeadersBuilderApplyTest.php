<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */
/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Builder;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Builder\SecurityHeadersBuilder;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\SecurityHeaders;

/**
 * Tests for SecurityHeadersBuilder apply() method behavior.
 *
 * Note: The apply() method itself calls header() which is marked @codeCoverageIgnore.
 * These tests verify the build() output that apply() would send.
 */
#[CoversClass(SecurityHeadersBuilder::class)]
final class SecurityHeadersBuilderApplyTest extends TestCase
{
    #[Test]
    public function testBuildReturnsHeadersForApply(): void
    {
        $headers = (new SecurityHeaders())
            ->withHsts(HstsConfig::strict());
        $builder = new SecurityHeadersBuilder($headers);

        $built = $builder->build();

        // Should have HSTS, X-Content-Type-Options, X-XSS-Protection
        $this->assertArrayHasKey('X-Content-Type-Options', $built);
        $this->assertArrayHasKey('X-XSS-Protection', $built);
        $this->assertArrayHasKey('Strict-Transport-Security', $built);
    }

    #[Test]
    public function testBuildFormatsValuesCorrectly(): void
    {
        $headers = SecurityHeaders::strict();
        $builder = new SecurityHeadersBuilder($headers);

        $built = $builder->build();

        // Verify all values are strings (some may be empty like X-XSS-Protection: 0)
        foreach ($built as $name => $value) {
            $this->assertIsString($name);
            $this->assertIsString($value);
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9-]+$/', $name);
        }
    }

    #[Test]
    public function testBuildWithMinimalHeadersReturnsEmpty(): void
    {
        $headers = (new SecurityHeaders())
            ->withoutXContentTypeOptions()
            ->withoutXXssProtection();
        $builder = new SecurityHeadersBuilder($headers);

        $built = $builder->build();

        // No headers should be present
        $this->assertEmpty($built);
    }

    #[Test]
    public function testApplyDoesNotThrowInCli(): void
    {
        $headers = new SecurityHeaders();
        $builder = new SecurityHeadersBuilder($headers);

        // apply() should not throw in CLI mode
        $builder->apply();
        $builder->apply(false);
        /** @noinspection PhpRedundantOptionalArgumentInspection Test explicitly verifies replace=true behavior */
        $builder->apply(true);

        $this->assertTrue(true);
    }
}
