<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Algorithm\AlgorithmType;
use Zappzarapp\Security\RateLimiting\RateLimitConfig;

#[CoversClass(RateLimitConfig::class)]
final class RateLimitConfigTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $config = new RateLimitConfig();

        $this->assertSame(100, $config->limit);
        $this->assertSame(3600, $config->window);
        $this->assertSame(0, $config->burst);
        $this->assertSame('rate_limit:', $config->prefix);
        $this->assertSame(AlgorithmType::SLIDING_WINDOW, $config->algorithm);
    }

    public function testCustomValues(): void
    {
        $config = new RateLimitConfig(
            limit: 50,
            window: 120,
            algorithm: AlgorithmType::TOKEN_BUCKET,
            burst: 10,
            prefix: 'api:'
        );

        $this->assertSame(50, $config->limit);
        $this->assertSame(120, $config->window);
        $this->assertSame(10, $config->burst);
        $this->assertSame('api:', $config->prefix);
        $this->assertSame(AlgorithmType::TOKEN_BUCKET, $config->algorithm);
    }

    public function testWithLimit(): void
    {
        $config    = new RateLimitConfig();
        $newConfig = $config->withLimit(50);

        $this->assertSame(100, $config->limit);
        $this->assertSame(50, $newConfig->limit);
        $this->assertNotSame($config, $newConfig);
    }

    public function testWithWindow(): void
    {
        $config    = new RateLimitConfig();
        $newConfig = $config->withWindow(120);

        $this->assertSame(3600, $config->window);
        $this->assertSame(120, $newConfig->window);
    }

    public function testWithBurst(): void
    {
        $config    = new RateLimitConfig();
        $newConfig = $config->withBurst(10);

        $this->assertSame(0, $config->burst);
        $this->assertSame(10, $newConfig->burst);
    }

    public function testWithPrefix(): void
    {
        $config    = new RateLimitConfig();
        $newConfig = $config->withPrefix('api:');

        $this->assertSame('rate_limit:', $config->prefix);
        $this->assertSame('api:', $newConfig->prefix);
    }

    public function testWithAlgorithm(): void
    {
        $config    = new RateLimitConfig();
        $newConfig = $config->withAlgorithm(AlgorithmType::TOKEN_BUCKET);

        $this->assertSame(AlgorithmType::SLIDING_WINDOW, $config->algorithm);
        $this->assertSame(AlgorithmType::TOKEN_BUCKET, $newConfig->algorithm);
    }

    public function testApiFactory(): void
    {
        $config = RateLimitConfig::api();

        $this->assertSame(1000, $config->limit);
        $this->assertSame(3600, $config->window);
        $this->assertSame(AlgorithmType::SLIDING_WINDOW, $config->algorithm);
    }

    public function testLoginFactory(): void
    {
        $config = RateLimitConfig::login();

        $this->assertSame(5, $config->limit);
        $this->assertSame(900, $config->window);
        $this->assertSame('login_limit:', $config->prefix);
    }

    public function testFormFactory(): void
    {
        $config = RateLimitConfig::form();

        $this->assertSame(10, $config->limit);
        $this->assertSame(60, $config->window);
        $this->assertSame('form_limit:', $config->prefix);
    }

    public function testStrictFactory(): void
    {
        $config = RateLimitConfig::strict(10);

        $this->assertSame(10, $config->limit);
        $this->assertSame(1, $config->window);
        $this->assertSame(20, $config->burst);
        $this->assertSame(AlgorithmType::TOKEN_BUCKET, $config->algorithm);
    }

    public function testImmutability(): void
    {
        $original = new RateLimitConfig();

        $original->withLimit(50);
        $original->withWindow(120);
        $original->withBurst(10);
        $original->withPrefix('api:');
        $original->withAlgorithm(AlgorithmType::TOKEN_BUCKET);

        $this->assertSame(100, $original->limit);
        $this->assertSame(3600, $original->window);
        $this->assertSame(0, $original->burst);
        $this->assertSame('rate_limit:', $original->prefix);
        $this->assertSame(AlgorithmType::SLIDING_WINDOW, $original->algorithm);
    }

    public function testChainedModifications(): void
    {
        $config = (new RateLimitConfig())
            ->withLimit(50)
            ->withWindow(120)
            ->withBurst(10)
            ->withPrefix('api:');

        $this->assertSame(50, $config->limit);
        $this->assertSame(120, $config->window);
        $this->assertSame(10, $config->burst);
        $this->assertSame('api:', $config->prefix);
    }

    public function testConstructorRejectsZeroLimit(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be greater than 0');

        new RateLimitConfig(limit: 0);
    }

    public function testConstructorRejectsNegativeLimit(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be greater than 0');

        new RateLimitConfig(limit: -1);
    }

    public function testConstructorRejectsZeroWindow(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Window must be greater than 0');

        new RateLimitConfig(window: 0);
    }

    public function testConstructorRejectsNegativeWindow(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Window must be greater than 0');

        new RateLimitConfig(window: -1);
    }

    public function testConstructorRejectsNegativeBurst(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Burst must be greater than or equal to 0');

        new RateLimitConfig(burst: -1);
    }

    public function testWithLimitRejectsZero(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be greater than 0');

        (new RateLimitConfig())->withLimit(0);
    }

    public function testWithLimitRejectsNegative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be greater than 0');

        (new RateLimitConfig())->withLimit(-5);
    }

    public function testWithWindowRejectsZero(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Window must be greater than 0');

        (new RateLimitConfig())->withWindow(0);
    }

    public function testWithWindowRejectsNegative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Window must be greater than 0');

        (new RateLimitConfig())->withWindow(-10);
    }

    public function testWithBurstRejectsNegative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Burst must be greater than or equal to 0');

        (new RateLimitConfig())->withBurst(-1);
    }

    public function testStrictRejectsZero(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Requests per second must be greater than 0');

        RateLimitConfig::strict(0);
    }

    public function testStrictRejectsNegative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Requests per second must be greater than 0');

        RateLimitConfig::strict(-5);
    }

    public function testValidEdgeCaseLimitOne(): void
    {
        $config = new RateLimitConfig(limit: 1);

        $this->assertSame(1, $config->limit);
    }

    public function testValidEdgeCaseWindowOne(): void
    {
        $config = new RateLimitConfig(window: 1);

        $this->assertSame(1, $config->window);
    }

    public function testValidEdgeCaseBurstZero(): void
    {
        $config = new RateLimitConfig(burst: 0);

        $this->assertSame(0, $config->burst);
    }

    public function testValidEdgeCaseStrictWithOne(): void
    {
        $config = RateLimitConfig::strict(1);

        $this->assertSame(1, $config->limit);
        $this->assertSame(1, $config->window);
        $this->assertSame(2, $config->burst);
    }
}
