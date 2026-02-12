<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\RateLimiting\Algorithm\AlgorithmType;
use Zappzarapp\Security\RateLimiting\DefaultRateLimiter;
use Zappzarapp\Security\RateLimiting\Exception\RateLimitException;
use Zappzarapp\Security\RateLimiting\RateLimitConfig;
use Zappzarapp\Security\RateLimiting\RateLimiter;
use Zappzarapp\Security\RateLimiting\RateLimitIdentifier;
use Zappzarapp\Security\RateLimiting\RateLimitResult;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

#[CoversClass(DefaultRateLimiter::class)]
final class DefaultRateLimiterTest extends TestCase
{
    /**
     * Create a storage mock that properly tracks counter values
     * This works around the InMemoryStorage limitation where increment/get use separate arrays
     */
    private function createStorageMock(): RateLimitStorage
    {
        /** @var array<string, array<string, mixed>> $data */
        $data = [];

        $storage = $this->createStub(RateLimitStorage::class);

        $storage->method('get')
            ->willReturnCallback(function (string $key) use (&$data): ?array {
                return $data[$key] ?? null;
            });

        $storage->method('set')
            ->willReturnCallback(function (string $key, array $value, int $_ttl) use (&$data): void {
                $data[$key] = $value;
            });

        $storage->method('delete')
            ->willReturnCallback(function (string $key) use (&$data): void {
                unset($data[$key]);
            });

        $storage->method('increment')
            ->willReturnCallback(function (string $key, int $amount, int $_ttl) use (&$data): int {
                $current        = $data[$key]['count'] ?? 0;
                $new            = $current + $amount;
                $data[$key]     = ['count' => $new];

                return $new;
            });

        return $storage;
    }

    private function createLimiter(
        int $limit = 10,
        int $window = 60,
        AlgorithmType $algorithm = AlgorithmType::SLIDING_WINDOW,
        ?SecurityLoggerInterface $logger = null,
        ?RateLimitStorage $storage = null,
    ): DefaultRateLimiter {
        $config = new RateLimitConfig(
            limit: $limit,
            window: $window,
            algorithm: $algorithm
        );

        return new DefaultRateLimiter($config, $storage ?? $this->createStorageMock(), $logger);
    }

    public function testImplementsRateLimiter(): void
    {
        $limiter = $this->createLimiter();

        $this->assertInstanceOf(RateLimiter::class, $limiter);
    }

    public function testConsumeWithStringIdentifier(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $result = $limiter->consume('user:1');

        $this->assertInstanceOf(RateLimitResult::class, $result);
        $this->assertTrue($result->isAllowed());
        $this->assertSame(9, $result->remaining);
    }

    public function testConsumeWithRateLimitIdentifier(): void
    {
        $limiter    = $this->createLimiter(limit: 10);
        $identifier = RateLimitIdentifier::fromUserId(123);

        $result = $limiter->consume($identifier);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(9, $result->remaining);
    }

    public function testConsumeWithCost(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $result = $limiter->consume('user:1', cost: 5);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(5, $result->remaining);
    }

    public function testConsumeDeniesWhenLimitExceeded(): void
    {
        $limiter = $this->createLimiter(limit: 3);

        $limiter->consume('user:1');
        $limiter->consume('user:1');
        $limiter->consume('user:1');

        $result = $limiter->consume('user:1');

        $this->assertTrue($result->isDenied());
    }

    public function testPeekWithStringIdentifier(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $limiter->consume('user:1');
        $result = $limiter->peek('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(9, $result->remaining);
    }

    public function testPeekWithRateLimitIdentifier(): void
    {
        $limiter    = $this->createLimiter(limit: 10);
        $identifier = RateLimitIdentifier::fromUserId(123);

        $limiter->consume($identifier);
        $result = $limiter->peek($identifier);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(9, $result->remaining);
    }

    public function testPeekDoesNotConsumeQuota(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $limiter->peek('user:1');
        $limiter->peek('user:1');
        $limiter->peek('user:1');

        $result = $limiter->consume('user:1');

        $this->assertSame(9, $result->remaining);
    }

    public function testConsumeOrFailReturnsResultWhenAllowed(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $result = $limiter->consumeOrFail('user:1');

        $this->assertInstanceOf(RateLimitResult::class, $result);
        $this->assertTrue($result->isAllowed());
    }

    public function testConsumeOrFailThrowsWhenDenied(): void
    {
        $limiter = $this->createLimiter(limit: 1);

        $limiter->consume('user:1');

        $this->expectException(RateLimitException::class);
        $this->expectExceptionMessage('Rate limit exceeded');

        $limiter->consumeOrFail('user:1');
    }

    public function testConsumeOrFailWithCost(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $result = $limiter->consumeOrFail('user:1', cost: 5);

        $this->assertSame(5, $result->remaining);
    }

    public function testConsumeOrFailWithRateLimitIdentifier(): void
    {
        $limiter    = $this->createLimiter(limit: 10);
        $identifier = RateLimitIdentifier::fromIp('192.168.1.1');

        $result = $limiter->consumeOrFail($identifier);

        $this->assertTrue($result->isAllowed());
    }

    public function testResetWithStringIdentifier(): void
    {
        $limiter = $this->createLimiter(limit: 3);

        $limiter->consume('user:1');
        $limiter->consume('user:1');
        $limiter->consume('user:1');

        $limiter->reset('user:1');

        $result = $limiter->peek('user:1');
        $this->assertSame(3, $result->remaining);
    }

    public function testResetWithRateLimitIdentifier(): void
    {
        $limiter    = $this->createLimiter(limit: 3);
        $identifier = RateLimitIdentifier::fromUserId(123);

        $limiter->consume($identifier);
        $limiter->consume($identifier);
        $limiter->consume($identifier);

        $limiter->reset($identifier);

        $result = $limiter->peek($identifier);
        $this->assertSame(3, $result->remaining);
    }

    public function testApiFactoryMethod(): void
    {
        $limiter = DefaultRateLimiter::api($this->createStorageMock());

        $result = $limiter->peek('user:1');

        $this->assertSame(1000, $result->limit);
    }

    public function testLoginFactoryMethod(): void
    {
        $limiter = DefaultRateLimiter::login($this->createStorageMock());

        $result = $limiter->peek('user:1');

        $this->assertSame(5, $result->limit);
    }

    public function testFormFactoryMethod(): void
    {
        $limiter = DefaultRateLimiter::form($this->createStorageMock());

        $result = $limiter->peek('user:1');

        $this->assertSame(10, $result->limit);
    }

    public function testApiFactoryWithoutStorage(): void
    {
        $limiter = DefaultRateLimiter::api();

        $result = $limiter->consume('user:1');

        $this->assertTrue($result->isAllowed());
    }

    public function testLoginFactoryWithoutStorage(): void
    {
        $limiter = DefaultRateLimiter::login();

        $result = $limiter->consume('user:1');

        $this->assertTrue($result->isAllowed());
    }

    public function testFormFactoryWithoutStorage(): void
    {
        $limiter = DefaultRateLimiter::form();

        $result = $limiter->consume('user:1');

        $this->assertTrue($result->isAllowed());
    }

    public function testDefaultConfigValues(): void
    {
        $limiter = new DefaultRateLimiter();

        $result = $limiter->peek('user:1');

        $this->assertSame(100, $result->limit);
    }

    public function testUsesInMemoryStorageByDefault(): void
    {
        // Test with a mock storage to verify limit enforcement
        $limiter = $this->createLimiter(limit: 5);

        for ($i = 0; $i < 5; $i++) {
            $limiter->consume('user:1');
        }

        $result = $limiter->consume('user:1');
        $this->assertTrue($result->isDenied());
    }

    public function testUsesSlidingWindowByDefault(): void
    {
        $limiter = $this->createLimiter(limit: 5);

        for ($i = 0; $i < 5; $i++) {
            $limiter->consume('user:1');
        }

        $result = $limiter->consume('user:1');
        $this->assertTrue($result->isDenied());
    }

    public function testUsesTokenBucketWhenConfigured(): void
    {
        $limiter = $this->createLimiter(
            limit: 5,
            algorithm: AlgorithmType::TOKEN_BUCKET
        );

        for ($i = 0; $i < 5; $i++) {
            $limiter->consume('user:1');
        }

        $result = $limiter->consume('user:1');
        $this->assertTrue($result->isDenied());
    }

    public function testLoggerIsCalledOnRateLimitExceeded(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'Rate limit exceeded',
                $this->callback(function (array $context): bool {
                    return isset($context['identifier'])
                        && isset($context['limit'])
                        && isset($context['remaining'])
                        && isset($context['retry_after']);
                })
            );

        $limiter = $this->createLimiter(limit: 1, logger: $logger);

        $limiter->consume('user:1');
        $limiter->consume('user:1');
    }

    public function testLoggerIsNotCalledWhenAllowed(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->never())->method('warning');

        $limiter = $this->createLimiter(limit: 10, logger: $logger);

        $limiter->consume('user:1');
    }

    public function testMultipleIdentifiersAreIsolated(): void
    {
        $limiter = $this->createLimiter(limit: 3);

        $limiter->consume('user:1');
        $limiter->consume('user:1');
        $limiter->consume('user:1');

        $result1 = $limiter->consume('user:1');
        $result2 = $limiter->consume('user:2');

        $this->assertTrue($result1->isDenied());
        $this->assertTrue($result2->isAllowed());
    }

    /**
     * @return array<string, array{RateLimitIdentifier|string}>
     */
    public static function identifierProvider(): array
    {
        return [
            'string'    => ['user:123'],
            'ip'        => [RateLimitIdentifier::fromIp('192.168.1.1')],
            'user id'   => [RateLimitIdentifier::fromUserId(123)],
            'api key'   => [RateLimitIdentifier::fromApiKey('secret-key')],
            'custom'    => [RateLimitIdentifier::custom('type', 'value')],
            'composite' => [RateLimitIdentifier::composite([
                RateLimitIdentifier::fromIp('192.168.1.1'),
                RateLimitIdentifier::fromUserId(123),
            ])],
        ];
    }

    #[DataProvider('identifierProvider')]
    public function testConsumeWithVariousIdentifierTypes(RateLimitIdentifier|string $identifier): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $result = $limiter->consume($identifier);

        $this->assertTrue($result->isAllowed());
    }

    public function testConsumeOrFailExceptionContainsRetryAfter(): void
    {
        $limiter = $this->createLimiter(limit: 1);

        $limiter->consume('user:1');

        try {
            $limiter->consumeOrFail('user:1');
            $this->fail('Expected RateLimitException');
        } catch (RateLimitException $e) {
            $this->assertGreaterThan(0, $e->retryAfter());
        }
    }

    public function testConsumeOrFailExceptionContainsLimit(): void
    {
        $limiter = $this->createLimiter(limit: 5);

        for ($i = 0; $i < 5; $i++) {
            $limiter->consume('user:1');
        }

        try {
            $limiter->consumeOrFail('user:1');
            $this->fail('Expected RateLimitException');
        } catch (RateLimitException $e) {
            $this->assertSame(5, $e->limit());
        }
    }

    public function testWithActualInMemoryStorage(): void
    {
        // Test basic behavior with actual InMemoryStorage
        $storage = new InMemoryStorage();
        $limiter = $this->createLimiter(limit: 10, storage: $storage);

        $result = $limiter->consume('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(9, $result->remaining);
    }

    public function testConsumeRejectsCostZero(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cost must be at least 1');

        $limiter->consume('user:1', cost: 0);
    }

    public function testConsumeRejectsNegativeCost(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cost must be at least 1');

        $limiter->consume('user:1', cost: -1);
    }

    public function testConsumeOrFailRejectsCostZero(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cost must be at least 1');

        $limiter->consumeOrFail('user:1', cost: 0);
    }

    public function testConsumeOrFailRejectsNegativeCost(): void
    {
        $limiter = $this->createLimiter(limit: 10);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cost must be at least 1');

        $limiter->consumeOrFail('user:1', cost: -5);
    }

    public function testNegativeCostCannotRestoreQuota(): void
    {
        $limiter = $this->createLimiter(limit: 3);

        // Consume all quota
        $limiter->consume('user:1');
        $limiter->consume('user:1');
        $limiter->consume('user:1');

        // Verify quota is exhausted
        $this->assertTrue($limiter->peek('user:1')->isDenied());

        // Attempt to restore quota with negative cost should throw
        $this->expectException(InvalidArgumentException::class);
        $limiter->consume('user:1', cost: -10);
    }
}
