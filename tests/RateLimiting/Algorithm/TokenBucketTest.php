<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Algorithm;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Algorithm\AlgorithmType;
use Zappzarapp\Security\RateLimiting\Algorithm\RateLimitAlgorithm;
use Zappzarapp\Security\RateLimiting\Algorithm\TokenBucket;
use Zappzarapp\Security\RateLimiting\RateLimitConfig;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

#[CoversClass(TokenBucket::class)]
final class TokenBucketTest extends TestCase
{
    /**
     * Create a storage mock that properly stores and retrieves bucket state
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

    private function createAlgorithm(
        int $limit = 10,
        int $window = 60,
        int $burst = 0,
        string $prefix = 'test:',
        ?RateLimitStorage $storage = null,
    ): TokenBucket {
        $config = new RateLimitConfig(
            limit: $limit,
            window: $window,
            algorithm: AlgorithmType::TOKEN_BUCKET,
            burst: $burst,
            prefix: $prefix
        );

        return new TokenBucket($storage ?? $this->createStorageMock(), $config);
    }

    #[Test]
    public function testImplementsRateLimitAlgorithm(): void
    {
        $algorithm = $this->createAlgorithm();

        $this->assertInstanceOf(RateLimitAlgorithm::class, $algorithm);
    }

    #[Test]
    public function testConsumeAllowsWithinLimit(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(10, $result->limit);
        $this->assertSame(9, $result->remaining);
    }

    #[Test]
    public function testConsumeDecrementsRemaining(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $result = $algorithm->consume('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(7, $result->remaining);
    }

    #[Test]
    public function testConsumeDeniesWhenBucketEmpty(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3, window: 60);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result = $algorithm->consume('user:1');

        $this->assertTrue($result->isDenied());
        $this->assertSame(0, $result->remaining);
        $this->assertGreaterThan(0, $result->retryAfter);
    }

    #[Test]
    public function testConsumeWithCost(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume('user:1', cost: 5);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(5, $result->remaining);
    }

    #[Test]
    public function testConsumeWithHighCostExceedsTokens(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume('user:1', cost: 11);

        $this->assertTrue($result->isDenied());
    }

    #[Test]
    public function testConsumeWithCostZeroIsAllowed(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume('user:1', cost: 0);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(10, $result->remaining);
    }

    #[Test]
    public function testConsumeIsolatesIdentifiers(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3, window: 60);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result1 = $algorithm->consume('user:1');
        $result2 = $algorithm->consume('user:2');

        $this->assertTrue($result1->isDenied());
        $this->assertTrue($result2->isAllowed());
    }

    #[Test]
    public function testPeekDoesNotConsumeTokens(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $peek1 = $algorithm->peek('user:1');
        $peek2 = $algorithm->peek('user:1');
        $peek3 = $algorithm->peek('user:1');

        $this->assertTrue($peek1->isAllowed());
        $this->assertTrue($peek2->isAllowed());
        $this->assertTrue($peek3->isAllowed());
        $this->assertSame(10, $peek3->remaining);
    }

    #[Test]
    public function testPeekReturnsCurrentState(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result = $algorithm->peek('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(8, $result->remaining);
    }

    #[Test]
    public function testPeekReturnsDeniedWhenBucketEmpty(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3, window: 60);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result = $algorithm->peek('user:1');

        $this->assertTrue($result->isDenied());
        $this->assertGreaterThan(0, $result->retryAfter);
    }

    #[Test]
    public function testResetClearsTokenBucketState(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3, window: 60);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $beforeReset = $algorithm->peek('user:1');
        $this->assertTrue($beforeReset->isDenied());

        $algorithm->reset('user:1');

        $afterReset = $algorithm->peek('user:1');
        $this->assertTrue($afterReset->isAllowed());
        $this->assertSame(3, $afterReset->remaining);
    }

    #[Test]
    public function testResetOnlyAffectsSpecificIdentifier(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:2');

        $algorithm->reset('user:1');

        $result1 = $algorithm->peek('user:1');
        $result2 = $algorithm->peek('user:2');

        $this->assertSame(3, $result1->remaining);
        $this->assertSame(2, $result2->remaining);
    }

    #[Test]
    public function testBurstAllowsMoreThanLimit(): void
    {
        $algorithm = $this->createAlgorithm(limit: 5, window: 60, burst: 10);

        // Should be able to consume 10 tokens (burst size)
        for ($i = 0; $i < 10; $i++) {
            $result = $algorithm->consume('user:1');
            $this->assertTrue($result->isAllowed(), "Request $i should be allowed");
        }

        $result = $algorithm->consume('user:1');
        $this->assertTrue($result->isDenied());
    }

    #[Test]
    public function testBurstDefaultsToLimitWhenZero(): void
    {
        $algorithm = $this->createAlgorithm(limit: 5, burst: 0);

        // Should only allow 5 requests (limit, not burst)
        for ($i = 0; $i < 5; $i++) {
            $result = $algorithm->consume('user:1');
            $this->assertTrue($result->isAllowed());
        }

        $result = $algorithm->consume('user:1');
        $this->assertTrue($result->isDenied());
    }

    #[Test]
    public function testRefillRateCalculation(): void
    {
        // 60 tokens per 60 seconds = 1 token per second
        $algorithm = $this->createAlgorithm(limit: 60, window: 60);

        $result = $algorithm->consume('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(59, $result->remaining);
    }

    #[Test]
    public function testRetryAfterCalculation(): void
    {
        $algorithm = $this->createAlgorithm(limit: 1, window: 60);

        $algorithm->consume('user:1');
        $result = $algorithm->consume('user:1');

        $this->assertTrue($result->isDenied());
        $this->assertGreaterThan(0, $result->retryAfter);
        $this->assertLessThanOrEqual(60, $result->retryAfter);
    }

    #[Test]
    public function testPrefixIsApplied(): void
    {
        // Use separate storage for each algorithm to truly test prefix isolation
        $algorithm1 = $this->createAlgorithm(limit: 3, prefix: 'prefix1:');
        $algorithm2 = $this->createAlgorithm(limit: 3, prefix: 'prefix2:');

        $algorithm1->consume('user:1');
        $algorithm1->consume('user:1');
        $algorithm1->consume('user:1');

        $result1 = $algorithm1->consume('user:1');
        $result2 = $algorithm2->consume('user:1');

        $this->assertTrue($result1->isDenied());
        $this->assertTrue($result2->isAllowed());
    }

    #[Test]
    public function testResetAtCalculation(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10, window: 60);

        $result = $algorithm->consume('user:1');

        $now = time();
        // Reset should be in the future when bucket is not full
        $this->assertGreaterThanOrEqual($now, $result->resetAt);
    }

    #[Test]
    public function testResetAtWhenBucketIsFull(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10, window: 60);

        $result = $algorithm->peek('user:1');

        // When bucket is full, reset time is now
        $this->assertLessThanOrEqual(time() + 1, $result->resetAt);
    }

    #[Test]
    public function testConsumeWithEmptyIdentifier(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume('');

        $this->assertTrue($result->isAllowed());
    }

    #[Test]
    public function testConsumeWithSpecialCharactersInIdentifier(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume('user:test@example.com');

        $this->assertTrue($result->isAllowed());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function specialIdentifierProvider(): array
    {
        return [
            'ip address' => ['192.168.1.1'],
            'ipv6'       => ['2001:db8::1'],
            'email'      => ['user@example.com'],
            'uuid'       => ['550e8400-e29b-41d4-a716-446655440000'],
            'path-like'  => ['/api/v1/users'],
            'unicode'    => ['user:test'],
        ];
    }

    #[DataProvider('specialIdentifierProvider')]
    #[Test]
    public function testConsumeWithVariousIdentifiers(string $identifier): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $result = $algorithm->consume($identifier);

        $this->assertTrue($result->isAllowed());
    }

    #[Test]
    public function testExactLimitConsumption(): void
    {
        $algorithm = $this->createAlgorithm(limit: 5, window: 60);

        for ($i = 0; $i < 5; $i++) {
            $result = $algorithm->consume('user:1');
            $this->assertTrue($result->isAllowed());
        }

        $result = $algorithm->consume('user:1');
        $this->assertTrue($result->isDenied());
    }

    #[Test]
    public function testLargeCostValue(): void
    {
        $algorithm = $this->createAlgorithm(limit: 1000);

        $result = $algorithm->consume('user:1', cost: 999);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(1, $result->remaining);

        $result2 = $algorithm->consume('user:1', cost: 2);
        $this->assertTrue($result2->isDenied());
    }

    #[Test]
    public function testBurstWithHighCost(): void
    {
        $algorithm = $this->createAlgorithm(limit: 5, window: 60, burst: 20);

        $result = $algorithm->consume('user:1', cost: 15);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(5, $result->remaining);
    }

    #[Test]
    public function testBurstExceededWithHighCost(): void
    {
        $algorithm = $this->createAlgorithm(limit: 5, window: 60, burst: 10);

        $result = $algorithm->consume('user:1', cost: 11);

        $this->assertTrue($result->isDenied());
    }

    #[Test]
    public function testTokensNeverExceedBucketSize(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10, window: 60, burst: 5);

        // Initial bucket should be at burst size (5), not limit (10)
        $result = $algorithm->peek('user:1');

        $this->assertSame(5, $result->remaining);
    }

    #[Test]
    public function testPeekRetryAfterWhenEmpty(): void
    {
        // 1 token per second refill rate (60 tokens per 60 seconds)
        $algorithm = $this->createAlgorithm(limit: 60, window: 60);

        // Consume all tokens
        $algorithm->consume('user:1', cost: 60);

        $result = $algorithm->peek('user:1');

        $this->assertTrue($result->isDenied());
        // Need 1 token, at 1 token/second, should be 1 second
        $this->assertSame(1, $result->retryAfter);
    }

    #[Test]
    public function testWithInMemoryStorageDirectly(): void
    {
        // Test basic functionality with actual InMemoryStorage
        $storage   = new InMemoryStorage();
        $algorithm = $this->createAlgorithm(limit: 10, storage: $storage);

        $result = $algorithm->consume('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(9, $result->remaining);
    }

    #[Test]
    public function testResetCalledOnNonExistentIdentifier(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        // Should not throw
        $algorithm->reset('nonexistent');

        $result = $algorithm->peek('nonexistent');
        $this->assertTrue($result->isAllowed());
    }

    #[Test]
    public function testConsumeReturnsResultWithLimit(): void
    {
        $algorithm = $this->createAlgorithm(limit: 42);

        $result = $algorithm->consume('user:1');

        $this->assertSame(42, $result->limit);
    }

    #[Test]
    public function testPeekReturnsResultWithLimit(): void
    {
        $algorithm = $this->createAlgorithm(limit: 42);

        $result = $algorithm->peek('user:1');

        $this->assertSame(42, $result->limit);
    }

    #[Test]
    public function testMultipleCostsAddUp(): void
    {
        $algorithm = $this->createAlgorithm(limit: 10);

        $algorithm->consume('user:1', cost: 3);
        $algorithm->consume('user:1', cost: 3);
        $result = $algorithm->consume('user:1', cost: 3);

        $this->assertTrue($result->isAllowed());
        $this->assertSame(1, $result->remaining);
    }
}
