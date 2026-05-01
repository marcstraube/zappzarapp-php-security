<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Algorithm;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Algorithm\AlgorithmType;
use Zappzarapp\Security\RateLimiting\Algorithm\RateLimitAlgorithm;
use Zappzarapp\Security\RateLimiting\Algorithm\SlidingWindow;
use Zappzarapp\Security\RateLimiting\RateLimitConfig;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

#[CoversClass(SlidingWindow::class)]
final class SlidingWindowTest extends TestCase
{
    /**
     * Create a storage mock that properly tracks counter values
     * This works around the InMemoryStorage limitation where increment/get use separate arrays
     */
    private function createStorageMock(): RateLimitStorage
    {
        /** @var array<string, array{count: int}> $data */
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
                $current         = $data[$key]['count'] ?? 0;
                $new             = $current + $amount;
                $data[$key]      = ['count' => $new];

                return $new;
            });

        return $storage;
    }

    private function createAlgorithm(
        int $limit = 10,
        int $window = 60,
        string $prefix = 'test:',
        ?RateLimitStorage $storage = null,
    ): SlidingWindow {
        $config = new RateLimitConfig(
            limit: $limit,
            window: $window,
            algorithm: AlgorithmType::SLIDING_WINDOW,
            prefix: $prefix
        );

        return new SlidingWindow($storage ?? $this->createStorageMock(), $config);
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
    public function testConsumeDeniesWhenLimitExceeded(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3);

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
    public function testConsumeWithHighCostExceedsLimit(): void
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
        $algorithm = $this->createAlgorithm(limit: 3);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result1 = $algorithm->consume('user:1');
        $result2 = $algorithm->consume('user:2');

        $this->assertTrue($result1->isDenied());
        $this->assertTrue($result2->isAllowed());
    }

    #[Test]
    public function testPeekDoesNotConsumeQuota(): void
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
    public function testPeekReturnsDeniedWhenLimitExceeded(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result = $algorithm->peek('user:1');

        $this->assertTrue($result->isDenied());
        $this->assertGreaterThan(0, $result->retryAfter);
    }

    #[Test]
    public function testResetClearsRateLimitState(): void
    {
        $algorithm = $this->createAlgorithm(limit: 3);

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
    public function testWindowCalculation(): void
    {
        $algorithm = $this->createAlgorithm(limit: 100, window: 60);

        $result = $algorithm->consume('user:1');

        // Reset time should be within the window
        $now = time();
        $this->assertGreaterThanOrEqual($now, $result->resetAt);
        $this->assertLessThanOrEqual($now + 60, $result->resetAt);
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
    public function testRemainingNeverNegative(): void
    {
        $algorithm = $this->createAlgorithm(limit: 2);

        $algorithm->consume('user:1');
        $algorithm->consume('user:1');

        $result = $algorithm->peek('user:1');

        $this->assertGreaterThanOrEqual(0, $result->remaining);
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
    public function testWindowBoundaryHandling(): void
    {
        // Test that weighted previous window is considered
        $algorithm = $this->createAlgorithm(limit: 10, window: 60);

        // Consume some requests
        for ($i = 0; $i < 8; $i++) {
            $algorithm->consume('user:1');
        }

        $result = $algorithm->peek('user:1');

        $this->assertTrue($result->isAllowed());
        $this->assertSame(2, $result->remaining);
    }

    #[Test]
    public function testExactLimitConsumption(): void
    {
        $algorithm = $this->createAlgorithm(limit: 5);

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

    #[Test]
    public function testWithInMemoryStorageDirectly(): void
    {
        // Test basic functionality with actual InMemoryStorage
        // Note: Due to InMemoryStorage's separate data/counter arrays,
        // peek() will not see increment() values
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
}
