<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Nonce;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NonceRegistry;
use Zappzarapp\Security\Csp\Nonce\NonceScope;

#[CoversClass(NonceScope::class)]
final class NonceScopeTest extends TestCase
{
    protected function tearDown(): void
    {
        // Ensure clean state after each test
        NonceRegistry::reset();
    }

    // --- Basic Functionality ---

    #[Test]
    public function testStartCreatesNewScope(): void
    {
        $scope = NonceScope::start();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies creation */
        $this->assertInstanceOf(NonceScope::class, $scope);

        $scope->end();
    }

    #[Test]
    public function testGetReturnsNonceValue(): void
    {
        $scope = NonceScope::start();

        $nonce = $scope->get();

        $this->assertNotEmpty($nonce);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/]+=*$/', $nonce);

        $scope->end();
    }

    #[Test]
    public function testGetReturnsSameValueWithinScope(): void
    {
        $scope = NonceScope::start();

        $nonce1 = $scope->get();
        $nonce2 = $scope->get();
        $nonce3 = $scope->get();

        $this->assertSame($nonce1, $nonce2);
        $this->assertSame($nonce2, $nonce3);

        $scope->end();
    }

    #[Test]
    public function testGeneratorReturnsNonceGenerator(): void
    {
        $scope = NonceScope::start();

        $generator = $scope->generator();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(NonceGenerator::class, $generator);
        $this->assertSame($scope->get(), $generator->get());

        $scope->end();
    }

    // --- Scope Isolation ---

    #[Test]
    public function testNewScopeHasDifferentNonce(): void
    {
        $scope1  = NonceScope::start();
        $nonce1  = $scope1->get();
        $scope1->end();

        $scope2 = NonceScope::start();
        $nonce2 = $scope2->get();
        $scope2->end();

        $this->assertNotSame($nonce1, $nonce2);
    }

    #[Test]
    public function testStartResetsGlobalRegistry(): void
    {
        // Set a nonce in the global registry
        $originalNonce = NonceRegistry::get();

        // Starting a new scope should reset global state
        $scope = NonceScope::start();

        // Global registry should now have a different nonce
        // (since NonceScope::start() calls reset())
        $newGlobalNonce = NonceRegistry::get();

        $this->assertNotSame($originalNonce, $newGlobalNonce);

        $scope->end();
    }

    #[Test]
    public function testEndResetsGlobalRegistry(): void
    {
        $scope = NonceScope::start();
        NonceRegistry::get(); // Initialize the registry

        $scope->end();

        // After end(), starting a new registry should give a fresh nonce
        $freshNonce = NonceRegistry::get();

        // Get another one to confirm isolation
        NonceRegistry::reset();
        $anotherFreshNonce = NonceRegistry::get();

        $this->assertNotSame($freshNonce, $anotherFreshNonce);
    }

    // --- End Lifecycle ---

    #[Test]
    public function testEndCanBeCalledMultipleTimes(): void
    {
        $scope = NonceScope::start();

        $scope->end();
        $scope->end();
        $scope->end();

        $this->assertTrue($scope->hasEnded());
    }

    #[Test]
    public function testHasEndedReturnsFalseBeforeEnd(): void
    {
        $scope = NonceScope::start();

        $this->assertFalse($scope->hasEnded());

        $scope->end();
    }

    #[Test]
    public function testHasEndedReturnsTrueAfterEnd(): void
    {
        $scope = NonceScope::start();
        $scope->end();

        $this->assertTrue($scope->hasEnded());
    }

    // --- Pre-existing Nonce ---

    #[Test]
    public function testWithNonceUsesProvidedValue(): void
    {
        $customNonce = base64_encode(random_bytes(32));

        $scope = NonceScope::withNonce($customNonce);

        $this->assertSame($customNonce, $scope->get());

        $scope->end();
    }

    #[Test]
    public function testWithNonceResetsGlobalRegistry(): void
    {
        $originalNonce = NonceRegistry::get();

        $scope = NonceScope::withNonce(base64_encode(random_bytes(32)));

        $newGlobalNonce = NonceRegistry::get();

        $this->assertNotSame($originalNonce, $newGlobalNonce);

        $scope->end();
    }

    // --- Try/Finally Pattern ---

    #[Test]
    public function testTryFinallyPatternEnsuresCleanup(): void
    {
        $scope         = NonceScope::start();
        $capturedNonce = $scope->get();

        try {
            // Simulate some work
            $this->assertNotEmpty($capturedNonce);
        } finally {
            $scope->end();
        }

        // After scope ends, new scope should have different nonce
        $newScope    = NonceScope::start();
        $freshNonce  = $newScope->get();
        $newScope->end();

        $this->assertNotSame($capturedNonce, $freshNonce);
    }

    #[Test]
    public function testTryFinallyPatternWithException(): void
    {
        $scope = NonceScope::start();
        $scope->get();

        try {
            throw new RuntimeException('Simulated error');
        } catch (RuntimeException) {
            // Expected
        } finally {
            $scope->end();
        }

        $this->assertTrue($scope->hasEnded());
    }

    // --- Concurrent Scope Simulation ---

    #[Test]
    public function testMultipleScopesAreIndependent(): void
    {
        // Simulate what would happen with concurrent fibers/coroutines
        // Each scope should maintain its own nonce

        $scope1 = NonceScope::start();
        $nonce1 = $scope1->get();

        // In a real async environment, this would be in a different fiber
        $scope2 = NonceScope::start();
        $nonce2 = $scope2->get();

        // Nonces should be different
        $this->assertNotSame($nonce1, $nonce2);

        // Clean up in reverse order (like nested fibers)
        $scope2->end();
        $scope1->end();
    }
}
