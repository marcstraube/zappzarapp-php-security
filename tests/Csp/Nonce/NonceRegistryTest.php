<?php
/** @noinspection PhpMultipleClassDeclarationsInspection - Psalm stubs conflict with native PHP 8.3 Override */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Nonce;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use ReflectionClass;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NonceRegistry;

final class NonceRegistryTest extends TestCase
{
    #[Override]
    protected function setUp(): void
    {
        NonceRegistry::reset();
    }

    #[Override]
    protected function tearDown(): void
    {
        NonceRegistry::reset();
    }

    public function testCannotBeInstantiated(): void
    {
        $reflection  = new ReflectionClass(NonceRegistry::class);
        $constructor = $reflection->getConstructor();

        $this->assertNotNull($constructor);
        $this->assertTrue($constructor->isPrivate());
    }

    public function testGeneratorReturnsNonceGeneratorInstance(): void
    {
        $generator = NonceRegistry::generator();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies factory return type */
        $this->assertInstanceOf(NonceGenerator::class, $generator);
    }

    public function testGeneratorReturnsSameInstance(): void
    {
        $generator1 = NonceRegistry::generator();
        $generator2 = NonceRegistry::generator();

        $this->assertSame($generator1, $generator2);
    }

    /**
     * @throws RandomException
     */
    public function testGetReturnsNonceValue(): void
    {
        $nonce = NonceRegistry::get();

        $this->assertNotEmpty($nonce);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/=]+$/', $nonce);
    }

    /**
     * @throws RandomException
     */
    public function testGetReturnsSameNonceValue(): void
    {
        $nonce1 = NonceRegistry::get();
        $nonce2 = NonceRegistry::get();

        $this->assertSame($nonce1, $nonce2);
    }

    /**
     * @throws RandomException
     */
    public function testGetReturnsValueFromGenerator(): void
    {
        $generatorNonce = NonceRegistry::generator()->get();
        $registryNonce  = NonceRegistry::get();

        $this->assertSame($generatorNonce, $registryNonce);
    }

    /**
     * @throws RandomException
     */
    public function testSetOverridesNonce(): void
    {
        $originalNonce = NonceRegistry::get();
        $customNonce   = 'custom-nonce-value';

        NonceRegistry::set($customNonce);

        $this->assertSame($customNonce, NonceRegistry::get());
        $this->assertNotSame($originalNonce, NonceRegistry::get());
    }

    /**
     * @throws RandomException
     */
    public function testSetAcceptsValidBase64Nonce(): void
    {
        $validNonce = 'dGVzdC1ub25jZS12YWx1ZQ==';

        NonceRegistry::set($validNonce);

        $this->assertSame($validNonce, NonceRegistry::get());
    }

    /**
     * @throws RandomException
     */
    public function testSetAcceptsAlphanumericNonce(): void
    {
        $validNonce = 'abc123XYZ789';

        NonceRegistry::set($validNonce);

        $this->assertSame($validNonce, NonceRegistry::get());
    }

    /**
     * @throws RandomException
     */
    public function testResetClearsGeneratorAndNonce(): void
    {
        $nonce1     = NonceRegistry::get();
        $generator1 = NonceRegistry::generator();

        NonceRegistry::reset();

        $nonce2     = NonceRegistry::get();
        $generator2 = NonceRegistry::generator();

        $this->assertNotSame($nonce1, $nonce2);
        $this->assertNotSame($generator1, $generator2);
    }

    public function testResetWhenGeneratorIsNull(): void
    {
        // Ensure generator is null (fresh state after setUp)
        NonceRegistry::reset();

        // This should not throw - covers the null check branch
        NonceRegistry::reset();

        // Generator should be null, next get() creates new one
        $this->assertInstanceOf(NonceGenerator::class, NonceRegistry::generator());
    }

    // Defense in Depth: Validation Tests
    public function testSetRejectsEmptyNonce(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('cannot be empty');

        NonceRegistry::set('');
    }

    public function testSetRejectsSemicolon(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains semicolon');

        NonceRegistry::set("valid'; script-src 'unsafe-inline");
    }

    public function testSetRejectsNewline(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains control character');

        NonceRegistry::set("valid\nX-Injected-Header: malicious");
    }

    public function testSetRejectsCarriageReturn(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains control character');

        NonceRegistry::set("valid\rX-Injected-Header: malicious");
    }

    public function testSetRejectsSingleQuote(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains single quote');

        NonceRegistry::set("valid' 'unsafe-inline");
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function injectionAttackVectorsProvider(): array
    {
        return [
            'CSP injection via semicolon' => [
                "abc; script-src 'unsafe-inline'",
                'contains semicolon',
            ],
            'Header injection via newline' => [
                "abc\nSet-Cookie: malicious=value",
                'contains control character',
            ],
            'Header injection via CRLF' => [
                "abc\r\nSet-Cookie: malicious=value",
                'contains control character',
            ],
            'Nonce delimiter escape' => [
                "abc' 'unsafe-eval",
                'contains single quote',
            ],
            'CSP value injection via space' => [
                "abc unsafe-inline",
                'contains space',
            ],
        ];
    }

    #[DataProvider('injectionAttackVectorsProvider')]
    public function testSetRejectsInjectionAttackVectors(
        string $maliciousNonce,
        string $expectedMessage,
    ): void {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage($expectedMessage);

        NonceRegistry::set($maliciousNonce);
    }

    /**
     * @throws RandomException
     */
    public function testLongRunningProcessWorkflow(): void
    {
        // Request 1
        $nonce1 = NonceRegistry::get();
        $this->assertNotEmpty($nonce1);

        // End of request 1 - reset for next request
        NonceRegistry::reset();

        // Request 2
        $nonce2 = NonceRegistry::get();
        $this->assertNotEmpty($nonce2);

        // Each request should have a different nonce
        $this->assertNotSame($nonce1, $nonce2);
    }

    /**
     * @throws RandomException
     */
    public function testFrameworkIntegrationWorkflow(): void
    {
        // Framework provides a nonce
        $frameworkNonce = 'framework-provided-nonce-123';
        NonceRegistry::set($frameworkNonce);

        // Library uses the same nonce
        $this->assertSame($frameworkNonce, NonceRegistry::get());

        // Generator also returns the same nonce
        $this->assertSame($frameworkNonce, NonceRegistry::generator()->get());
    }
}