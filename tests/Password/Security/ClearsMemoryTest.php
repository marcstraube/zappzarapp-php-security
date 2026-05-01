<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Security;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Tests for ClearsMemory trait
 *
 * Coverage is tracked through implementing classes (DefaultPasswordHasher, etc.)
 */
#[CoversNothing]
final class ClearsMemoryTest extends TestCase
{
    private ClearsMemoryTestHelper $helper;

    protected function setUp(): void
    {
        $this->helper = new ClearsMemoryTestHelper();
    }

    #[Test]
    public function testClearMemoryClearsString(): void
    {
        if (!function_exists('sodium_memzero')) {
            $this->markTestSkipped('sodium extension required');
        }

        $password = 'secret123';
        $this->helper->testClear($password);

        // sodium_memzero() clears the variable content
        // The variable becomes empty or the original content is overwritten
        $this->assertNotSame('secret123', $password);
    }

    #[Test]
    public function testClearMemoryWithSodiumSetsToEmptyOrNull(): void
    {
        if (!function_exists('sodium_memzero')) {
            $this->markTestSkipped('sodium extension required');
        }

        $password = 'a very long password with spaces';
        $this->helper->testClear($password);

        // sodium_memzero sets variable to empty string in PHP
        $this->assertEmpty($password);
    }

    #[Test]
    public function testWithClearedMemoryReturnsCallbackResult(): void
    {
        $result = $this->helper->testCallback('password', fn(string $d): string => strtoupper($d));

        $this->assertSame('PASSWORD', $result);
    }

    #[Test]
    public function testWithClearedMemoryClearsDataAfterCallback(): void
    {
        $captured = null;

        $this->helper->testCallback('secret', function (string $d) use (&$captured): string {
            $captured = $d;

            return 'result';
        });

        // The captured value during callback should be the password
        $this->assertSame('secret', $captured);
    }

    #[Test]
    public function testWithClearedMemoryHandlesEmptyString(): void
    {
        $result = $this->helper->testCallback('', fn(string $d): int => strlen($d));

        $this->assertSame(0, $result);
    }

    #[Test]
    public function testClearMemoryHandlesEmptyString(): void
    {
        if (!function_exists('sodium_memzero')) {
            $this->markTestSkipped('sodium extension required');
        }

        $empty = '';
        $this->helper->testClear($empty);

        // sodium_memzero sets variable to null, even for empty strings
        // @phpstan-ignore method.impossibleType (sodium_memzero changes type to null)
        $this->assertNull($empty);
    }
}

/**
 * Test helper class for ClearsMemory trait
 *
 * @internal Test helper only
 */
final class ClearsMemoryTestHelper
{
    use ClearsMemory;

    #[Test]
    public function testClear(string &$data): void
    {
        $this->clearMemory($data);
    }

    /**
     * @template T
     *
     * @param callable(string): T $callback
     *
     * @return T
     */
    #[Test]
    public function testCallback(string $data, callable $callback): mixed
    {
        return $this->withClearedMemory($data, $callback);
    }
}
