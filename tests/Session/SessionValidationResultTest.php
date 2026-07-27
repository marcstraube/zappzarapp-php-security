<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Session\SessionValidationResult;

#[CoversClass(SessionValidationResult::class)]
final class SessionValidationResultTest extends TestCase
{
    #[Test]
    public function testOnlyValidIsValid(): void
    {
        $this->assertTrue(SessionValidationResult::VALID->isValid());
        $this->assertFalse(SessionValidationResult::UNINITIALIZED->isValid());
        $this->assertFalse(SessionValidationResult::FINGERPRINT_MISMATCH->isValid());
        $this->assertFalse(SessionValidationResult::ABSOLUTE_TIMEOUT_EXCEEDED->isValid());
        $this->assertFalse(SessionValidationResult::IDLE_TIMEOUT_EXCEEDED->isValid());
    }

    #[DataProvider('descriptionProvider')]
    #[Test]
    public function testDescription(SessionValidationResult $result, string $expected): void
    {
        $this->assertSame($expected, $result->description());
    }

    /**
     * @return array<string, array{SessionValidationResult, string}>
     */
    public static function descriptionProvider(): array
    {
        return [
            'valid'                => [SessionValidationResult::VALID, 'Session passed all security checks'],
            'uninitialized'        => [SessionValidationResult::UNINITIALIZED, 'Session has no security metadata'],
            'fingerprint mismatch' => [SessionValidationResult::FINGERPRINT_MISMATCH, 'Session client fingerprint mismatch'],
            'absolute timeout'     => [SessionValidationResult::ABSOLUTE_TIMEOUT_EXCEEDED, 'Session exceeded its absolute lifetime'],
            'idle timeout'         => [SessionValidationResult::IDLE_TIMEOUT_EXCEEDED, 'Session idle timeout exceeded'],
        ];
    }
}
