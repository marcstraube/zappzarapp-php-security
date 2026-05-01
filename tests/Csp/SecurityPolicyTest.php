<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\SecurityPolicy;

final class SecurityPolicyTest extends TestCase
{
    #[Test]
    public function testStrictDisallowsAllUnsafeDirectives(): void
    {
        $this->assertFalse(SecurityPolicy::STRICT->allowsUnsafeEval());
        $this->assertFalse(SecurityPolicy::STRICT->allowsUnsafeInline());
    }

    #[Test]
    public function testLenientAllowsAllUnsafeDirectives(): void
    {
        $this->assertTrue(SecurityPolicy::LENIENT->allowsUnsafeEval());
        $this->assertTrue(SecurityPolicy::LENIENT->allowsUnsafeInline());
    }

    #[Test]
    public function testUnsafeEvalAllowsOnlyEval(): void
    {
        $this->assertTrue(SecurityPolicy::UNSAFE_EVAL->allowsUnsafeEval());
        $this->assertFalse(SecurityPolicy::UNSAFE_EVAL->allowsUnsafeInline());
    }

    #[Test]
    public function testUnsafeInlineAllowsOnlyInline(): void
    {
        $this->assertFalse(SecurityPolicy::UNSAFE_INLINE->allowsUnsafeEval());
        $this->assertTrue(SecurityPolicy::UNSAFE_INLINE->allowsUnsafeInline());
    }
}
