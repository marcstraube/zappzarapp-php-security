<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Tests for CspDirectives::toHeaderValue() - security policy behavior
 */
final class CspDirectivesHeaderPolicyTest extends TestCase
{
    public function testStrictPolicyDisallowsUnsafeDirectives(): void
    {
        $header = (new CspDirectives())->toHeaderValue('test-nonce');

        $this->assertStringNotContainsString("'unsafe-eval'", $header);
        $this->assertStringNotContainsString("'unsafe-inline'", $header);
    }

    /**
     * @throws RandomException
     */
    public function testLenientPolicyAllowsUnsafeDirectives(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives(securityPolicy: SecurityPolicy::LENIENT))->toHeaderValue($nonce);

        $this->assertStringContainsString("'unsafe-eval'", $header);
        $this->assertStringContainsString("'unsafe-inline'", $header);
    }

    public function testUnsafeEvalPolicyAllowsOnlyEval(): void
    {
        $directives = (new CspDirectives())->withSecurityPolicy(SecurityPolicy::UNSAFE_EVAL);
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString("'unsafe-eval'", $header);
        $this->assertStringNotContainsString("'unsafe-inline'", $header);
    }

    public function testUnsafeInlinePolicyAllowsOnlyInline(): void
    {
        $directives = (new CspDirectives())->withSecurityPolicy(SecurityPolicy::UNSAFE_INLINE);
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString("'unsafe-inline'", $header);
        $this->assertStringNotContainsString("'unsafe-eval'", $header);
    }
}
