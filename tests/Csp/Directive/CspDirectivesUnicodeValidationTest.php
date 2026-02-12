<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

/**
 * Tests for CspDirectives unicode whitespace validation (Defense-in-Depth)
 */
final class CspDirectivesUnicodeValidationTest extends TestCase
{
    public function testThrowsForNonBreakingSpaceInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('unicode whitespace');

        new CspDirectives(defaultSrc: "'self'\u{00A0}'unsafe-inline'");
    }

    public function testThrowsForNonBreakingSpaceInScriptSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('unicode whitespace');

        new CspDirectives(scriptSrc: "'self'\u{00A0}'unsafe-eval'");
    }

    public function testThrowsForNonBreakingSpaceInStyleSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('unicode whitespace');

        new CspDirectives(styleSrc: "'self'\u{00A0}'unsafe-inline'");
    }

    public function testThrowsForIdeographicSpaceInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('unicode whitespace');

        // U+3000 Ideographic Space
        new CspDirectives(defaultSrc: "'self'\u{3000}'unsafe-inline'");
    }

    public function testThrowsForEnSpaceInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('unicode whitespace');

        // U+2002 En Space
        new CspDirectives(defaultSrc: "'self'\u{2002}'unsafe-inline'");
    }
}
