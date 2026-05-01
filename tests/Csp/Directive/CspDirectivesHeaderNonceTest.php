<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;

/**
 * Tests for CspDirectives::toHeaderValue() - nonce injection behavior
 */
final class CspDirectivesHeaderNonceTest extends TestCase
{
    /**
     * @throws RandomException
     */
    #[Test]
    public function testAutoInjectsNonceInScriptSrc(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        $this->assertStringContainsString(sprintf("'nonce-%s'", $nonce), $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testAutoInjectsStrictDynamicInScriptSrc(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        $this->assertStringContainsString("'strict-dynamic'", $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testAutoInjectsNonceInStyleSrc(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        $this->assertStringContainsString(sprintf("style-src 'self' 'nonce-%s'", $nonce), $header);
    }

    #[Test]
    public function testSkipsNonceInjectionWithEmptyNonce(): void
    {
        $header = (new CspDirectives())->toHeaderValue('');

        $this->assertStringNotContainsString("'nonce-", $header);
        $this->assertStringContainsString("script-src 'self'", $header);
    }

    #[Test]
    public function testCustomScriptSrcWithEmptyNonceReturnsUnmodified(): void
    {
        $customScriptSrc = "'self' https://cdn.example.com";
        $directives      = (new CspDirectives())->withScriptSrc($customScriptSrc);
        $header          = $directives->toHeaderValue('');

        // With empty nonce, custom script-src should be returned as-is (no nonce prepended)
        $this->assertStringContainsString("script-src 'self' https://cdn.example.com", $header);
        $this->assertStringNotContainsString("'nonce-'", $header);
    }

    #[Test]
    public function testCustomStyleSrcWithEmptyNonceReturnsUnmodified(): void
    {
        $customStyleSrc = "'self' https://fonts.example.com";
        $directives     = (new CspDirectives())->withStyleSrc($customStyleSrc);
        $header         = $directives->toHeaderValue('');

        // With empty nonce, custom style-src should be returned as-is
        $this->assertStringContainsString("style-src 'self' https://fonts.example.com", $header);
        $this->assertStringNotContainsString("'nonce-'", $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testAutoInjectsNonceInCustomScriptSrc(): void
    {
        $generator  = new NonceGenerator();
        $nonce      = $generator->get();
        $directives = (new CspDirectives())->withScriptSrc("'self' https://trusted.com");
        $header     = $directives->toHeaderValue($nonce);

        $this->assertStringContainsString(sprintf("'nonce-%s'", $nonce), $header);
        $this->assertStringContainsString('https://trusted.com', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testDoesNotDuplicateNonceInCustomScriptSrc(): void
    {
        $generator  = new NonceGenerator();
        $nonce      = $generator->get();
        $directives = (new CspDirectives())->withScriptSrc(sprintf("'self' 'nonce-%s' https://trusted.com", $nonce));
        $header     = $directives->toHeaderValue($nonce);

        preg_match('/script-src ([^;]+)/', $header, $matches);
        $scriptSrc  = $matches[1] ?? '';
        $nonceCount = substr_count($scriptSrc, sprintf("'nonce-%s'", $nonce));

        $this->assertSame(1, $nonceCount);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testCustomScriptSrcWithNonceGetsPrependedNonce(): void
    {
        $generator       = new NonceGenerator();
        $nonce           = $generator->get();
        $customScriptSrc = "'self' https://cdn.example.com";
        $directives      = (new CspDirectives())->withScriptSrc($customScriptSrc);
        $header          = $directives->toHeaderValue($nonce);

        // Verify that nonce IS prepended when custom script-src doesn't have one
        preg_match('/script-src ([^;]+)/', $header, $matches);
        $scriptSrc = $matches[1] ?? '';

        // The nonce should be at the START of the script-src value
        $this->assertStringStartsWith(sprintf("'nonce-%s'", $nonce), $scriptSrc);
        // Original content should follow
        $this->assertStringContainsString($customScriptSrc, $scriptSrc);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testCustomStyleSrcWithNonceGetsPrependedNonce(): void
    {
        $generator      = new NonceGenerator();
        $nonce          = $generator->get();
        $customStyleSrc = "'self' https://fonts.example.com";
        $directives     = (new CspDirectives())->withStyleSrc($customStyleSrc);
        $header         = $directives->toHeaderValue($nonce);

        // Verify that nonce IS prepended when custom style-src doesn't have one
        preg_match('/style-src ([^;]+)/', $header, $matches);
        $styleSrc = $matches[1] ?? '';

        // The nonce should be at the START of the style-src value
        $this->assertStringStartsWith(sprintf("'nonce-%s'", $nonce), $styleSrc);
        // Original content should follow
        $this->assertStringContainsString($customStyleSrc, $styleSrc);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testCustomScriptSrcWithExistingNonceNotModified(): void
    {
        $generator       = new NonceGenerator();
        $nonce           = $generator->get();
        $existingNonce   = 'existing-nonce-value';
        $customScriptSrc = sprintf("'self' 'nonce-%s' https://cdn.example.com", $existingNonce);
        $directives      = (new CspDirectives())->withScriptSrc($customScriptSrc);
        $header          = $directives->toHeaderValue($nonce);

        // When custom script-src already has a nonce, it should NOT be modified
        preg_match('/script-src ([^;]+)/', $header, $matches);
        $scriptSrc = $matches[1] ?? '';

        // Should return exactly what was provided
        $this->assertSame($customScriptSrc, $scriptSrc);
        // Should NOT contain the new nonce
        $this->assertStringNotContainsString(sprintf("'nonce-%s'", $nonce), $scriptSrc);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testCustomStyleSrcWithExistingNonceNotModified(): void
    {
        $generator      = new NonceGenerator();
        $nonce          = $generator->get();
        $existingNonce  = 'existing-style-nonce';
        $customStyleSrc = sprintf("'self' 'nonce-%s' https://fonts.example.com", $existingNonce);
        $directives     = (new CspDirectives())->withStyleSrc($customStyleSrc);
        $header         = $directives->toHeaderValue($nonce);

        // When custom style-src already has a nonce, it should NOT be modified
        preg_match('/style-src ([^;]+)/', $header, $matches);
        $styleSrc = $matches[1] ?? '';

        // Should return exactly what was provided
        $this->assertSame($customStyleSrc, $styleSrc);
    }
}
