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
 * Tests for CspDirectives::toHeaderValue() - basic structure and format
 */
final class CspDirectivesHeaderStructureTest extends TestCase
{
    /**
     * @throws RandomException
     */
    #[Test]
    public function testIncludesAllDirectives(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        $this->assertStringContainsString("default-src 'self'", $header);
        $this->assertStringContainsString('script-src', $header);
        $this->assertStringContainsString('style-src', $header);
        $this->assertStringContainsString('img-src', $header);
        $this->assertStringContainsString('font-src', $header);
        $this->assertStringContainsString('connect-src', $header);
        $this->assertStringContainsString('media-src', $header);
        $this->assertStringContainsString('worker-src', $header);
        $this->assertStringContainsString('child-src', $header);
        $this->assertStringContainsString('frame-src', $header);
        $this->assertStringContainsString('manifest-src', $header);
        $this->assertStringContainsString("object-src 'none'", $header);
        $this->assertStringContainsString('frame-ancestors', $header);
        $this->assertStringContainsString('base-uri', $header);
        $this->assertStringContainsString('form-action', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testFormatsWithSemicolonSeparators(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        $this->assertStringContainsString('; ', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testDirectiveFormatIsCorrect(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        $parts = explode('; ', $header);
        foreach ($parts as $part) {
            if ($part === 'upgrade-insecure-requests') {
                continue;
            }
            $this->assertMatchesRegularExpression('/^[a-z-]+ .+$/', $part);
        }
    }
}
