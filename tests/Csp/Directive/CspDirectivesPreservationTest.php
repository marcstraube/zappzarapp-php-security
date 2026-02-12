<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Tests for CspDirectives value preservation in with* methods
 *
 * These tests ensure cloneWith() correctly preserves unchanged values
 * and kills mutation testing ?? swap mutations.
 */
final class CspDirectivesPreservationTest extends TestCase
{
    public function testWithMethodsPreserveOtherValues(): void
    {
        $original = new CspDirectives(
            defaultSrc: "'self' https://example.com",
            scriptSrc: "'self' https://scripts.example.com",
            websocketHost: 'ws.example.com:443',
            securityPolicy: SecurityPolicy::UNSAFE_EVAL,
        );

        $modified = $original->withImgSrc("'none'");

        $this->assertSame("'none'", $modified->resources->img);
        $this->assertSame("'self' https://example.com", $modified->defaultSrc);
        $this->assertSame("'self' https://scripts.example.com", $modified->scriptSrc);
        $this->assertSame('ws.example.com:443', $modified->websocketHost);
        $this->assertSame(SecurityPolicy::UNSAFE_EVAL, $modified->securityPolicy);
    }

    public function testWithScriptSrcOverridesExistingValue(): void
    {
        $original = new CspDirectives(scriptSrc: "'self' https://old.com");
        $modified = $original->withScriptSrc("'self' https://new.com");

        $this->assertSame("'self' https://new.com", $modified->scriptSrc);
    }

    public function testWithStyleSrcOverridesExistingValue(): void
    {
        $original = new CspDirectives(styleSrc: "'self' https://old.com");
        $modified = $original->withStyleSrc("'self' https://new.com");

        $this->assertSame("'self' https://new.com", $modified->styleSrc);
    }

    public function testWithWebSocketOverridesExistingValue(): void
    {
        $original = new CspDirectives(websocketHost: 'old.example.com:443');
        $modified = $original->withWebSocket('new.example.com:443');

        $this->assertSame('new.example.com:443', $modified->websocketHost);
    }

    public function testWithScriptSrcPreservesOtherValues(): void
    {
        $original = new CspDirectives(
            defaultSrc: "'self' https://example.com",
            scriptSrc: "'self' https://old-scripts.com",
            styleSrc: "'self' https://styles.com",
            websocketHost: 'ws.example.com:443',
        );

        $modified = $original->withScriptSrc("'self' https://new-scripts.com");

        $this->assertSame("'self' https://new-scripts.com", $modified->scriptSrc);
        $this->assertSame("'self' https://example.com", $modified->defaultSrc);
        $this->assertSame("'self' https://styles.com", $modified->styleSrc);
        $this->assertSame('ws.example.com:443', $modified->websocketHost);
    }

    public function testWithStyleSrcPreservesOtherValues(): void
    {
        $original = new CspDirectives(
            defaultSrc: "'self' https://example.com",
            scriptSrc: "'self' https://scripts.com",
            styleSrc: "'self' https://old-styles.com",
            websocketHost: 'ws.example.com:443',
        );

        $modified = $original->withStyleSrc("'self' https://new-styles.com");

        $this->assertSame("'self' https://new-styles.com", $modified->styleSrc);
        $this->assertSame("'self' https://example.com", $modified->defaultSrc);
        $this->assertSame("'self' https://scripts.com", $modified->scriptSrc);
        $this->assertSame('ws.example.com:443', $modified->websocketHost);
    }

    public function testWithWebSocketPreservesOtherValues(): void
    {
        $original = new CspDirectives(
            defaultSrc: "'self' https://example.com",
            scriptSrc: "'self' https://scripts.com",
            styleSrc: "'self' https://styles.com",
            websocketHost: 'old-ws.example.com:443',
        );

        $modified = $original->withWebSocket('new-ws.example.com:443');

        $this->assertSame('new-ws.example.com:443', $modified->websocketHost);
        $this->assertSame("'self' https://example.com", $modified->defaultSrc);
        $this->assertSame("'self' https://scripts.com", $modified->scriptSrc);
        $this->assertSame("'self' https://styles.com", $modified->styleSrc);
    }
}
