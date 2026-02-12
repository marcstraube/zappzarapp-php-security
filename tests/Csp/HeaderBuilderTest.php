<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp;

use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NullNonce;
use Zappzarapp\Security\Csp\SecurityPolicy;

final class HeaderBuilderTest extends TestCase
{
    // Strict Policy Tests
    /**
     * @throws RandomException
     */
    public function testBuildStrictCspWithDefaults(): void
    {
        $csp = HeaderBuilder::build(new CspDirectives());

        $this->assertStringContainsString("default-src 'self'", $csp);
        $this->assertStringContainsString("'strict-dynamic'", $csp);
        $this->assertStringNotContainsString("'unsafe-eval'", $csp);
        $this->assertStringNotContainsString("'unsafe-inline'", $csp);
    }

    /**
     * @throws RandomException
     */
    public function testBuildStrictCspContainsNonce(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $csp       = HeaderBuilder::build(new CspDirectives(), $generator);

        $this->assertStringContainsString(sprintf("'nonce-%s'", $nonce), $csp);
    }

    /**
     * @throws RandomException
     */
    public function testBuildStrictCspWithCustomImgSrc(): void
    {
        $directives = (new CspDirectives())->withImgSrc("'self' https://cdn.example.com");
        $csp        = HeaderBuilder::build($directives);

        $this->assertStringContainsString("img-src 'self' https://cdn.example.com", $csp);
    }

    /**
     * @throws RandomException
     */
    public function testBuildStrictCspWithWebSocket(): void
    {
        $directives = (new CspDirectives())->withWebSocket('api.example.com:443');
        $csp        = HeaderBuilder::build($directives);

        $this->assertStringContainsString("wss://api.example.com:443", $csp);
        $this->assertStringContainsString("https://api.example.com:443", $csp);
    }

    // Lenient Policy Tests
    /**
     * @throws RandomException
     */
    public function testBuildLenientCspWithDefaults(): void
    {
        $csp = HeaderBuilder::build(new CspDirectives(securityPolicy: SecurityPolicy::LENIENT));

        $this->assertStringContainsString("'unsafe-eval'", $csp);
        $this->assertStringContainsString("'unsafe-inline'", $csp);
    }

    /**
     * @throws RandomException
     */
    public function testBuildLenientCspWithCustomWebSocketHost(): void
    {
        $csp = HeaderBuilder::build(new CspDirectives(
            websocketHost: '192.168.1.100:5173',
            securityPolicy: SecurityPolicy::LENIENT,
        ));

        $this->assertStringContainsString("wss://192.168.1.100:5173", $csp);
        $this->assertStringContainsString("https://192.168.1.100:5173", $csp);
    }

    // Nonce Provider Tests
    /**
     * @throws RandomException
     */
    public function testBuildWithNullNonce(): void
    {
        $csp = HeaderBuilder::build(new CspDirectives(), new NullNonce());

        $this->assertStringContainsString("script-src 'self'", $csp);
        $this->assertStringNotContainsString("'nonce-", $csp);
    }

    /**
     * @throws RandomException
     */
    public function testBuildWithDefaultNonceProvider(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $csp       = HeaderBuilder::build(new CspDirectives(), $generator);

        $this->assertStringContainsString(sprintf("'nonce-%s'", $nonce), $csp);
    }

    // Fluent API Tests
    /**
     * @throws RandomException
     */
    public function testFluentApiWithMultipleCustomizations(): void
    {
        $directives = (new CspDirectives())
            ->withImgSrc("'self' https://images.example.com")
            ->withFontSrc("'self' https://fonts.gstatic.com")
            ->withWebSocket('api.example.com:443');

        $csp = HeaderBuilder::build($directives);

        $this->assertStringContainsString("img-src 'self' https://images.example.com", $csp);
        $this->assertStringContainsString("font-src 'self' https://fonts.gstatic.com", $csp);
        $this->assertStringContainsString("wss://api.example.com:443", $csp);
    }

    /**
     * @throws RandomException
     */
    public function testCustomScriptSrcAutoInjectsNonce(): void
    {
        $generator  = new NonceGenerator();
        $nonce      = $generator->get();
        $directives = (new CspDirectives())->withScriptSrc("'self' 'strict-dynamic' https://trusted.com");
        $csp        = HeaderBuilder::build($directives, $generator);

        $this->assertStringContainsString(sprintf("'nonce-%s'", $nonce), $csp);
        $this->assertStringContainsString("https://trusted.com", $csp);
    }

    /**
     * @throws RandomException
     */
    public function testCustomScriptSrcWithExistingNonceDoesNotDuplicate(): void
    {
        $generator  = new NonceGenerator();
        $nonce      = $generator->get();
        $directives = (new CspDirectives())->withScriptSrc(sprintf("'self' 'nonce-%s' 'strict-dynamic'", $nonce));
        $csp        = HeaderBuilder::build($directives, $generator);

        // Extract script-src directive
        preg_match("/script-src ([^;]+)/", $csp, $matches);
        $scriptSrc = $matches[1] ?? '';

        $nonceCount = substr_count($scriptSrc, sprintf("'nonce-%s'", $nonce));
        $this->assertSame(1, $nonceCount, 'Nonce should appear exactly once');
    }

    // Header Name Tests
    public function testGetHeaderNameReturnsEnforcementHeader(): void
    {
        $this->assertSame('Content-Security-Policy', HeaderBuilder::getHeaderName());
    }

    public function testGetReportOnlyHeaderNameReturnsReportOnlyHeader(): void
    {
        $this->assertSame('Content-Security-Policy-Report-Only', HeaderBuilder::getReportOnlyHeaderName());
    }

    public function testHeaderConstants(): void
    {
        $this->assertSame('Content-Security-Policy', HeaderBuilder::HEADER_CSP);
        $this->assertSame('Content-Security-Policy-Report-Only', HeaderBuilder::HEADER_CSP_REPORT_ONLY);
    }

    // Build Header Tests
    /**
     * @throws RandomException
     */
    public function testBuildHeaderReturnsCompleteHeaderString(): void
    {
        $header = HeaderBuilder::buildHeader(new CspDirectives());

        $this->assertStringStartsWith('Content-Security-Policy: ', $header);
        $this->assertStringContainsString("default-src 'self'", $header);
    }

    /**
     * @throws RandomException
     */
    public function testBuildReportOnlyHeader(): void
    {
        $header = HeaderBuilder::buildReportOnlyHeader(new CspDirectives());

        $this->assertStringStartsWith('Content-Security-Policy-Report-Only: ', $header);
        $this->assertStringContainsString("default-src 'self'", $header);
    }

    /**
     * @throws RandomException
     */
    public function testBuildHeaderWithNonceProvider(): void
    {
        $header = HeaderBuilder::buildHeader(new CspDirectives(), new NullNonce());

        $this->assertStringStartsWith('Content-Security-Policy: ', $header);
        $this->assertStringNotContainsString("'nonce-", $header);
    }

    /**
     * @throws RandomException
     */
    public function testBuildReportOnlyHeaderWithNonceProvider(): void
    {
        $header = HeaderBuilder::buildReportOnlyHeader(new CspDirectives(), new NullNonce());

        $this->assertStringStartsWith('Content-Security-Policy-Report-Only: ', $header);
        $this->assertStringNotContainsString("'nonce-", $header);
    }
}
