<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

final class NavigationDirectivesTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $navigation = new NavigationDirectives();

        $this->assertSame("'self'", $navigation->frameAncestors);
        $this->assertSame("'self'", $navigation->baseUri);
        $this->assertSame("'self'", $navigation->formAction);
    }

    public function testCustomValues(): void
    {
        $navigation = new NavigationDirectives(
            frameAncestors: "'none'",
            baseUri: "'self' https://example.com",
            formAction: "'self' https://submit.example.com"
        );

        $this->assertSame("'none'", $navigation->frameAncestors);
        $this->assertSame("'self' https://example.com", $navigation->baseUri);
        $this->assertSame("'self' https://submit.example.com", $navigation->formAction);
    }

    public function testWithFrameAncestorsReturnsNewInstance(): void
    {
        $original = new NavigationDirectives();
        $modified = $original->withFrameAncestors("'none'");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->frameAncestors);
        $this->assertSame("'none'", $modified->frameAncestors);
    }

    public function testWithBaseUriReturnsNewInstance(): void
    {
        $original = new NavigationDirectives();
        $modified = $original->withBaseUri("'none'");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->baseUri);
        $this->assertSame("'none'", $modified->baseUri);
    }

    public function testWithFormActionReturnsNewInstance(): void
    {
        $original = new NavigationDirectives();
        $modified = $original->withFormAction("'self' https://submit.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->formAction);
        $this->assertSame("'self' https://submit.example.com", $modified->formAction);
    }

    public function testFluentApiChaining(): void
    {
        $navigation = (new NavigationDirectives())
            ->withFrameAncestors("'none'")
            ->withBaseUri("'none'")
            ->withFormAction("'self' https://submit.example.com");

        $this->assertSame("'none'", $navigation->frameAncestors);
        $this->assertSame("'none'", $navigation->baseUri);
        $this->assertSame("'self' https://submit.example.com", $navigation->formAction);
    }

    // Validation Tests
    public function testValidationThrowsForSemicolonInFrameAncestors(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('frame-ancestors');

        new NavigationDirectives(frameAncestors: "'self'; evil");
    }

    public function testValidationThrowsForNewlineInFrameAncestors(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('frame-ancestors');

        new NavigationDirectives(frameAncestors: "'self'\nevil");
    }

    public function testValidationThrowsForSemicolonInBaseUri(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('base-uri');

        new NavigationDirectives(baseUri: "'self'; evil");
    }

    public function testValidationThrowsForSemicolonInFormAction(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('form-action');

        new NavigationDirectives(formAction: "'self'; evil");
    }

    public function testValidationThrowsForCarriageReturnInFormAction(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('form-action');

        new NavigationDirectives(formAction: "'self'\revil");
    }

    // Preservation Tests (kills ?? swap mutations)
    public function testWithFrameAncestorsPreservesOtherValues(): void
    {
        $original = new NavigationDirectives(
            frameAncestors: "'self'",
            baseUri: "'self' https://base.com",
            formAction: "'self' https://form.com",
        );

        $modified = $original->withFrameAncestors("'none'");

        $this->assertSame("'none'", $modified->frameAncestors);
        $this->assertSame("'self' https://base.com", $modified->baseUri);
        $this->assertSame("'self' https://form.com", $modified->formAction);
    }

    public function testWithBaseUriPreservesOtherValues(): void
    {
        $original = new NavigationDirectives(
            frameAncestors: "'self' https://ancestor.com",
            baseUri: "'self'",
            formAction: "'self' https://form.com",
        );

        $modified = $original->withBaseUri("'none'");

        $this->assertSame("'self' https://ancestor.com", $modified->frameAncestors);
        $this->assertSame("'none'", $modified->baseUri);
        $this->assertSame("'self' https://form.com", $modified->formAction);
    }

    public function testWithFormActionPreservesOtherValues(): void
    {
        $original = new NavigationDirectives(
            frameAncestors: "'self' https://ancestor.com",
            baseUri: "'self' https://base.com",
            formAction: "'self'",
        );

        $modified = $original->withFormAction("'none'");

        $this->assertSame("'self' https://ancestor.com", $modified->frameAncestors);
        $this->assertSame("'self' https://base.com", $modified->baseUri);
        $this->assertSame("'none'", $modified->formAction);
    }
}
