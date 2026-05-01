<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Html;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Html\AllowedAttributes;

#[CoversClass(AllowedAttributes::class)]
final class AllowedAttributesTest extends TestCase
{
    // =========================================================================
    // Constructor and Default Configuration
    // =========================================================================

    #[Test]
    public function testDefaultConstructorAllowsGlobalSafeAttributes(): void
    {
        $config = new AllowedAttributes();

        $this->assertTrue($config->isAllowed('div', 'id'));
        $this->assertTrue($config->isAllowed('div', 'class'));
        $this->assertTrue($config->isAllowed('div', 'title'));
        $this->assertTrue($config->isAllowed('div', 'lang'));
        $this->assertTrue($config->isAllowed('div', 'dir'));
    }

    #[Test]
    public function testDefaultConstructorHasNoElementSpecificAttributes(): void
    {
        $config = new AllowedAttributes();

        // href should not be allowed by default (it's element-specific)
        $this->assertFalse($config->isAllowed('a', 'href'));
        $this->assertFalse($config->isAllowed('img', 'src'));
    }

    // =========================================================================
    // Factory Method: standard()
    // =========================================================================

    #[Test]
    public function testStandardConfigAllowsCommonElements(): void
    {
        $config = AllowedAttributes::standard();

        // Anchor attributes
        $this->assertTrue($config->isAllowed('a', 'href'));
        $this->assertTrue($config->isAllowed('a', 'target'));
        $this->assertTrue($config->isAllowed('a', 'rel'));

        // Image attributes
        $this->assertTrue($config->isAllowed('img', 'src'));
        $this->assertTrue($config->isAllowed('img', 'srcset'));
        $this->assertTrue($config->isAllowed('img', 'alt'));
        $this->assertTrue($config->isAllowed('img', 'width'));
        $this->assertTrue($config->isAllowed('img', 'height'));
        $this->assertTrue($config->isAllowed('img', 'loading'));
    }

    #[Test]
    public function testStandardConfigAllowsMediaElements(): void
    {
        $config = AllowedAttributes::standard();

        // Video attributes
        $this->assertTrue($config->isAllowed('video', 'src'));
        $this->assertTrue($config->isAllowed('video', 'poster'));
        $this->assertTrue($config->isAllowed('video', 'controls'));
        $this->assertTrue($config->isAllowed('video', 'autoplay'));
        $this->assertTrue($config->isAllowed('video', 'loop'));
        $this->assertTrue($config->isAllowed('video', 'muted'));
        $this->assertTrue($config->isAllowed('video', 'preload'));

        // Audio attributes
        $this->assertTrue($config->isAllowed('audio', 'src'));
        $this->assertTrue($config->isAllowed('audio', 'controls'));

        // Source/track attributes
        $this->assertTrue($config->isAllowed('source', 'src'));
        $this->assertTrue($config->isAllowed('source', 'type'));
        $this->assertTrue($config->isAllowed('track', 'src'));
        $this->assertTrue($config->isAllowed('track', 'kind'));
    }

    #[Test]
    public function testStandardConfigAllowsCitationElements(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertTrue($config->isAllowed('blockquote', 'cite'));
        $this->assertTrue($config->isAllowed('q', 'cite'));
        $this->assertTrue($config->isAllowed('del', 'cite'));
        $this->assertTrue($config->isAllowed('del', 'datetime'));
        $this->assertTrue($config->isAllowed('ins', 'cite'));
        $this->assertTrue($config->isAllowed('ins', 'datetime'));
    }

    #[Test]
    public function testStandardConfigAllowsTableElements(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertTrue($config->isAllowed('td', 'colspan'));
        $this->assertTrue($config->isAllowed('td', 'rowspan'));
        $this->assertTrue($config->isAllowed('th', 'colspan'));
        $this->assertTrue($config->isAllowed('th', 'rowspan'));
        $this->assertTrue($config->isAllowed('th', 'scope'));
    }

    #[Test]
    public function testStandardConfigAllowsAreaElement(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertTrue($config->isAllowed('area', 'href'));
        $this->assertTrue($config->isAllowed('area', 'alt'));
        $this->assertTrue($config->isAllowed('area', 'shape'));
        $this->assertTrue($config->isAllowed('area', 'coords'));
        $this->assertTrue($config->isAllowed('area', 'target'));
        $this->assertTrue($config->isAllowed('area', 'rel'));
    }

    // =========================================================================
    // Factory Method: minimal()
    // =========================================================================

    #[Test]
    public function testMinimalConfigOnlyAllowsIdAndClass(): void
    {
        $config = AllowedAttributes::minimal();

        $this->assertTrue($config->isAllowed('div', 'id'));
        $this->assertTrue($config->isAllowed('div', 'class'));
        $this->assertFalse($config->isAllowed('div', 'title'));
        $this->assertFalse($config->isAllowed('div', 'lang'));
        $this->assertFalse($config->isAllowed('div', 'dir'));
    }

    #[Test]
    public function testMinimalConfigDoesNotAllowElementSpecificAttributes(): void
    {
        $config = AllowedAttributes::minimal();

        $this->assertFalse($config->isAllowed('a', 'href'));
        $this->assertFalse($config->isAllowed('img', 'src'));
        $this->assertFalse($config->isAllowed('video', 'controls'));
    }

    // =========================================================================
    // forElement() - Immutability
    // =========================================================================

    #[Test]
    public function testForElementReturnsNewInstance(): void
    {
        $original = new AllowedAttributes();
        $modified = $original->forElement('a', ['href', 'target']);

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testForElementDoesNotModifyOriginal(): void
    {
        $original = new AllowedAttributes();
        $original->forElement('a', ['href', 'target']);

        // Original should not have href allowed
        $this->assertFalse($original->isAllowed('a', 'href'));
    }

    #[Test]
    public function testForElementAddsAttributes(): void
    {
        $config = (new AllowedAttributes())
            ->forElement('custom', ['data-custom', 'data-id']);

        $this->assertTrue($config->isAllowed('custom', 'data-custom'));
        $this->assertTrue($config->isAllowed('custom', 'data-id'));
    }

    #[Test]
    public function testForElementNormalizesElementNameToLowercase(): void
    {
        $config = (new AllowedAttributes())
            ->forElement('CUSTOM', ['data-value']);

        $this->assertTrue($config->isAllowed('custom', 'data-value'));
        $this->assertTrue($config->isAllowed('CUSTOM', 'data-value'));
    }

    #[Test]
    public function testForElementOverwritesPreviousAttributes(): void
    {
        $config = (new AllowedAttributes())
            ->forElement('a', ['href', 'target'])
            ->forElement('a', ['href', 'rel']);

        $this->assertTrue($config->isAllowed('a', 'href'));
        $this->assertTrue($config->isAllowed('a', 'rel'));
        // target was overwritten
        $this->assertFalse($config->isAllowed('a', 'target'));
    }

    // =========================================================================
    // isAllowed() - XSS Prevention via Dangerous Attribute Blocking
    // =========================================================================

    #[DataProvider('dangerousAttributeProvider')]
    #[Test]
    public function testDangerousAttributesAreAlwaysBlocked(string $attribute): void
    {
        // Even with standard config, dangerous attributes should be blocked
        $config = AllowedAttributes::standard();

        $this->assertFalse($config->isAllowed('div', $attribute));
        $this->assertFalse($config->isAllowed('a', $attribute));
        $this->assertFalse($config->isAllowed('img', $attribute));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function dangerousAttributeProvider(): iterable
    {
        yield 'onabort' => ['onabort'];
        yield 'onblur' => ['onblur'];
        yield 'onchange' => ['onchange'];
        yield 'onclick' => ['onclick'];
        yield 'ondblclick' => ['ondblclick'];
        yield 'onerror' => ['onerror'];
        yield 'onfocus' => ['onfocus'];
        yield 'onkeydown' => ['onkeydown'];
        yield 'onkeypress' => ['onkeypress'];
        yield 'onkeyup' => ['onkeyup'];
        yield 'onload' => ['onload'];
        yield 'onmousedown' => ['onmousedown'];
        yield 'onmousemove' => ['onmousemove'];
        yield 'onmouseout' => ['onmouseout'];
        yield 'onmouseover' => ['onmouseover'];
        yield 'onmouseup' => ['onmouseup'];
        yield 'onreset' => ['onreset'];
        yield 'onresize' => ['onresize'];
        yield 'onselect' => ['onselect'];
        yield 'onsubmit' => ['onsubmit'];
        yield 'onunload' => ['onunload'];
        yield 'formaction' => ['formaction'];
        yield 'xlink:href' => ['xlink:href'];
    }

    #[Test]
    public function testAnyOnPrefixedAttributeIsBlocked(): void
    {
        $config = AllowedAttributes::standard();

        // Any on* attribute should be blocked, even custom ones
        $this->assertFalse($config->isAllowed('div', 'oncustom'));
        $this->assertFalse($config->isAllowed('div', 'onwhatever'));
        $this->assertFalse($config->isAllowed('div', 'ontouchstart'));
        $this->assertFalse($config->isAllowed('div', 'onanimationend'));
    }

    #[Test]
    public function testDangerousAttributesBlockedEvenIfExplicitlyAdded(): void
    {
        // Try to add dangerous attributes via forElement
        $config = (new AllowedAttributes())
            ->forElement('div', ['onclick', 'onerror', 'onload']);

        // They should still be blocked
        $this->assertFalse($config->isAllowed('div', 'onclick'));
        $this->assertFalse($config->isAllowed('div', 'onerror'));
        $this->assertFalse($config->isAllowed('div', 'onload'));
    }

    // =========================================================================
    // isAllowed() - Case Normalization
    // =========================================================================

    #[Test]
    public function testIsAllowedNormalizesElementName(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertTrue($config->isAllowed('A', 'href'));
        $this->assertTrue($config->isAllowed('a', 'href'));
        $this->assertTrue($config->isAllowed('IMG', 'src'));
        $this->assertTrue($config->isAllowed('img', 'src'));
    }

    #[Test]
    public function testIsAllowedNormalizesAttributeName(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertTrue($config->isAllowed('a', 'HREF'));
        $this->assertTrue($config->isAllowed('a', 'Href'));
        $this->assertTrue($config->isAllowed('img', 'SRC'));
        $this->assertTrue($config->isAllowed('img', 'Src'));
    }

    #[Test]
    public function testDangerousAttributesCaseInsensitive(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertFalse($config->isAllowed('div', 'ONCLICK'));
        $this->assertFalse($config->isAllowed('div', 'OnClick'));
        $this->assertFalse($config->isAllowed('div', 'ONERROR'));
        $this->assertFalse($config->isAllowed('div', 'OnError'));
    }

    // =========================================================================
    // isAllowed() - Attribute Check Priority
    // =========================================================================

    #[Test]
    public function testGlobalAttributesAllowedOnAnyElement(): void
    {
        $config = new AllowedAttributes();

        // Global attributes should be allowed even on elements without specific config
        $this->assertTrue($config->isAllowed('custom-element', 'id'));
        $this->assertTrue($config->isAllowed('custom-element', 'class'));
        $this->assertTrue($config->isAllowed('unknown', 'title'));
    }

    #[Test]
    public function testElementSpecificAttributesOnlyOnThatElement(): void
    {
        $config = AllowedAttributes::standard();

        // href only allowed on a, not on div
        $this->assertTrue($config->isAllowed('a', 'href'));
        $this->assertFalse($config->isAllowed('div', 'href'));

        // src only allowed on specific elements
        $this->assertTrue($config->isAllowed('img', 'src'));
        $this->assertFalse($config->isAllowed('div', 'src'));
    }

    // =========================================================================
    // forElementList() - Get All Allowed Attributes
    // =========================================================================

    #[Test]
    public function testForElementListReturnsGlobalAndElementAttributes(): void
    {
        $config = AllowedAttributes::standard();

        $anchorAttrs = $config->forElementList('a');

        // Should include global attributes
        $this->assertContains('id', $anchorAttrs);
        $this->assertContains('class', $anchorAttrs);
        $this->assertContains('title', $anchorAttrs);
        $this->assertContains('lang', $anchorAttrs);
        $this->assertContains('dir', $anchorAttrs);

        // Should include element-specific attributes
        $this->assertContains('href', $anchorAttrs);
        $this->assertContains('target', $anchorAttrs);
        $this->assertContains('rel', $anchorAttrs);
    }

    #[Test]
    public function testForElementListNormalizesElementName(): void
    {
        $config = AllowedAttributes::standard();

        $lowerAttrs = $config->forElementList('a');
        $upperAttrs = $config->forElementList('A');

        $this->assertSame($lowerAttrs, $upperAttrs);
    }

    #[Test]
    public function testForElementListReturnsOnlyGlobalForUnknownElement(): void
    {
        $config = new AllowedAttributes();

        $attrs = $config->forElementList('unknown-element');

        // Should only contain global attributes
        $this->assertContains('id', $attrs);
        $this->assertContains('class', $attrs);
        $this->assertContains('title', $attrs);
        $this->assertContains('lang', $attrs);
        $this->assertContains('dir', $attrs);
        $this->assertCount(5, $attrs);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[Test]
    public function testEmptyAttributeNameIsNotAllowed(): void
    {
        $config = AllowedAttributes::standard();

        $this->assertFalse($config->isAllowed('div', ''));
    }

    #[Test]
    public function testEmptyElementNameStillChecksGlobalAttributes(): void
    {
        $config = new AllowedAttributes();

        // Global attributes should work even with empty element name
        $this->assertTrue($config->isAllowed('', 'id'));
        $this->assertTrue($config->isAllowed('', 'class'));
    }

    #[Test]
    public function testForElementWithEmptyAttributeList(): void
    {
        $config = (new AllowedAttributes())
            ->forElement('custom', []);

        // Should still allow global attributes
        $this->assertTrue($config->isAllowed('custom', 'id'));
        // But no element-specific attributes
        $this->assertFalse($config->isAllowed('custom', 'href'));
    }

    #[Test]
    public function testChainedForElementCalls(): void
    {
        $config = (new AllowedAttributes())
            ->forElement('a', ['href'])
            ->forElement('img', ['src'])
            ->forElement('video', ['controls']);

        $this->assertTrue($config->isAllowed('a', 'href'));
        $this->assertTrue($config->isAllowed('img', 'src'));
        $this->assertTrue($config->isAllowed('video', 'controls'));
    }
}
