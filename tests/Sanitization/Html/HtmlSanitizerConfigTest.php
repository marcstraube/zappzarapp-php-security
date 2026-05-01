<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Html;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Html\AllowedAttributes;
use Zappzarapp\Security\Sanitization\Html\AllowedElements;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizerConfig;

#[CoversClass(HtmlSanitizerConfig::class)]
final class HtmlSanitizerConfigTest extends TestCase
{
    // =========================================================================
    // Constructor and Default Values
    // =========================================================================

    #[Test]
    public function testDefaultConstructorValues(): void
    {
        $config = new HtmlSanitizerConfig();

        $this->assertInstanceOf(AllowedElements::class, $config->elements);
        $this->assertInstanceOf(AllowedAttributes::class, $config->attributes);
        $this->assertFalse($config->removeEmpty);
        $this->assertTrue($config->balanceTags);
    }

    #[Test]
    public function testConstructorWithCustomValues(): void
    {
        $elements   = AllowedElements::full();
        $attributes = AllowedAttributes::standard();

        $config = new HtmlSanitizerConfig(
            elements: $elements,
            attributes: $attributes,
            removeEmpty: true,
            balanceTags: false
        );

        $this->assertSame($elements, $config->elements);
        $this->assertSame($attributes, $config->attributes);
        $this->assertTrue($config->removeEmpty);
        $this->assertFalse($config->balanceTags);
    }

    // =========================================================================
    // Factory Method: basic()
    // =========================================================================

    #[Test]
    public function testBasicConfigUsesBasicElements(): void
    {
        $config = HtmlSanitizerConfig::basic();

        // Should use AllowedElements::basic()
        $this->assertTrue($config->elements->isAllowed('p'));
        $this->assertTrue($config->elements->isAllowed('b'));
        $this->assertTrue($config->elements->isAllowed('i'));
        $this->assertFalse($config->elements->isAllowed('div'));
        $this->assertFalse($config->elements->isAllowed('a'));
    }

    #[Test]
    public function testBasicConfigUsesMinimalAttributes(): void
    {
        $config = HtmlSanitizerConfig::basic();

        // Should use AllowedAttributes::minimal()
        $this->assertTrue($config->attributes->isAllowed('p', 'id'));
        $this->assertTrue($config->attributes->isAllowed('p', 'class'));
        $this->assertFalse($config->attributes->isAllowed('p', 'title'));
        $this->assertFalse($config->attributes->isAllowed('a', 'href'));
    }

    // =========================================================================
    // Factory Method: standard()
    // =========================================================================

    #[Test]
    public function testStandardConfigUsesStandardElements(): void
    {
        $config = HtmlSanitizerConfig::standard();

        // Should use AllowedElements::standard()
        $this->assertTrue($config->elements->isAllowed('p'));
        $this->assertTrue($config->elements->isAllowed('div'));
        $this->assertTrue($config->elements->isAllowed('h1'));
        $this->assertTrue($config->elements->isAllowed('ul'));
        $this->assertFalse($config->elements->isAllowed('a'));
        $this->assertFalse($config->elements->isAllowed('img'));
    }

    #[Test]
    public function testStandardConfigUsesStandardAttributes(): void
    {
        $config = HtmlSanitizerConfig::standard();

        // Should use AllowedAttributes::standard()
        $this->assertTrue($config->attributes->isAllowed('div', 'id'));
        $this->assertTrue($config->attributes->isAllowed('div', 'class'));
        $this->assertTrue($config->attributes->isAllowed('div', 'title'));
        $this->assertTrue($config->attributes->isAllowed('a', 'href'));
        $this->assertTrue($config->attributes->isAllowed('img', 'src'));
    }

    // =========================================================================
    // Factory Method: rich()
    // =========================================================================

    #[Test]
    public function testRichConfigUsesRichElements(): void
    {
        $config = HtmlSanitizerConfig::rich();

        // Should use AllowedElements::rich()
        $this->assertTrue($config->elements->isAllowed('p'));
        $this->assertTrue($config->elements->isAllowed('div'));
        $this->assertTrue($config->elements->isAllowed('a'));
        $this->assertTrue($config->elements->isAllowed('img'));
        $this->assertFalse($config->elements->isAllowed('video'));
        $this->assertFalse($config->elements->isAllowed('audio'));
    }

    #[Test]
    public function testRichConfigUsesStandardAttributes(): void
    {
        $config = HtmlSanitizerConfig::rich();

        // Should use AllowedAttributes::standard()
        $this->assertTrue($config->attributes->isAllowed('a', 'href'));
        $this->assertTrue($config->attributes->isAllowed('a', 'target'));
        $this->assertTrue($config->attributes->isAllowed('img', 'src'));
        $this->assertTrue($config->attributes->isAllowed('img', 'alt'));
    }

    // =========================================================================
    // Factory Method: stripAll()
    // =========================================================================

    #[Test]
    public function testStripAllConfigUsesNoElements(): void
    {
        $config = HtmlSanitizerConfig::stripAll();

        // Should use AllowedElements::none()
        $this->assertFalse($config->elements->isAllowed('p'));
        $this->assertFalse($config->elements->isAllowed('div'));
        $this->assertFalse($config->elements->isAllowed('span'));
        $this->assertFalse($config->elements->isAllowed('a'));
        $this->assertFalse($config->elements->isAllowed('script'));
    }

    #[Test]
    public function testStripAllConfigUsesMinimalAttributes(): void
    {
        $config = HtmlSanitizerConfig::stripAll();

        // Should use AllowedAttributes::minimal()
        $this->assertTrue($config->attributes->isAllowed('div', 'id'));
        $this->assertTrue($config->attributes->isAllowed('div', 'class'));
        $this->assertFalse($config->attributes->isAllowed('div', 'title'));
    }

    // =========================================================================
    // withElements() - Immutability
    // =========================================================================

    #[Test]
    public function testWithElementsReturnsNewInstance(): void
    {
        $original = new HtmlSanitizerConfig();
        $modified = $original->withElements(AllowedElements::full());

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithElementsDoesNotModifyOriginal(): void
    {
        $original   = new HtmlSanitizerConfig();
        $originalEl = $original->elements;

        $original->withElements(AllowedElements::full());

        $this->assertSame($originalEl, $original->elements);
    }

    #[Test]
    public function testWithElementsPreservesOtherProperties(): void
    {
        $attributes = AllowedAttributes::standard();
        $original   = new HtmlSanitizerConfig(
            attributes: $attributes,
            removeEmpty: true,
            balanceTags: false
        );

        $modified = $original->withElements(AllowedElements::full());

        $this->assertSame($attributes, $modified->attributes);
        $this->assertTrue($modified->removeEmpty);
        $this->assertFalse($modified->balanceTags);
    }

    #[Test]
    public function testWithElementsSetsNewElements(): void
    {
        $original    = HtmlSanitizerConfig::basic();
        $newElements = AllowedElements::full();

        $modified = $original->withElements($newElements);

        $this->assertSame($newElements, $modified->elements);
        $this->assertTrue($modified->elements->isAllowed('video'));
    }

    // =========================================================================
    // withAttributes() - Immutability
    // =========================================================================

    #[Test]
    public function testWithAttributesReturnsNewInstance(): void
    {
        $original = new HtmlSanitizerConfig();
        $modified = $original->withAttributes(AllowedAttributes::standard());

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithAttributesDoesNotModifyOriginal(): void
    {
        $original     = new HtmlSanitizerConfig();
        $originalAttr = $original->attributes;

        $original->withAttributes(AllowedAttributes::standard());

        $this->assertSame($originalAttr, $original->attributes);
    }

    #[Test]
    public function testWithAttributesPreservesOtherProperties(): void
    {
        $elements = AllowedElements::full();
        $original = new HtmlSanitizerConfig(
            elements: $elements,
            removeEmpty: true,
            balanceTags: false
        );

        $modified = $original->withAttributes(AllowedAttributes::minimal());

        $this->assertSame($elements, $modified->elements);
        $this->assertTrue($modified->removeEmpty);
        $this->assertFalse($modified->balanceTags);
    }

    #[Test]
    public function testWithAttributesSetsNewAttributes(): void
    {
        $original      = HtmlSanitizerConfig::basic();
        $newAttributes = AllowedAttributes::standard();

        $modified = $original->withAttributes($newAttributes);

        $this->assertSame($newAttributes, $modified->attributes);
        $this->assertTrue($modified->attributes->isAllowed('a', 'href'));
    }

    // =========================================================================
    // Chaining with* Methods
    // =========================================================================

    #[Test]
    public function testWithMethodsCanBeChained(): void
    {
        $config = (new HtmlSanitizerConfig())
            ->withElements(AllowedElements::rich())
            ->withAttributes(AllowedAttributes::standard());

        $this->assertTrue($config->elements->isAllowed('a'));
        $this->assertTrue($config->attributes->isAllowed('a', 'href'));
    }

    // =========================================================================
    // Readonly Properties
    // =========================================================================

    #[Test]
    public function testPropertiesArePublicReadonly(): void
    {
        $config = new HtmlSanitizerConfig();

        // Properties should be accessible
        $this->assertInstanceOf(AllowedElements::class, $config->elements);
        $this->assertInstanceOf(AllowedAttributes::class, $config->attributes);
        $this->assertIsBool($config->removeEmpty);
        $this->assertIsBool($config->balanceTags);
    }

    // =========================================================================
    // Factory Methods Create New Instances
    // =========================================================================

    #[Test]
    public function testFactoryMethodsCreateNewInstances(): void
    {
        $basic1 = HtmlSanitizerConfig::basic();
        $basic2 = HtmlSanitizerConfig::basic();

        $this->assertNotSame($basic1, $basic2);

        $standard1 = HtmlSanitizerConfig::standard();
        $standard2 = HtmlSanitizerConfig::standard();

        $this->assertNotSame($standard1, $standard2);
    }

    // =========================================================================
    // Security Configurations
    // =========================================================================

    #[Test]
    public function testStripAllIsSecureDefault(): void
    {
        $config = HtmlSanitizerConfig::stripAll();

        // Dangerous elements should not be allowed
        $this->assertFalse($config->elements->isAllowed('script'));
        $this->assertFalse($config->elements->isAllowed('style'));
        $this->assertFalse($config->elements->isAllowed('iframe'));
        $this->assertFalse($config->elements->isAllowed('object'));
        $this->assertFalse($config->elements->isAllowed('embed'));
    }

    #[Test]
    public function testAllConfigsBlockDangerousAttributes(): void
    {
        $configs = [
            HtmlSanitizerConfig::basic(),
            HtmlSanitizerConfig::standard(),
            HtmlSanitizerConfig::rich(),
            HtmlSanitizerConfig::stripAll(),
        ];

        foreach ($configs as $config) {
            $this->assertFalse($config->attributes->isAllowed('div', 'onclick'));
            $this->assertFalse($config->attributes->isAllowed('div', 'onerror'));
            $this->assertFalse($config->attributes->isAllowed('div', 'onload'));
        }
    }
}
