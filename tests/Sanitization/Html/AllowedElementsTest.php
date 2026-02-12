<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Html;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Html\AllowedElements;

#[CoversClass(AllowedElements::class)]
final class AllowedElementsTest extends TestCase
{
    // =========================================================================
    // Constructor and Default Configuration
    // =========================================================================

    public function testDefaultConstructorCreatesEmptyList(): void
    {
        $config = new AllowedElements();

        $this->assertSame([], $config->all());
    }

    public function testDefaultConstructorAllowsNoElements(): void
    {
        $config = new AllowedElements();

        $this->assertFalse($config->isAllowed('p'));
        $this->assertFalse($config->isAllowed('div'));
        $this->assertFalse($config->isAllowed('span'));
    }

    public function testConstructorWithElementList(): void
    {
        $config = new AllowedElements(['p', 'span']);

        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('span'));
        $this->assertFalse($config->isAllowed('div'));
    }

    // =========================================================================
    // Factory Method: none()
    // =========================================================================

    public function testNoneCreatesEmptyConfiguration(): void
    {
        $config = AllowedElements::none();

        $this->assertSame([], $config->all());
        $this->assertFalse($config->isAllowed('p'));
        $this->assertFalse($config->isAllowed('script'));
    }

    // =========================================================================
    // Factory Method: basic()
    // =========================================================================

    public function testBasicIncludesFormattingElements(): void
    {
        $config = AllowedElements::basic();

        // Basic formatting
        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('br'));
        $this->assertTrue($config->isAllowed('hr'));

        // Text formatting
        $this->assertTrue($config->isAllowed('b'));
        $this->assertTrue($config->isAllowed('i'));
        $this->assertTrue($config->isAllowed('u'));
        $this->assertTrue($config->isAllowed('s'));
        $this->assertTrue($config->isAllowed('strong'));
        $this->assertTrue($config->isAllowed('em'));
        $this->assertTrue($config->isAllowed('mark'));

        // Subscript/superscript
        $this->assertTrue($config->isAllowed('sub'));
        $this->assertTrue($config->isAllowed('sup'));

        // Small
        $this->assertTrue($config->isAllowed('small'));
    }

    public function testBasicDoesNotIncludeStructureElements(): void
    {
        $config = AllowedElements::basic();

        $this->assertFalse($config->isAllowed('div'));
        $this->assertFalse($config->isAllowed('span'));
        $this->assertFalse($config->isAllowed('h1'));
    }

    // =========================================================================
    // Factory Method: standard()
    // =========================================================================

    public function testStandardIncludesBasicElements(): void
    {
        $config = AllowedElements::standard();

        // All basic elements should be included
        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('b'));
        $this->assertTrue($config->isAllowed('strong'));
    }

    public function testStandardIncludesStructureElements(): void
    {
        $config = AllowedElements::standard();

        $this->assertTrue($config->isAllowed('div'));
        $this->assertTrue($config->isAllowed('span'));
        $this->assertTrue($config->isAllowed('h1'));
        $this->assertTrue($config->isAllowed('h2'));
        $this->assertTrue($config->isAllowed('h3'));
        $this->assertTrue($config->isAllowed('h4'));
        $this->assertTrue($config->isAllowed('h5'));
        $this->assertTrue($config->isAllowed('h6'));
        $this->assertTrue($config->isAllowed('blockquote'));
        $this->assertTrue($config->isAllowed('pre'));
        $this->assertTrue($config->isAllowed('code'));
    }

    public function testStandardIncludesListElements(): void
    {
        $config = AllowedElements::standard();

        $this->assertTrue($config->isAllowed('ul'));
        $this->assertTrue($config->isAllowed('ol'));
        $this->assertTrue($config->isAllowed('li'));
        $this->assertTrue($config->isAllowed('dl'));
        $this->assertTrue($config->isAllowed('dt'));
        $this->assertTrue($config->isAllowed('dd'));
    }

    public function testStandardDoesNotIncludeLinkElements(): void
    {
        $config = AllowedElements::standard();

        $this->assertFalse($config->isAllowed('a'));
        $this->assertFalse($config->isAllowed('img'));
        $this->assertFalse($config->isAllowed('area'));
    }

    // =========================================================================
    // Factory Method: rich()
    // =========================================================================

    public function testRichIncludesAllStandardElements(): void
    {
        $config = AllowedElements::rich();

        // Standard elements
        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('div'));
        $this->assertTrue($config->isAllowed('ul'));
    }

    public function testRichIncludesLinkElements(): void
    {
        $config = AllowedElements::rich();

        $this->assertTrue($config->isAllowed('a'));
        $this->assertTrue($config->isAllowed('img'));
        $this->assertTrue($config->isAllowed('area'));
    }

    public function testRichDoesNotIncludeMediaElements(): void
    {
        $config = AllowedElements::rich();

        $this->assertFalse($config->isAllowed('video'));
        $this->assertFalse($config->isAllowed('audio'));
        $this->assertFalse($config->isAllowed('source'));
    }

    // =========================================================================
    // Factory Method: full()
    // =========================================================================

    public function testFullIncludesAllCommonElements(): void
    {
        $config = AllowedElements::full();

        // Basic
        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('br'));

        // Structure
        $this->assertTrue($config->isAllowed('div'));
        $this->assertTrue($config->isAllowed('h1'));

        // Lists
        $this->assertTrue($config->isAllowed('ul'));
        $this->assertTrue($config->isAllowed('li'));

        // Links
        $this->assertTrue($config->isAllowed('a'));
        $this->assertTrue($config->isAllowed('img'));
    }

    public function testFullIncludesMediaElements(): void
    {
        $config = AllowedElements::full();

        $this->assertTrue($config->isAllowed('video'));
        $this->assertTrue($config->isAllowed('audio'));
        $this->assertTrue($config->isAllowed('source'));
        $this->assertTrue($config->isAllowed('track'));
        $this->assertTrue($config->isAllowed('picture'));
        $this->assertTrue($config->isAllowed('figure'));
        $this->assertTrue($config->isAllowed('figcaption'));
    }

    public function testFullIncludesCitationElements(): void
    {
        $config = AllowedElements::full();

        $this->assertTrue($config->isAllowed('q'));
        $this->assertTrue($config->isAllowed('cite'));
        $this->assertTrue($config->isAllowed('del'));
        $this->assertTrue($config->isAllowed('ins'));
    }

    public function testFullIncludesTableElements(): void
    {
        $config = AllowedElements::full();

        $this->assertTrue($config->isAllowed('table'));
        $this->assertTrue($config->isAllowed('thead'));
        $this->assertTrue($config->isAllowed('tbody'));
        $this->assertTrue($config->isAllowed('tfoot'));
        $this->assertTrue($config->isAllowed('tr'));
        $this->assertTrue($config->isAllowed('th'));
        $this->assertTrue($config->isAllowed('td'));
        $this->assertTrue($config->isAllowed('caption'));
        $this->assertTrue($config->isAllowed('colgroup'));
        $this->assertTrue($config->isAllowed('col'));
    }

    // =========================================================================
    // with() - Immutability
    // =========================================================================

    public function testWithReturnsNewInstance(): void
    {
        $original = new AllowedElements();
        $modified = $original->with(['p', 'span']);

        $this->assertNotSame($original, $modified);
    }

    public function testWithDoesNotModifyOriginal(): void
    {
        $original = new AllowedElements();
        $original->with(['p', 'span']);

        $this->assertFalse($original->isAllowed('p'));
        $this->assertFalse($original->isAllowed('span'));
    }

    public function testWithAddsElements(): void
    {
        $config = (new AllowedElements())->with(['custom-element', 'another-element']);

        $this->assertTrue($config->isAllowed('custom-element'));
        $this->assertTrue($config->isAllowed('another-element'));
    }

    public function testWithCanBeChained(): void
    {
        $config = (new AllowedElements())
            ->with(['p'])
            ->with(['span'])
            ->with(['div']);

        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('span'));
        $this->assertTrue($config->isAllowed('div'));
    }

    public function testWithPreservesExistingElements(): void
    {
        $config = (new AllowedElements(['p']))
            ->with(['span']);

        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('span'));
    }

    public function testWithEmptyArrayDoesNotChangeElements(): void
    {
        $config = (new AllowedElements(['p', 'span']))
            ->with([]);

        $this->assertTrue($config->isAllowed('p'));
        $this->assertTrue($config->isAllowed('span'));
        $this->assertCount(2, $config->all());
    }

    // =========================================================================
    // isAllowed() - Case Normalization
    // =========================================================================

    public function testIsAllowedNormalizesToLowercase(): void
    {
        $config = new AllowedElements(['p', 'div']);

        $this->assertTrue($config->isAllowed('P'));
        $this->assertTrue($config->isAllowed('DIV'));
        $this->assertTrue($config->isAllowed('Div'));
    }

    public function testIsAllowedHandlesMixedCase(): void
    {
        $config = new AllowedElements(['custom']);

        $this->assertTrue($config->isAllowed('CUSTOM'));
        $this->assertTrue($config->isAllowed('Custom'));
        $this->assertTrue($config->isAllowed('cUsToM'));
    }

    // =========================================================================
    // all() - Get All Elements
    // =========================================================================

    public function testAllReturnsAllElements(): void
    {
        $elements = ['p', 'span', 'div'];
        $config   = new AllowedElements($elements);

        $this->assertSame($elements, $config->all());
    }

    public function testAllReturnsEmptyForNone(): void
    {
        $config = AllowedElements::none();

        $this->assertSame([], $config->all());
    }

    public function testAllReturnsCorrectCountForBasic(): void
    {
        $config = AllowedElements::basic();
        $all    = $config->all();

        // Basic has: p, br, hr, b, i, u, s, strong, em, mark, sub, sup, small
        $this->assertCount(13, $all);
    }

    // =========================================================================
    // Security: XSS Prevention
    // =========================================================================

    #[DataProvider('dangerousElementProvider')]
    public function testDangerousElementsNotInAnyPreset(string $element): void
    {
        $basic    = AllowedElements::basic();
        $standard = AllowedElements::standard();
        $rich     = AllowedElements::rich();
        $full     = AllowedElements::full();

        $this->assertFalse($basic->isAllowed($element));
        $this->assertFalse($standard->isAllowed($element));
        $this->assertFalse($rich->isAllowed($element));
        $this->assertFalse($full->isAllowed($element));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function dangerousElementProvider(): iterable
    {
        yield 'script' => ['script'];
        yield 'style' => ['style'];
        yield 'iframe' => ['iframe'];
        yield 'object' => ['object'];
        yield 'embed' => ['embed'];
        yield 'form' => ['form'];
        yield 'input' => ['input'];
        yield 'button' => ['button'];
        yield 'select' => ['select'];
        yield 'textarea' => ['textarea'];
        yield 'svg' => ['svg'];
        yield 'math' => ['math'];
        yield 'link' => ['link'];
        yield 'meta' => ['meta'];
        yield 'base' => ['base'];
        yield 'noscript' => ['noscript'];
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    public function testEmptyElementNameIsNotAllowed(): void
    {
        $config = AllowedElements::full();

        $this->assertFalse($config->isAllowed(''));
    }

    public function testWithDuplicateElementsPreservesDuplicates(): void
    {
        $config = (new AllowedElements(['p']))
            ->with(['p', 'span']);

        // The implementation uses spread operator, so p appears twice
        $all = $config->all();
        $this->assertContains('p', $all);
        $this->assertContains('span', $all);
    }

    public function testFactoryMethodsReturnNewInstances(): void
    {
        $none1 = AllowedElements::none();
        $none2 = AllowedElements::none();

        $this->assertNotSame($none1, $none2);

        $basic1 = AllowedElements::basic();
        $basic2 = AllowedElements::basic();

        $this->assertNotSame($basic1, $basic2);
    }

    public function testPresetHierarchy(): void
    {
        $basic    = AllowedElements::basic();
        $standard = AllowedElements::standard();
        $rich     = AllowedElements::rich();
        $full     = AllowedElements::full();

        // Each level should have more or equal elements than the previous
        $this->assertGreaterThanOrEqual(count($basic->all()), count($standard->all()));
        $this->assertGreaterThanOrEqual(count($standard->all()), count($rich->all()));
        $this->assertGreaterThanOrEqual(count($rich->all()), count($full->all()));
    }
}
