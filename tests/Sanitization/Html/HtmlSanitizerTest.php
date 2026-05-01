<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Html;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Html\AllowedAttributes;
use Zappzarapp\Security\Sanitization\Html\AllowedElements;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizer;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizerConfig;

#[CoversClass(HtmlSanitizer::class)]
final class HtmlSanitizerTest extends TestCase
{
    private HtmlSanitizer $sanitizer;

    protected function setUp(): void
    {
        $this->sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());
    }

    // =========================================================================
    // Empty String Handling (Mutants 5, 6)
    // =========================================================================

    #[Test]
    public function testEmptyStringReturnsEmptyString(): void
    {
        $result = $this->sanitizer->sanitize('');

        $this->assertSame('', $result);
    }

    #[Test]
    public function testNonEmptyStringIsProcessed(): void
    {
        $result = $this->sanitizer->sanitize('Hello');

        $this->assertNotSame('', $result);
        $this->assertStringContainsString('Hello', $result);
    }

    // =========================================================================
    // No Elements Allowed - Escape Everything (Mutants 7, 8)
    // =========================================================================

    #[Test]
    public function testNoElementsAllowedEscapesEverything(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::stripAll());

        $result = $sanitizer->sanitize('<script>alert("xss")</script>');

        // Should escape HTML entities, not return empty
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertNotSame('', $result);
        $this->assertStringContainsString('&lt;', $result);
        $this->assertStringContainsString('&gt;', $result);
    }

    #[Test]
    public function testStripAllConfigEscapesQuotes(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::stripAll());

        // ENT_QUOTES | ENT_HTML5 escapes double quotes as &quot; and single as &apos;
        $result = $sanitizer->sanitize('Test "double" and \'single\' quotes');

        $this->assertStringContainsString('&quot;', $result);
        $this->assertStringContainsString('&apos;', $result);
    }

    // =========================================================================
    // HTML Parsing and Wrapping (Mutants 9-16)
    // =========================================================================

    #[Test]
    public function testHtmlParsingPreservesContent(): void
    {
        $input  = '<p>Test content</p>';
        $result = $this->sanitizer->sanitize($input);

        // Content must be preserved, not mangled by incorrect concatenation
        $this->assertStringContainsString('Test content', $result);
        $this->assertStringContainsString('<p>', $result);
    }

    #[Test]
    public function testHtmlParsingWithSpecialCharacters(): void
    {
        $input  = '<p>Test with UTF-8: äöü</p>';
        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('äöü', $result);
    }

    #[Test]
    public function testMalformedHtmlIsSanitized(): void
    {
        // Without libxml flags (LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD), parsing could fail
        $input  = '<p>Unclosed paragraph';
        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Unclosed paragraph', $result);
    }

    // =========================================================================
    // Tag and Attribute Name Normalization (Mutants 17, 20, 22)
    // =========================================================================

    /**
     * @param list<string> $mustContain
     * @param list<string> $mustNotContain
     */
    #[DataProvider('uppercaseNormalizationProvider')]
    #[Test]
    public function testUppercaseNormalization(
        string $input,
        HtmlSanitizerConfig $config,
        array $mustContain,
        array $mustNotContain = []
    ): void {
        $sanitizer = new HtmlSanitizer($config);
        $result    = $sanitizer->sanitize($input);

        foreach ($mustContain as $substring) {
            $this->assertStringContainsString($substring, strtolower($result));
        }
        foreach ($mustNotContain as $substring) {
            $this->assertStringNotContainsString($substring, strtolower($result));
        }
    }

    /**
     * @return iterable<string, array{string, HtmlSanitizerConfig, list<string>, list<string>}>
     */
    public static function uppercaseNormalizationProvider(): iterable
    {
        $basicConfig = new HtmlSanitizerConfig(
            elements: AllowedElements::basic(),
            attributes: AllowedAttributes::minimal()
        );
        $richConfig = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );

        yield 'uppercase tag P is normalized' => [
            '<P>UPPERCASE TAG</P>',
            $basicConfig,
            ['uppercase tag', '<p>'],
            [],
        ];

        yield 'uppercase HREF attribute is normalized' => [
            '<a HREF="https://example.com">Link</a>',
            $richConfig,
            ['href='],
            [],
        ];

        yield 'uppercase P element matches allowed elements' => [
            '<P>Paragraph</P>',
            $basicConfig,
            ['<p>', 'paragraph'],
            [],
        ];

        yield 'uppercase HREF matches allowed attributes' => [
            '<a HREF="https://example.com">Link</a>',
            $richConfig,
            ['href='],
            [],
        ];
    }

    // =========================================================================
    // Loop Control Flow (Mutants 18, 21, 23)
    // =========================================================================

    #[Test]
    public function testMultipleDisallowedElementsAreRemoved(): void
    {
        $config    = new HtmlSanitizerConfig(AllowedElements::basic());
        $sanitizer = new HtmlSanitizer($config);

        // Multiple disallowed elements - continue vs break makes a difference
        $input = '<div>First</div><span>Second</span><div>Third</div>';

        $result = $sanitizer->sanitize($input);

        // All text content should be preserved (elements unwrapped)
        $this->assertStringContainsString('First', $result);
        $this->assertStringContainsString('Second', $result);
        $this->assertStringContainsString('Third', $result);
    }

    #[Test]
    public function testMultipleAttributesAreProcessed(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Multiple attributes - loop should process all
        $input = '<a href="https://example.com" title="Test" onclick="bad()">Link</a>';

        $result = $sanitizer->sanitize($input);

        // href and title should remain, onclick should be removed
        $this->assertStringContainsString('href=', $result);
        $this->assertStringContainsString('title=', $result);
        $this->assertStringNotContainsString('onclick', $result);
    }

    #[Test]
    public function testAttributeLoopProcessesAllAttributes(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Element with many disallowed attributes
        $input = '<a href="https://example.com" data-bad="1" onfocus="evil()" onmouseover="bad()">Link</a>';

        $result = $sanitizer->sanitize($input);

        // All disallowed attributes should be removed, not just the first
        $this->assertStringNotContainsString('data-bad', $result);
        $this->assertStringNotContainsString('onfocus', $result);
        $this->assertStringNotContainsString('onmouseover', $result);
    }

    // =========================================================================
    // Recursive Sanitization (Mutant 19)
    // =========================================================================

    #[Test]
    public function testNestedElementsAreSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::standard(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Nested structure - recursion is important
        $input = '<p><strong><em>Nested <span onclick="bad()">text</span></em></strong></p>';

        $result = $sanitizer->sanitize($input);

        // All nested text should be preserved
        $this->assertStringContainsString('Nested', $result);
        $this->assertStringContainsString('text', $result);
        // Dangerous attribute should be removed even in nested element
        $this->assertStringNotContainsString('onclick', $result);
    }

    #[Test]
    public function testDeeplyNestedStructure(): void
    {
        $input = '<p><strong><em><u>Deep</u></em></strong></p>';

        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Deep', $result);
    }

    // =========================================================================
    // Anchor Tag with Target - rel="noopener noreferrer" (Mutants 24-28)
    // =========================================================================

    /**
     * @param list<string> $mustContain
     * @param list<string> $mustNotContain
     */
    #[DataProvider('anchorRelProvider')]
    #[Test]
    public function testAnchorRelBehavior(
        string $input,
        array $mustContain,
        array $mustNotContain,
        ?int $noopenerCount = null
    ): void {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        $result = $sanitizer->sanitize($input);

        foreach ($mustContain as $substring) {
            $this->assertStringContainsString($substring, $result);
        }
        foreach ($mustNotContain as $substring) {
            $this->assertStringNotContainsString($substring, $result);
        }
        if ($noopenerCount !== null) {
            $this->assertSame($noopenerCount, substr_count($result, 'noopener'));
        }
    }

    /**
     * @return iterable<string, array{string, list<string>, list<string>, int|null}>
     */
    public static function anchorRelProvider(): iterable
    {
        yield 'target blank gets noopener noreferrer' => [
            '<a href="https://example.com" target="_blank">Link</a>',
            ['noopener', 'noreferrer'],
            [],
            null,
        ];

        yield 'existing rel is preserved with noopener added' => [
            '<a href="https://example.com" target="_blank" rel="author">Link</a>',
            ['author', 'noopener'],
            [],
            null,
        ];

        yield 'existing noopener not duplicated' => [
            '<a href="https://example.com" target="_blank" rel="noopener">Link</a>',
            ['noopener'],
            [],
            1,
        ];

        yield 'no target means no noopener' => [
            '<a href="https://example.com">Link</a>',
            [],
            ['noopener'],
            null,
        ];

        yield 'non-anchor does not get noopener' => [
            '<p>Test</p>',
            [],
            ['noopener'],
            null,
        ];
    }

    // =========================================================================
    // Remove Element Keep Content - While Loop (Mutant 29)
    // =========================================================================

    #[Test]
    public function testDisallowedElementChildrenArePreserved(): void
    {
        $config    = new HtmlSanitizerConfig(AllowedElements::basic());
        $sanitizer = new HtmlSanitizer($config);

        // div is not in basic elements, but its children should be kept
        $input = '<div><p>Keep this text</p></div>';

        $result = $sanitizer->sanitize($input);

        $this->assertStringContainsString('Keep this text', $result);
        $this->assertStringNotContainsString('<div', $result);
    }

    #[Test]
    public function testMultipleChildrenOfDisallowedElement(): void
    {
        $config    = new HtmlSanitizerConfig(AllowedElements::basic());
        $sanitizer = new HtmlSanitizer($config);

        // Multiple children that need to be moved
        $input = '<div><p>First</p><p>Second</p><p>Third</p></div>';

        $result = $sanitizer->sanitize($input);

        $this->assertStringContainsString('First', $result);
        $this->assertStringContainsString('Second', $result);
        $this->assertStringContainsString('Third', $result);
    }

    // =========================================================================
    // Extract HTML - Body Item Index (Mutants 30, 31, 32)
    // =========================================================================

    #[Test]
    public function testExtractHtmlReturnsBodyContent(): void
    {
        $input  = '<p>Body content</p>';
        $result = $this->sanitizer->sanitize($input);

        // The body content should be extracted correctly
        $this->assertStringContainsString('Body content', $result);
        // Should not include HTML structure
        $this->assertStringNotContainsString('<!DOCTYPE', $result);
        $this->assertStringNotContainsString('<html', $result);
    }

    #[Test]
    public function testExtractHtmlWithMultipleElements(): void
    {
        $input  = '<p>First</p><p>Second</p>';
        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('First', $result);
        $this->assertStringContainsString('Second', $result);
    }

    // =========================================================================
    // Extract HTML - Foreach Loop (Mutants 33, 34)
    // =========================================================================

    #[Test]
    public function testExtractHtmlConcatenatesAllChildren(): void
    {
        $input  = '<p>One</p><p>Two</p><p>Three</p>';
        $result = $this->sanitizer->sanitize($input);

        // All children should be concatenated
        $this->assertStringContainsString('One', $result);
        $this->assertStringContainsString('Two', $result);
        $this->assertStringContainsString('Three', $result);
    }

    #[Test]
    public function testExtractHtmlWithMixedContent(): void
    {
        $input  = 'Text before <p>Paragraph</p> text after';
        $result = $this->sanitizer->sanitize($input);

        // All parts should be included
        $this->assertStringContainsString('Text before', $result);
        $this->assertStringContainsString('Paragraph', $result);
        $this->assertStringContainsString('text after', $result);
    }

    // =========================================================================
    // IsSafe Always Returns True
    // =========================================================================

    #[Test]
    public function testIsSafeAlwaysReturnsTrue(): void
    {
        $this->assertTrue($this->sanitizer->isSafe('<script>evil</script>'));
        $this->assertTrue($this->sanitizer->isSafe(''));
        $this->assertTrue($this->sanitizer->isSafe('normal text'));
    }

    // =========================================================================
    // URL Attribute Sanitization (consolidated)
    // =========================================================================

    /**
     * @param list<string> $mustContain
     * @param list<string> $mustNotContain
     */
    #[DataProvider('urlAttributeProvider')]
    #[Test]
    public function testUrlAttributeSanitization(
        string $input,
        array $mustContain,
        array $mustNotContain
    ): void {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        $result = $sanitizer->sanitize($input);

        foreach ($mustContain as $substring) {
            $this->assertStringContainsString($substring, $result);
        }
        foreach ($mustNotContain as $substring) {
            $this->assertStringNotContainsString($substring, $result);
        }
    }

    /**
     * @return iterable<string, array{string, list<string>, list<string>}>
     */
    public static function urlAttributeProvider(): iterable
    {
        yield 'javascript href is removed' => [
            '<a href="javascript:alert(1)">Link</a>',
            [],
            ['javascript:'],
        ];

        yield 'valid img src is preserved' => [
            '<img src="https://example.com/img.jpg" alt="Test">',
            ['src=', 'example.com'],
            [],
        ];

        yield 'javascript img src is removed, alt preserved' => [
            '<img src="javascript:alert(1)" alt="test">',
            ['alt='],
            ['javascript:'],
        ];

        yield 'javascript form action is removed' => [
            '<form action="javascript:alert(1)">content</form>',
            [],
            ['javascript:'],
        ];

        yield 'non-url title attribute preserved' => [
            '<a href="https://example.com" title="Click here">Link</a>',
            ['title=', 'Click here'],
            [],
        ];

        yield 'valid src URL preserved exactly' => [
            '<img src="https://example.com/image.jpg" alt="Image">',
            ['src="https://example.com/image.jpg"'],
            [],
        ];

        yield 'valid href URL preserved exactly' => [
            '<a href="https://example.com/path">Link</a>',
            ['href="https://example.com/path"'],
            [],
        ];
    }

    #[Test]
    public function testImgSrcsetAndAltBehavior(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid srcset preserved
        $input  = '<img src="https://example.com/img.jpg" srcset="https://example.com/img-2x.jpg 2x">';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('srcset=', $result);

        // JavaScript in srcset removed (srcset IS a URL attribute)
        $malicious = '<img src="https://example.com/img.jpg" srcset="javascript:alert(1)">';
        $this->assertStringNotContainsString('javascript:', $sanitizer->sanitize($malicious));

        // Alt attribute is NOT a URL attribute - "javascript:" text should be preserved
        $altInput  = '<img src="https://example.com/img.jpg" alt="javascript: is a protocol">';
        $altResult = $sanitizer->sanitize($altInput);
        $this->assertStringContainsString('alt=', $altResult);
        $this->assertStringContainsString('javascript:', $altResult);
    }

    // =========================================================================
    // URL Attribute Coverage - All Element Types (isUrlAttribute branches)
    // =========================================================================

    #[Test]
    public function testAreaHrefIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid area href preserved
        $input  = '<area href="https://example.com/region" alt="Region">';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('href="https://example.com/region"', $result);

        // JavaScript in area href removed
        $malicious = '<area href="javascript:alert(1)" alt="Bad">';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testVideoSrcAndPosterAreUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid video src and poster preserved
        $input  = '<video src="https://example.com/video.mp4" poster="https://example.com/thumb.jpg"></video>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('src="https://example.com/video.mp4"', $result);
        $this->assertStringContainsString('poster="https://example.com/thumb.jpg"', $result);

        // JavaScript in video src removed
        $malicious = '<video src="javascript:alert(1)"></video>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);

        // JavaScript in poster removed
        $maliciousPoster = '<video src="https://example.com/v.mp4" poster="javascript:alert(1)"></video>';
        $result          = $sanitizer->sanitize($maliciousPoster);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testAudioSrcIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid audio src preserved
        $input  = '<audio src="https://example.com/audio.mp3"></audio>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('src="https://example.com/audio.mp3"', $result);

        // JavaScript in audio src removed
        $malicious = '<audio src="javascript:alert(1)"></audio>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testSourceSrcIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid source src preserved
        $input  = '<video><source src="https://example.com/video.webm" type="video/webm"></video>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('src="https://example.com/video.webm"', $result);

        // JavaScript in source src removed
        $malicious = '<video><source src="javascript:alert(1)" type="video/webm"></video>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testTrackSrcIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid track src preserved
        $input  = '<video><track src="https://example.com/captions.vtt" kind="captions"></video>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('src="https://example.com/captions.vtt"', $result);

        // JavaScript in track src removed
        $malicious = '<video><track src="javascript:alert(1)" kind="captions"></video>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testBlockquoteCiteIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid blockquote cite preserved
        $input  = '<blockquote cite="https://example.com/source">Quote text</blockquote>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('cite="https://example.com/source"', $result);

        // JavaScript in blockquote cite removed
        $malicious = '<blockquote cite="javascript:alert(1)">Quote</blockquote>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testQCiteIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid q cite preserved
        $input  = '<q cite="https://example.com/source">Quote text</q>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('cite="https://example.com/source"', $result);

        // JavaScript in q cite removed
        $malicious = '<q cite="javascript:alert(1)">Quote</q>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    #[Test]
    public function testDelInsCiteIsUrlSanitized(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::full(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Valid del cite preserved
        $input  = '<del cite="https://example.com/reason">Deleted text</del>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('cite="https://example.com/reason"', $result);

        // Valid ins cite preserved
        $input  = '<ins cite="https://example.com/reason">Inserted text</ins>';
        $result = $sanitizer->sanitize($input);
        $this->assertStringContainsString('cite="https://example.com/reason"', $result);

        // JavaScript in del cite removed
        $malicious = '<del cite="javascript:alert(1)">Text</del>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);

        // JavaScript in ins cite removed
        $malicious = '<ins cite="javascript:alert(1)">Text</ins>';
        $result    = $sanitizer->sanitize($malicious);
        $this->assertStringNotContainsString('javascript:', $result);
    }

    // =========================================================================
    // Additional Edge Cases
    // =========================================================================

    #[Test]
    public function testWhitespaceOnlyInput(): void
    {
        $result = $this->sanitizer->sanitize('   ');

        // Should handle whitespace-only input
        $this->assertNotNull($result);
    }

    #[Test]
    public function testSpecialHtmlEntities(): void
    {
        $input  = '<p>&amp; &lt; &gt;</p>';
        $result = $this->sanitizer->sanitize($input);

        // Should preserve or properly handle entities
        $this->assertNotSame('', $result);
    }

    #[DataProvider('xssPayloadProvider')]
    #[Test]
    public function testXssPayloadsAreSanitized(string $payload): void
    {
        $result = $this->sanitizer->sanitize($payload);

        // None of these dangerous patterns should remain
        $this->assertStringNotContainsString('<script', strtolower($result));
        $this->assertStringNotContainsString('javascript:', strtolower($result));
        $this->assertStringNotContainsString('onclick', strtolower($result));
        $this->assertStringNotContainsString('onerror', strtolower($result));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function xssPayloadProvider(): iterable
    {
        yield 'script tag' => ['<script>alert(1)</script>'];
        yield 'img onerror' => ['<img src=x onerror=alert(1)>'];
        yield 'body onload' => ['<body onload=alert(1)>'];
        yield 'svg onload' => ['<svg onload=alert(1)>'];
        yield 'a href javascript' => ['<a href="javascript:alert(1)">click</a>'];
    }

    // =========================================================================
    // rel Attribute Concatenation Order (Mutants 13, 14)
    // =========================================================================

    #[Test]
    public function testRelAttributePreservesExistingValueFirst(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Link with existing rel value
        $input = '<a href="https://example.com" target="_blank" rel="author">Link</a>';

        $result = $sanitizer->sanitize($input);

        // Should be "author noopener noreferrer", not "noopener noreferrer author"
        // The existing value comes first
        $this->assertMatchesRegularExpression('/rel="author\s+noopener/', $result);
    }

    #[Test]
    public function testRelAttributeWithEmptyValueGetsNoLeadingSpace(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Link without existing rel value
        $input = '<a href="https://example.com" target="_blank">Link</a>';

        $result = $sanitizer->sanitize($input);

        // Should not have leading space (trim is needed)
        $this->assertStringNotContainsString('rel=" noopener', $result);
        $this->assertStringContainsString('rel="noopener', $result);
    }

    // =========================================================================
    // Continue vs Break in Element Loop (Mutant 8)
    // =========================================================================

    #[Test]
    public function testAllDisallowedElementsAreProcessed(): void
    {
        $config    = new HtmlSanitizerConfig(AllowedElements::basic());
        $sanitizer = new HtmlSanitizer($config);

        // Multiple disallowed elements (divs) mixed with allowed elements (paragraphs)
        // With break instead of continue, only the first div would be processed
        // The text content is preserved when elements are removed
        $input = '<div>div1</div><p>para1</p><div>div2</div><p>para2</p><div>div3</div>';

        $result = $sanitizer->sanitize($input);

        // All div content should be present (divs removed, content kept)
        $this->assertStringContainsString('div1', $result);
        $this->assertStringContainsString('div2', $result);
        $this->assertStringContainsString('div3', $result);
        // All paragraph content should be present
        $this->assertStringContainsString('para1', $result);
        $this->assertStringContainsString('para2', $result);
        // But there should be no div tags
        $this->assertStringNotContainsString('<div', $result);
    }

    // =========================================================================
    // Attribute Loop Bounds (Mutant 10)
    // =========================================================================

    #[Test]
    public function testAllAttributesAreIterated(): void
    {
        $config = new HtmlSanitizerConfig(
            elements: AllowedElements::rich(),
            attributes: AllowedAttributes::standard()
        );
        $sanitizer = new HtmlSanitizer($config);

        // Element with exactly 2 attributes
        // Loop must use < not <= to avoid off-by-one
        $input = '<a href="https://example.com" title="Test">Link</a>';

        $result = $sanitizer->sanitize($input);

        // Both attributes should be present
        $this->assertStringContainsString('href=', $result);
        $this->assertStringContainsString('title=', $result);
    }

    // =========================================================================
    // Empty String Early Return (Mutant 2)
    // =========================================================================

    #[Test]
    public function testEmptyStringDoesNotContinueProcessing(): void
    {
        // The early return for empty string is important for performance
        // Without it, processing would continue and eventually return empty anyway
        // This test verifies the behavior is correct
        $result = $this->sanitizer->sanitize('');

        $this->assertSame('', $result);
        // If return is removed, might throw or return null
        $this->assertIsString($result);
    }

    // =========================================================================
    // UTF-8 Validation (mXSS Prevention)
    // =========================================================================

    #[Test]
    public function testInvalidUtf8IsNotParsedAsHtml(): void
    {
        // Invalid UTF-8 sequence (overlong encoding that could bypass filters)
        $invalidUtf8 = "Hello \xC0\xAF World";

        $result = $this->sanitizer->sanitize($invalidUtf8);

        // Invalid UTF-8 should NOT be parsed as HTML - it should be escaped
        // htmlspecialchars with ENT_QUOTES | ENT_HTML5 returns empty string for invalid UTF-8
        $this->assertStringNotContainsString('<script>', $result);

        // Verify it doesn't crash and returns something safe
        $this->assertIsString($result);
    }

    #[Test]
    public function testInvalidUtf8WithHtmlEntitiesUsesCorrectFlags(): void
    {
        // Input with < and > that would be escaped differently with different flags
        // Invalid UTF-8 followed by HTML-like content
        $invalidUtf8 = "\xFF<test>&amp;";

        $result = $this->sanitizer->sanitize($invalidUtf8);

        // With ENT_QUOTES | ENT_HTML5 (51), htmlspecialchars returns empty for invalid UTF-8
        // With ENT_QUOTES & ENT_HTML5 (0 = no flags), behavior differs
        // This verifies the correct flags are used
        $this->assertIsString($result);
        // Should not contain unescaped angle brackets if any output is produced
        if ($result !== '') {
            $this->assertStringNotContainsString('<test>', $result);
        }
    }

    #[Test]
    public function testValidUtf8IsProcessed(): void
    {
        // Valid UTF-8 with multibyte characters
        $validUtf8 = '<p>Hëllo Wörld 日本語</p>';

        $result = $this->sanitizer->sanitize($validUtf8);

        // Should be processed normally
        $this->assertStringContainsString('Hëllo', $result);
        $this->assertStringContainsString('日本語', $result);
    }

    // =========================================================================
    // Null Byte Removal (XSS Prevention)
    // =========================================================================

    #[Test]
    public function testNullBytesAreRemoved(): void
    {
        // Null bytes can be used to truncate strings in some contexts
        $inputWithNullByte = "<p>Hello\0<script>alert(1)</script></p>";

        $result = $this->sanitizer->sanitize($inputWithNullByte);

        // Null bytes should be removed before processing
        $this->assertStringNotContainsString("\0", $result);
        // Script tag should still be removed (not hidden by null byte)
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringContainsString('Hello', $result);
    }

    #[Test]
    public function testMultipleNullBytesAreRemoved(): void
    {
        $multiNullInput = "<p>Test\0\0\0String</p>";

        $result = $this->sanitizer->sanitize($multiNullInput);

        // All null bytes should be removed
        $this->assertStringNotContainsString("\0", $result);
        $this->assertStringContainsString('TestString', $result);
    }

    #[Test]
    public function testNullByteRemovalPreventsTagSplitting(): void
    {
        // Null byte in the middle of a tag name could potentially split the tag
        // This test ensures that null bytes are removed BEFORE any processing
        $input = "<p>Hello\0World</p>";

        $result = $this->sanitizer->sanitize($input);

        // The null byte should be removed and the text should be intact
        $this->assertStringNotContainsString("\0", $result);
        $this->assertStringContainsString('HelloWorld', $result);
    }

    #[Test]
    public function testNullByteInAttributeIsRemoved(): void
    {
        // Null byte in attribute value
        $input = '<a href="https://example.com/path?foo=bar' . "\0" . '&baz=qux">Link</a>';

        $result = $this->sanitizer->sanitize($input);

        // The null byte should be removed from the output
        $this->assertStringNotContainsString("\0", $result);
    }

    #[Test]
    public function testNullByteRemovalChangesStringContent(): void
    {
        // This test specifically verifies that str_replace for null bytes changes the input
        // Input with null byte between two characters that would otherwise be separate
        $input = "A\0B";

        $result = $this->sanitizer->sanitize($input);

        // After null byte removal, the string should be "AB" (concatenated)
        // Without removal, DOMDocument might treat the null byte differently
        $this->assertSame('AB', $result);
    }

    #[Test]
    public function testNullByteBetweenHtmlElementsIsRemoved(): void
    {
        // Null byte between HTML elements
        $input = '<p>First</p>' . "\0" . '<p>Second</p>';

        $result = $this->sanitizer->sanitize($input);

        // The null byte should be removed, and both paragraphs should be present
        $this->assertStringNotContainsString("\0", $result);
        $this->assertStringContainsString('First', $result);
        $this->assertStringContainsString('Second', $result);
    }

    #[Test]
    public function testNullByteRemovedWhenNoElementsAllowed(): void
    {
        // When no elements are allowed, input is escaped via htmlspecialchars
        // Null bytes should still be removed before escaping
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::stripAll());

        $input = "Test\0String";

        $result = $sanitizer->sanitize($input);

        // Null byte should be removed even without DOM parsing
        $this->assertStringNotContainsString("\0", $result);
        $this->assertSame('TestString', $result);
    }

    #[Test]
    public function testNullByteInScriptContentRemovedBeforeEscaping(): void
    {
        // With stripAll config, the whole input is escaped
        // Null bytes should be removed first
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::stripAll());

        $input = '<script>alert(' . "\0" . '1)</script>';

        $result = $sanitizer->sanitize($input);

        // The null byte should not be in the output
        $this->assertStringNotContainsString("\0", $result);
        // The content should be escaped (not parsed)
        $this->assertStringContainsString('&lt;script&gt;', $result);
    }

    // =========================================================================
    // HTML Comment Removal (Security Measure)
    // =========================================================================

    #[Test]
    public function testHtmlCommentsAreRemoved(): void
    {
        $input = '<p>Before</p><!-- This is a comment --><p>After</p>';

        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Before', $result);
        $this->assertStringContainsString('After', $result);
        $this->assertStringNotContainsString('<!--', $result);
        $this->assertStringNotContainsString('-->', $result);
        $this->assertStringNotContainsString('comment', $result);
    }

    #[Test]
    public function testMultipleHtmlCommentsAreRemoved(): void
    {
        $input = '<!-- First -->Text<!-- Second -->More<!-- Third -->';

        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Text', $result);
        $this->assertStringContainsString('More', $result);
        $this->assertStringNotContainsString('First', $result);
        $this->assertStringNotContainsString('Second', $result);
        $this->assertStringNotContainsString('Third', $result);
    }

    #[Test]
    public function testNestedHtmlCommentsInElementsAreRemoved(): void
    {
        $input = '<div><p>Text<!-- Hidden comment --></p></div>';

        $config    = new HtmlSanitizerConfig(AllowedElements::rich());
        $sanitizer = new HtmlSanitizer($config);

        $result = $sanitizer->sanitize($input);

        $this->assertStringContainsString('Text', $result);
        $this->assertStringNotContainsString('Hidden', $result);
        $this->assertStringNotContainsString('<!--', $result);
    }

    #[Test]
    public function testConditionalCommentsAreRemoved(): void
    {
        // Internet Explorer conditional comments (legacy XSS vector)
        $input = '<p>Safe</p><!--[if IE]><script>alert(1)</script><![endif]-->';

        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Safe', $result);
        $this->assertStringNotContainsString('script', $result);
        $this->assertStringNotContainsString('alert', $result);
        $this->assertStringNotContainsString('[if IE]', $result);
    }

    #[Test]
    public function testCommentsWithMaliciousContentAreRemoved(): void
    {
        // Comments can be used to hide malicious content that might be exposed by DOM quirks
        $input = '<p>Visible</p><!-- <script>document.write("XSS")</script> -->';

        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Visible', $result);
        $this->assertStringNotContainsString('script', $result);
        $this->assertStringNotContainsString('XSS', $result);
    }

    #[Test]
    public function testEmptyCommentsAreRemoved(): void
    {
        $input = '<p>Text</p><!----><p>More</p>';

        $result = $this->sanitizer->sanitize($input);

        $this->assertStringContainsString('Text', $result);
        $this->assertStringContainsString('More', $result);
        $this->assertStringNotContainsString('<!--', $result);
    }
}
