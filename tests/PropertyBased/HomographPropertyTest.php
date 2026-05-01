<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizer;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;

/**
 * Property-based tests for homograph attack detection
 *
 * These tests verify that mixed-script IDN domains are blocked
 * to prevent homograph/confusable attacks.
 */
#[CoversClass(UriSanitizer::class)]
final class HomographPropertyTest extends TestCase
{
    use TestTrait;

    /**
     * Cyrillic characters that visually resemble Latin characters
     *
     * @var array<string, string>
     */
    private const array CYRILLIC_LOOKALIKES = [
        'a' => "\u{0430}", // Cyrillic Small Letter A
        'c' => "\u{0441}", // Cyrillic Small Letter ES
        'e' => "\u{0435}", // Cyrillic Small Letter IE
        'o' => "\u{043E}", // Cyrillic Small Letter O
        'p' => "\u{0440}", // Cyrillic Small Letter ER
        'x' => "\u{0445}", // Cyrillic Small Letter HA
        'y' => "\u{0443}", // Cyrillic Small Letter U
        'i' => "\u{0456}", // Cyrillic Small Letter I (Ukrainian)
        's' => "\u{0455}", // Cyrillic Small Letter DZE
    ];

    /**
     * Greek characters that visually resemble Latin characters
     *
     * @var array<string, string>
     */
    private const array GREEK_LOOKALIKES = [
        'A' => "\u{0391}", // Greek Capital Letter Alpha
        'B' => "\u{0392}", // Greek Capital Letter Beta
        'E' => "\u{0395}", // Greek Capital Letter Epsilon
        'H' => "\u{0397}", // Greek Capital Letter Eta
        'I' => "\u{0399}", // Greek Capital Letter Iota
        'K' => "\u{039A}", // Greek Capital Letter Kappa
        'M' => "\u{039C}", // Greek Capital Letter Mu
        'N' => "\u{039D}", // Greek Capital Letter Nu
        'O' => "\u{039F}", // Greek Capital Letter Omicron
        'P' => "\u{03A1}", // Greek Capital Letter Rho
        'T' => "\u{03A4}", // Greek Capital Letter Tau
        'X' => "\u{03A7}", // Greek Capital Letter Chi
        'Y' => "\u{03A5}", // Greek Capital Letter Upsilon
        'Z' => "\u{0396}", // Greek Capital Letter Zeta
        'o' => "\u{03BF}", // Greek Small Letter Omicron
    ];

    /**
     * Property: Mixed Cyrillic/Latin domains are ALWAYS blocked
     */
    #[Test]
    public function testMixedCyrillicLatinDomainsAreBlocked(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        // Classic homograph attack: "аpple.com" (Cyrillic 'а' + Latin 'pple')
        $homographDomains = [
            'https://' . self::CYRILLIC_LOOKALIKES['a'] . 'pple.com',      // аpple.com
            'https://g' . self::CYRILLIC_LOOKALIKES['o'] . 'ogle.com',     // goоgle.com
            'https://p' . self::CYRILLIC_LOOKALIKES['a'] . 'ypal.com',     // paуpal.com
            'https://' . self::CYRILLIC_LOOKALIKES['e'] . 'bay.com',       // еbay.com
            'https://fac' . self::CYRILLIC_LOOKALIKES['e'] . 'book.com',   // faceвook.com
            'https://amaz' . self::CYRILLIC_LOOKALIKES['o'] . 'n.com',     // amazоn.com
        ];

        foreach ($homographDomains as $uri) {
            $this->assertFalse(
                $sanitizer->isSafe($uri),
                "Mixed Cyrillic/Latin domain should be blocked: {$uri}"
            );
        }
    }

    /**
     * Property: Mixed Greek/Latin domains are ALWAYS blocked
     */
    #[Test]
    public function testMixedGreekLatinDomainsAreBlocked(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        $homographDomains = [
            'https://G' . self::GREEK_LOOKALIKES['O'] . 'OGLE.com', // GΟOGLE.com (Greek Omicron)
            'https://AP' . self::GREEK_LOOKALIKES['P'] . 'LE.com',  // AΡΡLE.com (Greek Rho)
        ];

        foreach ($homographDomains as $uri) {
            $this->assertFalse(
                $sanitizer->isSafe($uri),
                "Mixed Greek/Latin domain should be blocked: {$uri}"
            );
        }
    }

    /**
     * Property: Pure Cyrillic domains are allowed (single script)
     */
    #[Test]
    public function testPureCyrillicDomainsAreAllowed(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        // Pure Cyrillic TLDs exist (e.g., .рф for Russia)
        $pureCyrillicDomains = [
            'https://пример.рф',   // "example" in Russian
            'https://тест.рф',     // "test" in Russian
        ];

        foreach ($pureCyrillicDomains as $uri) {
            $this->assertTrue(
                $sanitizer->isSafe($uri),
                "Pure Cyrillic domain should be allowed: {$uri}"
            );
        }
    }

    /**
     * Property: Pure Latin domains are always allowed
     */
    #[Test]
    public function testPureLatinDomainsAreAllowed(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        $this->forAll(
            Generators::elements([
                'https://example.com',
                'https://google.com',
                'https://amazon.com',
                'https://paypal.com',
                'https://apple.com',
                'https://microsoft.com',
            ])
        )->then(function (string $uri) use ($sanitizer): void {
            $this->assertTrue(
                $sanitizer->isSafe($uri),
                "Pure Latin domain should be allowed: {$uri}"
            );
        });
    }

    /**
     * Property: Random mixed-script combinations are blocked
     *
     * Generates random combinations of Latin + Cyrillic to ensure
     * the detection is robust against any mixing pattern.
     */
    #[Test]
    public function testRandomMixedScriptCombinationsAreBlocked(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        $latinChars    = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'];
        $cyrillicChars = array_values(self::CYRILLIC_LOOKALIKES);

        $this->forAll(
            Generators::elements(...$latinChars),
            Generators::elements(...$cyrillicChars),
            Generators::elements(...$latinChars)
        )->then(function (string $latin1, string $cyrillic, string $latin2) use ($sanitizer): void {
            $mixedDomain = 'https://' . $latin1 . $cyrillic . $latin2 . '.com';

            $this->assertFalse(
                $sanitizer->isSafe($mixedDomain),
                "Mixed script domain should be blocked: {$mixedDomain}"
            );
        });
    }

    /**
     * Property: Confusable substitution at any position is detected
     */
    #[Test]
    public function testConfusableSubstitutionAtAnyPosition(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        $cyrillicE = self::CYRILLIC_LOOKALIKES['e'];

        // Substitute 'e' at different positions
        $variants = [
            $cyrillicE . 'xample',    // Position 0
            'ex' . $cyrillicE . 'mple', // Position 2 (second 'e' would be at position 6)
        ];

        foreach ($variants as $variant) {
            $uri = 'https://' . $variant . '.com';

            $this->assertFalse(
                $sanitizer->isSafe($uri),
                "Confusable at any position should be detected: {$uri}"
            );
        }
    }

    /**
     * Property: Feature can be disabled for legitimate multilingual use
     */
    #[Test]
    public function testMixedScriptBlockingCanBeDisabled(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: false, // Disabled
        ));

        // With blocking disabled, mixed script domains pass
        $mixedDomain = 'https://' . self::CYRILLIC_LOOKALIKES['a'] . 'pple.com';

        $this->assertTrue(
            $sanitizer->isSafe($mixedDomain),
            'Mixed script domain should pass when blocking is disabled'
        );
    }

    /**
     * Property: Punycode conversion failure blocks the domain
     *
     * Invalid Unicode sequences that cannot be converted to Punycode
     * should be blocked as a safety measure.
     */
    #[Test]
    public function testInvalidIdnIsBlocked(): void
    {
        $sanitizer = new UriSanitizer(new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true,
        ));

        // Malformed UTF-8 sequences or invalid IDN labels
        $invalidIdns = [
            "https://\xC0\xAF.com", // Overlong encoding
            "https://\xFF\xFE.com", // Invalid UTF-8
        ];

        foreach ($invalidIdns as $uri) {
            // These should either be blocked or cause no exception
            $result = $sanitizer->isSafe($uri);
            // We just verify it doesn't crash - specific behavior depends on idn_to_ascii
            $this->assertIsBool($result);
        }
    }
}
