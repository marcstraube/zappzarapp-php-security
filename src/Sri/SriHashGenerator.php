<?php

/**
 * @noinspection HtmlUnknownTarget sprintf placeholders in HTML template strings
 * @noinspection HtmlUnknownAttribute sprintf placeholders in HTML template strings
 * @noinspection HtmlExtraClosingTag sprintf placeholders break HTML parsing
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

use RuntimeException;
use Zappzarapp\Security\Sri\Exception\FetchException;
use Zappzarapp\Security\Sri\Exception\HashMismatchException;

/**
 * SRI hash generator
 *
 * ## Basic Usage
 *
 * ```php
 * $sri = new SriHashGenerator();
 *
 * // Generate hash from content
 * $integrity = $sri->hash($cssContent);
 * echo '<link rel="stylesheet" href="style.css" integrity="' . $integrity . '">';
 *
 * // Generate hash from file
 * $integrity = $sri->hashFile('/path/to/script.js');
 *
 * // Generate hash from URL
 * $integrity = $sri->hashUrl('https://cdn.example.com/lib.js');
 * ```
 */
final readonly class SriHashGenerator
{
    public function __construct(private HashAlgorithm $defaultAlgorithm = HashAlgorithm::SHA384, private ?ResourceFetcher $fetcher = new ResourceFetcher())
    {
    }

    /**
     * Generate SRI hash from content
     *
     * @param string $content The content to hash
     * @param HashAlgorithm|null $algorithm Algorithm to use (default: SHA384)
     */
    public function hash(string $content, ?HashAlgorithm $algorithm = null): IntegrityAttribute
    {
        return IntegrityAttribute::fromContent($content, $algorithm ?? $this->defaultAlgorithm);
    }

    /**
     * Generate SRI hash from file
     *
     * @param string $path Path to the file
     * @param HashAlgorithm|null $algorithm Algorithm to use
     *
     * @throws RuntimeException If file cannot be read
     */
    public function hashFile(string $path, ?HashAlgorithm $algorithm = null): IntegrityAttribute
    {
        set_error_handler(static fn(): bool => true);
        try {
            $content = file_get_contents($path);
        } finally {
            restore_error_handler();
        }

        if ($content === false) {
            throw new RuntimeException(sprintf('Cannot read file: %s', $path));
        }

        return $this->hash($content, $algorithm);
    }

    /**
     * Generate SRI hash from URL
     *
     * @param string $url URL to fetch
     * @param HashAlgorithm|null $algorithm Algorithm to use
     *
     * @throws FetchException If URL cannot be fetched
     * @throws RuntimeException If no fetcher is configured
     */
    public function hashUrl(string $url, ?HashAlgorithm $algorithm = null): IntegrityAttribute
    {
        if (!$this->fetcher instanceof ResourceFetcher) {
            throw new RuntimeException('ResourceFetcher is required for URL hashing');
        }

        return $this->fetcher->fetchAndHash($url, $algorithm ?? $this->defaultAlgorithm);
    }

    /**
     * Generate multiple hashes for algorithm migration
     *
     * @param string $content The content to hash
     * @param list<HashAlgorithm> $algorithms Algorithms to use
     */
    public function hashMultiple(string $content, array $algorithms): IntegrityAttribute
    {
        if ($algorithms === []) {
            $algorithms = [$this->defaultAlgorithm];
        }

        $integrity = IntegrityAttribute::fromContent($content, $algorithms[0]);
        $counter   = count($algorithms);

        for ($i = 1; $i < $counter; $i++) {
            $hash      = base64_encode(hash($algorithms[$i]->value, $content, true));
            $integrity = $integrity->withHash($algorithms[$i], $hash);
        }

        return $integrity;
    }

    /**
     * Verify content matches an integrity attribute
     *
     * @param string $content The content to verify
     * @param IntegrityAttribute|string $integrity The expected integrity
     *
     * @throws HashMismatchException If content doesn't match
     */
    public function verify(string $content, IntegrityAttribute|string $integrity): void
    {
        if (is_string($integrity)) {
            $integrity = IntegrityAttribute::fromString($integrity);
        }

        if (!$integrity->verify($content)) {
            $actual = $this->hash($content, $integrity->primaryHash()['algorithm']);
            throw HashMismatchException::mismatch(
                $integrity->value(),
                $actual->value()
            );
        }
    }

    /**
     * Check if content matches integrity (without throwing)
     */
    public function isValid(string $content, IntegrityAttribute|string $integrity): bool
    {
        try {
            $this->verify($content, $integrity);

            return true;
        } catch (HashMismatchException) {
            return false;
        }
    }

    /**
     * Generate script tag with SRI
     *
     * @param string $src Script source URL
     * @param IntegrityAttribute|string $integrity Integrity attribute
     * @param CrossOrigin|null $crossOrigin CORS attribute
     */
    public function scriptTag(
        string $src,
        IntegrityAttribute|string $integrity,
        ?CrossOrigin $crossOrigin = CrossOrigin::ANONYMOUS,
    ): string {
        $integrityValue = is_string($integrity) ? $integrity : $integrity->value();
        $corsAttr       = $crossOrigin instanceof CrossOrigin ? ' crossorigin="' . $crossOrigin->attributeValue() . '"' : '';

        return sprintf(
            '<script src="%s" integrity="%s"%s></script>',
            htmlspecialchars($src, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            htmlspecialchars($integrityValue, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            $corsAttr
        );
    }

    /**
     * Generate link tag with SRI (for stylesheets)
     *
     * @param string $href Stylesheet URL
     * @param IntegrityAttribute|string $integrity Integrity attribute
     * @param CrossOrigin|null $crossOrigin CORS attribute
     */
    public function linkTag(
        string $href,
        IntegrityAttribute|string $integrity,
        ?CrossOrigin $crossOrigin = CrossOrigin::ANONYMOUS,
    ): string {
        $integrityValue = is_string($integrity) ? $integrity : $integrity->value();
        $corsAttr       = $crossOrigin instanceof CrossOrigin ? ' crossorigin="' . $crossOrigin->attributeValue() . '"' : '';

        return sprintf(
            '<link rel="stylesheet" href="%s" integrity="%s"%s>',
            htmlspecialchars($href, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            htmlspecialchars($integrityValue, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            $corsAttr
        );
    }
}
