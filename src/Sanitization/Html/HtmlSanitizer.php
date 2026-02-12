<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection HtmlRequiredLangAttribute Internal HTML template for parsing only
 * @noinspection PhpDuplicateMatchArmBodyInspection Match arms intentionally separate for semantic clarity
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Html;

use DOMAttr;
use DOMComment;
use DOMDocument;
use DOMElement;
use DOMNode;
use Override;
use Zappzarapp\Security\Sanitization\InputFilter;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizer;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;

/**
 * HTML sanitizer with XSS prevention
 *
 * Uses DOMDocument for proper parsing to prevent mXSS attacks.
 */
final readonly class HtmlSanitizer implements InputFilter
{
    private InputFilter $uriSanitizer;

    /**
     * @param HtmlSanitizerConfig $config HTML sanitization configuration
     * @param InputFilter|null $uriSanitizer Custom URI sanitizer (default: UriSanitizer with web config)
     */
    public function __construct(
        private HtmlSanitizerConfig $config = new HtmlSanitizerConfig(),
        ?InputFilter $uriSanitizer = null,
    ) {
        $this->uriSanitizer = $uriSanitizer ?? new UriSanitizer(UriSanitizerConfig::web());
    }

    /**
     * @psalm-taint-escape html
     */
    #[Override]
    public function sanitize(string $input): string
    {
        if ($input === '') {
            return '';
        }

        // Validate UTF-8 encoding (mXSS prevention)
        // Invalid UTF-8 sequences can be used to bypass sanitization:
        // - Truncated sequences can hide malicious content
        // - Overlong encodings can bypass character detection
        // - Invalid sequences may be interpreted differently by DOM parser vs browser
        if (!mb_check_encoding($input, 'UTF-8')) {
            return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        // Remove null bytes (XSS vector)
        // Null bytes can truncate strings in some contexts, hiding malicious content
        $input = str_replace("\0", '', $input);

        // If no elements allowed, just escape everything
        if ($this->config->elements->all() === []) {
            return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        // Parse HTML using DOMDocument
        $doc = $this->parseHtml($input);
        if (!$doc instanceof DOMDocument) {
            return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        // Sanitize the DOM
        $body = $doc->getElementsByTagName('body')->item(0);
        if ($body !== null) {
            $this->sanitizeNode($body);
        }

        // Extract sanitized HTML
        return $this->extractHtml($doc);
    }

    #[Override]
    public function isSafe(string $input): bool
    {
        // HTML sanitizer always makes input safe
        return true;
    }

    /**
     * Parse HTML into DOMDocument
     */
    private function parseHtml(string $html): ?DOMDocument
    {
        $doc = new DOMDocument('1.0', 'UTF-8');

        // Suppress errors for malformed HTML
        $internalErrors = libxml_use_internal_errors(true);

        // Wrap in HTML structure for proper parsing
        $wrapped = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>' . $html . '</body></html>';

        $result = $doc->loadHTML($wrapped, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        libxml_clear_errors();
        libxml_use_internal_errors($internalErrors);

        if (!$result) {
            return null;
        }

        return $doc;
    }

    /**
     * Sanitize a DOM node recursively
     *
     * Removes:
     * - Disallowed HTML elements (keeping text content)
     * - HTML comments (security: can hide content, conditional comments)
     */
    private function sanitizeNode(DOMNode $node): void
    {
        // Collect nodes to remove (can't modify during iteration)
        $toRemove           = [];
        $toRemoveCompletely = [];

        /** @var DOMNode $child */
        foreach ($node->childNodes as $child) {
            // Remove HTML comments entirely (security measure)
            // Comments can be used to hide malicious content or exploit
            // conditional comments in older browsers
            if ($child instanceof DOMComment) {
                $toRemoveCompletely[] = $child;
                continue;
            }

            if ($child instanceof DOMElement) {
                $tagName = strtolower($child->tagName);

                // Remove disallowed elements
                if (!$this->config->elements->isAllowed($tagName)) {
                    $toRemove[] = $child;
                    continue;
                }

                // Sanitize attributes
                $this->sanitizeAttributes($child);

                // Recurse into children
                $this->sanitizeNode($child);
            }
        }

        // Remove comments completely
        foreach ($toRemoveCompletely as $comment) {
            $node->removeChild($comment);
        }

        // Remove disallowed elements but keep their text content
        foreach ($toRemove as $element) {
            $this->removeElementKeepContent($element);
        }
    }

    /**
     * Sanitize element attributes
     */
    private function sanitizeAttributes(DOMElement $element): void
    {
        $tagName  = strtolower($element->tagName);
        $toRemove = [];

        $attributes = $element->attributes;

        for ($i = 0; $i < $attributes->length; $i++) {
            $attr = $attributes->item($i);
            if (!$attr instanceof DOMAttr) {
                continue;
            }

            $attrName  = strtolower($attr->name);
            $attrValue = $attr->value;

            // Remove disallowed attributes
            if (!$this->config->attributes->isAllowed($tagName, $attrName)) {
                $toRemove[] = $attr->name;
                continue;
            }

            // Sanitize URL attributes
            if ($this->isUrlAttribute($tagName, $attrName)) {
                $sanitized = $this->uriSanitizer->sanitize($attrValue);
                if ($sanitized === '') {
                    $toRemove[] = $attr->name;
                } else {
                    $element->setAttribute($attr->name, $sanitized);
                }
            }
        }

        foreach ($toRemove as $attrName) {
            $element->removeAttribute($attrName);
        }

        // Add rel="noopener noreferrer" to external links
        if ($tagName === 'a' && $element->hasAttribute('target')) {
            $rel = $element->getAttribute('rel');
            if (!str_contains($rel, 'noopener')) {
                $element->setAttribute('rel', trim($rel . ' noopener noreferrer'));
            }
        }
    }

    /**
     * Check if attribute is a URL that needs sanitization
     *
     * Covers all HTML5 elements with URL attributes to prevent XSS via
     * javascript:, data:, or other dangerous URI schemes.
     *
     * @see https://html.spec.whatwg.org/multipage/indices.html#attributes-3
     */
    private function isUrlAttribute(string $element, string $attribute): bool
    {
        return match ($element) {
            'a', 'area'              => $attribute === 'href',
            'img'                    => $attribute === 'src' || $attribute === 'srcset',
            'form'                   => $attribute === 'action',
            'video'                  => $attribute === 'src' || $attribute === 'poster',
            'audio', 'source'        => $attribute === 'src',
            'track'                  => $attribute === 'src',
            'iframe', 'embed'        => $attribute === 'src',
            'object'                 => $attribute === 'data',
            'input'                  => $attribute === 'src' || $attribute === 'formaction',
            'button'                 => $attribute === 'formaction',
            'link'                   => $attribute === 'href',
            'blockquote', 'q', 'del', 'ins' => $attribute === 'cite',
            default                  => false,
        };
    }

    /**
     * Remove element but keep its text content
     */
    private function removeElementKeepContent(DOMElement $element): void
    {
        $parent = $element->parentNode;
        if ($parent === null) {
            return;
        }

        // Move children before this element
        while ($element->firstChild !== null) {
            $parent->insertBefore($element->firstChild, $element);
        }

        // Remove the empty element
        $parent->removeChild($element);
    }

    /**
     * Extract HTML from body element
     */
    private function extractHtml(DOMDocument $doc): string
    {
        $body = $doc->getElementsByTagName('body')->item(0);
        if ($body === null) {
            return '';
        }

        $html = '';
        /** @var DOMNode $child */
        foreach ($body->childNodes as $child) {
            $html .= $doc->saveHTML($child);
        }

        return $html;
    }
}
