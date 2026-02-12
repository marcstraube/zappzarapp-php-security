<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Html;

/**
 * Allowed HTML attributes configuration
 */
final readonly class AllowedAttributes
{
    /**
     * Global attributes allowed on any element
     */
    private const array GLOBAL_SAFE = [
        'id', 'class', 'title', 'lang', 'dir',
    ];

    /**
     * Dangerous attributes that should never be allowed
     */
    private const array DANGEROUS = [
        'onabort', 'onblur', 'onchange', 'onclick', 'ondblclick',
        'onerror', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup',
        'onload', 'onmousedown', 'onmousemove', 'onmouseout',
        'onmouseover', 'onmouseup', 'onreset', 'onresize', 'onselect',
        'onsubmit', 'onunload', 'formaction', 'xlink:href',
    ];

    /**
     * @param array<string, list<string>> $elementAttributes Allowed attributes per element
     * @param list<string> $globalAttributes Attributes allowed on any element
     */
    public function __construct(
        private array $elementAttributes = [],
        private array $globalAttributes = self::GLOBAL_SAFE,
    ) {
    }

    /**
     * Add allowed attributes for an element
     *
     * @param list<string> $attributes
     */
    public function forElement(string $element, array $attributes): self
    {
        $newElementAttrs                       = $this->elementAttributes;
        $newElementAttrs[strtolower($element)] = $attributes;

        return new self($newElementAttrs, $this->globalAttributes);
    }

    /**
     * Check if attribute is allowed on element
     */
    public function isAllowed(string $element, string $attribute): bool
    {
        $element   = strtolower($element);
        $attribute = strtolower($attribute);

        // Never allow dangerous attributes
        if (in_array($attribute, self::DANGEROUS, true)) {
            return false;
        }

        // Never allow on* event handlers
        if (str_starts_with($attribute, 'on')) {
            return false;
        }

        // Check global attributes
        if (in_array($attribute, $this->globalAttributes, true)) {
            return true;
        }

        // Check element-specific attributes
        if (isset($this->elementAttributes[$element])) {
            return in_array($attribute, $this->elementAttributes[$element], true);
        }

        return false;
    }

    /**
     * Get allowed attributes for an element
     *
     * @return list<string>
     */
    public function forElementList(string $element): array
    {
        $element      = strtolower($element);
        $elementAttrs = $this->elementAttributes[$element] ?? [];

        return [...$this->globalAttributes, ...$elementAttrs];
    }

    /**
     * Create standard configuration
     *
     * Includes common elements with their URL attributes for proper sanitization.
     */
    public static function standard(): self
    {
        return (new self())
            ->forElement('a', ['href', 'target', 'rel'])
            ->forElement('area', ['href', 'alt', 'shape', 'coords', 'target', 'rel'])
            ->forElement('img', ['src', 'srcset', 'alt', 'width', 'height', 'loading'])
            ->forElement('video', ['src', 'poster', 'width', 'height', 'controls', 'autoplay', 'loop', 'muted', 'preload'])
            ->forElement('audio', ['src', 'controls', 'autoplay', 'loop', 'muted', 'preload'])
            ->forElement('source', ['src', 'type', 'media', 'srcset', 'sizes'])
            ->forElement('track', ['src', 'kind', 'srclang', 'label', 'default'])
            ->forElement('blockquote', ['cite'])
            ->forElement('q', ['cite'])
            ->forElement('del', ['cite', 'datetime'])
            ->forElement('ins', ['cite', 'datetime'])
            ->forElement('td', ['colspan', 'rowspan'])
            ->forElement('th', ['colspan', 'rowspan', 'scope']);
    }

    /**
     * Create minimal configuration
     */
    public static function minimal(): self
    {
        return new self([], ['id', 'class']);
    }
}
