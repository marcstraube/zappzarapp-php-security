<?php

/** @noinspection PhpParamsInspection const array with spread operator correctly produces string[] */

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Html;

/**
 * Allowed HTML elements configuration
 */
final readonly class AllowedElements
{
    /**
     * Basic formatting elements
     */
    private const array BASIC = [
        'p', 'br', 'hr',
        'b', 'i', 'u', 's', 'strong', 'em', 'mark',
        'sub', 'sup',
        'small',
    ];

    /**
     * Structure elements
     */
    private const array STRUCTURE = [
        'div', 'span',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'blockquote', 'pre', 'code',
    ];

    /**
     * List elements
     */
    private const array LISTS = [
        'ul', 'ol', 'li',
        'dl', 'dt', 'dd',
    ];

    /**
     * Link elements
     */
    private const array LINKS = [
        'a', 'img', 'area',
    ];

    /**
     * Media elements (HTML5)
     */
    private const array MEDIA = [
        'video', 'audio', 'source', 'track',
        'picture', 'figure', 'figcaption',
    ];

    /**
     * Citation elements (q, cite, del, ins)
     * Note: blockquote is in STRUCTURE
     */
    private const array CITATIONS = [
        'q', 'cite', 'del', 'ins',
    ];

    /**
     * Table elements
     */
    private const array TABLES = [
        'table', 'thead', 'tbody', 'tfoot',
        'tr', 'th', 'td',
        'caption', 'colgroup', 'col',
    ];

    /**
     * @param list<string> $elements Allowed element names (lowercase)
     */
    public function __construct(
        private array $elements = [],
    ) {
    }

    /**
     * Add elements
     *
     * @param list<string> $elements
     */
    public function with(array $elements): self
    {
        return new self([...$this->elements, ...$elements]);
    }

    /**
     * Get all allowed elements
     *
     * @return list<string>
     */
    public function all(): array
    {
        return $this->elements;
    }

    /**
     * Check if element is allowed
     */
    public function isAllowed(string $element): bool
    {
        return in_array(strtolower($element), $this->elements, true);
    }

    /**
     * Create with basic formatting elements
     */
    public static function basic(): self
    {
        return new self(self::BASIC);
    }

    /**
     * Create with basic + structure elements
     */
    public static function standard(): self
    {
        return new self([...self::BASIC, ...self::STRUCTURE, ...self::LISTS]);
    }

    /**
     * Create with standard + links
     */
    public static function rich(): self
    {
        return new self([...self::BASIC, ...self::STRUCTURE, ...self::LISTS, ...self::LINKS]);
    }

    /**
     * Create with all common elements including media
     */
    public static function full(): self
    {
        return new self([
            ...self::BASIC,
            ...self::STRUCTURE,
            ...self::LISTS,
            ...self::LINKS,
            ...self::MEDIA,
            ...self::CITATIONS,
            ...self::TABLES,
        ]);
    }

    /**
     * Create with no elements (strip all)
     */
    public static function none(): self
    {
        return new self([]);
    }
}
