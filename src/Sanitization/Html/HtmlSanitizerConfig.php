<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Html;

/**
 * HTML sanitizer configuration
 */
final readonly class HtmlSanitizerConfig
{
    public function __construct(
        public AllowedElements $elements = new AllowedElements(),
        public AllowedAttributes $attributes = new AllowedAttributes(),
        public bool $removeEmpty = false,
        public bool $balanceTags = true,
    ) {
    }

    /**
     * Create with allowed elements
     */
    public function withElements(AllowedElements $elements): self
    {
        return new self($elements, $this->attributes, $this->removeEmpty, $this->balanceTags);
    }

    /**
     * Create with allowed attributes
     */
    public function withAttributes(AllowedAttributes $attributes): self
    {
        return new self($this->elements, $attributes, $this->removeEmpty, $this->balanceTags);
    }

    /**
     * Create basic configuration
     */
    public static function basic(): self
    {
        return new self(
            AllowedElements::basic(),
            AllowedAttributes::minimal()
        );
    }

    /**
     * Create standard configuration
     */
    public static function standard(): self
    {
        return new self(
            AllowedElements::standard(),
            AllowedAttributes::standard()
        );
    }

    /**
     * Create rich configuration (with links/images)
     */
    public static function rich(): self
    {
        return new self(
            AllowedElements::rich(),
            AllowedAttributes::standard()
        );
    }

    /**
     * Create strip-all configuration
     */
    public static function stripAll(): self
    {
        return new self(
            AllowedElements::none(),
            AllowedAttributes::minimal()
        );
    }
}
