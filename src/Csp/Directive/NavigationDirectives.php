<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Directive;

use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\Validation\ValidatesDirectiveValues;

/**
 * CSP Document Navigation Directives
 *
 * Controls document navigation: embedding restrictions, base URL, form submissions.
 * Immutable value object with fluent API.
 *
 * @psalm-api
 */
final readonly class NavigationDirectives
{
    use ValidatesDirectiveValues;

    /**
     * @param string $frameAncestors Embedding restrictions (frame-ancestors)
     * @param string $baseUri Base URL restrictions (base-uri)
     * @param string $formAction Form submission restrictions (form-action)
     * @throws InvalidDirectiveValueException If values contain injection characters
     */
    public function __construct(
        public string $frameAncestors = "'self'",
        public string $baseUri = "'self'",
        public string $formAction = "'self'",
    ) {
        $this->validate();
    }

    /**
     * Validate all directive values for injection attacks
     *
     * @throws InvalidDirectiveValueException If any value contains semicolon or newline
     */
    private function validate(): void
    {
        $this->validateDirectiveValue('frame-ancestors', $this->frameAncestors);
        $this->validateDirectiveValue('base-uri', $this->baseUri);
        $this->validateDirectiveValue('form-action', $this->formAction);
    }

    /**
     * Create new instance with modified frame-ancestors
     *
     * @psalm-api
     */
    public function withFrameAncestors(string $value): self
    {
        return $this->cloneWith(frameAncestors: $value);
    }

    /**
     * Create new instance with modified base-uri
     *
     * @psalm-api
     */
    public function withBaseUri(string $value): self
    {
        return $this->cloneWith(baseUri: $value);
    }

    /**
     * Create new instance with modified form-action
     *
     * @psalm-api
     */
    public function withFormAction(string $value): self
    {
        return $this->cloneWith(formAction: $value);
    }

    /**
     * Create a clone with specified property overrides
     */
    private function cloneWith(
        ?string $frameAncestors = null,
        ?string $baseUri = null,
        ?string $formAction = null,
    ): self {
        return new self(
            frameAncestors: $frameAncestors ?? $this->frameAncestors,
            baseUri: $baseUri ?? $this->baseUri,
            formAction: $formAction ?? $this->formAction,
        );
    }
}
