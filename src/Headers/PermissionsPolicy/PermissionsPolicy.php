<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\PermissionsPolicy;

/**
 * Immutable Permissions-Policy configuration
 *
 * Builds the Permissions-Policy header value from directives.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
 */
final readonly class PermissionsPolicy
{
    /**
     * @param array<string, PermissionDirective> $directives Directives indexed by feature name
     */
    public function __construct(
        private array $directives = [],
    ) {
    }

    /**
     * Add or replace a directive
     */
    public function withDirective(PermissionDirective $directive): self
    {
        $newDirectives                                       = $this->directives;
        $newDirectives[$directive->feature->directiveName()] = $directive;

        return new self($newDirectives);
    }

    /**
     * Block a feature entirely
     */
    public function withBlocked(PermissionFeature $feature): self
    {
        return $this->withDirective(PermissionDirective::blocked($feature));
    }

    /**
     * Allow a feature for self only
     */
    public function withSelf(PermissionFeature $feature): self
    {
        return $this->withDirective(PermissionDirective::self($feature));
    }

    /**
     * Allow a feature for all origins
     */
    public function withAll(PermissionFeature $feature): self
    {
        return $this->withDirective(PermissionDirective::all($feature));
    }

    /**
     * Allow a feature for specific origins
     *
     * @param list<string> $origins
     */
    public function withOrigins(PermissionFeature $feature, array $origins): self
    {
        return $this->withDirective(PermissionDirective::origins($feature, $origins));
    }

    /**
     * Get all directives
     *
     * @return array<string, PermissionDirective>
     */
    public function directives(): array
    {
        return $this->directives;
    }

    /**
     * Get a specific directive
     */
    public function directive(PermissionFeature $feature): ?PermissionDirective
    {
        return $this->directives[$feature->directiveName()] ?? null;
    }

    /**
     * Check if a feature is blocked
     */
    public function isBlocked(PermissionFeature $feature): bool
    {
        $directive = $this->directive($feature);

        return $directive instanceof PermissionDirective && $directive->isBlocked();
    }

    /**
     * Build the header value string
     */
    public function headerValue(): string
    {
        if ($this->directives === []) {
            return '';
        }

        $parts = [];
        foreach ($this->directives as $directive) {
            $parts[] = $directive->build();
        }

        return implode(', ', $parts);
    }

    /**
     * Create strict policy (blocks most features)
     *
     * Blocks: camera, microphone, geolocation, payment, usb, bluetooth,
     * and other sensitive APIs. Allows: fullscreen, picture-in-picture for self.
     */
    public static function strict(): self
    {
        return (new self())
            ->withBlocked(PermissionFeature::CAMERA)
            ->withBlocked(PermissionFeature::MICROPHONE)
            ->withBlocked(PermissionFeature::GEOLOCATION)
            ->withBlocked(PermissionFeature::PAYMENT)
            ->withBlocked(PermissionFeature::USB)
            ->withBlocked(PermissionFeature::BLUETOOTH)
            ->withBlocked(PermissionFeature::SERIAL)
            ->withBlocked(PermissionFeature::HID)
            ->withBlocked(PermissionFeature::DISPLAY_CAPTURE)
            ->withSelf(PermissionFeature::FULLSCREEN)
            ->withSelf(PermissionFeature::PICTURE_IN_PICTURE);
    }

    /**
     * Create moderate policy (blocks high-risk, allows common)
     */
    public static function moderate(): self
    {
        return (new self())
            ->withBlocked(PermissionFeature::CAMERA)
            ->withBlocked(PermissionFeature::MICROPHONE)
            ->withBlocked(PermissionFeature::GEOLOCATION)
            ->withBlocked(PermissionFeature::USB)
            ->withBlocked(PermissionFeature::BLUETOOTH)
            ->withBlocked(PermissionFeature::SERIAL)
            ->withSelf(PermissionFeature::FULLSCREEN)
            ->withSelf(PermissionFeature::PICTURE_IN_PICTURE)
            ->withSelf(PermissionFeature::AUTOPLAY)
            ->withSelf(PermissionFeature::CLIPBOARD_WRITE);
    }

    /**
     * Create empty policy (no restrictions)
     */
    public static function empty(): self
    {
        return new self();
    }
}
