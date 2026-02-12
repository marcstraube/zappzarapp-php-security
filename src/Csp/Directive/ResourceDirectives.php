<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Directive;

use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\Validation\ValidatesDirectiveValues;

/**
 * CSP Resource Fetch Directives
 *
 * Controls where the application can load resources from (images, fonts, connections).
 * Immutable value object with fluent API.
 *
 * @psalm-api
 */
final readonly class ResourceDirectives
{
    use ValidatesDirectiveValues;

    /**
     * @param string $img Image sources (img-src)
     * @param string $font Font sources (font-src)
     * @param string $connect Connection sources for fetch, XHR, WebSocket (connect-src)
     * @param string $media Media sources for audio/video (media-src)
     * @param string $worker Web Worker sources (worker-src)
     * @param string $child Nested browsing context sources (child-src) - workers and frames
     * @param string $frame Frame/iframe sources (frame-src) - only frames
     * @param string $manifest Web app manifest sources (manifest-src)
     * @throws InvalidDirectiveValueException If values contain injection characters
     */
    public function __construct(
        public string $img = "'self' data:",
        public string $font = "'self'",
        public string $connect = "'self'",
        public string $media = "'self'",
        public string $worker = "'self'",
        public string $child = "'self'",
        public string $frame = "'self'",
        public string $manifest = "'self'",
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
        $this->validateDirectiveValue('img-src', $this->img);
        $this->validateDirectiveValue('font-src', $this->font);
        $this->validateDirectiveValue('connect-src', $this->connect);
        $this->validateDirectiveValue('media-src', $this->media);
        $this->validateDirectiveValue('worker-src', $this->worker);
        $this->validateDirectiveValue('child-src', $this->child);
        $this->validateDirectiveValue('frame-src', $this->frame);
        $this->validateDirectiveValue('manifest-src', $this->manifest);
    }

    /**
     * Create new instance with modified img-src
     *
     * @psalm-api
     */
    public function withImg(string $value): self
    {
        return $this->cloneWith(img: $value);
    }

    /**
     * Create new instance with modified font-src
     *
     * @psalm-api
     */
    public function withFont(string $value): self
    {
        return $this->cloneWith(font: $value);
    }

    /**
     * Create new instance with modified connect-src
     *
     * @psalm-api
     */
    public function withConnect(string $value): self
    {
        return $this->cloneWith(connect: $value);
    }

    /**
     * Create new instance with modified media-src
     *
     * @psalm-api
     */
    public function withMedia(string $value): self
    {
        return $this->cloneWith(media: $value);
    }

    /**
     * Create new instance with modified worker-src
     *
     * @psalm-api
     */
    public function withWorker(string $value): self
    {
        return $this->cloneWith(worker: $value);
    }

    /**
     * Create new instance with modified child-src
     *
     * @psalm-api
     */
    public function withChild(string $value): self
    {
        return $this->cloneWith(child: $value);
    }

    /**
     * Create new instance with modified frame-src
     *
     * @psalm-api
     */
    public function withFrame(string $value): self
    {
        return $this->cloneWith(frame: $value);
    }

    /**
     * Create new instance with modified manifest-src
     *
     * @psalm-api
     */
    public function withManifest(string $value): self
    {
        return $this->cloneWith(manifest: $value);
    }

    /**
     * Create a clone with specified property overrides
     */
    private function cloneWith(
        ?string $img = null,
        ?string $font = null,
        ?string $connect = null,
        ?string $media = null,
        ?string $worker = null,
        ?string $child = null,
        ?string $frame = null,
        ?string $manifest = null,
    ): self {
        return new self(
            img: $img ?? $this->img,
            font: $font ?? $this->font,
            connect: $connect ?? $this->connect,
            media: $media ?? $this->media,
            worker: $worker ?? $this->worker,
            child: $child ?? $this->child,
            frame: $frame ?? $this->frame,
            manifest: $manifest ?? $this->manifest,
        );
    }
}
