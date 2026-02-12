<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Nonce;
use Random\RandomException;

/**
 * Request-scoped nonce management for async environments
 *
 * This class provides explicit lifecycle management for CSP nonces,
 * solving the static state problem in async environments like Swoole,
 * RoadRunner, or PHP Fibers.
 *
 * ## Problem
 *
 * NonceRegistry uses static state, which can leak between requests
 * in long-running PHP processes (async workers, coroutines).
 *
 * ## Solution
 *
 * NonceScope provides RAII-style cleanup: the nonce is automatically
 * reset when the scope ends, preventing cross-request contamination.
 *
 * ## Usage with Swoole/RoadRunner
 *
 * ```php
 * $server->on('request', function ($request, $response) {
 *     $scope = NonceScope::start();
 *     try {
 *         // All nonce operations use the scoped generator
 *         $nonce = $scope->get();
 *         // ... handle request ...
 *     } finally {
 *         $scope->end();
 *     }
 * });
 * ```
 *
 * ## Usage with PHP 8.1+ Fibers
 *
 * ```php
 * $fiber = new Fiber(function () {
 *     $scope = NonceScope::start();
 *     try {
 *         // Fiber-local nonce handling
 *         $nonce = $scope->get();
 *         Fiber::suspend($response);
 *     } finally {
 *         $scope->end();
 *     }
 * });
 * ```
 *
 * ## Framework Middleware Example
 *
 * ```php
 * class CspMiddleware implements MiddlewareInterface
 * {
 *     public function process(Request $request, Handler $handler): Response
 *     {
 *         $scope = NonceScope::start();
 *         try {
 *             return $handler->handle($request->withAttribute('csp-nonce', $scope->get()));
 *         } finally {
 *             $scope->end();
 *         }
 *     }
 * }
 * ```
 *
 * @see NonceRegistry For traditional (non-async) PHP applications
 * @see NonceGenerator For dependency-injected nonce generation
 */
final class NonceScope
{
    private bool $ended = false;

    private function __construct(
        private readonly NonceGenerator $generator,
    ) {
    }

    /**
     * Start a new nonce scope
     *
     * Creates a fresh NonceGenerator and resets the global NonceRegistry.
     * This ensures complete isolation from any previous request state.
     *
     * @return self The scoped nonce manager
     */
    public static function start(): self
    {
        // Reset any existing global state
        NonceRegistry::reset();

        return new self(new NonceGenerator());
    }

    /**
     * Start a scope with a pre-existing nonce value
     *
     * Use when a nonce has already been generated (e.g., by upstream middleware).
     *
     * @param string $nonce Pre-existing nonce value
     *
     * @return self The scoped nonce manager
     */
    public static function withNonce(string $nonce): self
    {
        NonceRegistry::reset();
        $generator = new NonceGenerator();
        $generator->set($nonce);

        return new self($generator);
    }

    /**
     * Get the nonce value for this scope
     *
     * Generates the nonce on first call, then returns the same value
     * for all subsequent calls within this scope.
     *
     * @return string The base64-encoded nonce value
     *
     * @throws RandomException If no suitable random source is available
     */
    public function get(): string
    {
        return $this->generator->get();
    }

    /**
     * Get the underlying NonceGenerator
     *
     * Use this when you need to pass the generator to HeaderBuilder
     * or other components that accept NonceGenerator.
     *
     * @return NonceGenerator The scoped generator instance
     */
    public function generator(): NonceGenerator
    {
        return $this->generator;
    }

    /**
     * End the scope and reset global state
     *
     * This MUST be called when the request ends, typically in a finally block.
     * Failing to call this in async environments will cause nonce leakage.
     */
    public function end(): void
    {
        if ($this->ended) {
            return;
        }

        $this->ended = true;
        NonceRegistry::reset();
    }

    /**
     * Check if this scope has been ended
     */
    public function hasEnded(): bool
    {
        return $this->ended;
    }
}
