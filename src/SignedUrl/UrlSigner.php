<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl;

use Psr\Clock\ClockInterface;
use SodiumException;
use Zappzarapp\Security\Password\Security\ClearsMemory;
use Zappzarapp\Security\SignedUrl\Exception\InvalidContextException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidLifetimeException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidSignatureException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidUrlException;
use Zappzarapp\Security\SignedUrl\Exception\UrlExpiredException;

/**
 * HMAC-SHA-256 signed URLs with mandatory expiry
 *
 * Secure by design:
 *
 * - Expiry is mandatory. There deliberately is no way to sign a URL
 *   without one: a signed URL is a bearer capability, and an unbounded
 *   one is a credential that can never be revoked. Long-lived links must
 *   pass an explicitly long lifetime, keeping the decision visible at the
 *   call site.
 * - The signature covers scheme, host, port, path and every query
 *   parameter in its original position, so no parameter can be added,
 *   removed or reordered without invalidating it (no parameter smuggling,
 *   no reordering of repeated keys under last-wins parsers).
 * - An optional context value (user id, IP address, ...) is mixed into
 *   the MAC, binding the URL to that context without exposing it.
 * - Signatures are compared in constant time via hash_equals().
 * - Verification is total over attacker-controlled URL strings: malformed
 *   input throws typed exceptions, never PHP warnings or errors.
 *
 * ## Canonical MAC input (wire contract, version 1)
 *
 * ```text
 * input = enc("zappzarapp-signed-url-v1")
 *       . enc(scheme) . enc(host) . enc(port)
 *       . enc(path) . enc(query) . enc(expiry)
 *       . enc(contextFlag) . enc(context)
 *
 * enc(x)      = decimal byte length of x, ":", x   (e.g. "4:http")
 * scheme      = lowercased URL scheme ("http" or "https")
 * host        = lowercased URL host
 * port        = decimal effective port (explicit port, else 80/443)
 * path        = raw URL path, "" normalized to "/"
 * query       = query pairs without the reserved parameters, in their
 *               original order, each key and value rawurldecode()d then
 *               rawurlencode()d, encoded as "key=value" - or as bare "key"
 *               when the pair has no "=" separator - "&"-separated
 *               ("+" is NOT treated as space)
 * expiry      = decimal Unix timestamp of the expiry
 * contextFlag = "1" when a context is bound, "0" otherwise
 * context     = the context value, or "" when none is bound
 *
 * signature = base64url(HMAC-SHA-256(key, input)) without padding
 * ```
 *
 * The length prefix delimits every component, so no two distinct URLs
 * (or context bindings) share a MAC input. The signed URL is valid up to
 * and including the expiry timestamp.
 *
 * Order binding applies to the NON-RESERVED parameters: the reserved
 * zzp_expires / zzp_signature parameters are consumed by the verifier,
 * so their position within the query string is semantically irrelevant
 * and deliberately not covered by the signature (cf. AWS SigV4).
 *
 * ## Usage
 *
 * ```php
 * $signer = new UrlSigner(SigningKey::generate());
 *
 * $signed = $signer->sign('https://example.com/download?file=report.pdf', 3600);
 * // https://example.com/download?file=report.pdf&zzp_expires=...&zzp_signature=...
 *
 * $signer->verify($signed); // throws on tampering or expiry
 * ```
 */
final readonly class UrlSigner
{
    use ClearsMemory;

    /**
     * Reserved query parameter carrying the expiry timestamp
     */
    public const string EXPIRES_PARAM = 'zzp_expires';

    /**
     * Reserved query parameter carrying the signature
     */
    public const string SIGNATURE_PARAM = 'zzp_signature';

    /**
     * Version tag bound into the MAC - bump on any wire contract change
     */
    private const string VERSION = 'zappzarapp-signed-url-v1';

    /**
     * Maximum lifetime (100 years) - keeps now() + lifetime far away from
     * integer overflow and the expiry digit cap
     */
    public const int MAX_LIFETIME_SECONDS = 3_153_600_000;

    /**
     * Longest accepted expiry value - 18 decimal digits always fit in a
     * 64-bit integer, so the (int) cast can never overflow
     */
    private const int MAX_EXPIRY_DIGITS = 18;

    /**
     * Matches a "%" that is not followed by two hex digits
     */
    private const string MALFORMED_PERCENT = '/%(?![0-9A-Fa-f]{2})/';

    /**
     * Matches ASCII control characters (header injection guard)
     */
    private const string CONTROL_CHARACTERS = '/[\x00-\x1F\x7F]/';

    /**
     * @param SigningKey $key The HMAC signing key
     * @param ClockInterface|null $clock Optional PSR-20 clock (system time when null)
     */
    public function __construct(
        private SigningKey $key,
        private ?ClockInterface $clock = null,
    ) {
    }

    /**
     * Sign a URL, appending expiry and signature query parameters
     *
     * @param string $url Absolute http(s) URL without fragment or user info
     * @param int $lifetimeSeconds Seconds until the signed URL expires
     * @param string|null $context Optional value the URL is bound to (user id, IP, ...)
     *
     * @throws InvalidLifetimeException If the lifetime is not positive or exceeds the maximum
     * @throws InvalidContextException If the context contains control characters
     * @throws InvalidUrlException If the URL is malformed, non-http(s), or
     *                             already carries a reserved parameter
     * @throws SodiumException If the underlying sodium encoding fails
     */
    public function sign(string $url, int $lifetimeSeconds, ?string $context = null): string
    {
        if ($lifetimeSeconds < 1) {
            throw InvalidLifetimeException::nonPositive($lifetimeSeconds);
        }

        if ($lifetimeSeconds > self::MAX_LIFETIME_SECONDS) {
            throw InvalidLifetimeException::exceedsMaximum($lifetimeSeconds, self::MAX_LIFETIME_SECONDS);
        }

        $this->assertContextIsSafe($context);
        $canonical = $this->parse($url);

        foreach ($canonical['pairs'] as $pair) {
            if ($pair[0] === self::EXPIRES_PARAM || $pair[0] === self::SIGNATURE_PARAM) {
                throw InvalidUrlException::reservedParameter($pair[0]);
            }
        }

        $expiresAt = $this->now() + $lifetimeSeconds;
        $signature = $this->signature($canonical, $expiresAt, $context);
        $separator = str_contains($url, '?') ? '&' : '?';

        if (str_ends_with($url, '?') || str_ends_with($url, '&')) {
            $separator = '';
        }

        return $url . $separator
            . self::EXPIRES_PARAM . '=' . $expiresAt
            . '&' . self::SIGNATURE_PARAM . '=' . $signature;
    }

    /**
     * Verify a signed URL
     *
     * The signature is checked before the expiry so that unauthenticated
     * input reveals nothing about timestamp validity.
     *
     * @param string $url The signed URL to verify
     * @param string|null $context The context value passed to sign(), if any
     *
     * @throws InvalidContextException If the context contains control characters
     * @throws InvalidUrlException If the URL is malformed, non-http(s), or the
     *                             reserved parameters are missing, duplicated
     *                             or malformed
     * @throws InvalidSignatureException If the signature does not match
     * @throws UrlExpiredException If the signature matches but the URL has expired
     * @throws SodiumException If the underlying sodium encoding fails
     */
    public function verify(string $url, ?string $context = null): void
    {
        $this->assertContextIsSafe($context);
        $canonical = $this->parse($url);

        [$pairs, $expiryValues, $signatureValues] = $this->extractReservedParameters($canonical['pairs']);

        $signature = $this->exactlyOne($signatureValues, self::SIGNATURE_PARAM);
        $expiresAt = $this->parseExpiry($this->exactlyOne($expiryValues, self::EXPIRES_PARAM));

        $canonical['pairs'] = $pairs;

        if (!hash_equals($this->signature($canonical, $expiresAt, $context), $signature)) {
            throw InvalidSignatureException::mismatch();
        }

        $now = $this->now();

        if ($now > $expiresAt) {
            throw UrlExpiredException::expiredAt($expiresAt, $now);
        }
    }

    /**
     * Parse and canonicalize a URL
     *
     * @return array{scheme: string, host: string, port: int, path: string, pairs: list<array{string, string, bool}>}
     *
     * @throws InvalidUrlException If the URL violates the signing rules
     */
    private function parse(string $url): array
    {
        if (preg_match(self::CONTROL_CHARACTERS, $url) === 1) {
            throw InvalidUrlException::containsControlCharacters();
        }

        $parts = parse_url($url);

        if ($parts === false) {
            throw InvalidUrlException::malformed();
        }

        if (!isset($parts['scheme'])) {
            throw InvalidUrlException::missingScheme();
        }

        $scheme = strtolower($parts['scheme']);

        if ($scheme !== 'http' && $scheme !== 'https') {
            throw InvalidUrlException::unsupportedScheme($scheme);
        }

        if (!isset($parts['host']) || $parts['host'] === '') {
            throw InvalidUrlException::missingHost();
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw InvalidUrlException::userInfoNotAllowed();
        }

        if (isset($parts['fragment'])) {
            throw InvalidUrlException::fragmentNotAllowed();
        }

        $path = $parts['path'] ?? '';

        if ($path === '') {
            $path = '/';
        }

        $query = $parts['query'] ?? '';

        $this->assertWellFormedPercentEncoding($path);
        $this->assertWellFormedPercentEncoding($query);

        return [
            'scheme' => $scheme,
            'host'   => strtolower($parts['host']),
            'port'   => $parts['port'] ?? ($scheme === 'https' ? 443 : 80),
            'path'   => $path,
            'pairs'  => $this->queryPairs($query),
        ];
    }

    /**
     * Reject malformed percent-encoding - rawurldecode() would leave
     * invalid sequences untouched, making "%ZZ" and "%25ZZ" canonicalize
     * identically and the URL string malleable
     *
     * @throws InvalidUrlException If a "%" is not followed by two hex digits
     */
    private function assertWellFormedPercentEncoding(string $component): void
    {
        if (preg_match(self::MALFORMED_PERCENT, $component) === 1) {
            throw InvalidUrlException::malformedPercentEncoding();
        }
    }

    /**
     * Split a raw query string into decoded key/value pairs
     *
     * Duplicate keys are preserved, empty segments ("a&&b") are skipped,
     * and "+" is not treated as a space. The third element records whether
     * the pair carried an "=" separator, so "?flag" and "?flag=" stay
     * distinguishable in the MAC input.
     *
     * @return list<array{string, string, bool}>
     */
    private function queryPairs(string $query): array
    {
        $pairs = [];

        foreach (explode('&', $query) as $segment) {
            if ($segment === '') {
                continue;
            }

            $position = strpos($segment, '=');

            if ($position === false) {
                $pairs[] = [rawurldecode($segment), '', false];

                continue;
            }

            $pairs[] = [
                rawurldecode(substr($segment, 0, $position)),
                rawurldecode(substr($segment, $position + 1)),
                true,
            ];
        }

        return $pairs;
    }

    /**
     * Split query pairs into payload pairs and the reserved parameter values
     *
     * @param list<array{string, string, bool}> $pairs
     *
     * @return array{list<array{string, string, bool}>, list<string>, list<string>}
     */
    private function extractReservedParameters(array $pairs): array
    {
        $payload    = [];
        $expiry     = [];
        $signatures = [];

        foreach ($pairs as $pair) {
            if ($pair[0] === self::EXPIRES_PARAM) {
                $expiry[] = $pair[1];
            } elseif ($pair[0] === self::SIGNATURE_PARAM) {
                $signatures[] = $pair[1];
            } else {
                $payload[] = $pair;
            }
        }

        return [$payload, $expiry, $signatures];
    }

    /**
     * Require exactly one occurrence of a reserved parameter
     *
     * @param list<string> $values
     *
     * @throws InvalidUrlException If the parameter is missing or duplicated
     */
    private function exactlyOne(array $values, string $name): string
    {
        if ($values === []) {
            throw InvalidUrlException::missingParameter($name);
        }

        if (count($values) > 1) {
            throw InvalidUrlException::duplicateParameter($name);
        }

        return $values[0];
    }

    /**
     * Parse an expiry parameter value into a Unix timestamp
     *
     * @throws InvalidUrlException If the value is not a plain decimal timestamp
     */
    private function parseExpiry(string $value): int
    {
        if (!ctype_digit($value) || strlen($value) > self::MAX_EXPIRY_DIGITS) {
            throw InvalidUrlException::malformedExpiry($value);
        }

        $expiresAt = (int) $value;

        if ((string) $expiresAt !== $value) {
            // Leading zeros would make the URL string malleable without
            // changing the MAC input - only the canonical form is accepted
            throw InvalidUrlException::malformedExpiry($value);
        }

        return $expiresAt;
    }

    /**
     * Compute the base64url-encoded HMAC-SHA-256 signature
     *
     * @param array{scheme: string, host: string, port: int, path: string, pairs: list<array{string, string, bool}>} $canonical
     *
     * @throws SodiumException If the underlying sodium encoding fails
     */
    private function signature(array $canonical, int $expiresAt, ?string $context): string
    {
        $input = $this->encode(self::VERSION)
            . $this->encode($canonical['scheme'])
            . $this->encode($canonical['host'])
            . $this->encode((string) $canonical['port'])
            . $this->encode($canonical['path'])
            . $this->encode($this->canonicalQuery($canonical['pairs']))
            . $this->encode((string) $expiresAt)
            . $this->encode($context === null ? '0' : '1')
            . $this->encode($context ?? '');

        $keyBytes = $this->key->bytes();

        try {
            $mac = hash_hmac('sha256', $input, $keyBytes, true);
        } finally {
            $this->clearMemory($keyBytes);
        }

        return sodium_bin2base64($mac, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Build the canonical query component from decoded pairs
     *
     * Pairs are kept in their original order: the signer produces the URL
     * and the verifier receives it back, so order-tolerance buys nothing -
     * and sorting would let an attacker reorder repeated keys (last-wins
     * parsers, PHP array parameters) without invalidating the signature.
     * Pairs without an "=" separator are encoded as a bare key, keeping
     * "?flag" and "?flag=" distinguishable.
     *
     * @param list<array{string, string, bool}> $pairs
     */
    private function canonicalQuery(array $pairs): string
    {
        $encoded = array_map(
            static fn (array $pair): string => $pair[2]
                ? rawurlencode($pair[0]) . '=' . rawurlencode($pair[1])
                : rawurlencode($pair[0]),
            $pairs
        );

        return implode('&', $encoded);
    }

    /**
     * Length-prefix a MAC input component (e.g. "4:http")
     */
    private function encode(string $component): string
    {
        return strlen($component) . ':' . $component;
    }

    /**
     * Reject control characters in the context binding value
     *
     * @throws InvalidContextException If the context contains control characters
     */
    private function assertContextIsSafe(?string $context): void
    {
        if ($context !== null && preg_match(self::CONTROL_CHARACTERS, $context) === 1) {
            throw InvalidContextException::containsControlCharacters();
        }
    }

    /**
     * Current Unix timestamp from the injected clock or system time
     */
    private function now(): int
    {
        if (!$this->clock instanceof ClockInterface) {
            return time();
        }

        return $this->clock->now()->getTimestamp();
    }
}
