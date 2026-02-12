<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie;

/**
 * SameSite cookie attribute values
 *
 * Controls when cookies are sent with cross-site requests.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
 */
enum SameSitePolicy: string
{
    /**
     * Cookie is sent with all requests (including cross-site)
     *
     * Least secure. Requires Secure attribute in modern browsers.
     * Use only when cross-site functionality is required.
     */
    case NONE = 'None';

    /**
     * Cookie is sent with top-level navigations and GET from external sites
     *
     * Provides reasonable protection while allowing links to work.
     * Default value in modern browsers if not specified.
     */
    case LAX = 'Lax';

    /**
     * Cookie is only sent with same-site requests
     *
     * Most secure. Prevents CSRF attacks completely.
     * Recommended for session cookies and sensitive operations.
     */
    case STRICT = 'Strict';

    /**
     * Get the attribute value for Set-Cookie header
     *
     * @return 'Lax'|'None'|'Strict'
     */
    public function attributeValue(): string
    {
        return $this->value;
    }
}
