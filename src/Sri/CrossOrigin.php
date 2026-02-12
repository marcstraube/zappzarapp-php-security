<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

/**
 * CORS attribute values for cross-origin resources
 */
enum CrossOrigin: string
{
    /**
     * Anonymous CORS request (no credentials)
     *
     * Required for SRI on cross-origin resources.
     */
    case ANONYMOUS = 'anonymous';

    /**
     * CORS request with credentials
     *
     * Sends cookies, authorization headers, or TLS client certificates.
     */
    case USE_CREDENTIALS = 'use-credentials';

    /**
     * Get the attribute value
     */
    public function attributeValue(): string
    {
        return $this->value;
    }
}
